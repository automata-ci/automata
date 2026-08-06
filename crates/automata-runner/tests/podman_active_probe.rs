use std::{
    ffi::OsString,
    fs,
    net::SocketAddr,
    path::{Path, PathBuf},
    sync::Mutex,
    time::Duration,
};

#[cfg(all(target_os = "linux", target_env = "gnu"))]
use automata_runner::podman_probe::ElfScratchExecutableInspector;
use automata_runner::{
    capability_probe::{
        PODMAN_NETWORK_ISOLATION, ProbeReasonCode, ProbeStatus, usable_capabilities,
    },
    podman_probe::{
        ActiveProbeLimits, ActiveProbePlan, CommandExecutor, CommandOutput, CommandRequest,
        CommandTermination, ProbeCancellation, ReadinessProbe, ScratchCompatibility,
        ScratchExecutableInspector, SystemCommandExecutor, run_active_podman_probe_with,
        run_active_podman_probe_with_control,
    },
};
use uuid::Uuid;

#[cfg(unix)]
static SYSTEM_EXECUTOR_TEST_LOCK: Mutex<()> = Mutex::new(());

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
enum FakeMode {
    #[default]
    Success,
    FailNetworkCreate,
    TimeoutContainerRun,
    FailNetworkCleanup,
    NetworkOwnerMismatch,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ProvisioningStage {
    RootlessInfo,
    NetworkCreate,
    ImageBuild,
    ContainerRun,
    PortLookup,
}

#[derive(Clone, Debug)]
struct RecordedCommand {
    program: OsString,
    arguments: Vec<String>,
    timeout: Duration,
    output_limit: usize,
    cleanup: bool,
    cancellation_observed: bool,
}

#[derive(Debug, Default)]
struct FakeCommandExecutor {
    mode: FakeMode,
    cancel_after: Option<ProvisioningStage>,
    force_during_first_cleanup: bool,
    commands: Mutex<Vec<RecordedCommand>>,
    containerfile: Mutex<Option<String>>,
}

impl FakeCommandExecutor {
    fn with_mode(mode: FakeMode) -> Self {
        Self {
            mode,
            ..Self::default()
        }
    }

    fn cancelling_after(stage: ProvisioningStage) -> Self {
        Self {
            cancel_after: Some(stage),
            ..Self::default()
        }
    }

    fn forcing_during_first_cleanup() -> Self {
        Self {
            force_during_first_cleanup: true,
            ..Self::default()
        }
    }

    fn recorded(&self) -> Vec<RecordedCommand> {
        self.commands.lock().expect("commands lock").clone()
    }

    fn captured_containerfile(&self) -> Option<String> {
        self.containerfile
            .lock()
            .expect("Containerfile lock")
            .clone()
    }
}

impl CommandExecutor for FakeCommandExecutor {
    fn execute(&self, request: &CommandRequest, cancellation: &ProbeCancellation) -> CommandOutput {
        let arguments = request
            .arguments()
            .iter()
            .map(|argument| argument.to_string_lossy().into_owned())
            .collect::<Vec<_>>();
        self.commands
            .lock()
            .expect("commands lock")
            .push(RecordedCommand {
                program: request.program().to_owned(),
                arguments: arguments.clone(),
                timeout: request.timeout(),
                output_limit: request.output_limit(),
                cleanup: request.is_cleanup(),
                cancellation_observed: cancellation.is_cancelled(),
            });
        if request.is_cleanup()
            && self.force_during_first_cleanup
            && cancellation.signal_count() == 1
        {
            cancellation.cancel();
        }

        let command = arguments.get(1).map(String::as_str);
        let subcommand = arguments.get(2).map(String::as_str);
        let output = if command == Some("info") {
            CommandOutput::success("true\n")
        } else if command == Some("network") && subcommand == Some("create") {
            if self.mode == FakeMode::FailNetworkCreate {
                CommandOutput::failure(125, "netavark firewall setup failed")
            } else {
                CommandOutput::success("network-id\n")
            }
        } else if command == Some("build") {
            if let Some(file_index) = arguments.iter().position(|argument| argument == "--file") {
                let path = Path::new(
                    arguments
                        .get(file_index + 1)
                        .expect("--file must have a path"),
                );
                *self.containerfile.lock().expect("Containerfile lock") =
                    Some(fs::read_to_string(path).expect("probe Containerfile must be readable"));
            }
            CommandOutput::success("image-id\n")
        } else if command == Some("run") {
            if self.mode == FakeMode::TimeoutContainerRun {
                CommandOutput::timed_out("container start exceeded its deadline")
            } else {
                CommandOutput::success("container-id\n")
            }
        } else if command == Some("port") {
            CommandOutput::success("127.0.0.1:49152\n")
        } else if subcommand == Some("exists") {
            let resource_missing = (self.mode == FakeMode::FailNetworkCreate
                && command == Some("network"))
                || (self.mode == FakeMode::TimeoutContainerRun && command == Some("container"));
            if resource_missing {
                CommandOutput::failure(1, "resource does not exist")
            } else {
                CommandOutput::success(String::new())
            }
        } else if subcommand == Some("inspect") {
            let name = arguments.last().expect("inspect must name a resource");
            let identifier = name
                .get(name.len().saturating_sub(32)..)
                .expect("resource name must end in a probe identifier");
            let owner = if self.mode == FakeMode::NetworkOwnerMismatch && command == Some("network")
            {
                "another-owner"
            } else {
                "automata-runner"
            };
            CommandOutput::success(format!("{identifier}\n{owner}\n"))
        } else if command == Some("network")
            && subcommand == Some("rm")
            && self.mode == FakeMode::FailNetworkCleanup
        {
            CommandOutput::failure(125, "network remains busy")
        } else {
            CommandOutput::success(String::new())
        };

        if !request.is_cleanup()
            && provisioning_stage(&arguments).is_some_and(|stage| self.cancel_after == Some(stage))
        {
            cancellation.cancel();
        }
        output
    }
}

#[derive(Debug, Default)]
struct FakeReadinessProbe {
    calls: Mutex<Vec<(SocketAddr, String, Duration)>>,
    failure: Option<String>,
    cancellation_requests: u8,
}

impl FakeReadinessProbe {
    fn cancelling(requests: u8) -> Self {
        Self {
            cancellation_requests: requests,
            ..Self::default()
        }
    }
}

impl ReadinessProbe for FakeReadinessProbe {
    fn wait_until_ready(
        &self,
        address: SocketAddr,
        token: &str,
        timeout: Duration,
        cancellation: &ProbeCancellation,
    ) -> Result<(), String> {
        self.calls
            .lock()
            .expect("readiness lock")
            .push((address, token.to_owned(), timeout));
        for _ in 0..self.cancellation_requests {
            cancellation.cancel();
        }
        match &self.failure {
            Some(error) => Err(error.clone()),
            None if cancellation.is_cancelled() => Err("cancelled by test".to_owned()),
            None => Ok(()),
        }
    }
}

#[derive(Debug)]
struct FixedExecutableInspector(ScratchCompatibility);

impl ScratchExecutableInspector for FixedExecutableInspector {
    fn inspect(&self, _executable: &Path) -> ScratchCompatibility {
        self.0.clone()
    }
}

#[test]
fn successful_probe_uses_isolated_owned_resources_and_cleans_everything() {
    let fixture = ExecutableFixture::new();
    let plan = fixture.plan();
    let commands = FakeCommandExecutor::default();
    let readiness = FakeReadinessProbe::default();

    let probe = run_active_podman_probe_with(
        &plan,
        &commands,
        &readiness,
        &FixedExecutableInspector(ScratchCompatibility::Compatible),
    );

    assert_eq!(probe.capability(), PODMAN_NETWORK_ISOLATION);
    assert_eq!(probe.status(), ProbeStatus::Usable);
    assert!(probe.reason().is_none());
    assert!(usable_capabilities(&[probe]).contains(PODMAN_NETWORK_ISOLATION));
    assert!(!fixture.context_path().exists());
    assert_eq!(
        commands.captured_containerfile().as_deref(),
        Some(
            "FROM scratch\nCOPY automata-runner /automata-runner\nENTRYPOINT [\"/automata-runner\"]\n"
        )
    );

    let recorded = commands.recorded();
    assert!(recorded.iter().all(|command| command.program == "podman"));
    assert!(recorded.iter().all(|command| {
        command
            .arguments
            .first()
            .is_some_and(|arg| arg == "--remote=false")
    }));
    assert!(recorded.iter().all(|command| {
        command.timeout <= Duration::from_mins(1) && command.output_limit <= 16 * 1024
    }));

    let network = find_command(&recorded, "network", Some("create"));
    assert_has_ownership_labels(network, plan.identifier());
    let build = find_command(&recorded, "build", None);
    assert_has_ownership_labels(build, plan.identifier());
    assert!(build.arguments.iter().any(|arg| arg == "--pull=never"));
    assert!(build.arguments.iter().any(|arg| arg == "--network=none"));
    let run = find_command(&recorded, "run", None);
    assert_has_ownership_labels(run, plan.identifier());
    assert!(run.arguments.iter().any(|arg| arg == "--pull=never"));
    assert!(run.arguments.iter().any(|arg| arg == "127.0.0.1::8080/tcp"));
    assert!(run.arguments.iter().all(|arg| {
        !arg.contains("podman.sock")
            && !arg.contains("firewall=none")
            && arg != "--volume"
            && arg != "-v"
    }));
    assert!(has_command(&recorded, "rm", Some("--force")));
    assert!(has_command(&recorded, "network", Some("rm")));
    assert!(has_command(&recorded, "image", Some("rm")));
    assert_cleanup_ownership_is_immediate_and_stable(&recorded);

    let readiness_calls = readiness.calls.lock().expect("readiness lock");
    assert_eq!(readiness_calls.len(), 1);
    assert_eq!(readiness_calls[0].0, "127.0.0.1:49152".parse().unwrap());
    assert_eq!(readiness_calls[0].1, plan.identifier());
}

#[test]
fn dynamic_payload_is_rejected_before_podman_is_touched() {
    let fixture = ExecutableFixture::new();
    let commands = FakeCommandExecutor::default();

    let probe = run_active_podman_probe_with(
        &fixture.plan(),
        &commands,
        &FakeReadinessProbe::default(),
        &FixedExecutableInspector(ScratchCompatibility::Incompatible(
            "PT_INTERP is present".to_owned(),
        )),
    );

    assert_eq!(probe.status(), ProbeStatus::Degraded);
    assert_eq!(
        probe.reason().expect("probe needs a reason").code(),
        ProbeReasonCode::ProbeExecutableNotStatic
    );
    assert!(commands.recorded().is_empty());
}

#[test]
fn network_creation_failure_is_structured_and_still_cleans_the_context() {
    let fixture = ExecutableFixture::new();
    let commands = FakeCommandExecutor::with_mode(FakeMode::FailNetworkCreate);

    let probe = run_active_podman_probe_with(
        &fixture.plan(),
        &commands,
        &FakeReadinessProbe::default(),
        &FixedExecutableInspector(ScratchCompatibility::Compatible),
    );

    assert_eq!(probe.status(), ProbeStatus::Degraded);
    assert_eq!(
        probe.reason().expect("probe needs a reason").code(),
        ProbeReasonCode::ActiveProbeCommandFailed
    );
    assert!(!fixture.context_path().exists());
    assert!(has_command(&commands.recorded(), "network", Some("exists")));
}

#[test]
fn command_timeout_is_reported_and_owned_resources_are_removed() {
    let fixture = ExecutableFixture::new();
    let commands = FakeCommandExecutor::with_mode(FakeMode::TimeoutContainerRun);

    let probe = run_active_podman_probe_with(
        &fixture.plan(),
        &commands,
        &FakeReadinessProbe::default(),
        &FixedExecutableInspector(ScratchCompatibility::Compatible),
    );

    assert_eq!(probe.status(), ProbeStatus::Degraded);
    assert_eq!(
        probe.reason().expect("probe needs a reason").code(),
        ProbeReasonCode::ActiveProbeCommandTimedOut
    );
    let recorded = commands.recorded();
    assert!(has_command(&recorded, "container", Some("exists")));
    assert!(has_command(&recorded, "network", Some("rm")));
    assert!(has_command(&recorded, "image", Some("rm")));
    assert!(!fixture.context_path().exists());
}

#[test]
fn cleanup_failure_prevents_capability_advertisement() {
    let fixture = ExecutableFixture::new();
    let commands = FakeCommandExecutor::with_mode(FakeMode::FailNetworkCleanup);

    let probe = run_active_podman_probe_with(
        &fixture.plan(),
        &commands,
        &FakeReadinessProbe::default(),
        &FixedExecutableInspector(ScratchCompatibility::Compatible),
    );

    assert_eq!(probe.status(), ProbeStatus::Degraded);
    assert_eq!(
        probe.reason().expect("probe needs a reason").code(),
        ProbeReasonCode::ActiveProbeCleanupFailed
    );
    assert!(!usable_capabilities(&[probe]).contains(PODMAN_NETWORK_ISOLATION));
    assert!(!fixture.context_path().exists());
}

#[test]
fn cancellation_at_each_provisioning_command_starts_only_cleanup_afterward() {
    let stages = [
        ProvisioningStage::RootlessInfo,
        ProvisioningStage::NetworkCreate,
        ProvisioningStage::ImageBuild,
        ProvisioningStage::ContainerRun,
        ProvisioningStage::PortLookup,
    ];
    for stage in stages {
        let fixture = ExecutableFixture::new();
        let cancellation = ProbeCancellation::default();
        let commands = FakeCommandExecutor::cancelling_after(stage);

        let probe = controlled_probe(
            &fixture,
            &commands,
            &FakeReadinessProbe::default(),
            &cancellation,
            ActiveProbeLimits::default(),
        );

        assert_interrupted(&probe);
        assert!(!fixture.context_path().exists());
        let recorded = commands.recorded();
        assert!(
            recorded.iter().any(|command| command.cleanup)
                || stage == ProvisioningStage::RootlessInfo
        );
        assert!(
            recorded
                .iter()
                .filter(|command| command.cancellation_observed)
                .all(|command| command.cleanup),
            "provisioning command started after cancellation at {stage:?}: {recorded:?}"
        );
        let actual_stages = recorded
            .iter()
            .filter(|command| !command.cleanup)
            .filter_map(|command| provisioning_stage(&command.arguments))
            .collect::<Vec<_>>();
        let expected_end = stages
            .iter()
            .position(|candidate| *candidate == stage)
            .expect("stage must be in fixture")
            + 1;
        assert_eq!(actual_stages, stages[..expected_end]);
    }
}

#[test]
fn cancellation_during_readiness_enters_cleanup_only_mode() {
    let fixture = ExecutableFixture::new();
    let cancellation = ProbeCancellation::default();
    let commands = FakeCommandExecutor::default();

    let probe = controlled_probe(
        &fixture,
        &commands,
        &FakeReadinessProbe::cancelling(1),
        &cancellation,
        ActiveProbeLimits::default(),
    );

    assert_interrupted(&probe);
    assert!(
        commands
            .recorded()
            .iter()
            .filter(|command| command.cancellation_observed)
            .all(|command| command.cleanup)
    );
    assert!(!fixture.context_path().exists());
}

#[test]
fn cancellation_before_start_creates_nothing() {
    let fixture = ExecutableFixture::new();
    let cancellation = ProbeCancellation::default();
    cancellation.cancel();
    let commands = FakeCommandExecutor::default();

    let probe = controlled_probe(
        &fixture,
        &commands,
        &FakeReadinessProbe::default(),
        &cancellation,
        ActiveProbeLimits::default(),
    );

    assert_interrupted(&probe);
    assert!(commands.recorded().is_empty());
    assert!(!fixture.context_path().exists());
}

#[test]
fn second_cancellation_stops_podman_cleanup_but_removes_local_context() {
    let fixture = ExecutableFixture::new();
    let cancellation = ProbeCancellation::default();
    let commands = FakeCommandExecutor::default();

    let probe = controlled_probe(
        &fixture,
        &commands,
        &FakeReadinessProbe::cancelling(2),
        &cancellation,
        ActiveProbeLimits::default(),
    );

    assert_interrupted(&probe);
    assert!(probe.detail().contains("second shutdown request"));
    assert!(commands.recorded().iter().all(|command| !command.cleanup));
    assert!(!fixture.context_path().exists());
}

#[test]
fn second_cancellation_during_cleanup_stops_all_later_cleanup_commands() {
    let fixture = ExecutableFixture::new();
    let cancellation = ProbeCancellation::default();
    let commands = FakeCommandExecutor::forcing_during_first_cleanup();

    let probe = controlled_probe(
        &fixture,
        &commands,
        &FakeReadinessProbe::cancelling(1),
        &cancellation,
        ActiveProbeLimits::default(),
    );

    assert_interrupted(&probe);
    assert!(probe.detail().contains("second shutdown request"));
    assert_eq!(
        commands
            .recorded()
            .iter()
            .filter(|command| command.cleanup)
            .count(),
        1
    );
    assert!(!fixture.context_path().exists());
}

#[test]
fn aggregate_cleanup_deadline_is_structured_and_never_advertised() {
    let fixture = ExecutableFixture::new();
    let cancellation = ProbeCancellation::default();
    let commands = FakeCommandExecutor::default();

    let probe = controlled_probe(
        &fixture,
        &commands,
        &FakeReadinessProbe::default(),
        &cancellation,
        ActiveProbeLimits::new(Duration::from_secs(1), Duration::ZERO),
    );

    assert_eq!(probe.status(), ProbeStatus::Degraded);
    assert_eq!(
        probe.reason().expect("probe needs a reason").code(),
        ProbeReasonCode::ActiveProbeCleanupFailed
    );
    assert!(
        probe
            .detail()
            .contains("aggregate cleanup deadline expired")
    );
    assert!(!usable_capabilities(&[probe]).contains(PODMAN_NETWORK_ISOLATION));
    assert!(commands.recorded().iter().all(|command| !command.cleanup));
    assert!(!fixture.context_path().exists());
}

#[test]
fn cleanup_refuses_a_resource_if_either_ownership_label_mismatches() {
    let fixture = ExecutableFixture::new();
    let commands = FakeCommandExecutor::with_mode(FakeMode::NetworkOwnerMismatch);

    let probe = run_active_podman_probe_with(
        &fixture.plan(),
        &commands,
        &FakeReadinessProbe::default(),
        &FixedExecutableInspector(ScratchCompatibility::Compatible),
    );

    assert_eq!(probe.status(), ProbeStatus::Degraded);
    assert_eq!(
        probe.reason().expect("probe needs a reason").code(),
        ProbeReasonCode::ActiveProbeCleanupFailed
    );
    assert!(probe.detail().contains("another-owner"));
    assert!(!has_command(&commands.recorded(), "network", Some("rm")));
}

#[cfg(unix)]
#[test]
fn system_executor_cancellation_terminates_the_full_process_group() {
    let _executor_lock = lock_system_executor_tests();
    let cancellation = ProbeCancellation::default();
    let cancellation_trigger = cancellation.clone();
    let fixture = ProcessGroupFixture::new();
    let pid_file_for_trigger = fixture.pid_file.clone();
    let trigger = std::thread::spawn(move || {
        let deadline = std::time::Instant::now() + Duration::from_secs(2);
        while !pid_file_for_trigger.exists() && std::time::Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(10));
        }
        cancellation_trigger.cancel();
    });

    let request = fixture.request(Duration::from_secs(5));
    let output = SystemCommandExecutor.execute(&request, &cancellation);
    trigger.join().expect("cancellation trigger must finish");

    assert_eq!(output.termination(), &CommandTermination::Cancelled);
    fixture.assert_descendant_gone();
}

#[cfg(unix)]
#[test]
fn system_executor_timeout_terminates_the_full_process_group() {
    let _executor_lock = lock_system_executor_tests();
    let fixture = ProcessGroupFixture::new();
    let request = fixture.request(Duration::from_secs(1));

    let output = SystemCommandExecutor.execute(&request, &ProbeCancellation::default());

    assert_eq!(output.termination(), &CommandTermination::TimedOut);
    fixture.assert_descendant_gone();
}

#[cfg(unix)]
#[test]
fn system_executor_cleans_up_inherited_pipes_after_the_leader_exits() {
    let _executor_lock = lock_system_executor_tests();
    let fixture = ProcessGroupFixture::new();
    let request = fixture.leader_exit_request(Duration::from_secs(5));
    let started = std::time::Instant::now();

    let output = SystemCommandExecutor.execute(&request, &ProbeCancellation::default());

    assert_eq!(output.termination(), &CommandTermination::Exited(Some(0)));
    assert!(
        started.elapsed() < Duration::from_secs(2),
        "executor waited for an inherited pipe instead of cleaning the process group"
    );
    fixture.assert_descendant_gone();
}

#[cfg(target_os = "linux")]
#[test]
fn system_executor_bounds_output_capture_when_a_descendant_escapes_the_group() {
    let _executor_lock = lock_system_executor_tests();
    let fixture = ProcessGroupFixture::new();
    let request = fixture.escaped_pipe_request(Duration::from_millis(400));
    let started = std::time::Instant::now();

    let output = SystemCommandExecutor.execute(&request, &ProbeCancellation::default());
    let elapsed = started.elapsed();
    fixture.terminate_descendant_group();

    assert_eq!(output.termination(), &CommandTermination::TimedOut);
    assert!(output.was_truncated());
    assert!(output.stderr().contains("pipe remained open"));
    assert!(
        elapsed < Duration::from_secs(2),
        "output capture exceeded its command deadline: {elapsed:?}"
    );
    fixture.assert_descendant_gone();
}

#[cfg(target_os = "linux")]
#[test]
fn cancellation_interrupts_output_capture_after_the_leader_exits() {
    let _executor_lock = lock_system_executor_tests();
    let fixture = ProcessGroupFixture::new();
    let cancellation = ProbeCancellation::default();
    let cancellation_trigger = cancellation.clone();
    let pid_file_for_trigger = fixture.pid_file.clone();
    let trigger = std::thread::spawn(move || {
        let deadline = std::time::Instant::now() + Duration::from_secs(2);
        while !pid_file_for_trigger.exists() && std::time::Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(10));
        }
        cancellation_trigger.cancel();
    });
    let request = fixture.escaped_pipe_request(Duration::from_secs(5));
    let started = std::time::Instant::now();

    let output = SystemCommandExecutor.execute(&request, &cancellation);
    let elapsed = started.elapsed();
    trigger.join().expect("cancellation trigger must finish");
    fixture.terminate_descendant_group();

    assert_eq!(output.termination(), &CommandTermination::Cancelled);
    assert!(output.stderr().contains("capture interrupted by shutdown"));
    assert!(
        elapsed < Duration::from_secs(2),
        "output capture ignored cancellation: {elapsed:?}"
    );
    fixture.assert_descendant_gone();
}

#[cfg(target_os = "linux")]
#[test]
fn escaped_open_pipes_do_not_leave_capture_workers_or_descriptors_behind() {
    let _executor_lock = lock_system_executor_tests();
    assert!(named_capture_workers().is_empty());
    let fixture = ProcessGroupFixture::new();
    let request = fixture.indefinite_escaped_pipe_request(Duration::from_millis(400));
    let (output_sender, output_receiver) = std::sync::mpsc::sync_channel(1);
    let executor = std::thread::spawn(move || {
        let output = SystemCommandExecutor.execute(&request, &ProbeCancellation::default());
        let _ignored = output_sender.send(output);
    });

    let output = match output_receiver.recv_timeout(Duration::from_secs(2)) {
        Ok(output) => output,
        Err(error) => {
            fixture.terminate_descendant_group();
            executor.join().expect("executor thread must be reapable");
            panic!("executor did not stop its capture workers by the deadline: {error}");
        }
    };
    let descendant_was_alive = fixture.descendant_exists();
    let remaining_workers = named_capture_workers();
    fixture.terminate_descendant_group();
    executor.join().expect("executor thread must be reapable");

    assert_eq!(output.termination(), &CommandTermination::TimedOut);
    assert!(
        descendant_was_alive,
        "escaped pipe holder ended unexpectedly"
    );
    assert!(
        remaining_workers.is_empty(),
        "capture workers survived executor return: {remaining_workers:?}"
    );
    fixture.assert_descendant_gone();
}

#[cfg(unix)]
#[test]
fn probe_plan_rejects_a_system_temporary_scratch_root() {
    let fixture = ExecutableFixture::new();
    let result = ActiveProbePlan::new_in(
        fixture.executable.clone(),
        fixture.identifier.clone(),
        PathBuf::from("/tmp/automata-runner"),
    );

    assert_eq!(
        result.expect_err("system temporary root must be rejected"),
        "runner scratch root must not use /tmp"
    );
}

#[cfg(unix)]
#[test]
fn probe_plan_rejects_a_lexically_disguised_system_temporary_root() {
    let fixture = ExecutableFixture::new();
    let result = ActiveProbePlan::new_in(
        fixture.executable.clone(),
        fixture.identifier.clone(),
        PathBuf::from("/var/../tmp/automata-runner"),
    );

    assert_eq!(
        result.expect_err("normalized system temporary root must be rejected"),
        "runner scratch root must not use /tmp"
    );
}

#[test]
fn probe_plan_stores_a_lexically_normalized_scratch_root() {
    let fixture = ExecutableFixture::new();
    let expected = fs::canonicalize(runner_test_root())
        .expect("runner test root must be canonicalizable")
        .join("normalized-scratch");
    let plan = ActiveProbePlan::new_in(
        fixture.executable.clone(),
        fixture.identifier.clone(),
        runner_test_root().join("discarded/../normalized-scratch"),
    )
    .expect("safe normalized scratch root must be accepted");

    assert_eq!(plan.scratch_root(), expected);
}

#[cfg(unix)]
#[test]
fn active_probe_resolves_a_safe_symlinked_parent_before_using_it() {
    use std::os::unix::fs::symlink;

    let executable = ExecutableFixture::new();
    let directories = DirectoryFixture::new();
    let resolved_parent = directories.path("resolved-parent");
    fs::create_dir(&resolved_parent).expect("resolved parent must be creatable");
    let parent_alias = directories.path("parent-alias");
    symlink(&resolved_parent, &parent_alias).expect("parent alias must be creatable");
    let plan = ActiveProbePlan::new_in(
        executable.executable.clone(),
        executable.identifier.clone(),
        parent_alias.join("scratch"),
    )
    .expect("safe symlinked parent must be accepted by the lexical plan");
    let commands = FakeCommandExecutor::default();

    let probe = run_active_podman_probe_with(
        &plan,
        &commands,
        &FakeReadinessProbe::default(),
        &FixedExecutableInspector(ScratchCompatibility::Compatible),
    );

    assert_eq!(probe.status(), ProbeStatus::Usable);
    let expected_context = fs::canonicalize(&resolved_parent)
        .expect("resolved parent must be canonicalizable")
        .join("scratch")
        .join(format!("automata-podman-probe-{}", executable.identifier));
    let recorded = commands.recorded();
    let build = find_command(&recorded, "build", None);
    assert_eq!(
        build.arguments.last().map(PathBuf::from).as_deref(),
        Some(expected_context.as_path())
    );
    assert!(!expected_context.exists());
}

#[cfg(unix)]
#[test]
fn active_probe_rejects_a_symlink_as_the_scratch_root() {
    use std::os::unix::fs::symlink;

    let executable = ExecutableFixture::new();
    let directories = DirectoryFixture::new();
    let target = directories.path("target");
    fs::create_dir(&target).expect("symlink target must be creatable");
    let scratch_alias = directories.path("scratch-alias");
    symlink(&target, &scratch_alias).expect("scratch alias must be creatable");
    let plan = ActiveProbePlan::new_in(
        executable.executable.clone(),
        executable.identifier.clone(),
        scratch_alias,
    )
    .expect("lexical plan construction does not access the filesystem");

    let probe = run_active_podman_probe_with(
        &plan,
        &FakeCommandExecutor::default(),
        &FakeReadinessProbe::default(),
        &FixedExecutableInspector(ScratchCompatibility::Compatible),
    );

    assert_eq!(probe.status(), ProbeStatus::Indeterminate);
    assert_eq!(
        probe.reason().expect("probe needs a reason").code(),
        ProbeReasonCode::ActiveProbePreparationFailed
    );
    assert!(probe.detail().contains("not a symlink"));
}

#[cfg(all(target_os = "linux", target_env = "gnu"))]
#[test]
fn real_elf_inspector_rejects_the_dynamic_test_executable() {
    let executable = std::env::current_exe().expect("test executable path");
    let result = ElfScratchExecutableInspector.inspect(&executable);

    assert!(matches!(result, ScratchCompatibility::Incompatible(_)));
}

fn controlled_probe(
    fixture: &ExecutableFixture,
    commands: &dyn CommandExecutor,
    readiness: &dyn ReadinessProbe,
    cancellation: &ProbeCancellation,
    limits: ActiveProbeLimits,
) -> automata_runner::capability_probe::CapabilityProbe {
    run_active_podman_probe_with_control(
        &fixture.plan(),
        commands,
        readiness,
        &FixedExecutableInspector(ScratchCompatibility::Compatible),
        cancellation,
        limits,
    )
}

fn assert_interrupted(probe: &automata_runner::capability_probe::CapabilityProbe) {
    assert_eq!(probe.status(), ProbeStatus::Indeterminate);
    assert_eq!(
        probe.reason().expect("probe needs a reason").code(),
        ProbeReasonCode::ActiveProbeInterrupted
    );
    assert!(!usable_capabilities(std::slice::from_ref(probe)).contains(PODMAN_NETWORK_ISOLATION));
}

fn provisioning_stage(arguments: &[String]) -> Option<ProvisioningStage> {
    let command = arguments.get(1).map(String::as_str);
    let subcommand = arguments.get(2).map(String::as_str);
    match (command, subcommand) {
        (Some("info"), _) => Some(ProvisioningStage::RootlessInfo),
        (Some("network"), Some("create")) => Some(ProvisioningStage::NetworkCreate),
        (Some("build"), _) => Some(ProvisioningStage::ImageBuild),
        (Some("run"), _) => Some(ProvisioningStage::ContainerRun),
        (Some("port"), _) => Some(ProvisioningStage::PortLookup),
        _ => None,
    }
}

fn find_command<'a>(
    commands: &'a [RecordedCommand],
    command: &str,
    subcommand: Option<&str>,
) -> &'a RecordedCommand {
    commands
        .iter()
        .find(|recorded| command_matches(recorded, command, subcommand))
        .expect("expected command must have run")
}

fn has_command(commands: &[RecordedCommand], command: &str, subcommand: Option<&str>) -> bool {
    commands
        .iter()
        .any(|recorded| command_matches(recorded, command, subcommand))
}

fn command_matches(recorded: &RecordedCommand, command: &str, subcommand: Option<&str>) -> bool {
    recorded.arguments.get(1).is_some_and(|arg| arg == command)
        && subcommand.is_none_or(|subcommand| {
            recorded
                .arguments
                .get(2)
                .is_some_and(|arg| arg == subcommand)
        })
}

fn assert_has_ownership_labels(command: &RecordedCommand, identifier: &str) {
    assert!(
        command
            .arguments
            .iter()
            .any(|arg| arg == "io.automata.owner=automata-runner")
    );
    assert!(
        command
            .arguments
            .iter()
            .any(|arg| arg == &format!("io.automata.probe-id={identifier}"))
    );
}

fn assert_cleanup_ownership_is_immediate_and_stable(commands: &[RecordedCommand]) {
    for (index, deletion) in commands.iter().enumerate().filter(|(_index, command)| {
        command.cleanup
            && (command_matches(command, "rm", Some("--force"))
                || command_matches(command, "network", Some("rm"))
                || command_matches(command, "image", Some("rm")))
    }) {
        let inspection = index
            .checked_sub(1)
            .and_then(|previous| commands.get(previous))
            .expect("ownership inspection must immediately precede deletion");
        assert!(inspection.cleanup);
        assert_eq!(
            inspection.arguments.get(2).map(String::as_str),
            Some("inspect")
        );
        let template = inspection
            .arguments
            .iter()
            .find(|argument| argument.contains("io.automata.probe-id"))
            .expect("inspection template must include probe ID");
        assert!(template.contains("io.automata.owner"));
        assert_eq!(inspection.arguments.last(), deletion.arguments.last());
    }
}

fn runner_test_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../target/agent-scratch/runner")
}

#[cfg(unix)]
fn lock_system_executor_tests() -> std::sync::MutexGuard<'static, ()> {
    SYSTEM_EXECUTOR_TEST_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

#[cfg(target_os = "linux")]
fn named_capture_workers() -> Vec<String> {
    fs::read_dir("/proc/self/task")
        .expect("Linux task directory must be readable")
        .filter_map(Result::ok)
        .filter_map(|entry| fs::read_to_string(entry.path().join("comm")).ok())
        .map(|name| name.trim().to_owned())
        .filter(|name| name == "automata-stdout" || name == "automata-stderr")
        .collect()
}

#[cfg(unix)]
#[derive(Debug)]
struct ProcessGroupFixture {
    pid_file: PathBuf,
}

#[cfg(unix)]
impl ProcessGroupFixture {
    fn new() -> Self {
        let identifier = Uuid::new_v4().simple().to_string();
        fs::create_dir_all(runner_test_root()).expect("runner test scratch must be creatable");
        let pid_file = runner_test_root().join(format!("process-group-child-{identifier}.pid"));
        assert!(
            !pid_file.exists(),
            "collision-resistant PID path must be new"
        );
        Self { pid_file }
    }

    fn request(&self, timeout: Duration) -> CommandRequest {
        let mut request = CommandRequest::new("/bin/sh", timeout, 1024);
        request
            .arg("-c")
            .arg("sleep 30 & printf '%s\\n' \"$!\" > \"$1\"; wait")
            .arg("automata-process-group-test")
            .arg(&self.pid_file);
        request
    }

    fn leader_exit_request(&self, timeout: Duration) -> CommandRequest {
        let mut request = CommandRequest::new("/bin/sh", timeout, 1024);
        request
            .arg("-c")
            .arg("sleep 30 & printf '%s\\n' \"$!\" > \"$1\"; exit 0")
            .arg("automata-process-group-leader-exit-test")
            .arg(&self.pid_file);
        request
    }

    #[cfg(target_os = "linux")]
    fn escaped_pipe_request(&self, timeout: Duration) -> CommandRequest {
        let setsid = ["/usr/bin/setsid", "/bin/setsid"]
            .into_iter()
            .find(|candidate| Path::new(candidate).is_file())
            .expect("Linux test host must provide setsid");
        let mut request = CommandRequest::new("/bin/sh", timeout, 1024);
        request
            .arg("-c")
            .arg(
                "\"$2\" /bin/sh -c 'printf \"%s\\n\" \"$$\" > \"$1\"; /bin/sleep 30 & sleeper=$!; /bin/sleep 3; kill -KILL \"$sleeper\"; wait \"$sleeper\" 2>/dev/null; exit 0' automata-escaped-session \"$1\" & exit 0",
            )
            .arg("automata-escaped-pipe-test")
            .arg(&self.pid_file)
            .arg(setsid);
        request
    }

    #[cfg(target_os = "linux")]
    fn indefinite_escaped_pipe_request(&self, timeout: Duration) -> CommandRequest {
        let setsid = ["/usr/bin/setsid", "/bin/setsid"]
            .into_iter()
            .find(|candidate| Path::new(candidate).is_file())
            .expect("Linux test host must provide setsid");
        let mut request = CommandRequest::new("/bin/sh", timeout, 1024);
        request
            .arg("-c")
            .arg(
                "\"$2\" /bin/sh -c 'printf \"%s\\n\" \"$$\" > \"$1\"; exec /bin/sleep 86400' automata-indefinite-session \"$1\" & exit 0",
            )
            .arg("automata-indefinite-pipe-test")
            .arg(&self.pid_file)
            .arg(setsid);
        request
    }

    #[cfg(target_os = "linux")]
    fn terminate_descendant_group(&self) {
        let child_pid = self.child_pid();
        let Some(child_pid) = i32::try_from(child_pid)
            .ok()
            .and_then(rustix::process::Pid::from_raw)
        else {
            panic!("recorded child PID must be valid");
        };
        match rustix::process::kill_process_group(child_pid, rustix::process::Signal::KILL) {
            Ok(()) | Err(rustix::io::Errno::SRCH) => {}
            Err(error) => panic!("escaped descendant group must be killable: {error}"),
        }
    }

    fn child_pid(&self) -> u32 {
        fs::read_to_string(&self.pid_file)
            .expect("child PID must be recorded")
            .trim()
            .parse::<u32>()
            .expect("child PID must be numeric")
    }

    #[cfg(target_os = "linux")]
    fn descendant_exists(&self) -> bool {
        PathBuf::from(format!("/proc/{}", self.child_pid())).exists()
    }

    fn assert_descendant_gone(&self) {
        let child_pid = self.child_pid();
        let child_proc = PathBuf::from(format!("/proc/{child_pid}"));
        let deadline = std::time::Instant::now() + Duration::from_secs(2);
        while child_proc.exists() && std::time::Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(10));
        }
        assert!(
            !child_proc.exists(),
            "descendant {child_pid} survived process-group termination"
        );
    }
}

#[derive(Debug)]
struct DirectoryFixture {
    root: PathBuf,
}

impl DirectoryFixture {
    fn new() -> Self {
        let root =
            runner_test_root().join(format!("directory-fixture-{}", Uuid::new_v4().simple()));
        fs::create_dir_all(&root).expect("directory fixture must be creatable");
        Self { root }
    }

    fn path(&self, name: &str) -> PathBuf {
        self.root.join(name)
    }
}

impl Drop for DirectoryFixture {
    fn drop(&mut self) {
        let _ignored = fs::remove_dir_all(&self.root);
    }
}

#[cfg(unix)]
impl Drop for ProcessGroupFixture {
    fn drop(&mut self) {
        let _ignored = fs::remove_file(&self.pid_file);
    }
}

#[derive(Debug)]
struct ExecutableFixture {
    identifier: String,
    executable: PathBuf,
}

impl ExecutableFixture {
    fn new() -> Self {
        let identifier = Uuid::new_v4().simple().to_string();
        let root = runner_test_root();
        fs::create_dir_all(&root).expect("runner test scratch must be creatable");
        let executable = root.join(format!("automata-probe-fixture-{identifier}"));
        fs::write(&executable, b"mock static executable").expect("fixture must be writable");
        Self {
            identifier,
            executable,
        }
    }

    fn plan(&self) -> ActiveProbePlan {
        ActiveProbePlan::new_in(
            self.executable.clone(),
            self.identifier.clone(),
            runner_test_root(),
        )
        .expect("fixture plan must be valid")
    }

    fn context_path(&self) -> PathBuf {
        runner_test_root().join(format!("automata-podman-probe-{}", self.identifier))
    }
}

impl Drop for ExecutableFixture {
    fn drop(&mut self) {
        let _ignored = fs::remove_file(&self.executable);
        let _ignored = fs::remove_dir_all(self.context_path());
    }
}
