#![cfg(target_os = "linux")]

use std::{
    ffi::OsString,
    fs,
    net::SocketAddr,
    path::{Path, PathBuf},
    sync::Mutex,
    time::Duration,
};

use automata_ci_execution::NetworkPolicy;
#[cfg(all(target_os = "linux", target_env = "gnu"))]
use automata_ci_runner::podman_probe::ElfScratchExecutableInspector;
use automata_ci_runner::{
    capability_probe::{
        PODMAN_NETWORK_ISOLATION, ProbeCleanupStatus, ProbeReasonCode, ProbeStatus,
        usable_capabilities,
    },
    podman_probe::{
        ActiveProbeLimits, ActiveProbePlan, CommandExecutor, CommandOutput, CommandRequest,
        CommandTermination, ProbeCancellation, ReadinessProbe, ScratchCompatibility,
        ScratchExecutableInspector, SystemCommandExecutor, run_active_podman_probe_with_control,
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
    UnexpectedNetworkCreateName,
    TimeoutContainerRun,
    TimeoutContainerRunAndFailNetworkCleanup,
    FailNetworkCleanup,
    SuccessfulNoOpNetworkCleanup,
    NetworkOwnerMismatch,
    NetworkIdentifierLooksLikeAnOption,
    NetworkIdentifierChangedBeforeCleanup,
    ContainerExtraNetwork,
    UnexpectedContextEntry,
    ContextNameReplacement,
    ContextNameReplacementDuringRun,
    PayloadMutationDuringRun,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ProvisioningStage {
    NetworkCreate,
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
    removed_resources: Mutex<Vec<(String, String)>>,
    created_network: Mutex<Option<(String, bool)>>,
    probe_identifier: Mutex<Option<String>>,
    rootfs_path: Mutex<Option<PathBuf>>,
    displaced_context: Mutex<Option<PathBuf>>,
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

    fn displaced_context(&self) -> Option<PathBuf> {
        self.displaced_context
            .lock()
            .expect("displaced context lock")
            .clone()
    }

    fn record_request(
        &self,
        request: &CommandRequest,
        cancellation: &ProbeCancellation,
    ) -> Vec<String> {
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
        arguments
    }

    fn synthetic_output(&self, arguments: &[String]) -> CommandOutput {
        if let Some(identifier) = arguments
            .iter()
            .find_map(|argument| argument.strip_prefix("io.automata.probe-id="))
        {
            *self.probe_identifier.lock().expect("probe identifier lock") =
                Some(identifier.to_owned());
        }
        let command = arguments.get(1).map(String::as_str);
        let subcommand = arguments.get(2).map(String::as_str);
        if command == Some("network") && subcommand == Some("create") {
            self.synthetic_network_create(arguments)
        } else if command == Some("run") {
            self.synthetic_container_run(arguments)
        } else if command == Some("port") {
            CommandOutput::success("127.0.0.1:49152\n")
        } else if subcommand == Some("exists") {
            self.synthetic_resource_exists(arguments, command)
        } else if command == Some("network")
            && subcommand == Some("inspect")
            && arguments
                .iter()
                .any(|argument| argument.contains(".Internal"))
        {
            let (_name, internal) = self
                .created_network
                .lock()
                .expect("created network lock")
                .clone()
                .expect("network identity inspection follows creation");
            CommandOutput::success(format!("{}\t{internal}\n", resource_identifier("network")))
        } else if command == Some("container")
            && subcommand == Some("inspect")
            && arguments
                .iter()
                .any(|argument| argument.contains("NetworkSettings.Networks"))
        {
            let (network, _internal) = self
                .created_network
                .lock()
                .expect("created network lock")
                .clone()
                .expect("container inspection follows network creation");
            let extra = if self.mode == FakeMode::ContainerExtraNetwork {
                "podman\tanother-network-id\n"
            } else {
                ""
            };
            CommandOutput::success(format!(
                "{network}\t{}\n{extra}",
                resource_identifier("network")
            ))
        } else if subcommand == Some("inspect") {
            let identifier = self
                .probe_identifier
                .lock()
                .expect("probe identifier lock")
                .clone()
                .expect("probe resources carry a probe identifier");
            let owner = if self.mode == FakeMode::NetworkOwnerMismatch && command == Some("network")
            {
                "another-owner"
            } else {
                "automata-runner"
            };
            let resource_identifier = match (self.mode, command) {
                (FakeMode::NetworkIdentifierLooksLikeAnOption, Some("network")) => "--all",
                (FakeMode::NetworkIdentifierChangedBeforeCleanup, Some("network")) => {
                    "4444444444444444444444444444444444444444444444444444444444444444"
                }
                (_, Some(kind)) => resource_identifier(kind),
                (_, None) => panic!("inspect identifies a resource kind"),
            };
            CommandOutput::success(format!("{resource_identifier}\n{identifier}\n{owner}\n"))
        } else if command == Some("network") && subcommand == Some("rm") {
            self.synthetic_network_removal()
        } else {
            CommandOutput::success(String::new())
        }
    }

    fn synthetic_network_removal(&self) -> CommandOutput {
        if matches!(
            self.mode,
            FakeMode::FailNetworkCleanup | FakeMode::TimeoutContainerRunAndFailNetworkCleanup
        ) {
            return CommandOutput::failure(125, "network remains busy");
        }
        match self.mode {
            FakeMode::UnexpectedContextEntry => self.add_unexpected_context_entry(),
            FakeMode::ContextNameReplacement => self.replace_context_name(),
            _ => {}
        }
        CommandOutput::success(String::new())
    }

    fn synthetic_network_create(&self, arguments: &[String]) -> CommandOutput {
        if self.mode == FakeMode::FailNetworkCreate {
            return CommandOutput::failure(125, "netavark firewall setup failed");
        }
        let network = arguments
            .last()
            .expect("network create must name the network");
        *self.created_network.lock().expect("created network lock") = Some((
            network.clone(),
            arguments.iter().any(|argument| argument == "--internal"),
        ));
        if self.mode == FakeMode::UnexpectedNetworkCreateName {
            CommandOutput::success("different-network\n")
        } else {
            CommandOutput::success(format!("{network}\n"))
        }
    }

    fn synthetic_container_run(&self, arguments: &[String]) -> CommandOutput {
        let rootfs_argument = argument_after(arguments, "--rootfs")
            .expect("container run must select an explicit rootfs");
        let rootfs = PathBuf::from(
            rootfs_argument
                .strip_suffix(":O")
                .expect("container run must isolate rootfs writes in a disposable overlay"),
        );
        let entries = fs::read_dir(&rootfs)
            .expect("probe rootfs must be readable")
            .map(|entry| entry.expect("probe rootfs entry").file_name())
            .collect::<Vec<_>>();
        assert_eq!(entries, [OsString::from("automata-runner")]);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;

            assert_eq!(
                fs::metadata(&rootfs)
                    .expect("probe rootfs metadata must be readable")
                    .permissions()
                    .mode()
                    & 0o777,
                0o711,
                "the private parent's rootfs child must be traversable by uid 65532"
            );
        }
        assert_eq!(
            argument_after(arguments, rootfs_argument),
            Some("/automata-runner")
        );
        *self.rootfs_path.lock().expect("rootfs path lock") = Some(rootfs.clone());
        if self.mode == FakeMode::ContextNameReplacementDuringRun {
            self.replace_context_name();
        }
        #[cfg(unix)]
        if self.mode == FakeMode::PayloadMutationDuringRun {
            Self::mutate_payload_bytes(&rootfs);
        }
        if matches!(
            self.mode,
            FakeMode::TimeoutContainerRun | FakeMode::TimeoutContainerRunAndFailNetworkCleanup
        ) {
            CommandOutput::timed_out("container start exceeded its deadline")
        } else {
            CommandOutput::success(format!("{}\n", resource_identifier("container")))
        }
    }

    fn synthetic_resource_exists(
        &self,
        arguments: &[String],
        command: Option<&str>,
    ) -> CommandOutput {
        let name = arguments.last().expect("exists must name a resource");
        let was_removed = self
            .removed_resources
            .lock()
            .expect("removed resources lock")
            .iter()
            .any(|(kind, removed_name)| {
                kind == command.expect("exists must identify a resource kind")
                    && removed_name == name
            });
        let timed_out_container = matches!(
            self.mode,
            FakeMode::TimeoutContainerRun | FakeMode::TimeoutContainerRunAndFailNetworkCleanup
        ) && command == Some("container");
        let resource_missing = (self.mode == FakeMode::FailNetworkCreate
            && command == Some("network"))
            || timed_out_container
            || was_removed;
        if resource_missing {
            CommandOutput::failure(1, "resource does not exist")
        } else {
            CommandOutput::success(String::new())
        }
    }

    fn record_successful_removal(&self, arguments: &[String], output: &CommandOutput) {
        if !output.succeeded() {
            return;
        }
        let command = arguments.get(1).map(String::as_str);
        let subcommand = arguments.get(2).map(String::as_str);
        let removed = match (command, subcommand) {
            (Some("rm"), _) => arguments
                .last()
                .map(|name| ("container".to_owned(), name.clone())),
            (Some("network"), Some("rm")) => arguments
                .last()
                .map(|name| ("network".to_owned(), name.clone())),
            _ => None,
        };
        if let Some(removed) = removed {
            let successful_no_op =
                self.mode == FakeMode::SuccessfulNoOpNetworkCleanup && removed.0 == "network";
            if !successful_no_op {
                self.removed_resources
                    .lock()
                    .expect("removed resources lock")
                    .push(removed);
            }
        }
    }

    fn replace_context_name(&self) {
        if self
            .displaced_context
            .lock()
            .expect("displaced context lock")
            .is_some()
        {
            return;
        }
        let context = self
            .rootfs_path
            .lock()
            .expect("rootfs path lock")
            .clone()
            .expect("rootfs path is captured before cleanup");
        let displaced = context.with_file_name(format!(
            "{}-displaced",
            context
                .file_name()
                .expect("context has a file name")
                .to_string_lossy()
        ));
        fs::rename(&context, &displaced).expect("owned context must be displaceable");
        fs::create_dir(&context).expect("replacement context must be creatable");
        fs::write(context.join("do-not-delete"), b"replacement")
            .expect("replacement sentinel must be writable");
        *self
            .displaced_context
            .lock()
            .expect("displaced context lock") = Some(displaced);
    }

    fn add_unexpected_context_entry(&self) {
        let context = self
            .rootfs_path
            .lock()
            .expect("rootfs path lock")
            .clone()
            .expect("rootfs path is captured before cleanup");
        fs::write(
            context.join("unexpected"),
            b"must not be recursively removed",
        )
        .expect("unexpected rootfs entry must be injectable");
    }

    #[cfg(unix)]
    fn mutate_payload_bytes(rootfs: &Path) {
        use std::os::unix::fs::PermissionsExt as _;

        let payload = rootfs.join("automata-runner");
        let mut bytes = fs::read(&payload).expect("probe payload must be readable");
        bytes[0] ^= 1;
        fs::set_permissions(&payload, fs::Permissions::from_mode(0o755))
            .expect("probe payload must be made writable for mutation");
        fs::write(&payload, bytes).expect("probe payload bytes must be mutable by the owner");
        fs::set_permissions(&payload, fs::Permissions::from_mode(0o555))
            .expect("mutated payload mode must be restored");
    }
}

impl CommandExecutor for FakeCommandExecutor {
    fn execute(&self, request: &CommandRequest, cancellation: &ProbeCancellation) -> CommandOutput {
        let arguments = self.record_request(request, cancellation);
        if request.is_cleanup()
            && self.force_during_first_cleanup
            && cancellation.signal_count() == 1
        {
            cancellation.cancel();
        }
        let output = self.synthetic_output(&arguments);
        self.record_successful_removal(&arguments, &output);

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
    fn inspect(&self, _executable: &[u8]) -> ScratchCompatibility {
        self.0.clone()
    }
}

#[test]
fn successful_probe_uses_isolated_owned_resources_and_cleans_everything() {
    let fixture = ExecutableFixture::new();
    let plan = fixture.plan();
    let commands = FakeCommandExecutor::default();
    let readiness = FakeReadinessProbe::default();

    let probe = active_probe_with_default_control(
        &plan,
        &commands,
        &readiness,
        &FixedExecutableInspector(ScratchCompatibility::Compatible),
    );

    assert_eq!(probe.capability(), PODMAN_NETWORK_ISOLATION);
    assert_eq!(probe.status(), ProbeStatus::Usable);
    assert_eq!(probe.cleanup_status(), ProbeCleanupStatus::Complete);
    assert!(probe.reason().is_none());
    assert!(usable_capabilities(&[probe]).contains(PODMAN_NETWORK_ISOLATION));
    assert!(!fixture.context_path().exists());

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
    assert!(!has_command(&recorded, "build", None));
    let run = find_command(&recorded, "run", None);
    assert_has_ownership_labels(run, plan.identifier());
    assert!(
        run.arguments
            .iter()
            .any(|arg| arg == resource_identifier("network"))
    );
    let expected_rootfs = format!("{}:O", fixture.context_path().display());
    assert_eq!(
        argument_after(&run.arguments, "--rootfs"),
        Some(expected_rootfs.as_str())
    );
    assert_eq!(
        argument_after(&run.arguments, &expected_rootfs),
        Some("/automata-runner")
    );
    assert!(run.arguments.iter().all(|arg| arg != "--pull=never"));
    assert!(run.arguments.iter().any(|arg| arg == "127.0.0.1::8080/tcp"));
    assert!(run.arguments.iter().all(|arg| {
        !arg.contains("podman.sock")
            && !arg.contains("firewall=none")
            && arg != "--volume"
            && arg != "-v"
    }));
    assert!(has_command(&recorded, "rm", Some("--force")));
    assert!(has_command(&recorded, "network", Some("rm")));
    assert!(!has_command(&recorded, "image", Some("rm")));
    let container_network_inspect = recorded
        .iter()
        .find(|command| {
            command_matches(command, "container", Some("inspect"))
                && command
                    .arguments
                    .iter()
                    .any(|argument| argument.contains("NetworkSettings.Networks"))
        })
        .expect("container network inspection");
    assert_eq!(
        container_network_inspect
            .arguments
            .last()
            .map(String::as_str),
        Some(resource_identifier("container"))
    );
    assert_eq!(
        find_command(&recorded, "port", None)
            .arguments
            .last()
            .map(String::as_str),
        Some("8080/tcp")
    );
    let port = find_command(&recorded, "port", None);
    assert_eq!(
        port.arguments.get(2).map(String::as_str),
        Some(resource_identifier("container"))
    );
    assert_cleanup_force_is_limited_to_the_owned_container(&recorded);
    assert_cleanup_ownership_is_immediate_and_stable(&recorded);

    let readiness_calls = readiness.calls.lock().expect("readiness lock");
    assert_eq!(readiness_calls.len(), 1);
    assert_eq!(readiness_calls[0].0, "127.0.0.1:49152".parse().unwrap());
    assert_eq!(readiness_calls[0].1, plan.identifier());
}

#[test]
fn disabled_network_policy_is_created_and_verified_as_internal() {
    let fixture = ExecutableFixture::new();
    let plan = fixture.plan_with_network(NetworkPolicy::Disabled);
    let commands = FakeCommandExecutor::default();

    let probe = active_probe_with_default_control(
        &plan,
        &commands,
        &FakeReadinessProbe::default(),
        &FixedExecutableInspector(ScratchCompatibility::Compatible),
    );

    assert_eq!(probe.status(), ProbeStatus::Usable);
    let recorded = commands.recorded();
    let network = find_command(&recorded, "network", Some("create"));
    assert!(
        network
            .arguments
            .iter()
            .any(|argument| argument == "--internal")
    );
    assert!(recorded.iter().any(|command| {
        command_matches(command, "network", Some("inspect"))
            && command
                .arguments
                .iter()
                .any(|argument| argument.contains(".Internal"))
    }));
}

#[test]
fn unexpected_container_network_membership_is_rejected_before_readiness() {
    let fixture = ExecutableFixture::new();
    let commands = FakeCommandExecutor::with_mode(FakeMode::ContainerExtraNetwork);
    let readiness = FakeReadinessProbe::default();

    let probe = active_probe_with_default_control(
        &fixture.plan(),
        &commands,
        &readiness,
        &FixedExecutableInspector(ScratchCompatibility::Compatible),
    );

    assert_eq!(probe.status(), ProbeStatus::Degraded);
    assert_eq!(
        probe.reason().expect("probe needs a reason").code(),
        ProbeReasonCode::ActiveProbeCommandFailed
    );
    assert!(probe.detail().contains("exclusively"));
    assert!(readiness.calls.lock().expect("readiness lock").is_empty());
    assert!(!usable_capabilities(&[probe]).contains(PODMAN_NETWORK_ISOLATION));
}

#[test]
fn dynamic_payload_is_rejected_before_podman_is_touched() {
    let fixture = ExecutableFixture::new();
    let commands = FakeCommandExecutor::default();

    let probe = active_probe_with_default_control(
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

    let probe = active_probe_with_default_control(
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
fn network_creation_requires_the_exact_requested_name_before_inspection() {
    let fixture = ExecutableFixture::new();
    let commands = FakeCommandExecutor::with_mode(FakeMode::UnexpectedNetworkCreateName);

    let probe = active_probe_with_default_control(
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
    assert!(probe.detail().contains("unexpected resource name"));
    assert!(!has_command(&commands.recorded(), "build", None));
    assert!(!fixture.context_path().exists());
}

#[test]
fn command_timeout_is_reported_and_owned_resources_are_removed() {
    let fixture = ExecutableFixture::new();
    let commands = FakeCommandExecutor::with_mode(FakeMode::TimeoutContainerRun);

    let probe = active_probe_with_default_control(
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
    assert!(!has_command(&recorded, "image", Some("rm")));
    assert!(!fixture.context_path().exists());
}

#[test]
fn primary_failure_retains_a_structured_cleanup_failure() {
    let fixture = ExecutableFixture::new();
    let commands =
        FakeCommandExecutor::with_mode(FakeMode::TimeoutContainerRunAndFailNetworkCleanup);

    let probe = active_probe_with_default_control(
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
    assert_eq!(probe.cleanup_status(), ProbeCleanupStatus::Failed);
    assert!(probe.detail().contains("cleanup"));
    assert!(!usable_capabilities(&[probe]).contains(PODMAN_NETWORK_ISOLATION));
}

#[test]
fn cleanup_failure_prevents_capability_advertisement() {
    let fixture = ExecutableFixture::new();
    let commands = FakeCommandExecutor::with_mode(FakeMode::FailNetworkCleanup);

    let probe = active_probe_with_default_control(
        &fixture.plan(),
        &commands,
        &FakeReadinessProbe::default(),
        &FixedExecutableInspector(ScratchCompatibility::Compatible),
    );

    assert_eq!(probe.status(), ProbeStatus::Degraded);
    assert_eq!(probe.cleanup_status(), ProbeCleanupStatus::Failed);
    assert_eq!(
        probe.reason().expect("probe needs a reason").code(),
        ProbeReasonCode::ActiveProbeCleanupFailed
    );
    assert!(!usable_capabilities(&[probe]).contains(PODMAN_NETWORK_ISOLATION));
    assert!(!fixture.context_path().exists());
}

#[test]
fn successful_noop_cleanup_prevents_capability_advertisement() {
    let fixture = ExecutableFixture::new();
    let commands = FakeCommandExecutor::with_mode(FakeMode::SuccessfulNoOpNetworkCleanup);

    let probe = active_probe_with_default_control(
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
    assert!(probe.detail().contains("still exists"));
    assert!(!usable_capabilities(&[probe]).contains(PODMAN_NETWORK_ISOLATION));
    assert!(!fixture.context_path().exists());
}

#[cfg(unix)]
#[test]
fn local_context_cleanup_rejects_unexpected_entries_without_recursive_deletion() {
    let fixture = ExecutableFixture::new();
    let commands = FakeCommandExecutor::with_mode(FakeMode::UnexpectedContextEntry);

    let probe = active_probe_with_default_control(
        &fixture.plan(),
        &commands,
        &FakeReadinessProbe::default(),
        &FixedExecutableInspector(ScratchCompatibility::Compatible),
    );

    assert_eq!(probe.status(), ProbeStatus::Degraded);
    assert_eq!(probe.cleanup_status(), ProbeCleanupStatus::Failed);
    assert_eq!(
        probe.reason().expect("probe needs a reason").code(),
        ProbeReasonCode::ActiveProbeCleanupFailed
    );
    assert!(probe.detail().contains("unexpected entry"));
    assert_eq!(
        fs::read(fixture.context_path().join("unexpected"))
            .expect("unexpected entry must be retained"),
        b"must not be recursively removed"
    );
    assert!(fixture.context_path().join("automata-runner").is_file());
}

#[cfg(unix)]
#[test]
fn local_context_cleanup_refuses_a_name_replacement() {
    let fixture = ExecutableFixture::new();
    let commands = FakeCommandExecutor::with_mode(FakeMode::ContextNameReplacement);

    let probe = active_probe_with_default_control(
        &fixture.plan(),
        &commands,
        &FakeReadinessProbe::default(),
        &FixedExecutableInspector(ScratchCompatibility::Compatible),
    );

    assert_eq!(probe.status(), ProbeStatus::Degraded);
    assert_eq!(probe.cleanup_status(), ProbeCleanupStatus::Failed);
    assert!(probe.detail().contains("no longer identifies"));
    assert_eq!(
        fs::read(fixture.context_path().join("do-not-delete"))
            .expect("replacement entry must be retained"),
        b"replacement"
    );
    let displaced = commands
        .displaced_context()
        .expect("the owned context must have been displaced");
    assert!(displaced.join("automata-runner").is_file());
    fs::remove_dir_all(displaced).expect("displaced test context must be removable");
}

#[cfg(unix)]
#[test]
fn container_start_rejects_a_rootfs_name_replacement_before_readiness() {
    let fixture = ExecutableFixture::new();
    let commands = FakeCommandExecutor::with_mode(FakeMode::ContextNameReplacementDuringRun);
    let readiness = FakeReadinessProbe::default();

    let probe = active_probe_with_default_control(
        &fixture.plan(),
        &commands,
        &readiness,
        &FixedExecutableInspector(ScratchCompatibility::Compatible),
    );

    assert_eq!(probe.status(), ProbeStatus::Indeterminate);
    assert_eq!(probe.cleanup_status(), ProbeCleanupStatus::Failed);
    assert_eq!(
        probe.reason().expect("probe needs a reason").code(),
        ProbeReasonCode::ActiveProbePreparationFailed
    );
    assert!(probe.detail().contains("no longer identifies"));
    assert!(readiness.calls.lock().expect("readiness lock").is_empty());
    assert_eq!(
        fs::read(fixture.context_path().join("do-not-delete"))
            .expect("replacement entry must be retained"),
        b"replacement"
    );
    let displaced = commands
        .displaced_context()
        .expect("the original rootfs must have been displaced");
    assert!(displaced.join("automata-runner").is_file());
    fs::remove_dir_all(displaced).expect("displaced test context must be removable");
}

#[cfg(unix)]
#[test]
fn container_start_rejects_same_length_payload_mutation_before_readiness() {
    let fixture = ExecutableFixture::new();
    let commands = FakeCommandExecutor::with_mode(FakeMode::PayloadMutationDuringRun);
    let readiness = FakeReadinessProbe::default();

    let probe = active_probe_with_default_control(
        &fixture.plan(),
        &commands,
        &readiness,
        &FixedExecutableInspector(ScratchCompatibility::Compatible),
    );

    assert_eq!(probe.status(), ProbeStatus::Indeterminate);
    assert_eq!(probe.cleanup_status(), ProbeCleanupStatus::Complete);
    assert_eq!(
        probe.reason().expect("probe needs a reason").code(),
        ProbeReasonCode::ActiveProbePreparationFailed
    );
    assert!(probe.detail().contains("payload bytes changed"));
    assert!(readiness.calls.lock().expect("readiness lock").is_empty());
    assert!(!fixture.context_path().exists());
}

#[test]
fn cancellation_at_each_provisioning_command_starts_only_cleanup_afterward() {
    let stages = [
        ProvisioningStage::NetworkCreate,
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
        assert!(recorded.iter().any(|command| command.cleanup));
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
fn interruption_retains_a_structured_cleanup_failure() {
    let fixture = ExecutableFixture::new();
    let cancellation = ProbeCancellation::default();
    let commands = FakeCommandExecutor::with_mode(FakeMode::FailNetworkCleanup);

    let probe = controlled_probe(
        &fixture,
        &commands,
        &FakeReadinessProbe::cancelling(1),
        &cancellation,
        ActiveProbeLimits::default(),
    );

    assert_interrupted(&probe);
    assert_eq!(probe.cleanup_status(), ProbeCleanupStatus::Failed);
    assert!(probe.detail().contains("cleanup"));
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
fn second_cancellation_stops_podman_cleanup_and_retains_the_backing_rootfs() {
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
    assert!(fixture.context_path().join("automata-runner").is_file());
}

#[test]
fn second_cancellation_during_cleanup_retains_the_unconfirmed_container_rootfs() {
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
    assert!(fixture.context_path().join("automata-runner").is_file());
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
    assert!(fixture.context_path().join("automata-runner").is_file());
}

#[test]
fn cleanup_refuses_a_resource_if_either_ownership_label_mismatches() {
    let fixture = ExecutableFixture::new();
    let commands = FakeCommandExecutor::with_mode(FakeMode::NetworkOwnerMismatch);

    let probe = active_probe_with_default_control(
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

#[test]
fn cleanup_rejects_an_inspected_identifier_that_could_be_parsed_as_an_option() {
    let fixture = ExecutableFixture::new();
    let commands = FakeCommandExecutor::with_mode(FakeMode::NetworkIdentifierLooksLikeAnOption);

    let probe = active_probe_with_default_control(
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
    assert!(probe.detail().contains("identifier validity false"));
    assert!(!has_command(&commands.recorded(), "network", Some("rm")));
}

#[test]
fn cleanup_does_not_delete_a_name_replacement_with_copied_labels() {
    let fixture = ExecutableFixture::new();
    let commands = FakeCommandExecutor::with_mode(FakeMode::NetworkIdentifierChangedBeforeCleanup);

    let probe = active_probe_with_default_control(
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
    assert!(probe.detail().contains("created-identifier match false"));
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
    let leader_pid_file_for_trigger = fixture.leader_pid_file.clone();
    let trigger = std::thread::spawn(move || {
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        let capture_ready = loop {
            let child_pid = ProcessGroupFixture::recorded_pid(&pid_file_for_trigger);
            let leader_exited = ProcessGroupFixture::recorded_pid(&leader_pid_file_for_trigger)
                .is_some_and(ProcessGroupFixture::process_has_exited);
            if child_pid.is_some() && leader_exited {
                break true;
            }
            if std::time::Instant::now() >= deadline {
                break false;
            }
            std::thread::sleep(Duration::from_millis(10));
        };
        let cancelled_at = std::time::Instant::now();
        cancellation_trigger.cancel();
        (capture_ready, cancelled_at)
    });
    let request = fixture.escaped_pipe_request(Duration::from_secs(15));

    let output = SystemCommandExecutor.execute(&request, &cancellation);
    let (capture_ready, cancelled_at) = trigger.join().expect("cancellation trigger must finish");
    let elapsed = cancelled_at.elapsed();
    if ProcessGroupFixture::recorded_pid(&fixture.pid_file).is_some() {
        fixture.terminate_descendant_group();
    }

    assert!(
        capture_ready,
        "escaped descendant and exited leader must be observed before cancellation"
    );
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
        NetworkPolicy::PrivateEgress,
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
        NetworkPolicy::PrivateEgress,
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
        NetworkPolicy::PrivateEgress,
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
        NetworkPolicy::PrivateEgress,
    )
    .expect("safe symlinked parent must be accepted by the lexical plan");
    let commands = FakeCommandExecutor::default();

    let probe = active_probe_with_default_control(
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
    let expected_rootfs = format!("{}:O", expected_context.display());
    assert_eq!(
        argument_after(&find_command(&recorded, "run", None).arguments, "--rootfs"),
        Some(expected_rootfs.as_str()),
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
        NetworkPolicy::PrivateEgress,
    )
    .expect("lexical plan construction does not access the filesystem");

    let probe = active_probe_with_default_control(
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
fn real_elf_inspector_never_accepts_the_dynamic_test_executable() {
    let executable = std::env::current_exe().expect("test executable path");
    let executable = fs::read(executable).expect("test executable must be readable");
    let result = ElfScratchExecutableInspector.inspect(&executable);

    assert!(
        !matches!(result, ScratchCompatibility::Compatible),
        "an oversized or dynamically linked test executable must never be accepted for scratch"
    );
}

fn active_probe_with_default_control(
    plan: &ActiveProbePlan,
    commands: &dyn CommandExecutor,
    readiness: &dyn ReadinessProbe,
    executable_inspector: &dyn ScratchExecutableInspector,
) -> automata_ci_runner::capability_probe::CapabilityProbe {
    run_active_podman_probe_with_control(
        plan,
        commands,
        readiness,
        executable_inspector,
        &ProbeCancellation::default(),
        ActiveProbeLimits::default(),
    )
}

fn controlled_probe(
    fixture: &ExecutableFixture,
    commands: &dyn CommandExecutor,
    readiness: &dyn ReadinessProbe,
    cancellation: &ProbeCancellation,
    limits: ActiveProbeLimits,
) -> automata_ci_runner::capability_probe::CapabilityProbe {
    run_active_podman_probe_with_control(
        &fixture.plan(),
        commands,
        readiness,
        &FixedExecutableInspector(ScratchCompatibility::Compatible),
        cancellation,
        limits,
    )
}

fn assert_interrupted(probe: &automata_ci_runner::capability_probe::CapabilityProbe) {
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
        (Some("network"), Some("create")) => Some(ProvisioningStage::NetworkCreate),
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

fn argument_after<'arguments>(
    arguments: &'arguments [String],
    flag: &str,
) -> Option<&'arguments str> {
    arguments
        .windows(2)
        .find(|pair| pair[0] == flag)
        .map(|pair| pair[1].as_str())
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
                || command_matches(command, "network", Some("rm")))
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
        assert!(template.contains(".Id") || template.contains(".ID"));
        let resource_kind =
            deletion
                .arguments
                .get(1)
                .map(String::as_str)
                .map_or("container", |command| match command {
                    "network" => "network",
                    _ => "container",
                });
        assert_eq!(
            deletion.arguments.last().map(String::as_str),
            Some(resource_identifier(resource_kind))
        );
        let existence = commands
            .get(index.saturating_sub(2))
            .expect("identity-bound existence check precedes ownership inspection");
        assert!(existence.cleanup);
        assert_eq!(
            existence.arguments.last().map(String::as_str),
            Some(resource_identifier(resource_kind))
        );
    }
}

fn assert_cleanup_force_is_limited_to_the_owned_container(commands: &[RecordedCommand]) {
    let container_removal = find_command(commands, "rm", Some("--force"));
    assert!(
        container_removal
            .arguments
            .iter()
            .any(|argument| argument == "--force")
    );
    for command in commands
        .iter()
        .filter(|command| command_matches(command, "network", Some("rm")))
    {
        assert!(
            command
                .arguments
                .iter()
                .all(|argument| argument != "--force"),
            "network cleanup must not remove foreign dependents"
        );
    }
}

fn resource_identifier(kind: &str) -> &'static str {
    match kind {
        "container" => "1111111111111111111111111111111111111111111111111111111111111111",
        "network" => "2222222222222222222222222222222222222222222222222222222222222222",
        _ => panic!("unexpected resource kind {kind}"),
    }
}

fn runner_test_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("runner crate must be nested beneath the workspace root")
        .join("target/agent-scratch/runner")
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
    leader_pid_file: PathBuf,
}

#[cfg(unix)]
impl ProcessGroupFixture {
    fn new() -> Self {
        let identifier = Uuid::new_v4().simple().to_string();
        fs::create_dir_all(runner_test_root()).expect("runner test scratch must be creatable");
        let pid_file = runner_test_root().join(format!("process-group-child-{identifier}.pid"));
        let leader_pid_file =
            runner_test_root().join(format!("process-group-leader-{identifier}.pid"));
        assert!(
            !pid_file.exists() && !leader_pid_file.exists(),
            "collision-resistant PID paths must be new"
        );
        Self {
            pid_file,
            leader_pid_file,
        }
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
                "printf '%s\\n' \"$$\" > \"$2\"; \"$3\" /bin/sh -c 'printf \"%s\\n\" \"$$\" > \"$1\"; /bin/sleep 30 & sleeper=$!; /bin/sleep 3; kill -KILL \"$sleeper\"; wait \"$sleeper\" 2>/dev/null; exit 0' automata-escaped-session \"$1\" & while [ ! -s \"$1\" ]; do /bin/sleep 0.01; done; exit 0",
            )
            .arg("automata-escaped-pipe-test")
            .arg(&self.pid_file)
            .arg(&self.leader_pid_file)
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
                "printf '%s\\n' \"$$\" > \"$2\"; \"$3\" /bin/sh -c 'printf \"%s\\n\" \"$$\" > \"$1\"; exec /bin/sleep 86400' automata-indefinite-session \"$1\" & while [ ! -s \"$1\" ]; do /bin/sleep 0.01; done; exit 0",
            )
            .arg("automata-indefinite-pipe-test")
            .arg(&self.pid_file)
            .arg(&self.leader_pid_file)
            .arg(setsid);
        request
    }

    #[cfg(target_os = "linux")]
    fn recorded_pid(path: &Path) -> Option<u32> {
        fs::read_to_string(path).ok()?.trim().parse::<u32>().ok()
    }

    #[cfg(target_os = "linux")]
    fn process_has_exited(pid: u32) -> bool {
        match fs::read_to_string(format!("/proc/{pid}/status")) {
            Ok(status) => {
                status
                    .lines()
                    .find(|line| line.starts_with("State:"))
                    .and_then(|line| line.split_whitespace().nth(1))
                    == Some("Z")
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => true,
            Err(error) => panic!("process leader state must be readable: {error}"),
        }
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
        let _ignored = fs::remove_file(&self.leader_pid_file);
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
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;

            fs::set_permissions(&executable, fs::Permissions::from_mode(0o700))
                .expect("fixture must be executable");
        }
        Self {
            identifier,
            executable,
        }
    }

    fn plan(&self) -> ActiveProbePlan {
        self.plan_with_network(NetworkPolicy::PrivateEgress)
    }

    fn plan_with_network(&self, network_policy: NetworkPolicy) -> ActiveProbePlan {
        ActiveProbePlan::new_in(
            self.executable.clone(),
            self.identifier.clone(),
            runner_test_root(),
            network_policy,
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
