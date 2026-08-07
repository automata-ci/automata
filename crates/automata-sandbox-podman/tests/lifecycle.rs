#![cfg(target_os = "linux")]

mod support;

use std::{
    sync::Arc,
    time::{Duration, Instant},
};

use automata_execution::{
    CopyFromRequest, CopyToRequest, DestroyDisposition, DestroySandbox, EnvironmentName,
    EnvironmentValue, EnvironmentVariable, ExecutionArgv, ExecutionCommand, ExecutionEnvironment,
    ExecutionErrorKind, ExecutionSignal, NetworkPolicy, NeverCancelled, OperationId,
    ProviderErrorKind, RootFilesystemPolicy, SandboxCapability, SandboxGeneration,
    SandboxPrivilegePolicy, SandboxProvider, SandboxSpec, SandboxState, SignalRequest, TargetPath,
    WaitRequest,
};
use automata_sandbox_podman::{
    CommandOutput, PodmanCommandExecutor, PodmanHostGatewayAlias, RootlessPodmanProvider,
};

use support::{CopyAttack, Fixture, sample_spec, sample_spec_with, sample_spec_with_digest};

#[test]
fn whole_job_create_replay_exec_and_destroy_are_exact() {
    let fixture = Fixture::new("whole-job");
    let operation_id = OperationId::new();
    let spec = sample_spec(operation_id);
    let cancellation = NeverCancelled;

    let created = fixture
        .provider
        .create(&spec, &cancellation)
        .expect("create must succeed");
    assert_eq!(created.state(), SandboxState::Running);
    assert_eq!(created.profile(), spec.profile().attestation());
    assert_eq!(
        fixture
            .provider
            .create(&spec, &cancellation)
            .expect("exact create replay")
            .handle(),
        created.handle()
    );
    let inspection = fixture
        .provider
        .inspect(created.handle(), &cancellation)
        .expect("inspect");
    assert_eq!(inspection.state(), SandboxState::Running);
    assert_eq!(inspection.profile(), spec.profile().attestation());

    let endpoint = fixture
        .provider
        .attach(created.handle(), &cancellation)
        .expect("attach");
    let command = ExecutionCommand::new(
        OperationId::new(),
        ExecutionArgv::new(
            TargetPath::posix("/bin/echo").expect("program"),
            vec!["hello".to_owned()],
        )
        .expect("argv"),
        TargetPath::posix("/__w").expect("working directory"),
        ExecutionEnvironment::empty(),
        Duration::from_secs(5),
        4_096,
    )
    .expect("command");
    let output = endpoint.exec(&command, &cancellation).expect("exec");
    assert_eq!(output.stdout(), b"executed\n");

    let disposition = fixture
        .provider
        .destroy(
            &DestroySandbox::new(
                OperationId::new(),
                created.handle().clone(),
                created.generation(),
            ),
            &cancellation,
        )
        .expect("destroy");
    assert_eq!(disposition, DestroyDisposition::Destroyed);
    assert_eq!(
        fixture
            .provider
            .destroy(
                &DestroySandbox::new(
                    OperationId::new(),
                    created.handle().clone(),
                    created.generation(),
                ),
                &cancellation,
            )
            .expect("destroy replay"),
        DestroyDisposition::AlreadyAbsent
    );
    assert!(fixture.fake.is_empty());
    assert_hardened_commands(&fixture.fake.commands());
    assert_inspection_immediately_precedes_deletion(&fixture.fake.commands());
}

#[test]
fn partial_workspace_cleanup_reopens_and_retries_only_the_exact_user_namespace_target() {
    let fixture = Fixture::new("workspace-cleanup-reopen");
    let created = fixture
        .provider
        .create(&sample_spec(OperationId::new()), &NeverCancelled)
        .expect("create sandbox");
    let generation = created.generation();
    let handle = created.handle().clone();
    let workspace = std::fs::read_dir(fixture.scratch.path().join("workspaces"))
        .expect("workspace root")
        .next()
        .expect("created workspace")
        .expect("workspace entry")
        .path();
    std::fs::create_dir_all(workspace.join("mapped-owner/nested"))
        .expect("seed nested workspace residue");
    std::fs::write(workspace.join("mapped-owner/nested/output"), b"retained")
        .expect("seed workspace output");
    fixture.fake.fail_once(&["unshare", "/usr/bin/rm"]);

    let first = fixture
        .provider
        .destroy(
            &DestroySandbox::new(OperationId::new(), handle.clone(), generation),
            &NeverCancelled,
        )
        .expect_err("injected exact workspace deletion failure");
    assert_eq!(first.kind(), ProviderErrorKind::BackendRejected);
    assert_eq!(
        first.outcome(),
        automata_execution::OperationOutcome::Uncertain
    );
    assert!(
        fixture.fake.is_empty(),
        "primary resources were removed first"
    );
    assert!(
        workspace.is_dir(),
        "failed cleanup retains its exact target"
    );

    let support::Fixture {
        provider,
        fake,
        scratch,
    } = fixture;
    let first_commands = fake.commands();
    let first_cleanup = first_commands
        .iter()
        .find(|command| semantic_starts_with(command, &["unshare", "/usr/bin/rm"]))
        .expect("rootless user-namespace cleanup command");
    assert_eq!(first_cleanup.last(), Some(&workspace.display().to_string()));
    assert!(
        first_cleanup
            .iter()
            .any(|value| value == "--one-file-system")
    );
    assert!(!first_cleanup.iter().any(|value| value == "prune"));
    drop(provider);

    let reopened_fake = Arc::new(support::FakePodman::default());
    let reopened = RootlessPodmanProvider::open_with_executor(
        support::options(scratch.path()),
        Arc::clone(&reopened_fake) as Arc<dyn PodmanCommandExecutor>,
    )
    .expect("reopen exact provider state");
    let disposition = reopened
        .destroy(
            &DestroySandbox::new(OperationId::new(), handle, generation),
            &NeverCancelled,
        )
        .expect("replay partial exact cleanup");
    assert_eq!(disposition, DestroyDisposition::Destroyed);
    assert!(!workspace.exists());
    let reopened_commands = reopened_fake.commands();
    let cleanup = reopened_commands
        .iter()
        .find(|command| semantic_starts_with(command, &["unshare", "/usr/bin/rm"]))
        .expect("reopened exact cleanup command");
    assert_eq!(cleanup.last(), Some(&workspace.display().to_string()));
    assert!(!cleanup.iter().any(|value| value == "prune"));
}

#[cfg(unix)]
#[test]
fn workspace_cleanup_rejects_a_swapped_symlink_without_touching_its_target() {
    let fixture = Fixture::new("workspace-cleanup-symlink");
    let created = fixture
        .provider
        .create(&sample_spec(OperationId::new()), &NeverCancelled)
        .expect("create sandbox");
    let workspace = std::fs::read_dir(fixture.scratch.path().join("workspaces"))
        .expect("workspace root")
        .next()
        .expect("created workspace")
        .expect("workspace entry")
        .path();
    std::fs::remove_dir(&workspace).expect("remove empty workspace for attack");
    let outside = fixture.scratch.path().join("outside-workspace-target");
    std::fs::create_dir(&outside).expect("create symlink target");
    std::fs::write(outside.join("retained"), b"must survive").expect("seed symlink target");
    std::os::unix::fs::symlink(&outside, &workspace).expect("swap workspace for symlink");
    let before = fixture.fake.commands().len();

    let error = fixture
        .provider
        .destroy(
            &DestroySandbox::new(
                OperationId::new(),
                created.handle().clone(),
                created.generation(),
            ),
            &NeverCancelled,
        )
        .expect_err("symlinked workspace fails closed");
    assert_eq!(error.kind(), ProviderErrorKind::LocalStorage);
    assert_eq!(
        error.outcome(),
        automata_execution::OperationOutcome::Uncertain
    );
    assert_eq!(
        std::fs::read(outside.join("retained")).expect("outside content survives"),
        b"must survive"
    );
    assert!(
        fixture.fake.commands()[before..]
            .iter()
            .all(|command| { !semantic_starts_with(command, &["unshare", "/usr/bin/rm"]) })
    );
}

#[test]
fn exec_honors_validated_step_timeout_and_output_limit() {
    let fixture = Fixture::new("exec-request-bounds");
    let created = fixture
        .provider
        .create(&sample_spec(OperationId::new()), &NeverCancelled)
        .expect("create");
    let endpoint = fixture
        .provider
        .attach(created.handle(), &NeverCancelled)
        .expect("attach");
    let timeout = Duration::from_mins(7);
    let output_limit = 128 * 1024;
    let output = vec![b'x'; 96 * 1024];
    fixture
        .fake
        .set_exec_output(CommandOutput::success(output.clone()));
    let before = Instant::now();
    let command = ExecutionCommand::new(
        OperationId::new(),
        ExecutionArgv::new(TargetPath::posix("/bin/true").expect("path"), Vec::new())
            .expect("argv"),
        TargetPath::posix("/__w").expect("working directory"),
        ExecutionEnvironment::empty(),
        timeout,
        output_limit,
    )
    .expect("command");

    let result = endpoint
        .exec(&command, &NeverCancelled)
        .expect("bounded exec");
    let captured = fixture
        .fake
        .last_exec_request()
        .expect("exec request must be captured");

    assert_eq!(captured.timeout, timeout);
    assert!(captured.aggregate_deadline >= before + timeout);
    assert_eq!(captured.output_limit, output_limit);
    assert_eq!(result.stdout(), output);
}

#[test]
fn explicit_host_gateway_alias_is_one_create_argument_and_changes_spec_fingerprint() {
    let spec = sample_spec(OperationId::new());
    let baseline = Fixture::new("host-gateway-baseline");
    baseline
        .provider
        .create(&spec, &NeverCancelled)
        .expect("baseline create");
    let alias = PodmanHostGatewayAlias::new("automata-git.localhost").expect("valid alias");
    let mapped = Fixture::new_with_options("host-gateway-mapped", |options| {
        options.with_host_gateway_alias(alias)
    });
    mapped
        .provider
        .create(&spec, &NeverCancelled)
        .expect("mapped create");

    let baseline_commands = baseline.fake.commands();
    assert!(baseline_commands.iter().all(|command| {
        !command
            .iter()
            .any(|argument| argument.starts_with("--add-host"))
    }));
    let mapped_commands = mapped.fake.commands();
    let pod_create = mapped_commands
        .iter()
        .find(|command| {
            semantic_starts_with(command, &["pod", "create"])
                && command
                    .iter()
                    .any(|argument| argument == "--add-host=automata-git.localhost:host-gateway")
        })
        .expect("pod create must carry the exact host-gateway alias");
    assert_eq!(
        pod_create
            .iter()
            .filter(|argument| argument.starts_with("--add-host"))
            .count(),
        1
    );
    assert!(!pod_create.iter().any(|argument| argument == "--add-host"));

    assert_ne!(
        spec_fingerprint(&baseline_commands),
        spec_fingerprint(&mapped_commands),
        "provider-owned replay fingerprint must cover the alias"
    );
}

#[test]
fn writable_ephemeral_rootfs_is_explicit_and_retains_isolation_controls() {
    let fixture = Fixture::new("writable-rootfs");
    assert!(
        fixture
            .provider
            .capabilities()
            .supports(SandboxCapability::WritableRootFilesystem)
    );
    let baseline = sample_spec(OperationId::new());
    let spec = SandboxSpec::new(
        OperationId::new(),
        SandboxGeneration::new(1).expect("generation"),
        baseline.profile().clone(),
        baseline.workspace().clone(),
        NetworkPolicy::PrivateEgress,
        RootFilesystemPolicy::Writable,
        baseline.resources(),
    )
    .with_privilege(SandboxPrivilegePolicy::Administrator);
    let created = fixture
        .provider
        .create(&spec, &NeverCancelled)
        .expect("writable rootfs is a supported explicit policy");

    let commands = fixture.fake.commands();
    let container_create = commands
        .iter()
        .find(|command| {
            semantic(command)
                .first()
                .is_some_and(|argument| argument == "create")
        })
        .expect("container create command");
    assert!(!container_create.iter().any(|value| value == "--read-only"));
    assert!(
        !container_create
            .iter()
            .any(|value| value == "--read-only-tmpfs=false")
    );
    for capability in ["chown", "setuid", "setgid"] {
        assert!(
            container_create
                .windows(2)
                .any(|arguments| arguments == ["--cap-add", capability])
        );
    }
    assert!(!container_create.iter().any(|value| value == "--privileged"));
    for required in [
        "--pull=never",
        "--cap-drop=all",
        "--security-opt=no-new-privileges",
        "--unsetenv-all",
        "--init",
    ] {
        assert!(container_create.iter().any(|value| value == required));
    }
    let pod_create = commands
        .iter()
        .find(|command| semantic_starts_with(command, &["pod", "create"]))
        .expect("pod create command");
    assert!(
        pod_create
            .windows(2)
            .any(|arguments| arguments == ["--userns", "keep-id:uid=0,gid=0"])
    );

    fixture
        .provider
        .destroy(
            &DestroySandbox::new(
                OperationId::new(),
                created.handle().clone(),
                created.generation(),
            ),
            &NeverCancelled,
        )
        .expect("destroy writable sandbox");
    assert!(fixture.fake.is_empty());
}

#[test]
fn partial_create_failure_returns_recovery_handle_and_replays() {
    let fixture = Fixture::new("partial-create");
    let spec = sample_spec(OperationId::new());
    fixture.fake.fail_once(&["pod", "create"]);

    let error = fixture
        .provider
        .create(&spec, &NeverCancelled)
        .expect_err("injected pod failure");
    assert_eq!(error.kind(), ProviderErrorKind::BackendRejected);
    assert_eq!(
        error.outcome(),
        automata_execution::OperationOutcome::Uncertain
    );
    let recovery = error
        .recovery_handle()
        .expect("mutation failure must expose opaque recovery handle")
        .clone();

    let replay = fixture
        .provider
        .create(&spec, &NeverCancelled)
        .expect("partial create must resume");
    assert_eq!(replay.handle(), &recovery);
    let network_creates = fixture
        .fake
        .commands()
        .iter()
        .filter(|command| semantic_starts_with(command, &["network", "create"]))
        .count();
    assert_eq!(network_creates, 1, "replay must reuse owned network");
}

#[test]
fn conflicting_spec_and_foreign_ownership_fail_closed() {
    let fixture = Fixture::new("ownership");
    let operation_id = OperationId::new();
    let first = sample_spec(operation_id);
    let created = fixture
        .provider
        .create(&first, &NeverCancelled)
        .expect("initial create");
    let conflicting = sample_spec_with(
        operation_id,
        "automata.dev/different-profile-v1",
        NetworkPolicy::Disabled,
    );
    let error = fixture
        .provider
        .create(&conflicting, &NeverCancelled)
        .expect_err("same id cannot change immutable spec");
    assert_eq!(error.kind(), ProviderErrorKind::Conflict);

    fixture.fake.replace_owner("foreign-runner");
    let before = fixture.fake.commands().len();
    let error = fixture
        .provider
        .destroy(
            &DestroySandbox::new(
                OperationId::new(),
                created.handle().clone(),
                created.generation(),
            ),
            &NeverCancelled,
        )
        .expect_err("foreign resource must survive");
    assert_eq!(error.kind(), ProviderErrorKind::OwnershipMismatch);
    assert!(
        fixture.fake.commands()[before..]
            .iter()
            .all(|command| !semantic(command).iter().any(|value| value == "rm"))
    );
    assert!(!fixture.fake.is_empty());
}

#[test]
fn same_profile_id_with_a_different_attestation_digest_cannot_replay() {
    let fixture = Fixture::new("profile-attestation");
    let operation_id = OperationId::new();
    let first = sample_spec(operation_id);
    fixture
        .provider
        .create(&first, &NeverCancelled)
        .expect("initial create");

    let conflicting = sample_spec_with_digest(
        operation_id,
        first.profile().id().as_str(),
        [0x22; 32],
        first.network(),
    );
    let error = fixture
        .provider
        .create(&conflicting, &NeverCancelled)
        .expect_err("same profile name cannot weaken the attestation digest");
    assert_eq!(error.kind(), ProviderErrorKind::Conflict);
}

#[test]
fn environment_values_are_exact_redacted_and_do_not_control_the_podman_client() {
    let fixture = Fixture::new("environment");
    let created = fixture
        .provider
        .create(&sample_spec(OperationId::new()), &NeverCancelled)
        .expect("create");
    let endpoint = fixture
        .provider
        .attach(created.handle(), &NeverCancelled)
        .expect("attach");
    for capability in [
        SandboxCapability::EnvironmentInjection,
        SandboxCapability::CopyTo,
        SandboxCapability::CopyFrom,
    ] {
        assert!(endpoint.capabilities().contains(&capability));
        assert!(fixture.provider.capabilities().supports(capability));
    }
    let secret = "first-line\nsecond-line";
    let home = "/__w/_home";
    let path = "/opt/tool/bin:/usr/bin";
    let temporary = "/__w/target/task-tmp/ci";
    let preload = "/__w/not-a-host-library.so";
    let environment = environment(&[
        ("TOKEN", secret),
        ("HOME", home),
        ("PATH", path),
        ("TMPDIR", temporary),
        ("LD_PRELOAD", preload),
        ("AUTOMATA_EMPTY", ""),
    ]);
    let command = ExecutionCommand::new(
        OperationId::new(),
        ExecutionArgv::new(TargetPath::posix("/bin/true").expect("path"), Vec::new())
            .expect("argv"),
        TargetPath::posix("/__w").expect("cwd"),
        environment,
        Duration::from_secs(5),
        1_024,
    )
    .expect("command");
    endpoint
        .exec(&command, &NeverCancelled)
        .expect("environment injection");

    let captured = fixture.fake.last_exec_environment();
    assert_eq!(captured.get("TOKEN").map(String::as_str), Some(secret));
    assert_eq!(captured.get("HOME").map(String::as_str), Some(home));
    assert_eq!(captured.get("PATH").map(String::as_str), Some(path));
    assert_eq!(captured.get("TMPDIR").map(String::as_str), Some(temporary));
    assert_eq!(
        captured.get("LD_PRELOAD").map(String::as_str),
        Some(preload)
    );
    assert_eq!(captured.get("AUTOMATA_EMPTY").map(String::as_str), Some(""));
    assert_eq!(
        fixture.fake.last_dynamic_environment_names(),
        vec!["TOKEN".to_owned(), "AUTOMATA_EMPTY".to_owned()]
    );
    assert_eq!(
        fixture.fake.last_process_home(),
        Some(fixture.scratch.path().to_path_buf())
    );
    assert_eq!(
        fixture.fake.last_process_temporary_directory(),
        Some(fixture.scratch.path().join("process-transient"))
    );
    assert!(fixture.fake.commands().iter().flatten().all(|argument| {
        argument != secret
            && argument != home
            && argument != path
            && argument != temporary
            && argument != preload
    }));
    assert!(transfer_directory_is_empty(&fixture));

    fixture.fake.set_exec_output(CommandOutput::terminated(
        automata_sandbox_podman::CommandTermination::Cancelled,
    ));
    let output = endpoint
        .exec(&command, &NeverCancelled)
        .expect("cancelled exec is a terminal result");
    assert_eq!(
        output.termination(),
        automata_execution::ExecutionTermination::Cancelled
    );
    assert!(transfer_directory_is_empty(&fixture));
}

#[test]
fn provider_control_environment_and_unrepresentable_env_file_values_fail_closed() {
    let fixture = Fixture::new("environment-rejection");
    let created = fixture
        .provider
        .create(&sample_spec(OperationId::new()), &NeverCancelled)
        .expect("create");
    let endpoint = fixture
        .provider
        .attach(created.handle(), &NeverCancelled)
        .expect("attach");

    for (name, value) in [
        ("CONTAINER_HOST", "unix:///host/podman.sock"),
        ("XDG_RUNTIME_DIR", "/host/control"),
        ("HOME", "/__w/home\nINJECTED=value"),
        ("PATH", ""),
    ] {
        let command = execution_command(environment(&[(name, value)]));
        let error = endpoint
            .exec(&command, &NeverCancelled)
            .expect_err("unsafe environment must be rejected");
        assert_eq!(error.kind(), ExecutionErrorKind::InvalidEnvironment);
        assert!(
            fixture
                .fake
                .commands()
                .iter()
                .flatten()
                .all(|argument| argument != value)
        );
    }
    let oversized = "x".repeat(64 * 1024);
    let command = execution_command(environment(&[("HOME", &oversized)]));
    assert_eq!(
        endpoint
            .exec(&command, &NeverCancelled)
            .expect_err("Podman env-file line bound must be enforced")
            .kind(),
        ExecutionErrorKind::InvalidEnvironment
    );
    assert!(transfer_directory_is_empty(&fixture));
}

#[test]
fn bounded_copy_round_trips_and_cleans_staging_on_success_and_failure() {
    let fixture = Fixture::new("copy-round-trip");
    let created = fixture
        .provider
        .create(&sample_spec(OperationId::new()), &NeverCancelled)
        .expect("create");
    let endpoint = fixture
        .provider
        .attach(created.handle(), &NeverCancelled)
        .expect("attach");
    let target = TargetPath::posix("/__w/exact-artifact").expect("target");
    let outbound = b"copy-to-secret\nwith-newline".to_vec();
    endpoint
        .copy_to(
            &CopyToRequest::new(OperationId::new(), target.clone(), outbound.clone())
                .expect("copy to"),
            &NeverCancelled,
        )
        .expect("copy to sandbox");
    assert_eq!(fixture.fake.copied_to(), Some(outbound));
    assert_eq!(fixture.fake.staged_input_mode(), Some(0o600));
    assert!(transfer_directory_is_empty(&fixture));

    let inbound = b"copy-from-secret\nwith-newline".to_vec();
    fixture.fake.set_copy_from(inbound.clone());
    let copied = endpoint
        .copy_from(
            &CopyFromRequest::new(OperationId::new(), target.clone(), 1_024).expect("copy from"),
            &NeverCancelled,
        )
        .expect("copy from sandbox");
    assert_eq!(copied, inbound);
    assert!(transfer_directory_is_empty(&fixture));

    fixture.fake.fail_once(&["cp"]);
    let error = endpoint
        .copy_to(
            &CopyToRequest::new(OperationId::new(), target, b"failure-secret".to_vec())
                .expect("copy to"),
            &NeverCancelled,
        )
        .expect_err("backend failure");
    assert_eq!(error.kind(), ExecutionErrorKind::BackendRejected);
    assert!(transfer_directory_is_empty(&fixture));

    fixture.fake.cancel_once(&["cp"]);
    let error = endpoint
        .copy_to(
            &CopyToRequest::new(
                OperationId::new(),
                TargetPath::posix("/__w/cancelled-artifact").expect("target"),
                b"cancelled-secret".to_vec(),
            )
            .expect("copy to"),
            &NeverCancelled,
        )
        .expect_err("cancelled backend copy");
    assert_eq!(error.kind(), ExecutionErrorKind::Cancelled);
    assert!(transfer_directory_is_empty(&fixture));
}

#[test]
fn copy_from_rejects_symlinks_directories_and_oversized_payloads_without_escape() {
    let fixture = Fixture::new("copy-attacks");
    let created = fixture
        .provider
        .create(&sample_spec(OperationId::new()), &NeverCancelled)
        .expect("create");
    let endpoint = fixture
        .provider
        .attach(created.handle(), &NeverCancelled)
        .expect("attach");
    let source = TargetPath::posix("/__w/artifact").expect("source");
    let outside = fixture.scratch.path().join("outside");
    std::fs::write(&outside, b"outside-must-survive").expect("outside fixture");

    fixture
        .fake
        .set_copy_attack(CopyAttack::Symlink(outside.clone()));
    let error = endpoint
        .copy_from(
            &CopyFromRequest::new(OperationId::new(), source.clone(), 1_024).expect("copy request"),
            &NeverCancelled,
        )
        .expect_err("symlink output must fail closed");
    assert_eq!(error.kind(), ExecutionErrorKind::LocalStorage);
    assert_eq!(
        std::fs::read(&outside).expect("outside remains"),
        b"outside-must-survive"
    );
    assert!(transfer_directory_is_empty(&fixture));

    fixture.fake.set_copy_attack(CopyAttack::Directory);
    assert_eq!(
        endpoint
            .copy_from(
                &CopyFromRequest::new(OperationId::new(), source.clone(), 1_024)
                    .expect("copy request"),
                &NeverCancelled,
            )
            .expect_err("directories are not byte payloads")
            .kind(),
        ExecutionErrorKind::LocalStorage
    );
    assert!(transfer_directory_is_empty(&fixture));

    fixture.fake.set_copy_from(vec![0x41; 65]);
    assert_eq!(
        endpoint
            .copy_from(
                &CopyFromRequest::new(OperationId::new(), source, 64).expect("copy request"),
                &NeverCancelled,
            )
            .expect_err("oversized payload")
            .kind(),
        ExecutionErrorKind::OutputLimitExceeded
    );
    assert!(transfer_directory_is_empty(&fixture));
}

fn environment(values: &[(&str, &str)]) -> ExecutionEnvironment {
    ExecutionEnvironment::new(
        values
            .iter()
            .map(|(name, value)| {
                EnvironmentVariable::new(
                    EnvironmentName::new(*name).expect("environment name"),
                    EnvironmentValue::new(*value).expect("environment value"),
                )
            })
            .collect(),
    )
    .expect("execution environment")
}

fn execution_command(environment: ExecutionEnvironment) -> ExecutionCommand {
    ExecutionCommand::new(
        OperationId::new(),
        ExecutionArgv::new(TargetPath::posix("/bin/true").expect("path"), Vec::new())
            .expect("argv"),
        TargetPath::posix("/__w").expect("cwd"),
        environment,
        Duration::from_secs(5),
        1_024,
    )
    .expect("command")
}

fn transfer_directory_is_empty(fixture: &Fixture) -> bool {
    std::fs::read_dir(fixture.scratch.path().join("transfers"))
        .expect("transfer directory")
        .next()
        .is_none()
}

#[test]
fn interrupted_exec_stops_the_owned_whole_job() {
    let fixture = Fixture::new("exec-interruption");
    let created = fixture
        .provider
        .create(&sample_spec(OperationId::new()), &NeverCancelled)
        .expect("create");
    let endpoint = fixture
        .provider
        .attach(created.handle(), &NeverCancelled)
        .expect("attach");
    fixture.fake.set_exec_output(CommandOutput::terminated(
        automata_sandbox_podman::CommandTermination::TimedOut,
    ));
    let command = ExecutionCommand::new(
        OperationId::new(),
        ExecutionArgv::new(
            TargetPath::posix("/bin/sleep").expect("path"),
            vec!["30".into()],
        )
        .expect("argv"),
        TargetPath::posix("/__w").expect("cwd"),
        ExecutionEnvironment::empty(),
        Duration::from_secs(1),
        1_024,
    )
    .expect("command");
    assert_eq!(
        endpoint
            .exec(&command, &NeverCancelled)
            .expect("timeout is a terminal output")
            .termination(),
        automata_execution::ExecutionTermination::TimedOut
    );
    assert_eq!(
        fixture
            .provider
            .inspect(created.handle(), &NeverCancelled)
            .expect("inspect stopped sandbox")
            .state(),
        SandboxState::Stopped
    );
}

#[test]
fn signal_and_wait_target_only_the_owned_primary_workload() {
    let fixture = Fixture::new("signal-wait");
    let created = fixture
        .provider
        .create(&sample_spec(OperationId::new()), &NeverCancelled)
        .expect("create");
    let endpoint = fixture
        .provider
        .attach(created.handle(), &NeverCancelled)
        .expect("attach");

    endpoint
        .signal(
            SignalRequest::new(OperationId::new(), ExecutionSignal::Terminate),
            &NeverCancelled,
        )
        .expect("signal");
    let status = endpoint
        .wait(
            WaitRequest::new(OperationId::new(), Duration::from_secs(5)).expect("wait request"),
            &NeverCancelled,
        )
        .expect("wait");

    assert_eq!(status, 137);
    let commands = fixture.fake.commands();
    assert!(commands.iter().any(|command| {
        semantic(command)
            .windows(3)
            .any(|window| window == ["kill", "--signal", "TERM"])
    }));
    assert!(commands.iter().any(|command| {
        semantic(command)
            .windows(3)
            .any(|window| window == ["wait", "--condition", "exited"])
    }));
}

fn semantic(command: &[String]) -> &[String] {
    let index = command
        .iter()
        .position(|argument| !argument.starts_with("--"))
        .unwrap_or(command.len());
    &command[index..]
}

fn spec_fingerprint(commands: &[Vec<String>]) -> String {
    commands
        .iter()
        .flat_map(|command| command.windows(2))
        .find_map(|window| {
            (window[0] == "--label")
                .then(|| window[1].strip_prefix("io.automata.spec-sha256="))
                .flatten()
        })
        .expect("create command must carry a spec fingerprint label")
        .to_owned()
}

fn semantic_starts_with(command: &[String], prefix: &[&str]) -> bool {
    semantic(command)
        .iter()
        .map(String::as_str)
        .zip(prefix.iter().copied())
        .all(|(actual, expected)| actual == expected)
        && semantic(command).len() >= prefix.len()
}

fn assert_hardened_commands(commands: &[Vec<String>]) {
    assert!(commands.iter().all(|command| {
        command
            .first()
            .is_some_and(|value| value == "--remote=false")
            && command
                .get(1)
                .is_some_and(|value| value.starts_with("--hooks-dir="))
            && command.iter().all(|argument| {
                !argument.contains("podman.sock")
                    && argument != "prune"
                    && argument != "--url"
                    && argument != "--authfile"
            })
    }));
    let container_create = commands
        .iter()
        .find(|command| {
            semantic(command)
                .first()
                .is_some_and(|value| value == "create")
        })
        .expect("container create command");
    for required in [
        "--pull=never",
        "--read-only",
        "--read-only-tmpfs=false",
        "--cap-drop=all",
        "--security-opt=no-new-privileges",
        "--unsetenv-all",
        "--init",
    ] {
        assert!(container_create.iter().any(|value| value == required));
    }
    assert_eq!(
        container_create
            .iter()
            .filter(|value| value.as_str() == "--volume")
            .count(),
        1
    );
    assert_eq!(
        commands
            .iter()
            .filter(|command| semantic_starts_with(command, &["network", "create"]))
            .count(),
        1
    );
    assert_eq!(
        commands
            .iter()
            .filter(|command| semantic_starts_with(command, &["pod", "create"]))
            .count(),
        1
    );
    assert_eq!(
        commands
            .iter()
            .filter(|command| semantic(command)
                .first()
                .is_some_and(|value| value == "create"))
            .count(),
        1
    );
}

fn assert_inspection_immediately_precedes_deletion(commands: &[Vec<String>]) {
    for (index, command) in commands.iter().enumerate() {
        if !semantic(command).iter().any(|argument| argument == "rm") {
            continue;
        }
        assert!(index > 0, "deletion must have a preceding inspect");
        assert!(
            semantic(&commands[index - 1])
                .iter()
                .any(|argument| argument == "inspect"),
            "ownership inspect must be immediately before exact deletion"
        );
    }
}
