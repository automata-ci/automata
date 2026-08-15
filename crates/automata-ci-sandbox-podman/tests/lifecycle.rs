#![cfg(target_os = "linux")]

use crate::support;

use std::{
    num::NonZeroU16,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};

use automata_ci_execution::{
    CopyFromRequest, CopyToRequest, DestroyDisposition, DestroySandbox, EnvironmentName,
    EnvironmentValue, EnvironmentVariable, ExecutionArgv, ExecutionCommand, ExecutionEnvironment,
    ExecutionErrorKind, ExecutionSignal, NetworkPolicy, NeverCancelled, OperationId,
    ProviderErrorKind, RootFilesystemPolicy, RunnerId, SandboxCapability, SandboxCustody,
    SandboxGeneration, SandboxPrivilegePolicy, SandboxProvider, SandboxSpec, SandboxState,
    SignalRequest, TargetPath, WaitRequest,
};
use automata_ci_sandbox_podman::{
    CommandOutput, PodmanCommandExecutor, PodmanHostGatewayAlias, PodmanLaunchTrust,
    PodmanLaunchTrustHandle, RootlessPodmanProvider,
};

use support::{
    Fixture, sample_spec, sample_spec_with, sample_spec_with_digest, test_single_file_tar,
};

#[derive(Debug)]
struct ToggleLaunchTrust(Arc<AtomicBool>);

impl PodmanLaunchTrust for ToggleLaunchTrust {
    fn revalidate(&self) -> bool {
        self.0.load(Ordering::SeqCst)
    }
}

#[test]
fn provider_use_quarantines_before_dynamic_state_or_podman_work() {
    let admitted = Arc::new(AtomicBool::new(true));
    let trust = PodmanLaunchTrustHandle::new(Arc::new(ToggleLaunchTrust(Arc::clone(&admitted))));
    let fixture = Fixture::new_with_options("provider-launch-trust", |options| {
        options.with_launch_trust(trust)
    });
    admitted.store(false, Ordering::SeqCst);
    let spec = sample_spec(OperationId::new());

    let first = fixture
        .provider
        .create(&spec, &NeverCancelled)
        .expect_err("mount drift must quarantine provider use");
    assert_eq!(first.kind(), ProviderErrorKind::InvalidState);
    assert_eq!(
        first.stage(),
        automata_ci_execution::ProviderStage::CreateSandbox
    );
    admitted.store(true, Ordering::SeqCst);
    let restored = fixture
        .provider
        .create(&spec, &NeverCancelled)
        .expect_err("restoring host state must not clear quarantine");
    assert_eq!(restored.kind(), ProviderErrorKind::InvalidState);
    assert!(fixture.fake.commands().is_empty());
    assert!(
        std::fs::read_dir(fixture.scratch.path().join("workspaces"))
            .expect("workspace root")
            .next()
            .is_none(),
        "provider trust must run before dynamic workspace creation"
    );
}

#[test]
fn create_rejects_native_scratch_before_podman_or_filesystem_work() {
    let fixture = Fixture::new("native-scratch");
    let spec = sample_spec(OperationId::new())
        .with_scratch(TargetPath::posix("/__automata/scratch/job").expect("scratch path"));

    let error = fixture
        .provider
        .create(&spec, &NeverCancelled)
        .expect_err("Podman must reject native-provider scratch material");
    assert_eq!(error.kind(), ProviderErrorKind::UnsupportedCapability);
    assert_eq!(
        error.stage(),
        automata_ci_execution::ProviderStage::Validate
    );
    assert!(fixture.fake.commands().is_empty());
    assert!(
        std::fs::read_dir(fixture.scratch.path().join("workspaces"))
            .expect("workspace root")
            .next()
            .is_none(),
        "validation must run before dynamic workspace creation"
    );
}

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
    assert_eq!(fixture.fake.no_swap_verifications(), 3);
    assert_hardened_commands(&fixture.fake.commands(), fixture.scratch.path());
    assert_inspection_immediately_precedes_deletion(&fixture.fake.commands());
}

#[test]
fn create_fails_uncertain_when_the_live_cgroup_can_swap() {
    let fixture = Fixture::new("swap-enabled-cgroup");
    fixture.fake.fail_no_swap_verification_once();
    let spec = sample_spec(OperationId::new());

    let error = fixture
        .provider
        .create(&spec, &NeverCancelled)
        .expect_err("a swappable live cgroup must fail closed");
    assert_eq!(error.kind(), ProviderErrorKind::InvalidState);
    assert_eq!(error.stage(), automata_ci_execution::ProviderStage::Start);
    assert_eq!(
        error.outcome(),
        automata_ci_execution::OperationOutcome::Uncertain
    );
    let handle = error
        .recovery_handle()
        .expect("failed start retains an exact recovery handle")
        .clone();
    assert_eq!(fixture.fake.no_swap_verifications(), 1);
    assert_eq!(
        fixture
            .provider
            .inspect(&handle, &NeverCancelled)
            .expect("quarantined sandbox remains inspectable")
            .state(),
        SandboxState::Stopped
    );

    let replay = fixture
        .provider
        .create(&spec, &NeverCancelled)
        .expect("exact replay restarts and reverifies the quarantined sandbox");
    assert_eq!(replay.handle(), &handle);
    assert_eq!(fixture.fake.no_swap_verifications(), 2);
    fixture
        .provider
        .destroy(
            &DestroySandbox::new(OperationId::new(), handle, spec.generation()),
            &NeverCancelled,
        )
        .expect("destroy replayed sandbox");
}

#[test]
fn attach_reverifies_and_quarantines_a_running_sandbox() {
    let fixture = Fixture::new("attach-no-swap-reverification");
    let spec = sample_spec(OperationId::new());
    let created = fixture
        .provider
        .create(&spec, &NeverCancelled)
        .expect("create sandbox");
    fixture.fake.fail_no_swap_verification_once();

    let error = fixture
        .provider
        .attach(created.handle(), &NeverCancelled)
        .expect_err("attach must reverify the live cgroup");
    assert_eq!(error.kind(), ProviderErrorKind::InvalidState);
    assert_eq!(error.stage(), automata_ci_execution::ProviderStage::Attach);
    assert_eq!(
        fixture
            .provider
            .inspect(created.handle(), &NeverCancelled)
            .expect("quarantined sandbox remains inspectable")
            .state(),
        SandboxState::Stopped
    );

    let replay = fixture
        .provider
        .create(&spec, &NeverCancelled)
        .expect("create replay restarts and reverifies");
    fixture
        .provider
        .attach(replay.handle(), &NeverCancelled)
        .expect("verified replay can attach");
    assert_eq!(fixture.fake.no_swap_verifications(), 4);
    fixture
        .provider
        .destroy(
            &DestroySandbox::new(
                OperationId::new(),
                replay.handle().clone(),
                replay.generation(),
            ),
            &NeverCancelled,
        )
        .expect("destroy verified replay");
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
        automata_ci_execution::OperationOutcome::Uncertain
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
        automata_ci_execution::OperationOutcome::Uncertain
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
    let alias = PodmanHostGatewayAlias::new("automata-git.invalid", 8088).expect("valid alias");
    let mapped = Fixture::new_with_options("host-gateway-mapped", |options| {
        options
            .with_host_gateway_alias(alias)
            .expect("host gateway configuration")
    });
    let other_port_alias =
        PodmanHostGatewayAlias::new("automata-git.invalid", 8089).expect("valid alias");
    let other_port = Fixture::new_with_options("host-gateway-other-port", |options| {
        options
            .with_host_gateway_alias(other_port_alias)
            .expect("host gateway configuration")
    });
    mapped
        .provider
        .create(&spec, &NeverCancelled)
        .expect("mapped create");
    other_port
        .provider
        .create(&spec, &NeverCancelled)
        .expect("other-port create");

    let baseline_commands = baseline.fake.commands();
    assert!(baseline_commands.iter().all(|command| {
        !command
            .iter()
            .any(|argument| argument.starts_with("--add-host"))
    }));
    let mapped_commands = mapped.fake.commands();
    let other_port_commands = other_port.fake.commands();
    let pod_create = mapped_commands
        .iter()
        .find(|command| {
            semantic_starts_with(command, &["pod", "create"])
                && command
                    .iter()
                    .any(|argument| argument == "--add-host=automata-git.invalid:host-gateway")
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

    let baseline_configuration = std::fs::read_to_string(
        baseline
            .scratch
            .path()
            .join("podman-system-config/containers.conf"),
    )
    .expect("baseline containers.conf");
    let mapped_configuration = std::fs::read_to_string(
        mapped
            .scratch
            .path()
            .join("podman-system-config/containers.conf"),
    )
    .expect("mapped containers.conf");
    assert!(!baseline_configuration.contains("pasta_options"));
    assert!(mapped_configuration.contains("pasta_options = [\"--tcp-ns\", \"8088\"]"));

    assert_ne!(
        spec_fingerprint(&baseline_commands),
        spec_fingerprint(&mapped_commands),
        "provider-owned replay fingerprint must cover the alias"
    );
    assert_ne!(
        spec_fingerprint(&mapped_commands),
        spec_fingerprint(&other_port_commands),
        "provider-owned replay fingerprint must cover the forwarded port"
    );
}

#[test]
fn explicit_host_gateway_alias_rejects_disabled_network_before_podman_or_filesystem_work() {
    let alias = PodmanHostGatewayAlias::new("automata-git.invalid", 8088).expect("valid alias");
    let fixture = Fixture::new_with_options("host-gateway-disabled-network", |options| {
        options
            .with_host_gateway_alias(alias)
            .expect("host gateway configuration")
    });
    assert!(
        !fixture
            .provider
            .capabilities()
            .supports(SandboxCapability::NetworkDisabled),
        "mapped providers must not advertise disabled-network support"
    );
    let spec = sample_spec_with(
        OperationId::new(),
        "automata.dev/archlinux-x86-64-v1",
        NetworkPolicy::Disabled,
    );

    let error = fixture
        .provider
        .create(&spec, &NeverCancelled)
        .expect_err("disabled networking must reject the provider-wide host mapping");
    assert_eq!(error.kind(), ProviderErrorKind::UnsupportedCapability);
    assert_eq!(
        error.stage(),
        automata_ci_execution::ProviderStage::Validate
    );
    assert!(fixture.fake.commands().is_empty());
    assert!(
        std::fs::read_dir(fixture.scratch.path().join("workspaces"))
            .expect("workspace root")
            .next()
            .is_none(),
        "validation must run before dynamic workspace creation"
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
        baseline.custody(),
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
        automata_ci_execution::OperationOutcome::Uncertain
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
fn recovery_reports_custody_and_rejects_wrong_runner_slot_and_old_resource_schema() {
    let fixture = Fixture::new("custody-runner");
    let spec = sample_spec(OperationId::new());
    let record = fixture
        .provider
        .create(&spec, &NeverCancelled)
        .expect("create current custody resources");
    assert_eq!(
        fixture
            .provider
            .inspect(record.handle(), &NeverCancelled)
            .expect("inspect current custody")
            .custody(),
        spec.custody()
    );

    let wrong_runner = RunnerId::new();
    fixture
        .fake
        .replace_custody("profile-admission", wrong_runner, 0);
    assert_eq!(
        fixture
            .provider
            .inspect(record.handle(), &NeverCancelled)
            .expect("custody remains directly inspectable")
            .custody(),
        SandboxCustody::ProfileAdmission {
            runner_id: wrong_runner,
        }
    );
    let wrong_runner = fixture
        .provider
        .create(&spec, &NeverCancelled)
        .expect_err("create replay must reject a wrong runner label");
    assert_eq!(wrong_runner.kind(), ProviderErrorKind::OwnershipMismatch);

    let fixture = Fixture::new("custody-slot");
    let baseline = sample_spec(OperationId::new());
    let runner_id = RunnerId::new();
    let spec = SandboxSpec::new(
        baseline.operation_id(),
        baseline.generation(),
        SandboxCustody::Job {
            runner_id,
            slot_ordinal: NonZeroU16::new(2).expect("non-zero slot"),
        },
        baseline.profile().clone(),
        baseline.workspace().clone(),
        baseline.network(),
        baseline.root_filesystem(),
        baseline.resources(),
    );
    let record = fixture
        .provider
        .create(&spec, &NeverCancelled)
        .expect("create slot test resources");
    fixture.fake.replace_custody("job", runner_id, 1);
    assert_eq!(
        fixture
            .provider
            .inspect(record.handle(), &NeverCancelled)
            .expect("wrong slot remains explicit recovery evidence")
            .custody(),
        SandboxCustody::Job {
            runner_id,
            slot_ordinal: NonZeroU16::new(1).expect("non-zero slot"),
        }
    );
    let wrong_slot = fixture
        .provider
        .create(&spec, &NeverCancelled)
        .expect_err("create replay must reject a wrong slot label");
    assert_eq!(wrong_slot.kind(), ProviderErrorKind::OwnershipMismatch);

    let fixture = Fixture::new("custody-schema");
    let spec = sample_spec(OperationId::new());
    let record = fixture
        .provider
        .create(&spec, &NeverCancelled)
        .expect("create schema test resources");
    fixture.fake.replace_resource_schema("1");
    let old_schema = fixture
        .provider
        .inspect(record.handle(), &NeverCancelled)
        .expect_err("schema-1 Podman resources must not recover");
    assert_eq!(old_schema.kind(), ProviderErrorKind::InvalidState);
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
#[allow(clippy::too_many_lines)] // One adversarial transcript proves environment isolation end to end.
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
    let secret = "single-line-secret";
    let home = "/__w/_home";
    let path = "/opt/tool/bin:/usr/bin";
    let temporary = "/__w/target/task-tmp/ci";
    let preload = "/__w/not-a-host-library.so";
    let multiline = "/opt/cargo/registry/cache\n/opt/cargo/registry/index";
    let environment = environment_with_secrets(
        &[
            ("TOKEN", secret),
            ("HOME", home),
            ("PATH", path),
            ("TMPDIR", temporary),
            ("LD_PRELOAD", preload),
            ("AUTOMATA_EMPTY", ""),
            ("INPUT_PATH", multiline),
        ],
        &["TOKEN", "HOME", "INPUT_PATH"],
    );
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
        captured.get("INPUT_PATH").map(String::as_str),
        Some(multiline)
    );
    assert_eq!(
        fixture.fake.last_dynamic_environment_names(),
        ["INPUT_PATH"]
    );
    let commands = fixture.fake.commands();
    let exec = commands
        .iter()
        .find(|command| semantic_starts_with(command, &["exec"]))
        .expect("exec command");
    assert!(
        exec.windows(2)
            .any(|window| window == ["--env-file", "/dev/stdin"])
    );
    assert_eq!(
        fixture.fake.last_process_home(),
        Some(fixture.scratch.path().to_path_buf())
    );
    assert_eq!(
        fixture.fake.last_process_temporary_directory(),
        Some(fixture.scratch.path().join("process-transient"))
    );
    assert!(commands.iter().flatten().all(|argument| {
        argument != secret
            && argument != home
            && argument != path
            && argument != temporary
            && argument != preload
            && argument != multiline
    }));
    assert!(persistent_transfer_state_is_absent(&fixture));

    fixture.fake.set_exec_output(CommandOutput::terminated(
        automata_ci_sandbox_podman::CommandTermination::Cancelled,
    ));
    let output = endpoint
        .exec(&command, &NeverCancelled)
        .expect("cancelled exec is a terminal result");
    assert_eq!(
        output.termination(),
        automata_ci_execution::ExecutionTermination::Cancelled
    );
    assert!(persistent_transfer_state_is_absent(&fixture));
}

#[test]
fn provider_control_environment_and_unrepresentable_document_values_fail_closed() {
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
            .expect_err("Podman environment-document line bound must be enforced")
            .kind(),
        ExecutionErrorKind::InvalidEnvironment
    );
    assert!(persistent_transfer_state_is_absent(&fixture));
}

#[test]
fn bounded_copy_round_trips_without_durable_payload_staging() {
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
    assert!(persistent_transfer_state_is_absent(&fixture));

    let inbound = b"copy-from-secret\nwith-newline".to_vec();
    fixture.fake.set_copy_from(inbound.clone());
    let copied = endpoint
        .copy_from(
            &CopyFromRequest::new(OperationId::new(), target.clone(), 1_024).expect("copy from"),
            &NeverCancelled,
        )
        .expect("copy from sandbox");
    assert_eq!(copied, inbound);
    assert!(persistent_transfer_state_is_absent(&fixture));
    let copy_commands = fixture
        .fake
        .commands()
        .into_iter()
        .filter(|command| semantic_starts_with(command, &["cp"]))
        .collect::<Vec<_>>();
    assert_eq!(copy_commands.len(), 2);
    assert!(copy_commands.iter().all(|command| {
        command.iter().any(|argument| argument == "-")
            && command
                .iter()
                .all(|argument| !argument.contains("/transfers/"))
    }));

    fixture.fake.fail_once(&["cp"]);
    let error = endpoint
        .copy_to(
            &CopyToRequest::new(OperationId::new(), target, b"failure-secret".to_vec())
                .expect("copy to"),
            &NeverCancelled,
        )
        .expect_err("backend failure");
    assert_eq!(error.kind(), ExecutionErrorKind::BackendRejected);
    assert!(!format!("{error:?}").contains("failure-secret"));
    assert!(persistent_transfer_state_is_absent(&fixture));

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
    assert!(!format!("{error:?}").contains("cancelled-secret"));
    assert!(persistent_transfer_state_is_absent(&fixture));
}

#[test]
fn copy_from_rejects_nonregular_malformed_and_oversized_archives() {
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

    let mut symlink = test_single_file_tar("artifact", b"ignored");
    symlink[156] = b'2';
    fixture.fake.set_copy_archive(symlink);
    let error = endpoint
        .copy_from(
            &CopyFromRequest::new(OperationId::new(), source.clone(), 1_024).expect("copy request"),
            &NeverCancelled,
        )
        .expect_err("symlink archive must fail closed");
    assert_eq!(error.kind(), ExecutionErrorKind::BackendRejected);
    assert!(persistent_transfer_state_is_absent(&fixture));

    let mut directory = test_single_file_tar("artifact", b"ignored");
    directory[156] = b'5';
    fixture.fake.set_copy_archive(directory);
    assert_eq!(
        endpoint
            .copy_from(
                &CopyFromRequest::new(OperationId::new(), source.clone(), 1_024)
                    .expect("copy request"),
                &NeverCancelled,
            )
            .expect_err("directory archive must fail closed")
            .kind(),
        ExecutionErrorKind::BackendRejected
    );
    assert!(persistent_transfer_state_is_absent(&fixture));

    fixture.fake.set_copy_archive(vec![0_u8; 3 * 512]);
    assert_eq!(
        endpoint
            .copy_from(
                &CopyFromRequest::new(OperationId::new(), source.clone(), 1_024)
                    .expect("copy request"),
                &NeverCancelled,
            )
            .expect_err("malformed archive must fail closed")
            .kind(),
        ExecutionErrorKind::BackendRejected
    );
    assert!(persistent_transfer_state_is_absent(&fixture));

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
    assert!(persistent_transfer_state_is_absent(&fixture));
}

fn environment(values: &[(&str, &str)]) -> ExecutionEnvironment {
    environment_with_secrets(values, &[])
}

fn environment_with_secrets(
    values: &[(&str, &str)],
    secret_names: &[&str],
) -> ExecutionEnvironment {
    ExecutionEnvironment::new(
        values
            .iter()
            .map(|(name, value)| {
                let name = EnvironmentName::new(*name).expect("environment name");
                let value = EnvironmentValue::new(*value).expect("environment value");
                if secret_names.contains(&name.as_str()) {
                    EnvironmentVariable::secret(name, value)
                } else {
                    EnvironmentVariable::new(name, value)
                }
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

fn persistent_transfer_state_is_absent(fixture: &Fixture) -> bool {
    !fixture.scratch.path().join("transfers").exists()
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
        automata_ci_sandbox_podman::CommandTermination::TimedOut,
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
        automata_ci_execution::ExecutionTermination::TimedOut
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

fn assert_hardened_commands(commands: &[Vec<String>], state_root: &std::path::Path) {
    let expected_prefix = expected_global_prefix(state_root);
    assert!(commands.iter().all(|command| {
        command.starts_with(&expected_prefix)
            && command.iter().all(|argument| {
                !argument.contains("podman.sock")
                    && argument != "prune"
                    && argument != "--url"
                    && argument != "--authfile"
            })
    }));
    assert_hardened_container_create(commands);
    assert_hardened_pod_create(commands);
}

fn expected_global_prefix(state_root: &std::path::Path) -> Vec<String> {
    let graph_root = state_root.join("podman-graph");
    let runtime_root = state_root.join("runtime/automata-ci-podman");
    vec![
        "--remote=false".to_owned(),
        format!("--root={}", graph_root.display()),
        format!("--runroot={}", runtime_root.join("shared-run").display()),
        "--storage-driver=vfs".to_owned(),
        "--storage-opt=".to_owned(),
        "--transient-store=false".to_owned(),
        format!("--hooks-dir={}", state_root.join("empty-hooks").display()),
        format!(
            "--cdi-spec-dir={}",
            state_root.join("podman-system-config/empty-cdi").display()
        ),
        format!(
            "--default-mounts-file={}",
            state_root
                .join("podman-system-config/mounts.conf")
                .display()
        ),
        format!(
            "--network-config-dir={}",
            graph_root.join("networks").display()
        ),
        format!("--tmpdir={}", runtime_root.join("shared-tmp").display()),
        format!("--volumepath={}", graph_root.join("volumes").display()),
        "--events-backend=none".to_owned(),
        "--conmon=/usr/bin/true".to_owned(),
        "--runtime=/usr/bin/true".to_owned(),
        "--cgroup-manager=cgroupfs".to_owned(),
    ]
}

fn assert_hardened_container_create(commands: &[Vec<String>]) {
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
}

fn assert_hardened_pod_create(commands: &[Vec<String>]) {
    let pod_create = commands
        .iter()
        .find(|command| semantic_starts_with(command, &["pod", "create"]))
        .expect("pod create command");
    for option in ["--memory", "--memory-swap"] {
        assert!(
            pod_create
                .windows(2)
                .any(|arguments| arguments == [option, "536870912b"]),
            "missing exact {option} limit"
        );
    }
    assert!(
        pod_create
            .windows(2)
            .any(|arguments| arguments == ["--cgroup-parent", "/automata-runner.service"]),
        "missing exact delegated cgroup parent"
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
