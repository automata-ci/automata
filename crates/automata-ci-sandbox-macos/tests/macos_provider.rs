#![cfg(target_os = "macos")]
#![forbid(unsafe_code)]

use std::{
    fs,
    path::{Path, PathBuf},
    process::{Command, Stdio},
    thread,
    time::{Duration, Instant},
};

use automata_ci_execution::{
    DestroySandbox, EnvironmentProfile, EnvironmentProfileId, ExecutionArgv, ExecutionCommand,
    ExecutionEnvironment, ExecutionErrorKind, ExecutionTermination, NetworkPolicy, NeverCancelled,
    OperationId, OperationOutcome, ProviderErrorKind, ProviderStage, ResourceLimits,
    RootFilesystemPolicy, RunnerId, SandboxCustody, SandboxEnvironment, SandboxGeneration,
    SandboxHandle, SandboxProvider, SandboxSpec, Sha256Digest, TargetPath,
    discard_execution_output,
};
use automata_ci_sandbox_guest::GUEST_PROTOCOL_VERSION;
use automata_ci_sandbox_macos::{MacosVirtualizationProvider, MacosVirtualizationProviderOptions};
use static_assertions::assert_impl_all;

assert_impl_all!(MacosVirtualizationProvider: Send, Sync, Clone);

const PHYSICAL_CHILD_ENV: &str = "AUTOMATA_MACOS_ORPHAN_RECOVERY_CHILD";
const PHYSICAL_MARKER_ENV: &str = "AUTOMATA_MACOS_ORPHAN_RECOVERY_MARKER";
const VM_HELPER_ENV: &str = "AUTOMATA_MACOS_VM_HELPER";
const VM_HELPER_SHA256_ENV: &str = "AUTOMATA_MACOS_VM_HELPER_SHA256";
const VM_HELPER_REQUIREMENT_ENV: &str = "AUTOMATA_MACOS_VM_HELPER_REQUIREMENT";
const VM_TEMPLATE_MANIFEST_ENV: &str = "AUTOMATA_MACOS_VM_TEMPLATE_MANIFEST";
const VM_TEMPLATE_SHA256_ENV: &str = "AUTOMATA_MACOS_VM_TEMPLATE_SHA256";
const VM_STORAGE_ROOT_ENV: &str = "AUTOMATA_MACOS_VM_STORAGE_ROOT";
const VM_STORAGE_VOLUME_UUID_ENV: &str = "AUTOMATA_MACOS_VM_STORAGE_VOLUME_UUID";
const VM_STORAGE_QUOTA_BYTES_ENV: &str = "AUTOMATA_MACOS_VM_STORAGE_QUOTA_BYTES";

#[test]
fn swift_template_and_bridge_track_the_guest_protocol() {
    let expected = format!("private let guestProtocol: UInt16 = {GUEST_PROTOCOL_VERSION}");
    for source in [
        include_str!("../swift/Sources/AutomataMacOSTemplateTool/main.swift"),
        include_str!("../swift/Sources/AutomataMacOSVsockBridge/main.swift"),
    ] {
        assert!(
            source.lines().any(|line| line == expected),
            "Swift protocol constant must match the Rust guest"
        );
    }
}

fn options(
    root: impl Into<PathBuf>,
) -> Result<MacosVirtualizationProviderOptions, automata_ci_execution::ProviderError> {
    options_with_storage(
        root,
        "01234567-89AB-CDEF-0123-456789ABCDEF",
        256 * 1024 * 1024 * 1024,
    )
}

fn options_with_storage(
    root: impl Into<PathBuf>,
    storage_volume_uuid: &str,
    storage_quota_bytes: u64,
) -> Result<MacosVirtualizationProviderOptions, automata_ci_execution::ProviderError> {
    MacosVirtualizationProviderOptions::new(
        root,
        "/Library/Automata/bin/automata-macos-vm-helper",
        Sha256Digest::from_bytes([0x11; 32]),
        "identifier \"dev.automata.macos-vm-helper\" and anchor apple generic and certificate leaf[subject.OU] = \"ABCDEFGHIJ\"".to_owned(),
        "/Library/Automata/templates/macos-15-arm64-v1/manifest.json",
        Sha256Digest::from_bytes([0x22; 32]),
        storage_volume_uuid,
        storage_quota_bytes,
        Duration::from_mins(5),
        Duration::from_secs(10),
    )
}

#[test]
fn virtualization_options_require_a_pinned_bounded_apfs_quota() {
    let root = "/Volumes/AutomataVM/state";
    for uuid in ["", "not-a-uuid", "01234567-89AB-CDEF-0123-456789ABCDEG"] {
        assert_eq!(
            options_with_storage(root, uuid, 256 * 1024 * 1024 * 1024)
                .expect_err("invalid UUID must fail")
                .kind(),
            ProviderErrorKind::InvalidConfiguration
        );
    }
    for quota in [
        63 * 1024 * 1024 * 1024,
        256 * 1024 * 1024 * 1024 + 1,
        1025 * 1024 * 1024 * 1024,
    ] {
        assert_eq!(
            options_with_storage(root, "01234567-89AB-CDEF-0123-456789ABCDEF", quota,)
                .expect_err("invalid quota must fail")
                .kind(),
            ProviderErrorKind::InvalidConfiguration
        );
    }
}

#[test]
fn virtualization_options_require_absolute_normalized_paths_and_bounded_timeouts() {
    let valid = options("/Volumes/AutomataVM/state").expect("valid VM provider options");
    assert_eq!(
        valid.provider_root(),
        std::path::Path::new("/Volumes/AutomataVM/state")
    );

    for invalid in [
        "relative",
        "/",
        "/Users/runner/../runner/vm",
        "/Users/automata-runner/Library/Application Support/Automata/vm",
    ] {
        assert_eq!(
            options(invalid).expect_err("invalid root must fail").kind(),
            ProviderErrorKind::InvalidConfiguration
        );
    }
}

#[test]
fn provider_open_fails_closed_before_accepting_unpinned_artifacts() {
    let error = MacosVirtualizationProvider::open(
        options("/Volumes/AutomataVM/test-state").expect("syntactically valid options"),
    )
    .expect_err("uninstalled pinned helper and template must be rejected");
    assert_eq!(error.kind(), ProviderErrorKind::InvalidConfiguration);
}

#[test]
#[ignore = "requires a sealed VM template on a physical Apple Silicon runner"]
fn provider_reconciles_a_live_orphan_after_owner_process_loss() {
    if std::env::var_os(PHYSICAL_CHILD_ENV).is_some() {
        create_physical_orphan();
        return;
    }

    let root = required_path(VM_STORAGE_ROOT_ENV);
    assert_attempts_empty(&root);
    let marker = std::env::temp_dir().join(format!(
        "automata-macos-orphan-recovery-{}",
        OperationId::new()
    ));
    let mut child = Command::new(std::env::current_exe().expect("current test executable"))
        .args([
            "--exact",
            "provider_reconciles_a_live_orphan_after_owner_process_loss",
            "--ignored",
            "--nocapture",
        ])
        .env(PHYSICAL_CHILD_ENV, "1")
        .env(PHYSICAL_MARKER_ENV, &marker)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn isolated provider owner");
    let deadline = Instant::now() + Duration::from_mins(8);
    while !marker.exists() {
        if let Some(status) = child.try_wait().expect("inspect provider owner") {
            panic!("provider owner exited before creating a VM: {status}");
        }
        if Instant::now() >= deadline {
            child.kill().expect("kill timed-out provider owner");
            child.wait().expect("reap timed-out provider owner");
            panic!("provider owner did not create a VM within eight minutes");
        }
        thread::sleep(Duration::from_millis(100));
    }
    let orphan_count = attempt_count(&root);
    child.kill().expect("kill provider owner");
    let status = child.wait().expect("reap provider owner");
    assert!(
        !status.success(),
        "fault injection did not kill provider owner"
    );
    fs::remove_file(&marker).expect("remove orphan-ready marker");
    assert_eq!(orphan_count, 1, "child did not leave one live clone");

    let recovered = MacosVirtualizationProvider::open(physical_options(root.clone()))
        .expect("startup must reconcile the orphaned VM clone");
    assert_attempts_empty(&root);
    drop(recovered);
}

#[test]
#[ignore = "requires a sealed VM template on a physical Apple Silicon runner"]
fn provider_cleans_up_and_reuses_slot_after_live_helper_loss() {
    let root = required_path(VM_STORAGE_ROOT_ENV);
    assert_attempts_empty(&root);
    let provider = MacosVirtualizationProvider::open(physical_options(root.clone()))
        .expect("open physical macOS provider");

    let first_spec = physical_spec("helper-loss");
    let first = provider
        .create(&first_spec, &NeverCancelled)
        .expect("create helper-loss VM");
    let mut first_cleanup = PhysicalSandboxCleanup::new(
        provider.clone(),
        first.handle().clone(),
        first_spec.generation(),
        first_spec.custody(),
    );
    let endpoint = provider
        .attach(first.handle(), &NeverCancelled)
        .expect("attach helper-loss VM");
    kill_attempt_helper(&root, first.handle());
    let error = endpoint
        .exec(
            &probe_command(first_spec.workspace()),
            &NeverCancelled,
            discard_execution_output(),
        )
        .expect_err("a killed helper must close the guest endpoint");
    assert_eq!(error.kind(), ExecutionErrorKind::BackendRejected);
    drop(endpoint);
    provider
        .destroy(
            &DestroySandbox::new(
                OperationId::new(),
                first.handle().clone(),
                first_spec.generation(),
                first_spec.custody(),
            ),
            &NeverCancelled,
        )
        .expect("destroy VM after helper loss");
    first_cleanup.disarm();
    assert_attempts_empty(&root);

    let second_spec = physical_spec("helper-loss-reuse");
    let second = provider
        .create(&second_spec, &NeverCancelled)
        .expect("reuse provider slot after helper loss");
    let mut second_cleanup = PhysicalSandboxCleanup::new(
        provider.clone(),
        second.handle().clone(),
        second_spec.generation(),
        second_spec.custody(),
    );
    let endpoint = provider
        .attach(second.handle(), &NeverCancelled)
        .expect("attach replacement VM");
    let output = endpoint
        .exec(
            &probe_command(second_spec.workspace()),
            &NeverCancelled,
            discard_execution_output(),
        )
        .expect("execute in replacement VM");
    assert_eq!(output.termination(), ExecutionTermination::Exited(0));
    drop(endpoint);
    provider
        .destroy(
            &DestroySandbox::new(
                OperationId::new(),
                second.handle().clone(),
                second_spec.generation(),
                second_spec.custody(),
            ),
            &NeverCancelled,
        )
        .expect("destroy replacement VM");
    second_cleanup.disarm();
    assert_attempts_empty(&root);
}

#[test]
#[ignore = "requires a sealed VM template on a physical Apple Silicon runner"]
fn provider_recovers_an_interrupted_launch_and_reuses_the_slot() {
    let root = required_path(VM_STORAGE_ROOT_ENV);
    assert_attempts_empty(&root);
    let provider = MacosVirtualizationProvider::open(physical_options(root.clone()))
        .expect("open physical macOS provider");

    let interrupted_spec = physical_spec("launch-helper-loss");
    let (attempt, result) = thread::scope(|scope| {
        let create = scope.spawn(|| provider.create(&interrupted_spec, &NeverCancelled));
        let attempt = wait_for_single_attempt(&root, Duration::from_secs(30));
        kill_helper_for_attempt(&root, &attempt, Duration::from_secs(30));
        let result = create.join().expect("join interrupted VM create");
        (attempt, result)
    });
    let error = result.expect_err("killing the helper must interrupt VM launch");
    assert_eq!(error.kind(), ProviderErrorKind::AdapterUnavailable);
    assert_eq!(error.stage(), ProviderStage::CreateSandbox);
    assert_eq!(error.outcome(), OperationOutcome::Uncertain);
    let handle = error
        .recovery_handle()
        .expect("interrupted launch must return its exact recovery handle");
    assert_eq!(handle.opaque(), attempt);
    provider
        .destroy(
            &DestroySandbox::new(
                OperationId::new(),
                handle.clone(),
                interrupted_spec.generation(),
                interrupted_spec.custody(),
            ),
            &NeverCancelled,
        )
        .expect("reconcile interrupted VM launch");
    assert_attempts_empty(&root);

    create_probe_and_destroy(
        &provider,
        &physical_spec("launch-helper-loss-reuse"),
        "reuse provider slot after interrupted launch",
    );
    assert_attempts_empty(&root);
}

struct PhysicalSandboxCleanup {
    provider: MacosVirtualizationProvider,
    handle: SandboxHandle,
    generation: SandboxGeneration,
    custody: SandboxCustody,
    armed: bool,
}

impl PhysicalSandboxCleanup {
    fn new(
        provider: MacosVirtualizationProvider,
        handle: SandboxHandle,
        generation: SandboxGeneration,
        custody: SandboxCustody,
    ) -> Self {
        Self {
            provider,
            handle,
            generation,
            custody,
            armed: true,
        }
    }

    fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Drop for PhysicalSandboxCleanup {
    fn drop(&mut self) {
        if self.armed {
            let _ = self.provider.destroy(
                &DestroySandbox::new(
                    OperationId::new(),
                    self.handle.clone(),
                    self.generation,
                    self.custody,
                ),
                &NeverCancelled,
            );
        }
    }
}

fn physical_spec(name: &str) -> SandboxSpec {
    let manifest = required_digest(VM_TEMPLATE_SHA256_ENV);
    let profile = SandboxEnvironment::virtual_machine(
        EnvironmentProfile::new(
            EnvironmentProfileId::new("automata.dev/macos-15-arm64-vm-v1")
                .expect("physical profile ID"),
            manifest,
        ),
        manifest,
        TargetPath::posix("/Users/automata-job/workspaces").expect("profile workspace"),
        ExecutionEnvironment::empty(),
    )
    .expect("physical VM environment");
    SandboxSpec::new(
        OperationId::new(),
        SandboxGeneration::new(1).expect("sandbox generation"),
        SandboxCustody::ProfileAdmission {
            runner_id: RunnerId::new(),
        },
        profile,
        TargetPath::posix(format!("/Users/automata-job/workspaces/{name}")).expect("job workspace"),
        NetworkPolicy::Disabled,
        RootFilesystemPolicy::Writable,
        ResourceLimits::new(8 * 1024 * 1024 * 1024, 4_000, 512).expect("physical resources"),
    )
    .with_scratch(
        TargetPath::posix(format!("/Users/automata-job/runner/{name}")).expect("job scratch"),
    )
}

fn probe_command(working_directory: &TargetPath) -> ExecutionCommand {
    ExecutionCommand::new(
        OperationId::new(),
        ExecutionArgv::new(
            TargetPath::posix("/usr/bin/true").expect("true path"),
            Vec::new(),
        )
        .expect("probe argv"),
        working_directory.clone(),
        ExecutionEnvironment::empty(),
        Duration::from_secs(5),
        16 * 1024,
    )
    .expect("probe command")
}

fn create_probe_and_destroy(
    provider: &MacosVirtualizationProvider,
    spec: &SandboxSpec,
    create_label: &str,
) {
    let created = provider
        .create(spec, &NeverCancelled)
        .unwrap_or_else(|error| panic!("{create_label}: {error}"));
    let mut cleanup = PhysicalSandboxCleanup::new(
        provider.clone(),
        created.handle().clone(),
        spec.generation(),
        spec.custody(),
    );
    let endpoint = provider
        .attach(created.handle(), &NeverCancelled)
        .expect("attach replacement VM");
    let output = endpoint
        .exec(
            &probe_command(spec.workspace()),
            &NeverCancelled,
            discard_execution_output(),
        )
        .expect("execute in replacement VM");
    assert_eq!(output.termination(), ExecutionTermination::Exited(0));
    drop(endpoint);
    provider
        .destroy(
            &DestroySandbox::new(
                OperationId::new(),
                created.handle().clone(),
                spec.generation(),
                spec.custody(),
            ),
            &NeverCancelled,
        )
        .expect("destroy replacement VM");
    cleanup.disarm();
}

fn wait_for_single_attempt(root: &Path, timeout: Duration) -> String {
    let deadline = Instant::now() + timeout;
    loop {
        let attempts: Vec<_> = fs::read_dir(root.join("attempts"))
            .expect("read physical provider attempts")
            .map(|entry| entry.expect("read physical provider attempt entry"))
            .collect();
        match attempts.as_slice() {
            [attempt] => {
                return attempt
                    .file_name()
                    .into_string()
                    .expect("physical attempt name must be UTF-8");
            }
            [] if Instant::now() < deadline => thread::sleep(Duration::from_millis(10)),
            [] => panic!("provider did not create one VM attempt before the deadline"),
            _ => panic!("provider created more than one physical VM attempt"),
        }
    }
}

fn kill_helper_for_attempt(root: &Path, attempt: &str, timeout: Duration) {
    let lock = root.join("attempts").join(attempt).join(".vm.lock");
    let deadline = Instant::now() + timeout;
    loop {
        let pids = helper_pids_for_lock(&lock);
        match pids.as_slice() {
            [pid] => {
                let status = Command::new("/bin/kill")
                    .args(["-KILL", &pid.to_string()])
                    .status()
                    .expect("kill physical VM helper");
                assert!(status.success(), "physical VM helper kill failed");
                return;
            }
            [] if Instant::now() < deadline => thread::sleep(Duration::from_millis(10)),
            [] => panic!("physical VM helper did not start before the deadline"),
            _ => panic!("more than one helper owns the physical VM attempt"),
        }
    }
}

fn helper_pids_for_lock(lock: &Path) -> Vec<u32> {
    let helper = required_path(VM_HELPER_ENV);
    let expected = format!("{} run --lock {}", helper.display(), lock.display());
    let output = Command::new("/bin/ps")
        .args(["-axo", "pid=,command="])
        .output()
        .expect("list physical host processes");
    assert!(output.status.success(), "physical host ps failed");
    String::from_utf8(output.stdout)
        .expect("physical host process list must be UTF-8")
        .lines()
        .filter_map(|line| {
            let mut fields = line.trim_start().splitn(2, char::is_whitespace);
            let pid = fields.next()?.parse().ok()?;
            let command = fields.next()?.trim_start();
            (command == expected).then_some(pid)
        })
        .collect()
}

fn kill_attempt_helper(root: &Path, handle: &SandboxHandle) {
    let lock = root.join("attempts").join(handle.opaque()).join(".vm.lock");
    let pids = helper_pids_for_lock(&lock);
    assert_eq!(
        pids.len(),
        1,
        "expected exactly one helper for the owned VM attempt"
    );
    let status = Command::new("/bin/kill")
        .args(["-KILL", &pids[0].to_string()])
        .status()
        .expect("kill physical VM helper");
    assert!(status.success(), "physical VM helper kill failed");
}

fn create_physical_orphan() {
    let root = required_path(VM_STORAGE_ROOT_ENV);
    let provider = MacosVirtualizationProvider::open(physical_options(root))
        .expect("open physical macOS provider");
    let spec = physical_spec("orphan-recovery");
    provider
        .create(&spec, &NeverCancelled)
        .expect("create physical VM orphan fixture");
    fs::write(
        required_path(PHYSICAL_MARKER_ENV),
        b"provider owns a running VM\n",
    )
    .expect("publish orphan-ready marker");
    loop {
        thread::park();
    }
}

fn physical_options(root: PathBuf) -> MacosVirtualizationProviderOptions {
    MacosVirtualizationProviderOptions::new(
        root,
        required_path(VM_HELPER_ENV),
        required_digest(VM_HELPER_SHA256_ENV),
        required_value(VM_HELPER_REQUIREMENT_ENV),
        required_path(VM_TEMPLATE_MANIFEST_ENV),
        required_digest(VM_TEMPLATE_SHA256_ENV),
        &required_value(VM_STORAGE_VOLUME_UUID_ENV),
        required_value(VM_STORAGE_QUOTA_BYTES_ENV)
            .parse()
            .expect("storage quota must be decimal bytes"),
        Duration::from_mins(5),
        Duration::from_secs(10),
    )
    .expect("physical VM provider options")
}

fn required_value(name: &str) -> String {
    std::env::var(name).unwrap_or_else(|_| panic!("{name} is required"))
}

fn required_path(name: &str) -> PathBuf {
    PathBuf::from(required_value(name))
}

fn required_digest(name: &str) -> Sha256Digest {
    required_value(name)
        .parse()
        .unwrap_or_else(|_| panic!("{name} must be a SHA-256 digest"))
}

fn attempt_count(root: &Path) -> usize {
    fs::read_dir(root.join("attempts"))
        .expect("read provider attempts")
        .count()
}

fn assert_attempts_empty(root: &Path) {
    assert_eq!(attempt_count(root), 0, "provider left a VM clone behind");
}
