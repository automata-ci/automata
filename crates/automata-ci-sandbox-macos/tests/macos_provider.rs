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
    EnvironmentProfile, EnvironmentProfileId, ExecutionEnvironment, NetworkPolicy, NeverCancelled,
    OperationId, ProviderErrorKind, ResourceLimits, RootFilesystemPolicy, RunnerId, SandboxCustody,
    SandboxEnvironment, SandboxGeneration, SandboxProvider, SandboxSpec, Sha256Digest, TargetPath,
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

fn create_physical_orphan() {
    let root = required_path(VM_STORAGE_ROOT_ENV);
    let provider = MacosVirtualizationProvider::open(physical_options(root))
        .expect("open physical macOS provider");
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
    let spec = SandboxSpec::new(
        OperationId::new(),
        SandboxGeneration::new(1).expect("sandbox generation"),
        SandboxCustody::ProfileAdmission {
            runner_id: RunnerId::new(),
        },
        profile,
        TargetPath::posix("/Users/automata-job/workspaces/orphan-recovery").expect("job workspace"),
        NetworkPolicy::Disabled,
        RootFilesystemPolicy::Writable,
        ResourceLimits::new(8 * 1024 * 1024 * 1024, 4_000, 512).expect("physical resources"),
    )
    .with_scratch(
        TargetPath::posix("/Users/automata-job/runner/orphan-recovery").expect("job scratch"),
    );
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
