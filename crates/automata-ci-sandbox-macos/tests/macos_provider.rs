#![cfg(target_os = "macos")]
#![forbid(unsafe_code)]

use std::{
    fs::{self, File, OpenOptions},
    io::Write as _,
    os::unix::fs::PermissionsExt as _,
    path::{Path, PathBuf},
};

use automata_ci_execution::{
    Cancellation, CopyFromRequest, CopyToRequest, DestroyDisposition, DestroySandbox,
    EnvironmentName, EnvironmentProfile, EnvironmentProfileId, EnvironmentValue,
    EnvironmentVariable, ExecutionEnvironment, ExecutionErrorKind, NetworkPolicy, NeverCancelled,
    OperationId, ProviderErrorKind, RootFilesystemPolicy, SandboxCapability, SandboxEnvironment,
    SandboxGeneration, SandboxPrivilegePolicy, SandboxProvider, SandboxSpec, SandboxState,
    Sha256Digest, TargetPath,
};
use automata_ci_sandbox_macos::{MacosSandboxProvider, MacosSandboxProviderOptions};
use static_assertions::assert_impl_all;

assert_impl_all!(MacosSandboxProvider: Send, Sync, Clone);

struct AlwaysCancelled;

impl Cancellation for AlwaysCancelled {
    fn is_cancelled(&self) -> bool {
        true
    }
}

#[test]
fn lifecycle_copy_replay_and_destroy_are_generation_fenced() {
    let fixture = Fixture::new("lifecycle");
    let spec = fixture.spec();
    let record = fixture
        .provider
        .create(&spec, &NeverCancelled)
        .expect("create macOS sandbox");
    assert_eq!(record.state(), SandboxState::Running);
    assert_eq!(
        fixture
            .provider
            .create(&spec, &NeverCancelled)
            .expect("replay exact create"),
        record
    );
    assert!(
        fixture
            .provider
            .capabilities()
            .supports(SandboxCapability::HostResources)
    );
    assert!(
        !fixture
            .provider
            .capabilities()
            .supports(SandboxCapability::ResourceLimits)
    );

    let endpoint = fixture
        .provider
        .attach(record.handle(), &NeverCancelled)
        .expect("attach macOS sandbox");
    let payload = fixture.workspace.join("payload.txt");
    let copy_to = CopyToRequest::new(OperationId::new(), target(&payload), b"payload".to_vec())
        .expect("copy request");
    endpoint
        .copy_to(&copy_to, &NeverCancelled)
        .expect("copy into sandbox");
    endpoint
        .copy_to(&copy_to, &NeverCancelled)
        .expect("replay copy into sandbox");
    let copy_from =
        CopyFromRequest::new(OperationId::new(), target(&payload), 64).expect("copy-from request");
    assert_eq!(
        endpoint
            .copy_from(&copy_from, &NeverCancelled)
            .expect("copy out of sandbox"),
        b"payload"
    );
    drop(endpoint);

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
            .expect("replay destroy"),
        DestroyDisposition::Destroyed
    );
    assert!(!fixture.workspace.exists());
    assert!(!fixture.scratch.exists());
}

#[test]
fn restart_reconciles_live_sandbox_and_preserves_create_witness() {
    let root = TestRoot::new("restart");
    let profile_workspace = root.path.join("workspaces");
    let workspace = profile_workspace.join("job-a");
    let scratch = root.path.join("scratch-a");
    let spec = spec(
        &profile_workspace,
        &workspace,
        &scratch,
        ExecutionEnvironment::empty(),
    );
    let record = {
        let provider = open(&root.path);
        provider
            .create(&spec, &NeverCancelled)
            .expect("create before restart")
    };
    assert!(workspace.is_dir());
    assert!(scratch.is_dir());

    OpenOptions::new()
        .append(true)
        .open(root.path.join(".automata-macos-provider-v1.events"))
        .and_then(|mut journal| journal.write_all(b"interrupted-tail"))
        .expect("append crash-truncated journal tail");

    let provider = open(&root.path);
    assert!(!workspace.exists());
    assert!(!scratch.exists());
    assert_eq!(
        provider
            .inspect(record.handle(), &NeverCancelled)
            .expect("inspect recovered handle")
            .state(),
        SandboxState::Absent
    );
    assert_eq!(
        provider
            .create(&spec, &NeverCancelled)
            .expect("replay recovered create")
            .state(),
        SandboxState::Absent
    );
}

#[test]
fn provider_is_single_slot_generation_fenced_and_cancellation_safe() {
    let fixture = Fixture::new("single-slot");
    let cancelled = AlwaysCancelled;
    assert_eq!(
        fixture
            .provider
            .create(&fixture.spec(), &cancelled)
            .expect_err("cancelled create must stop before mutation")
            .kind(),
        ProviderErrorKind::Cancelled
    );
    assert!(!fixture.workspace.exists());
    assert!(!fixture.scratch.exists());

    let record = fixture
        .provider
        .create(&fixture.spec(), &NeverCancelled)
        .expect("create first sandbox");
    let second_workspace = fixture.profile_workspace.join("job-b");
    let second_scratch = fixture.root.path.join("scratch-b");
    let second = spec(
        &fixture.profile_workspace,
        &second_workspace,
        &second_scratch,
        ExecutionEnvironment::empty(),
    );
    assert_eq!(
        fixture
            .provider
            .create(&second, &NeverCancelled)
            .expect_err("one provider root must admit one slot")
            .kind(),
        ProviderErrorKind::Conflict
    );
    let stale = DestroySandbox::new(
        OperationId::new(),
        record.handle().clone(),
        SandboxGeneration::new(record.generation().get() + 1).expect("stale generation"),
    );
    assert_eq!(
        fixture
            .provider
            .destroy(&stale, &NeverCancelled)
            .expect_err("stale generation must not destroy the live sandbox")
            .kind(),
        ProviderErrorKind::OwnershipMismatch
    );
    assert!(fixture.workspace.is_dir());
}

#[test]
fn provider_lock_and_bounded_journal_fail_closed() {
    let root = TestRoot::new("exclusive-lock");
    let provider = open(&root.path);
    let error = MacosSandboxProvider::open(
        MacosSandboxProviderOptions::new(&root.path, "/bin/sh").expect("provider options"),
    )
    .expect_err("a second provider process must not share one root");
    assert_eq!(error.kind(), ProviderErrorKind::Conflict);
    drop(provider);

    let corrupt = TestRoot::new("corrupt-journal");
    prepare_journal(
        &corrupt.path,
        Some(b"{\"schema\":1,\"corrupt\":true}\n"),
        None,
    );
    assert_eq!(
        MacosSandboxProvider::open(
            MacosSandboxProviderOptions::new(&corrupt.path, "/bin/sh").expect("provider options"),
        )
        .expect_err("corrupt journal must fail closed")
        .kind(),
        ProviderErrorKind::LocalStorage
    );

    let oversized = TestRoot::new("oversized-journal");
    prepare_journal(&oversized.path, None, Some(16 * 1024 * 1024 + 1));
    assert_eq!(
        MacosSandboxProvider::open(
            MacosSandboxProviderOptions::new(&oversized.path, "/bin/sh").expect("provider options"),
        )
        .expect_err("oversized journal must fail closed")
        .kind(),
        ProviderErrorKind::LocalStorage
    );
}

#[test]
fn copy_rejects_symlink_escape_without_touching_foreign_file() {
    let fixture = Fixture::new("symlink");
    let record = fixture
        .provider
        .create(&fixture.spec(), &NeverCancelled)
        .expect("create sandbox");
    let endpoint = fixture
        .provider
        .attach(record.handle(), &NeverCancelled)
        .expect("attach sandbox");
    let foreign = fixture.root.path.join("foreign.txt");
    fs::write(&foreign, b"foreign").expect("write foreign sentinel");
    let link = fixture.workspace.join("escape.txt");
    std::os::unix::fs::symlink(&foreign, &link).expect("create attack symlink");
    let error = endpoint
        .copy_to(
            &CopyToRequest::new(OperationId::new(), target(&link), b"changed".to_vec())
                .expect("copy request"),
            &NeverCancelled,
        )
        .expect_err("copy must not follow symlink");
    assert_eq!(
        error.kind(),
        automata_ci_execution::ExecutionErrorKind::OwnershipMismatch
    );
    assert_eq!(fs::read(&foreign).expect("read sentinel"), b"foreign");
}

#[test]
fn copy_rejects_hard_links_and_bounds_reads() {
    let fixture = Fixture::new("hard-link");
    let record = fixture
        .provider
        .create(&fixture.spec(), &NeverCancelled)
        .expect("create sandbox");
    let endpoint = fixture
        .provider
        .attach(record.handle(), &NeverCancelled)
        .expect("attach sandbox");
    let foreign = fixture.root.path.join("foreign.txt");
    fs::write(&foreign, b"foreign").expect("write foreign sentinel");
    let link = fixture.workspace.join("linked.txt");
    fs::hard_link(&foreign, &link).expect("create attack hard link");
    assert_eq!(
        endpoint
            .copy_to(
                &CopyToRequest::new(OperationId::new(), target(&link), b"changed".to_vec())
                    .expect("copy request"),
                &NeverCancelled,
            )
            .expect_err("copy must reject a multiply linked target")
            .kind(),
        ExecutionErrorKind::OwnershipMismatch
    );
    assert_eq!(fs::read(&foreign).expect("read sentinel"), b"foreign");

    let payload = fixture.workspace.join("bounded.txt");
    fs::write(&payload, b"12345").expect("write bounded payload");
    assert_eq!(
        endpoint
            .copy_from(
                &CopyFromRequest::new(OperationId::new(), target(&payload), 4)
                    .expect("copy-from request"),
                &NeverCancelled,
            )
            .expect_err("copy must not return content beyond the caller's bound")
            .kind(),
        ExecutionErrorKind::OutputLimitExceeded
    );
}

#[test]
fn host_policy_and_nonsecret_profile_defaults_are_mandatory() {
    let fixture = Fixture::new("policy");
    let enforced = SandboxSpec::new(
        OperationId::new(),
        SandboxGeneration::new(2).expect("generation"),
        environment(&fixture.profile_workspace, ExecutionEnvironment::empty()),
        target(&fixture.workspace),
        NetworkPolicy::Host,
        RootFilesystemPolicy::Host,
        automata_ci_execution::ResourceLimits::new(64 * 1024 * 1024, 1_000, 8).expect("limits"),
    )
    .with_privilege(SandboxPrivilegePolicy::Host)
    .with_scratch(target(&fixture.scratch));
    assert_eq!(
        fixture
            .provider
            .create(&enforced, &NeverCancelled)
            .expect_err("hard-limit claim must be rejected")
            .kind(),
        ProviderErrorKind::InvalidConfiguration
    );

    let defaults = ExecutionEnvironment::new(vec![EnvironmentVariable::secret(
        EnvironmentName::new("PROFILE_SECRET").expect("name"),
        EnvironmentValue::new("never-persist").expect("value"),
    )])
    .expect("secret defaults");
    let secret = spec(
        &fixture.profile_workspace,
        &fixture.workspace,
        &fixture.scratch,
        defaults,
    );
    assert_eq!(
        fixture
            .provider
            .create(&secret, &NeverCancelled)
            .expect_err("secret profile default must be rejected")
            .kind(),
        ProviderErrorKind::InvalidConfiguration
    );
}

struct Fixture {
    provider: MacosSandboxProvider,
    profile_workspace: PathBuf,
    workspace: PathBuf,
    scratch: PathBuf,
    root: TestRoot,
}

impl Fixture {
    fn new(label: &str) -> Self {
        let root = TestRoot::new(label);
        let provider = open(&root.path);
        let profile_workspace = root.path.join("workspaces");
        let workspace = profile_workspace.join("job-a");
        let scratch = root.path.join("scratch-a");
        Self {
            provider,
            profile_workspace,
            workspace,
            scratch,
            root,
        }
    }

    fn spec(&self) -> SandboxSpec {
        spec(
            &self.profile_workspace,
            &self.workspace,
            &self.scratch,
            ExecutionEnvironment::empty(),
        )
    }
}

fn spec(
    profile_workspace: &Path,
    workspace: &Path,
    scratch: &Path,
    defaults: ExecutionEnvironment,
) -> SandboxSpec {
    SandboxSpec::host_shared(
        OperationId::new(),
        SandboxGeneration::new(1).expect("generation"),
        environment(profile_workspace, defaults),
        target(workspace),
        NetworkPolicy::Host,
        RootFilesystemPolicy::Host,
    )
    .with_privilege(SandboxPrivilegePolicy::Host)
    .with_scratch(target(scratch))
}

fn environment(workspace: &Path, defaults: ExecutionEnvironment) -> SandboxEnvironment {
    SandboxEnvironment::native_posix(
        EnvironmentProfile::new(
            EnvironmentProfileId::new("automata.dev/macos-native-arm64-v1").expect("profile ID"),
            Sha256Digest::from_bytes([0x6d; 32]),
        ),
        target(workspace),
        defaults,
    )
    .expect("native POSIX environment")
}

fn open(root: &Path) -> MacosSandboxProvider {
    MacosSandboxProvider::open(
        MacosSandboxProviderOptions::new(root, "/bin/sh").expect("provider options"),
    )
    .expect("open macOS provider")
}

fn prepare_journal(root: &Path, bytes: Option<&[u8]>, length: Option<u64>) {
    fs::create_dir_all(root).expect("create provider root");
    fs::set_permissions(root, fs::Permissions::from_mode(0o700)).expect("restrict provider root");
    let path = root.join(".automata-macos-provider-v1.events");
    match bytes {
        Some(bytes) => fs::write(&path, bytes).expect("write journal fixture"),
        None => {
            File::create(&path)
                .and_then(|journal| journal.set_len(length.expect("journal fixture length")))
                .expect("size journal fixture");
        }
    }
    fs::set_permissions(path, fs::Permissions::from_mode(0o600)).expect("restrict journal fixture");
}

fn target(path: &Path) -> TargetPath {
    TargetPath::posix(path.to_str().expect("Unicode test path")).expect("POSIX target")
}

struct TestRoot {
    path: PathBuf,
}

impl TestRoot {
    fn new(label: &str) -> Self {
        let path = std::env::current_dir()
            .expect("current directory")
            .join("target/agent-scratch/macos-provider")
            .join(format!("{label}-{}", uuid::Uuid::new_v4()));
        Self { path }
    }
}

impl Drop for TestRoot {
    fn drop(&mut self) {
        if self.path.exists() {
            fs::remove_dir_all(&self.path).expect("remove exact test root");
        }
    }
}
