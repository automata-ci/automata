use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, File, Metadata},
    os::unix::fs::MetadataExt as _,
    path::{Component, Path, PathBuf},
};

use automata_ci_sandbox_podman::{PodmanLaunchTrust, PodmanOptions};

use super::super::state::RuntimeMountSnapshot;

const APPROVED_HELPERS: [&str; 7] = [
    "aardvark-dns",
    "netavark",
    "newgidmap",
    "newuidmap",
    "nft",
    "pasta",
    "rootlessport",
];
const PODMAN_ROOTLESS_PAUSE_INIT: &str = "/usr/bin/catatonit";
const PODMAN_COMPILED_PAUSE_INIT: &str = "/usr/libexec/podman/catatonit";

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct PodmanProcessTrust {
    binary: PathBuf,
    approved_helper_directory: PathBuf,
    conmon_path: PathBuf,
    oci_runtime_path: PathBuf,
    init_path: PathBuf,
    seccomp_profile_path: PathBuf,
    home: PathBuf,
    runtime_directory: PathBuf,
    runtime_root: PathBuf,
    runtime_job_engines_root: PathBuf,
    state_root: PathBuf,
    process_transient_directory: PathBuf,
    system_config_directory: PathBuf,
    hooks_directory: PathBuf,
    cdi_directory: PathBuf,
    probe_directory: PathBuf,
    shared_graph_root: PathBuf,
    shared_run_root: PathBuf,
    shared_tmp_directory: PathBuf,
    rootless_pause_init: PathBuf,
    compiled_pause_init: PathBuf,
    user_namespace_remove: PathBuf,
    registry_certificate_directories: Vec<PathBuf>,
    administrator_user: u32,
    runtime_mount: RuntimeMountSnapshot,
    synthetic_runtime_mount: bool,
    immutable: BTreeMap<PathBuf, FileIdentity>,
    private_roots: BTreeMap<PathBuf, NodeIdentity>,
}

impl PodmanProcessTrust {
    pub(super) fn capture(
        options: &PodmanOptions,
        runtime_mount: RuntimeMountSnapshot,
    ) -> Result<Self, TrustError> {
        Self::capture_snapshot(
            options,
            HostInputPolicy::production(options),
            runtime_mount,
            false,
        )
    }

    #[cfg(test)]
    fn capture_with_policy(
        options: &PodmanOptions,
        policy: HostInputPolicy,
    ) -> Result<Self, TrustError> {
        Self::capture_snapshot(
            options,
            policy,
            RuntimeMountSnapshot::synthetic_for_test(
                options.process_environment().runtime_directory(),
            ),
            true,
        )
    }

    fn capture_snapshot(
        options: &PodmanOptions,
        policy: HostInputPolicy,
        runtime_mount: RuntimeMountSnapshot,
        synthetic_runtime_mount: bool,
    ) -> Result<Self, TrustError> {
        let binary = options.binary().as_path().to_path_buf();
        let environment = options.process_environment();
        let approved_helper_directory = environment.approved_helper_directory().to_path_buf();
        let conmon_path = environment.conmon_path().to_path_buf();
        let oci_runtime_path = environment.oci_runtime_path().to_path_buf();
        let init_path = environment.init_path().to_path_buf();
        let seccomp_profile_path = environment.seccomp_profile_path().to_path_buf();
        let home = environment.home().to_path_buf();
        let runtime_directory = environment.runtime_directory().to_path_buf();
        let runtime_root = options.runtime_root();
        let runtime_job_engines_root = runtime_root.join("job-engines");
        let state_root = environment.state_root().to_path_buf();
        let process_transient_directory = environment.process_transient_directory().to_path_buf();
        let system_config_directory = environment.system_config_directory().to_path_buf();
        let hooks_directory = environment.empty_hooks_directory().to_path_buf();
        let cdi_directory = environment.empty_cdi_directory().to_path_buf();
        let probe_directory = options.state_root().as_path().join("active-probe");
        let shared_graph_root = options.shared_graph_root();
        let shared_run_root = options.shared_run_root();
        let shared_tmp_directory = options.shared_tmp_dir();

        let mut snapshot = Self {
            binary,
            approved_helper_directory,
            conmon_path,
            oci_runtime_path,
            init_path,
            seccomp_profile_path,
            home,
            runtime_directory,
            runtime_root,
            runtime_job_engines_root,
            state_root,
            process_transient_directory,
            system_config_directory,
            hooks_directory,
            cdi_directory,
            probe_directory,
            shared_graph_root,
            shared_run_root,
            shared_tmp_directory,
            rootless_pause_init: policy.rootless_pause_init,
            compiled_pause_init: policy.compiled_pause_init,
            user_namespace_remove: policy.user_namespace_remove,
            registry_certificate_directories: policy.registry_certificate_directories,
            administrator_user: policy.administrator_user,
            runtime_mount,
            synthetic_runtime_mount,
            immutable: BTreeMap::new(),
            private_roots: BTreeMap::new(),
        };
        snapshot.inspect()?;
        snapshot.revalidate_runtime_mount()?;
        Ok(snapshot)
    }

    pub(super) fn revalidate(&self) -> Result<(), TrustError> {
        let mut current = self.clone();
        current.immutable.clear();
        current.private_roots.clear();
        current.inspect()?;
        current.revalidate_runtime_mount()?;
        if self != &current {
            return Err(TrustError::Changed);
        }
        Ok(())
    }

    fn revalidate_runtime_mount(&self) -> Result<(), TrustError> {
        if self.synthetic_runtime_mount {
            #[cfg(test)]
            return Ok(());
            #[cfg(not(test))]
            return Err(TrustError::UnprotectedStorage);
        }
        self.runtime_mount
            .revalidate(&self.runtime_directory)
            .map_err(|_| TrustError::UnprotectedStorage)
    }

    fn inspect(&mut self) -> Result<(), TrustError> {
        inspect_binary(&self.binary, &mut self.immutable, self.administrator_user)?;
        inspect_approved_helper_directory(
            &self.approved_helper_directory,
            &mut self.immutable,
            self.administrator_user,
        )?;
        for binary in [
            &self.conmon_path,
            &self.oci_runtime_path,
            &self.init_path,
            &self.rootless_pause_init,
            &self.user_namespace_remove,
        ] {
            inspect_binary(binary, &mut self.immutable, self.administrator_user)?;
        }
        inspect_administrator_file(
            &self.seccomp_profile_path,
            &mut self.immutable,
            false,
            self.administrator_user,
        )?;
        inspect_absent_administrator_path(
            &self.compiled_pause_init,
            &mut self.immutable,
            self.administrator_user,
        )?;
        for directory in &self.registry_certificate_directories {
            inspect_optional_empty_administrator_directory(
                directory,
                &mut self.immutable,
                self.administrator_user,
            )?;
        }

        for directory in [
            &self.home,
            &self.runtime_directory,
            &self.runtime_root,
            &self.runtime_job_engines_root,
            &self.state_root,
            &self.process_transient_directory,
            &self.system_config_directory,
            &self.probe_directory,
            &self.hooks_directory,
            &self.cdi_directory,
            &self.shared_graph_root,
            &self.shared_run_root,
            &self.shared_tmp_directory,
        ] {
            inspect_private_root(directory, &mut self.private_roots)?;
        }
        inspect_optional_empty_private_directory(
            &self.home.join(".config/containers"),
            &mut self.private_roots,
        )?;
        inspect_optional_empty_private_directory(
            &self.home.join(".docker"),
            &mut self.private_roots,
        )?;
        inspect_absent_private_path(&self.home.join(".dockercfg"))?;
        ensure_empty_directory(&self.hooks_directory)?;
        ensure_empty_directory(&self.cdi_directory)?;
        for path in [
            self.system_config_directory.join("containers.conf"),
            self.system_config_directory.join("storage.conf"),
            self.system_config_directory.join("registries.conf"),
            self.system_config_directory.join("policy.json"),
            self.system_config_directory.join("mounts.conf"),
            self.system_config_directory.join("auth.json"),
        ] {
            inspect_private_file(&path, &mut self.immutable)?;
        }

        Ok(())
    }
}

impl PodmanLaunchTrust for PodmanProcessTrust {
    fn revalidate(&self) -> bool {
        PodmanProcessTrust::revalidate(self).is_ok()
    }
}

#[derive(Clone, Debug)]
struct HostInputPolicy {
    rootless_pause_init: PathBuf,
    compiled_pause_init: PathBuf,
    user_namespace_remove: PathBuf,
    registry_certificate_directories: Vec<PathBuf>,
    administrator_user: u32,
}

impl HostInputPolicy {
    fn production(options: &PodmanOptions) -> Self {
        Self {
            rootless_pause_init: PathBuf::from(PODMAN_ROOTLESS_PAUSE_INIT),
            compiled_pause_init: PathBuf::from(PODMAN_COMPILED_PAUSE_INIT),
            user_namespace_remove: options.user_namespace_remove_program().to_path_buf(),
            registry_certificate_directories: registry_certificate_directories(
                rustix::process::geteuid().as_raw(),
            ),
            administrator_user: 0,
        }
    }
}

fn registry_certificate_directories(effective_user: u32) -> Vec<PathBuf> {
    [
        format!("/etc/containers/certs.rootless.d/{effective_user}"),
        "/etc/containers/certs.rootless.d".to_owned(),
        "/etc/containers/certs.d".to_owned(),
        format!("/usr/share/containers/certs.rootless.d/{effective_user}"),
        "/usr/share/containers/certs.rootless.d".to_owned(),
        "/usr/share/containers/certs.d".to_owned(),
        "/etc/docker/certs.d".to_owned(),
    ]
    .map(PathBuf::from)
    .into()
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct FileIdentity {
    device: u64,
    inode: u64,
    length: u64,
    mode: u32,
    user: u32,
    group: u32,
    modified_seconds: i64,
    modified_nanoseconds: i64,
    changed_seconds: i64,
    changed_nanoseconds: i64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct NodeIdentity {
    device: u64,
    inode: u64,
    mode: u32,
    user: u32,
    group: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum TrustError {
    InvalidPath,
    Unavailable,
    WrongKind,
    Ownership,
    Permissions,
    NotEmpty,
    UnprotectedStorage,
    Changed,
}

fn inspect_binary(
    path: &Path,
    immutable: &mut BTreeMap<PathBuf, FileIdentity>,
    administrator_user: u32,
) -> Result<(), TrustError> {
    inspect_administrator_file(path, immutable, true, administrator_user)
}

fn inspect_administrator_file(
    path: &Path,
    immutable: &mut BTreeMap<PathBuf, FileIdentity>,
    executable: bool,
    administrator_user: u32,
) -> Result<(), TrustError> {
    validate_normalized_absolute(path)?;
    let path_metadata = fs::symlink_metadata(path).map_err(map_io)?;
    if path_metadata.file_type().is_symlink() || !path_metadata.is_file() {
        return Err(TrustError::WrongKind);
    }
    inspect_administrator_directory(
        path.parent().ok_or(TrustError::InvalidPath)?,
        immutable,
        administrator_user,
    )?;
    require_administrator_controlled(&path_metadata, administrator_user)?;
    if executable && path_metadata.mode() & 0o111 == 0 {
        return Err(TrustError::Permissions);
    }

    let descriptor = rustix::fs::open(
        path,
        rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::CLOEXEC | rustix::fs::OFlags::NOFOLLOW,
        rustix::fs::Mode::empty(),
    )
    .map_err(|_| TrustError::Unavailable)?;
    let descriptor_metadata = File::from(descriptor).metadata().map_err(map_io)?;
    if !descriptor_metadata.is_file()
        || file_identity(&path_metadata) != file_identity(&descriptor_metadata)
    {
        return Err(TrustError::Changed);
    }
    immutable.insert(path.to_path_buf(), file_identity(&descriptor_metadata));
    Ok(())
}

fn inspect_approved_helper_directory(
    path: &Path,
    immutable: &mut BTreeMap<PathBuf, FileIdentity>,
    administrator_user: u32,
) -> Result<(), TrustError> {
    validate_normalized_absolute(path)?;
    if !path.ends_with(Path::new("usr/sbin")) {
        return Err(TrustError::InvalidPath);
    }
    inspect_administrator_directory(path, immutable, administrator_user)?;
    if fs::canonicalize(path).map_err(map_io)? != path {
        return Err(TrustError::InvalidPath);
    }
    let directory_metadata = fs::symlink_metadata(path).map_err(map_io)?;
    if !directory_metadata.is_dir()
        || directory_metadata.file_type().is_symlink()
        || directory_metadata.mode() & 0o555 != 0o555
    {
        return Err(TrustError::Permissions);
    }

    let expected = APPROVED_HELPERS
        .into_iter()
        .map(str::to_owned)
        .collect::<BTreeSet<_>>();
    let mut actual = BTreeSet::new();
    for entry in fs::read_dir(path).map_err(map_io)? {
        let entry = entry.map_err(map_io)?;
        let name = entry
            .file_name()
            .to_str()
            .ok_or(TrustError::InvalidPath)?
            .to_owned();
        if !expected.contains(&name) || !actual.insert(name.clone()) {
            return Err(TrustError::NotEmpty);
        }
        let helper_path = path.join(&name);
        let metadata = fs::symlink_metadata(&helper_path).map_err(map_io)?;
        if metadata.file_type().is_symlink() {
            if metadata.uid() != administrator_user {
                return Err(TrustError::Ownership);
            }
            insert_identity(immutable, &helper_path, file_identity(&metadata))?;
            let canonical = fs::canonicalize(&helper_path).map_err(map_io)?;
            inspect_binary(&canonical, immutable, administrator_user)?;
        } else {
            inspect_binary(&helper_path, immutable, administrator_user)?;
        }
    }
    if actual != expected {
        return Err(TrustError::NotEmpty);
    }
    Ok(())
}

fn inspect_administrator_directory(
    path: &Path,
    immutable: &mut BTreeMap<PathBuf, FileIdentity>,
    administrator_user: u32,
) -> Result<(), TrustError> {
    validate_normalized_absolute(path)?;
    for ancestor in ordered_ancestors(path) {
        let metadata = fs::symlink_metadata(ancestor).map_err(map_io)?;
        if metadata.file_type().is_symlink() {
            if metadata.uid() != administrator_user {
                return Err(TrustError::Ownership);
            }
        } else {
            if !metadata.is_dir() {
                return Err(TrustError::WrongKind);
            }
            require_administrator_controlled(&metadata, administrator_user)?;
        }
        insert_identity(immutable, ancestor, file_identity(&metadata))?;
    }

    let canonical = fs::canonicalize(path).map_err(map_io)?;
    for ancestor in ordered_ancestors(&canonical) {
        let metadata = fs::symlink_metadata(ancestor).map_err(map_io)?;
        if !metadata.is_dir() || metadata.file_type().is_symlink() {
            return Err(TrustError::WrongKind);
        }
        require_administrator_controlled(&metadata, administrator_user)?;
        insert_identity(immutable, ancestor, file_identity(&metadata))?;
    }
    Ok(())
}

fn inspect_absent_administrator_path(
    path: &Path,
    immutable: &mut BTreeMap<PathBuf, FileIdentity>,
    administrator_user: u32,
) -> Result<(), TrustError> {
    validate_normalized_absolute(path)?;
    require_absent(path)?;
    let ancestor = nearest_existing_ancestor(path)?;
    inspect_administrator_directory(&ancestor, immutable, administrator_user)?;
    require_absent(path)
}

fn inspect_optional_empty_administrator_directory(
    path: &Path,
    immutable: &mut BTreeMap<PathBuf, FileIdentity>,
    administrator_user: u32,
) -> Result<(), TrustError> {
    validate_normalized_absolute(path)?;
    match fs::symlink_metadata(path) {
        Ok(metadata) => {
            if metadata.file_type().is_symlink() || !metadata.is_dir() {
                return Err(TrustError::WrongKind);
            }
            inspect_administrator_directory(path, immutable, administrator_user)?;
            ensure_empty_directory(path)
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            let ancestor = nearest_existing_ancestor(path)?;
            inspect_administrator_directory(&ancestor, immutable, administrator_user)?;
            require_absent(path)
        }
        Err(error) => Err(map_io(error)),
    }
}

fn inspect_optional_empty_private_directory(
    path: &Path,
    roots: &mut BTreeMap<PathBuf, NodeIdentity>,
) -> Result<(), TrustError> {
    validate_normalized_absolute(path)?;
    match fs::symlink_metadata(path) {
        Ok(_) => {
            inspect_private_root(path, roots)?;
            ensure_empty_directory(path)
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            let ancestor = nearest_existing_ancestor(path)?;
            inspect_private_ancestor(&ancestor, roots)?;
            require_absent(path)
        }
        Err(error) => Err(map_io(error)),
    }
}

fn inspect_absent_private_path(path: &Path) -> Result<(), TrustError> {
    validate_normalized_absolute(path)?;
    require_absent(path)?;
    let ancestor = nearest_existing_ancestor(path)?;
    let mut roots = BTreeMap::new();
    inspect_private_ancestor(&ancestor, &mut roots)?;
    require_absent(path)
}

fn nearest_existing_ancestor(path: &Path) -> Result<PathBuf, TrustError> {
    let mut candidate = path.parent().ok_or(TrustError::InvalidPath)?;
    loop {
        match fs::symlink_metadata(candidate) {
            Ok(_) => return Ok(candidate.to_path_buf()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                candidate = candidate.parent().ok_or(TrustError::InvalidPath)?;
            }
            Err(error) => return Err(map_io(error)),
        }
    }
}

fn require_absent(path: &Path) -> Result<(), TrustError> {
    match fs::symlink_metadata(path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Ok(_) => Err(TrustError::Changed),
        Err(error) => Err(map_io(error)),
    }
}

fn inspect_private_root(
    path: &Path,
    roots: &mut BTreeMap<PathBuf, NodeIdentity>,
) -> Result<(), TrustError> {
    validate_normalized_absolute(path)?;
    let effective_user = rustix::process::geteuid().as_raw();
    for ancestor in ordered_ancestors(path) {
        let metadata = fs::symlink_metadata(ancestor).map_err(map_io)?;
        if !metadata.is_dir() || metadata.file_type().is_symlink() {
            return Err(TrustError::WrongKind);
        }
        if metadata.uid() != 0 && metadata.uid() != effective_user {
            return Err(TrustError::Ownership);
        }
        if metadata.mode() & 0o022 != 0 {
            return Err(TrustError::Permissions);
        }
    }
    let metadata = fs::symlink_metadata(path).map_err(map_io)?;
    if metadata.uid() != effective_user {
        return Err(TrustError::Ownership);
    }
    if metadata.mode() & 0o777 != 0o700 {
        return Err(TrustError::Permissions);
    }
    roots.insert(path.to_path_buf(), node_identity(&metadata));
    Ok(())
}

fn inspect_private_ancestor(
    path: &Path,
    roots: &mut BTreeMap<PathBuf, NodeIdentity>,
) -> Result<(), TrustError> {
    validate_normalized_absolute(path)?;
    let effective_user = rustix::process::geteuid().as_raw();
    for ancestor in ordered_ancestors(path) {
        let metadata = fs::symlink_metadata(ancestor).map_err(map_io)?;
        if !metadata.is_dir() || metadata.file_type().is_symlink() {
            return Err(TrustError::WrongKind);
        }
        if metadata.uid() != 0 && metadata.uid() != effective_user {
            return Err(TrustError::Ownership);
        }
        if metadata.mode() & 0o022 != 0 {
            return Err(TrustError::Permissions);
        }
    }
    let metadata = fs::symlink_metadata(path).map_err(map_io)?;
    roots.insert(path.to_path_buf(), node_identity(&metadata));
    Ok(())
}

fn inspect_private_file(
    path: &Path,
    immutable: &mut BTreeMap<PathBuf, FileIdentity>,
) -> Result<(), TrustError> {
    validate_normalized_absolute(path)?;
    let path_metadata = fs::symlink_metadata(path).map_err(map_io)?;
    if path_metadata.file_type().is_symlink()
        || !path_metadata.is_file()
        || path_metadata.uid() != rustix::process::geteuid().as_raw()
        || path_metadata.mode() & 0o7777 != 0o600
        || path_metadata.nlink() != 1
    {
        return Err(TrustError::Permissions);
    }
    let descriptor = rustix::fs::open(
        path,
        rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::CLOEXEC | rustix::fs::OFlags::NOFOLLOW,
        rustix::fs::Mode::empty(),
    )
    .map_err(|_| TrustError::Unavailable)?;
    let descriptor_metadata = File::from(descriptor).metadata().map_err(map_io)?;
    if file_identity(&path_metadata) != file_identity(&descriptor_metadata) {
        return Err(TrustError::Changed);
    }
    insert_identity(immutable, path, file_identity(&descriptor_metadata))?;
    Ok(())
}

fn ensure_empty_directory(path: &Path) -> Result<(), TrustError> {
    let mut entries = fs::read_dir(path).map_err(map_io)?;
    match entries.next() {
        None => Ok(()),
        Some(Ok(_)) => Err(TrustError::NotEmpty),
        Some(Err(error)) => Err(map_io(error)),
    }
}

fn require_administrator_controlled(
    metadata: &Metadata,
    administrator_user: u32,
) -> Result<(), TrustError> {
    if metadata.uid() != administrator_user && !(administrator_user != 0 && metadata.uid() == 0) {
        return Err(TrustError::Ownership);
    }
    if metadata.mode() & 0o022 != 0 {
        return Err(TrustError::Permissions);
    }
    Ok(())
}

fn validate_normalized_absolute(path: &Path) -> Result<(), TrustError> {
    if !path.is_absolute()
        || path.parent().is_none()
        || path
            .components()
            .any(|component| matches!(component, Component::CurDir | Component::ParentDir))
    {
        return Err(TrustError::InvalidPath);
    }
    Ok(())
}

fn ordered_ancestors(path: &Path) -> Vec<&Path> {
    let mut ancestors = path.ancestors().collect::<Vec<_>>();
    ancestors.reverse();
    ancestors
}

fn insert_identity(
    entries: &mut BTreeMap<PathBuf, FileIdentity>,
    path: &Path,
    identity: FileIdentity,
) -> Result<(), TrustError> {
    if entries
        .insert(path.to_path_buf(), identity)
        .is_some_and(|old| old != identity)
    {
        return Err(TrustError::Changed);
    }
    Ok(())
}

fn file_identity(metadata: &Metadata) -> FileIdentity {
    FileIdentity {
        device: metadata.dev(),
        inode: metadata.ino(),
        length: metadata.len(),
        mode: metadata.mode(),
        user: metadata.uid(),
        group: metadata.gid(),
        modified_seconds: metadata.mtime(),
        modified_nanoseconds: metadata.mtime_nsec(),
        changed_seconds: metadata.ctime(),
        changed_nanoseconds: metadata.ctime_nsec(),
    }
}

fn node_identity(metadata: &Metadata) -> NodeIdentity {
    NodeIdentity {
        device: metadata.dev(),
        inode: metadata.ino(),
        mode: metadata.mode(),
        user: metadata.uid(),
        group: metadata.gid(),
    }
}

fn map_io(_error: std::io::Error) -> TrustError {
    TrustError::Unavailable
}

#[cfg(test)]
mod tests {
    use std::{
        os::unix::fs::{PermissionsExt as _, symlink},
        sync::{
            Arc, Mutex, MutexGuard, PoisonError,
            atomic::{AtomicU64, Ordering},
        },
        time::{Duration, Instant},
    };

    use automata_ci_execution::NeverCancelled;
    use automata_ci_sandbox_podman::{
        CommandRequest, CommandTermination, PodmanBinary, PodmanCommandExecutor,
        PodmanLaunchTrustHandle, PodmanProcessEnvironment, PodmanStateRoot, SystemCommandExecutor,
    };

    use super::*;

    static NEXT_DIRECTORY: AtomicU64 = AtomicU64::new(0);
    static TEST_DIRECTORY_LOCK: Mutex<()> = Mutex::new(());

    struct TestDirectory {
        path: PathBuf,
        _guard: MutexGuard<'static, ()>,
    }

    impl TestDirectory {
        fn new() -> Self {
            let guard = TEST_DIRECTORY_LOCK
                .lock()
                .unwrap_or_else(PoisonError::into_inner);
            let repository = Path::new(env!("CARGO_MANIFEST_DIR"))
                .parent()
                .and_then(Path::parent)
                .expect("runner crate must be below repository root");
            let path = repository.join("target/task-tmp").join(format!(
                "capability-binary-trust-{}-{}",
                std::process::id(),
                NEXT_DIRECTORY.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir_all(&path).expect("create test directory");
            fs::set_permissions(&path, fs::Permissions::from_mode(0o700))
                .expect("make test directory private");
            Self {
                path,
                _guard: guard,
            }
        }

        fn child(&self, name: &str) -> PathBuf {
            self.path.join(name)
        }
    }

    impl Drop for TestDirectory {
        fn drop(&mut self) {
            fs::remove_dir_all(&self.path).expect("remove test directory");
        }
    }

    struct AdmittedFixture {
        _directory: TestDirectory,
        options: PodmanOptions,
        trust: PodmanProcessTrust,
        conmon: PathBuf,
        registry_certificates: PathBuf,
        marker: PathBuf,
    }

    fn admitted_fixture() -> AdmittedFixture {
        let directory = TestDirectory::new();
        let home = private_directory(&directory.child("home"));
        let runtime = private_directory(&directory.child("runtime"));
        let state = private_directory(&directory.child("state"));
        let helpers = directory.child("private/usr/sbin");
        fs::create_dir_all(&helpers).expect("create helper hierarchy");
        fs::set_permissions(&helpers, fs::Permissions::from_mode(0o755))
            .expect("set helper directory mode");
        for helper in APPROVED_HELPERS {
            executable_file(&helpers.join(helper), b"test helper");
        }

        let marker = directory.child("spawned");
        let binary = directory.child("podman");
        executable_file(
            &binary,
            format!("#!/bin/sh\nprintf launched >> '{}'\n", marker.display()).as_bytes(),
        );
        let conmon = directory.child("conmon");
        let runtime_binary = directory.child("crun");
        let init = directory.child("catatonit");
        let seccomp = directory.child("seccomp.json");
        let pause_init = directory.child("pause-init");
        let remove = directory.child("rm");
        for path in [&conmon, &runtime_binary, &init, &pause_init, &remove] {
            executable_file(path, b"test executable");
        }
        fs::write(&seccomp, b"{}").expect("write seccomp fixture");
        fs::set_permissions(&seccomp, fs::Permissions::from_mode(0o644))
            .expect("set seccomp fixture mode");

        let environment = PodmanProcessEnvironment::new(
            home,
            runtime,
            state.clone(),
            helpers,
            conmon.clone(),
            runtime_binary,
            init,
            seccomp,
        )
        .expect("construct syntactic process environment");
        let options = PodmanOptions::new(
            PodmanBinary::new(binary).expect("test Podman binary path"),
            PodmanStateRoot::existing(state.clone()).expect("test state root"),
            environment,
        )
        .expect("coherent test options");
        options
            .prepare_state()
            .expect("prepare exact generated state");
        private_directory(&state.join("active-probe"));
        let registry_certificates = directory.child("registry-certs");
        fs::create_dir(&registry_certificates).expect("create empty registry certificate tree");
        fs::set_permissions(&registry_certificates, fs::Permissions::from_mode(0o755))
            .expect("make registry certificate tree root-controlled");
        let policy = HostInputPolicy {
            rootless_pause_init: pause_init,
            compiled_pause_init: directory.child("compiled/podman/catatonit"),
            user_namespace_remove: remove,
            registry_certificate_directories: vec![registry_certificates.clone()],
            administrator_user: rustix::process::geteuid().as_raw(),
        };
        let trust = PodmanProcessTrust::capture_with_policy(&options, policy)
            .expect("capture complete test trust boundary");
        AdmittedFixture {
            _directory: directory,
            options,
            trust,
            conmon,
            registry_certificates,
            marker,
        }
    }

    fn private_directory(path: &Path) -> PathBuf {
        fs::create_dir_all(path).expect("create private fixture directory");
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))
            .expect("set private fixture directory mode");
        path.to_path_buf()
    }

    fn executable_file(path: &Path, content: &[u8]) {
        fs::write(path, content).expect("write executable fixture");
        fs::set_permissions(path, fs::Permissions::from_mode(0o755))
            .expect("set executable fixture mode");
    }

    #[test]
    fn configured_binary_rejects_symlinks_non_regular_files_and_runner_owned_files() {
        let fixture = TestDirectory::new();
        let target = fixture.child("target");
        File::create(&target).expect("create target");
        fs::set_permissions(&target, fs::Permissions::from_mode(0o700))
            .expect("make target executable");
        let link = fixture.child("podman-link");
        symlink(&target, &link).expect("create symlink");

        assert_eq!(
            inspect_binary(&link, &mut BTreeMap::new(), 0),
            Err(TrustError::WrongKind)
        );
        assert_eq!(
            inspect_binary(&fixture.path, &mut BTreeMap::new(), 0),
            Err(TrustError::WrongKind)
        );
        assert_eq!(
            inspect_binary(&target, &mut BTreeMap::new(), 0),
            Err(TrustError::Ownership)
        );
    }

    #[test]
    fn approved_helper_directory_requires_the_closed_usr_sbin_shape_and_root_control() {
        let fixture = TestDirectory::new();
        assert_eq!(
            inspect_approved_helper_directory(&fixture.child("helpers"), &mut BTreeMap::new(), 0,),
            Err(TrustError::InvalidPath)
        );

        let helper_directory = fixture.child("private/usr/sbin");
        fs::create_dir_all(&helper_directory).expect("create helper-directory shape");
        fs::set_permissions(&helper_directory, fs::Permissions::from_mode(0o755))
            .expect("make helper directory traversable");
        assert_eq!(
            inspect_approved_helper_directory(&helper_directory, &mut BTreeMap::new(), 0),
            Err(TrustError::Ownership)
        );
    }

    #[test]
    fn private_roots_reject_writable_ancestry_and_require_exact_owner_only_mode() {
        let fixture = TestDirectory::new();
        let private = fixture.child("private");
        fs::create_dir(&private).expect("create private root");
        fs::set_permissions(&private, fs::Permissions::from_mode(0o700)).expect("set private mode");
        inspect_private_root(&private, &mut BTreeMap::new()).expect("private root accepted");

        fs::set_permissions(&fixture.path, fs::Permissions::from_mode(0o777))
            .expect("make ancestor writable");
        assert_eq!(
            inspect_private_root(&private, &mut BTreeMap::new()),
            Err(TrustError::Permissions)
        );
    }

    #[test]
    fn empty_hooks_directory_rejects_every_entry() {
        let fixture = TestDirectory::new();
        ensure_empty_directory(&fixture.path).expect("empty directory accepted");
        File::create(fixture.child("hook.json")).expect("create hook entry");
        assert_eq!(
            ensure_empty_directory(&fixture.path),
            Err(TrustError::NotEmpty)
        );
    }

    #[test]
    fn generated_private_file_snapshot_rejects_replacement_metadata() {
        let fixture = TestDirectory::new();
        let configuration = fixture.child("containers.conf");
        fs::write(&configuration, b"exact").expect("write private configuration");
        fs::set_permissions(&configuration, fs::Permissions::from_mode(0o600))
            .expect("set private configuration mode");
        inspect_private_file(&configuration, &mut BTreeMap::new())
            .expect("private configuration accepted");

        fs::set_permissions(&configuration, fs::Permissions::from_mode(0o640))
            .expect("widen private configuration mode");
        assert_eq!(
            inspect_private_file(&configuration, &mut BTreeMap::new()),
            Err(TrustError::Permissions)
        );
    }

    #[test]
    fn exact_snapshot_revalidates_then_prevents_spawn_after_external_input_drift() {
        let fixture = admitted_fixture();
        fixture.trust.revalidate().expect("unchanged snapshot");
        let options = fixture
            .options
            .with_launch_trust(PodmanLaunchTrustHandle::new(Arc::new(
                fixture.trust.clone(),
            )));
        let request = CommandRequest::new(
            options.binary().as_path().to_path_buf(),
            Vec::new(),
            Duration::from_secs(2),
            Instant::now() + Duration::from_secs(2),
            1_024,
        );
        let executor = SystemCommandExecutor;
        let first = executor.execute(&request, options.process_environment(), &NeverCancelled);
        assert_eq!(first.termination(), CommandTermination::Exited(Some(0)));

        executable_file(&fixture.conmon, b"replacement executable");
        assert_eq!(fixture.trust.revalidate(), Err(TrustError::Changed));
        let second = executor.execute(&request, options.process_environment(), &NeverCancelled);
        assert_eq!(second.termination(), CommandTermination::FailedToStart);
        assert_eq!(
            fs::read_to_string(&fixture.marker).expect("read spawn marker"),
            "launched"
        );
    }

    #[test]
    fn credential_fallback_locations_are_absent_or_exactly_empty_and_private() {
        let fixture = TestDirectory::new();
        let containers = fixture.child(".config/containers");
        inspect_optional_empty_private_directory(&containers, &mut BTreeMap::new())
            .expect("absent containers configuration");
        private_directory(&containers);
        inspect_optional_empty_private_directory(&containers, &mut BTreeMap::new())
            .expect("empty private containers configuration");
        File::create(containers.join("auth.json")).expect("create ambient auth file");
        assert_eq!(
            inspect_optional_empty_private_directory(&containers, &mut BTreeMap::new()),
            Err(TrustError::NotEmpty)
        );

        let legacy = fixture.child(".dockercfg");
        inspect_absent_private_path(&legacy).expect("absent legacy Docker credentials");
        File::create(&legacy).expect("create legacy Docker credentials");
        assert_eq!(
            inspect_absent_private_path(&legacy),
            Err(TrustError::Changed)
        );
    }

    #[test]
    fn registry_certificate_fallback_trees_are_empty_root_controlled_and_exact() {
        let fixture = TestDirectory::new();
        let certificates = fixture.child("certs.d");
        let administrator_user = rustix::process::geteuid().as_raw();
        let inspect = |path: &Path| {
            for _attempt in 0..100 {
                let result = inspect_optional_empty_administrator_directory(
                    path,
                    &mut BTreeMap::new(),
                    administrator_user,
                );
                if result != Err(TrustError::Changed) {
                    return result;
                }
                std::thread::yield_now();
            }
            Err(TrustError::Changed)
        };
        inspect(&certificates).expect("absent registry certificate tree");

        fs::create_dir(&certificates).expect("create registry certificate tree");
        fs::set_permissions(&certificates, fs::Permissions::from_mode(0o755))
            .expect("set registry certificate tree mode");
        inspect(&certificates).expect("empty root-controlled registry certificate tree");
        File::create(certificates.join("client.key")).expect("create ambient client key");
        assert!(
            inspect(&certificates).is_err(),
            "an ambient registry client key must be rejected"
        );
        drop(fixture);

        let admitted = admitted_fixture();
        fs::remove_dir(&admitted.registry_certificates)
            .expect("remove admitted registry certificate tree");
        fs::create_dir(&admitted.registry_certificates)
            .expect("replace admitted registry certificate tree");
        fs::set_permissions(
            &admitted.registry_certificates,
            fs::Permissions::from_mode(0o755),
        )
        .expect("restore registry certificate tree mode");
        assert_eq!(admitted.trust.revalidate(), Err(TrustError::Changed));
    }
}
