//! Pinned, bounded Docker Compose process boundary for lifecycle convergence.

use std::{
    ffi::OsStr,
    fs::{self, File},
    io::Read as _,
    os::{
        fd::{AsRawFd as _, OwnedFd},
        unix::fs::MetadataExt as _,
    },
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};

use processkit::{Command as ContainedCommand, OutputBufferPolicy, Stdin};
use rustix::fs::{Mode, OFlags, open};
use serde::Deserialize;
use tokio_util::sync::CancellationToken;

#[cfg(test)]
use std::os::unix::process::CommandExt as _;
#[cfg(test)]
use tokio::process::Command as ProcessCommand;

use crate::{DoctorReport, EngineSelection, Installation, MAX_COMMAND_STREAM_BYTES};

use super::{LocalInitError, LocalInitErrorCode, engine::LifecycleMutationFence};

const FIXED_DOCKER_HOST: &str = "unix:///var/run/docker.sock";
const FIXED_DOCKER_API_VERSION: &str = "1.48";
const ABSENT_CONFIG_ROOT: &str = "/nonexistent/automata-local-docker-config";
pub(super) const COMPOSE_PROJECT_DIRECTORY: &str = "/";
const MAX_COMPOSE_OUTPUT: usize = 64 * 1024;
const COMPOSE_PLUGIN_METADATA_SCHEMA: &str = "0.1.0";
const COMPOSE_PLUGIN_NAME: &str = "compose";
const MAX_PROC_ENTRIES: usize = 1_048_576;
const MAX_PROC_CMDLINE_BYTES: u64 = 64 * 1024;

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct QualifiedDockerCli {
    docker: ExecutableAuthority,
    compose: ExecutableAuthority,
    compose_version: String,
}

#[derive(Clone, Debug)]
struct ExecutableAuthority {
    path: PathBuf,
    descriptor: Arc<OwnedFd>,
    identity: ExecutableIdentity,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ExecutableIdentity {
    device: u64,
    inode: u64,
    length: u64,
    modified_seconds: i64,
    modified_nanoseconds: i64,
    changed_seconds: i64,
    changed_nanoseconds: i64,
    uid: u32,
    gid: u32,
    mode: u32,
    links: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) enum ComposeStep<'a> {
    Validate,
    UpDependencies,
    UpControl,
    UpRelay,
    UpRunner,
    RunOneOff {
        service: &'a str,
        container_name: &'a str,
    },
    StopRunner,
    Down,
}

impl QualifiedDockerCli {
    pub(super) async fn qualify(report: &DoctorReport) -> Result<Self, LocalInitError> {
        if !report.ready() {
            return Err(engine_unavailable());
        }
        let selection = report.selected_engine().ok_or_else(engine_unavailable)?;
        if selection.connection_host() != FIXED_DOCKER_HOST {
            return Err(engine_unavailable());
        }
        let docker = resolve_docker_executable()?;
        // Resolve the implementation through the held Docker CLI once, before
        // lifecycle mutation, then execute only the retained plugin below.
        let plugins = run_held(
            &docker,
            selection,
            &[
                "--host",
                FIXED_DOCKER_HOST,
                "--config",
                ABSENT_CONFIG_ROOT,
                "info",
                "--format",
                "{{json .ClientInfo.Plugins}}",
            ],
            None,
            Duration::from_secs(10),
            &CancellationToken::new(),
        )
        .await?;
        let plugin = selected_compose_plugin(&plugins, selection.compose_version())?;
        let compose = ExecutableAuthority::open(Path::new(&plugin.path))?;
        let qualified = Self {
            docker,
            compose,
            compose_version: selection.compose_version().to_owned(),
        };
        qualified.verify_identity()?;
        let metadata = run_held(
            &qualified.compose,
            selection,
            &["docker-cli-plugin-metadata"],
            None,
            Duration::from_secs(10),
            &CancellationToken::new(),
        )
        .await?;
        let metadata: ComposePluginMetadata =
            serde_json::from_slice(&metadata).map_err(|_| engine_unavailable())?;
        if !plugin.matches_direct_metadata(&metadata) {
            return Err(engine_unavailable());
        }
        let output = run_held(
            &qualified.compose,
            selection,
            &["--host", FIXED_DOCKER_HOST, "version", "--format", "json"],
            None,
            Duration::from_secs(10),
            &CancellationToken::new(),
        )
        .await?;
        let version: ComposeVersion =
            serde_json::from_slice(&output).map_err(|_| engine_unavailable())?;
        if version.version != qualified.compose_version {
            return Err(engine_unavailable());
        }
        qualified.verify_identity()?;
        Ok(qualified)
    }

    pub(super) async fn validate(
        &self,
        selection: &EngineSelection,
        installation: &Installation,
        compose_bytes: &[u8],
        cancellation: &CancellationToken,
    ) -> Result<Vec<u8>, LocalInitError> {
        self.execute_inner(
            selection,
            installation,
            compose_bytes,
            ComposeStep::Validate,
            cancellation,
            None,
        )
        .await
    }

    pub(super) async fn execute(
        &self,
        selection: &EngineSelection,
        installation: &Installation,
        compose_bytes: &[u8],
        step: ComposeStep<'_>,
        cancellation: &CancellationToken,
        mutation: &LifecycleMutationFence,
    ) -> Result<Vec<u8>, LocalInitError> {
        if step == ComposeStep::Validate {
            return Err(reset_required());
        }
        self.execute_inner(
            selection,
            installation,
            compose_bytes,
            step,
            cancellation,
            Some(mutation),
        )
        .await
    }

    async fn execute_inner(
        &self,
        selection: &EngineSelection,
        installation: &Installation,
        compose_bytes: &[u8],
        step: ComposeStep<'_>,
        cancellation: &CancellationToken,
        mutation: Option<&LifecycleMutationFence>,
    ) -> Result<Vec<u8>, LocalInitError> {
        if compose_bytes.is_empty() || !compose_bytes.ends_with(b"\n") {
            return Err(reset_required());
        }
        self.verify_identity()?;
        if selection.connection_host() != FIXED_DOCKER_HOST {
            return Err(engine_unavailable());
        }
        let mut arguments = vec![
            "--host".to_owned(),
            FIXED_DOCKER_HOST.to_owned(),
            "--ansi".to_owned(),
            "never".to_owned(),
            "--parallel".to_owned(),
            "1".to_owned(),
            "--project-name".to_owned(),
            installation.compose_project().to_string(),
            "--project-directory".to_owned(),
            COMPOSE_PROJECT_DIRECTORY.to_owned(),
            "--env-file".to_owned(),
            "/dev/null".to_owned(),
            "--file".to_owned(),
            "-".to_owned(),
        ];
        let operation_timeout = append_step(&step, &mut arguments);
        let arguments = arguments.iter().map(String::as_str).collect::<Vec<_>>();
        if let Some(mutation) = mutation {
            mutation.authorize().await?;
        }
        let output = run_held(
            &self.compose,
            selection,
            &arguments,
            Some(compose_bytes),
            operation_timeout,
            cancellation,
        )
        .await;
        self.verify_identity()?;
        output
    }

    fn verify_identity(&self) -> Result<(), LocalInitError> {
        self.docker.verify_identity()?;
        self.compose.verify_identity()
    }
}

/// Conservative process fence for reset, which does not otherwise need a
/// Compose executable authority. Any same-user process carrying our exact
/// canonical project argument blocks stopped-lock recovery.
pub(super) fn attest_no_project_compose_processes(
    installation: &Installation,
) -> Result<(), LocalInitError> {
    attest_project_process_quiescent(installation)
}

fn attest_project_process_quiescent(installation: &Installation) -> Result<(), LocalInitError> {
    let project = installation.compose_project().as_str();
    let euid = rustix::process::geteuid().as_raw();
    let current_pid = std::process::id();
    let entries = fs::read_dir("/proc").map_err(|_| engine_unavailable())?;
    for (index, entry) in entries.enumerate() {
        if index >= MAX_PROC_ENTRIES {
            return Err(engine_unavailable());
        }
        let entry = entry.map_err(|_| engine_unavailable())?;
        let Some(pid) = entry
            .file_name()
            .to_str()
            .and_then(|name| name.parse::<u32>().ok())
        else {
            continue;
        };
        if pid == current_pid {
            continue;
        }
        let Ok(process_metadata) = entry.path().metadata() else {
            continue;
        };
        if process_metadata.uid() != euid {
            continue;
        }
        let mut cmdline = Vec::new();
        File::open(entry.path().join("cmdline"))
            .map_err(|_| engine_unavailable())?
            .take(MAX_PROC_CMDLINE_BYTES + 1)
            .read_to_end(&mut cmdline)
            .map_err(|_| engine_unavailable())?;
        if cmdline.len() as u64 > MAX_PROC_CMDLINE_BYTES {
            return Err(engine_unavailable());
        }
        let arguments = cmdline
            .split(|byte| *byte == 0)
            .filter(|argument| !argument.is_empty())
            .collect::<Vec<_>>();
        if arguments.windows(2).any(|arguments| {
            arguments[0] == b"--project-name" && arguments[1] == project.as_bytes()
        }) {
            return Err(LocalInitError::new(LocalInitErrorCode::OperationInProgress));
        }
    }
    Ok(())
}

impl PartialEq for ExecutableAuthority {
    fn eq(&self, other: &Self) -> bool {
        self.path == other.path && self.identity == other.identity
    }
}

impl Eq for ExecutableAuthority {}

impl ExecutableAuthority {
    fn open(path: &Path) -> Result<Self, LocalInitError> {
        let canonical = path.canonicalize().map_err(|_| engine_unavailable())?;
        let initial = exact_executable_metadata(&canonical)?;
        let descriptor = open(
            &canonical,
            OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::NONBLOCK,
            Mode::empty(),
        )
        .map_err(|_| engine_unavailable())?;
        let held = descriptor_metadata(&descriptor)?;
        ensure_exact_executable_metadata(&held)?;
        let current = exact_executable_metadata(&canonical)?;
        let identity = ExecutableIdentity::new(&held);
        if ExecutableIdentity::new(&initial) != identity
            || ExecutableIdentity::new(&current) != identity
        {
            return Err(engine_unavailable());
        }
        let authority = Self {
            path: canonical,
            descriptor: Arc::new(descriptor),
            identity,
        };
        authority.verify_identity()?;
        Ok(authority)
    }

    fn verify_identity(&self) -> Result<(), LocalInitError> {
        let held = descriptor_metadata(&self.descriptor)?;
        ensure_exact_executable_metadata(&held)?;
        let named = exact_executable_metadata(&self.path)?;
        let executable = fs::metadata(self.descriptor_path()).map_err(|_| engine_unavailable())?;
        if ExecutableIdentity::new(&held) != self.identity
            || ExecutableIdentity::new(&named) != self.identity
            || ExecutableIdentity::new(&executable) != self.identity
        {
            return Err(engine_unavailable());
        }
        Ok(())
    }

    #[cfg(test)]
    fn process_command(&self) -> Result<ProcessCommand, LocalInitError> {
        self.verify_identity()?;
        // The descriptor remains open through exec pathname resolution and is
        // close-on-exec, so the selected binary cannot be replaced or leaked.
        let mut command = ProcessCommand::new(self.descriptor_path());
        command.as_std_mut().arg0(&self.path);
        Ok(command)
    }

    fn descriptor_path(&self) -> PathBuf {
        PathBuf::from(format!("/proc/self/fd/{}", self.descriptor.as_raw_fd()))
    }
}

impl ExecutableIdentity {
    fn new(metadata: &fs::Metadata) -> Self {
        Self {
            device: metadata.dev(),
            inode: metadata.ino(),
            length: metadata.len(),
            modified_seconds: metadata.mtime(),
            modified_nanoseconds: metadata.mtime_nsec(),
            changed_seconds: metadata.ctime(),
            changed_nanoseconds: metadata.ctime_nsec(),
            uid: metadata.uid(),
            gid: metadata.gid(),
            mode: metadata.mode(),
            links: metadata.nlink(),
        }
    }
}

async fn run_held(
    authority: &ExecutableAuthority,
    selection: &EngineSelection,
    arguments: &[&str],
    stdin: Option<&[u8]>,
    deadline: Duration,
    cancellation: &CancellationToken,
) -> Result<Vec<u8>, LocalInitError> {
    if cancellation.is_cancelled() {
        return Err(LocalInitError::new(LocalInitErrorCode::Cancelled));
    }
    verify_absent_config_root()?;
    if selection.connection_host() != FIXED_DOCKER_HOST {
        return Err(engine_unavailable());
    }
    authority.verify_identity()?;
    let mut command = ContainedCommand::new(authority.descriptor_path())
        .arg0(authority.path.as_os_str())
        .env_clear()
        .env("DOCKER_CONFIG", ABSENT_CONFIG_ROOT)
        .env("DOCKER_HOST", FIXED_DOCKER_HOST)
        .env("DOCKER_API_VERSION", FIXED_DOCKER_API_VERSION)
        .env("HOME", "/nonexistent")
        .env("LANG", "C")
        .env("LC_ALL", "C")
        .env("PATH", "/usr/bin:/bin")
        .env("XDG_CONFIG_HOME", "/nonexistent")
        .current_dir(COMPOSE_PROJECT_DIRECTORY)
        .args(arguments)
        .timeout(deadline)
        .cancel_on(cancellation.clone())
        .kill_on_parent_death()
        .output_buffer(
            OutputBufferPolicy::fail_loud(usize::MAX).with_max_bytes(MAX_COMMAND_STREAM_BYTES),
        );
    if let Some(stdin) = stdin {
        command = command.stdin(Stdin::from_bytes(stdin.to_vec()));
    }
    let captured = command.output_bytes().await;
    authority.verify_identity()?;
    verify_absent_config_root()?;
    let captured = match captured {
        Ok(captured) => captured,
        Err(_) if cancellation.is_cancelled() => {
            return Err(LocalInitError::new(LocalInitErrorCode::Cancelled));
        }
        Err(_) => return Err(engine_unavailable()),
    };
    if captured.stdout().len() > MAX_COMPOSE_OUTPUT
        || captured.stderr().len() > MAX_COMMAND_STREAM_BYTES
    {
        return Err(engine_unavailable());
    }
    if !captured.is_success() {
        return Err(reset_required());
    }
    if selection.connection_host() != FIXED_DOCKER_HOST {
        return Err(engine_unavailable());
    }
    Ok(captured.into_stdout())
}

fn append_step(step: &ComposeStep<'_>, arguments: &mut Vec<String>) -> Duration {
    match step {
        ComposeStep::Validate => {
            arguments.extend(["config", "--quiet"].map(str::to_owned));
            Duration::from_secs(15)
        }
        ComposeStep::UpDependencies => {
            arguments.extend(
                [
                    "up",
                    "--detach",
                    "--pull",
                    "never",
                    "--no-build",
                    "--wait",
                    "--wait-timeout",
                    "120",
                    "--no-deps",
                    "postgres",
                    "rustfs",
                ]
                .map(str::to_owned),
            );
            Duration::from_mins(3)
        }
        ComposeStep::UpControl => {
            arguments.extend(
                [
                    "up",
                    "--detach",
                    "--pull",
                    "never",
                    "--no-build",
                    "--wait",
                    "--wait-timeout",
                    "120",
                    "--no-deps",
                    "automata",
                ]
                .map(str::to_owned),
            );
            Duration::from_mins(3)
        }
        ComposeStep::UpRelay => {
            arguments.extend(
                [
                    "up",
                    "--detach",
                    "--pull",
                    "never",
                    "--no-build",
                    "--wait",
                    "--wait-timeout",
                    "120",
                    "--no-deps",
                    "engine-relay",
                ]
                .map(str::to_owned),
            );
            Duration::from_mins(3)
        }
        ComposeStep::UpRunner => {
            arguments.extend(
                [
                    "up",
                    "--detach",
                    "--pull",
                    "never",
                    "--no-build",
                    "--wait",
                    "--wait-timeout",
                    "120",
                    "--no-deps",
                    "runner",
                ]
                .map(str::to_owned),
            );
            Duration::from_mins(3)
        }
        ComposeStep::RunOneOff {
            service,
            container_name,
        } => {
            arguments.extend(
                [
                    "--profile",
                    "automata-lifecycle",
                    "run",
                    "--detach",
                    "--interactive=false",
                    "--no-tty",
                    "--use-aliases",
                    "--pull",
                    "never",
                    "--no-build",
                    "--no-deps",
                    "--name",
                    container_name,
                    service,
                ]
                .into_iter()
                .map(ToOwned::to_owned),
            );
            Duration::from_secs(30)
        }
        ComposeStep::StopRunner => {
            arguments.extend(["stop", "--timeout", "30", "runner"].map(str::to_owned));
            Duration::from_secs(45)
        }
        ComposeStep::Down => {
            arguments.extend(["down", "--remove-orphans", "--timeout", "30"].map(str::to_owned));
            Duration::from_mins(2)
        }
    }
}

fn resolve_docker_executable() -> Result<ExecutableAuthority, LocalInitError> {
    let path = std::env::var_os("PATH").ok_or_else(engine_unavailable)?;
    for directory in std::env::split_paths(&path) {
        if !directory.is_absolute() {
            continue;
        }
        let candidate = directory.join(OsStr::new("docker"));
        let Ok(metadata) = candidate.metadata() else {
            continue;
        };
        if metadata.is_file() && metadata.mode() & 0o111 != 0 {
            let canonical = candidate.canonicalize().map_err(|_| engine_unavailable())?;
            return ExecutableAuthority::open(&canonical);
        }
    }
    Err(engine_unavailable())
}

fn exact_executable_metadata(path: &Path) -> Result<fs::Metadata, LocalInitError> {
    if !path.is_absolute() {
        return Err(engine_unavailable());
    }
    let metadata = path.symlink_metadata().map_err(|_| engine_unavailable())?;
    ensure_exact_executable_metadata(&metadata)?;
    Ok(metadata)
}

fn descriptor_metadata(descriptor: &OwnedFd) -> Result<fs::Metadata, LocalInitError> {
    let duplicate = descriptor.try_clone().map_err(|_| engine_unavailable())?;
    fs::File::from(duplicate)
        .metadata()
        .map_err(|_| engine_unavailable())
}

fn verify_absent_config_root() -> Result<(), LocalInitError> {
    match fs::symlink_metadata(ABSENT_CONFIG_ROOT) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Ok(_) | Err(_) => Err(engine_unavailable()),
    }
}

fn ensure_exact_executable_metadata(metadata: &fs::Metadata) -> Result<(), LocalInitError> {
    let euid = rustix::process::geteuid().as_raw();
    if !metadata.file_type().is_file()
        || metadata.file_type().is_symlink()
        || metadata.nlink() != 1
        || metadata.uid() != 0 && metadata.uid() != euid
        || metadata.mode() & 0o022 != 0
        || metadata.mode() & 0o6000 != 0
        || metadata.mode() & 0o111 == 0
    {
        return Err(engine_unavailable());
    }
    Ok(())
}

fn selected_compose_plugin(
    bytes: &[u8],
    expected_version: &str,
) -> Result<DockerCliPlugin, LocalInitError> {
    let plugins: Vec<DockerCliPlugin> =
        serde_json::from_slice(bytes).map_err(|_| engine_unavailable())?;
    let mut compose = plugins
        .into_iter()
        .filter(|plugin| plugin.name == COMPOSE_PLUGIN_NAME);
    let plugin = compose.next().ok_or_else(engine_unavailable)?;
    if compose.next().is_some()
        || plugin.schema_version != COMPOSE_PLUGIN_METADATA_SCHEMA
        || plugin.vendor.is_empty()
        || plugin.version != expected_version
        || plugin.short_description.is_empty()
        || !Path::new(&plugin.path).is_absolute()
    {
        return Err(engine_unavailable());
    }
    Ok(plugin)
}

#[derive(Deserialize)]
struct ComposeVersion {
    version: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct DockerCliPlugin {
    schema_version: String,
    vendor: String,
    version: String,
    short_description: String,
    name: String,
    path: String,
}

impl DockerCliPlugin {
    fn matches_direct_metadata(&self, metadata: &ComposePluginMetadata) -> bool {
        metadata.schema_version == COMPOSE_PLUGIN_METADATA_SCHEMA
            && metadata.schema_version == self.schema_version
            && metadata.vendor == self.vendor
            && metadata.version == self.version
            && metadata.short_description == self.short_description
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct ComposePluginMetadata {
    schema_version: String,
    vendor: String,
    version: String,
    short_description: String,
}

fn engine_unavailable() -> LocalInitError {
    LocalInitError::new(LocalInitErrorCode::EngineUnavailable)
}

fn reset_required() -> LocalInitError {
    LocalInitError::new(LocalInitErrorCode::ResetRequired)
}

#[cfg(test)]
mod tests {
    use std::{
        fs,
        path::{Path, PathBuf},
    };

    use uuid::Uuid;

    use super::{ExecutableAuthority, LocalInitErrorCode, selected_compose_plugin};

    struct FixtureDirectory {
        path: PathBuf,
    }

    impl FixtureDirectory {
        fn new() -> Self {
            let root = Path::new(env!("CARGO_MANIFEST_DIR"))
                .parent()
                .and_then(Path::parent)
                .expect("local crate must be nested beneath the workspace root")
                .join("target/agent-scratch/local-compose-authority");
            fs::create_dir_all(&root).expect("fixture root must be creatable");
            let path = root.join(Uuid::new_v4().simple().to_string());
            fs::create_dir(&path).expect("fixture directory must be unique");
            Self { path }
        }

        fn path(&self, name: &str) -> PathBuf {
            self.path.join(name)
        }
    }

    impl Drop for FixtureDirectory {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.path);
        }
    }

    fn copy_executable(source: &str, target: &Path) {
        fs::copy(source, target).expect("fixture executable must copy");
    }

    #[tokio::test]
    async fn held_descriptor_does_not_follow_a_verify_spawn_path_swap() {
        let fixture = FixtureDirectory::new();
        let executable = fixture.path("docker-compose");
        let displaced = fixture.path("qualified-compose");
        copy_executable("/bin/echo", &executable);
        let authority = ExecutableAuthority::open(&executable).expect("authority must open");
        let mut command = authority
            .process_command()
            .expect("held command must construct");
        command.arg("retained-authority");

        fs::rename(&executable, &displaced).expect("qualified path must move");
        copy_executable("/bin/false", &executable);

        let output = command
            .output()
            .await
            .expect("retained descriptor must remain executable");
        assert!(output.status.success());
        assert_eq!(output.stdout, b"retained-authority\n");
        assert_eq!(
            authority.verify_identity().unwrap_err().code(),
            LocalInitErrorCode::EngineUnavailable
        );
    }

    #[test]
    fn command_construction_rejects_a_preexisting_path_swap() {
        let fixture = FixtureDirectory::new();
        let executable = fixture.path("docker");
        copy_executable("/bin/true", &executable);
        let authority = ExecutableAuthority::open(&executable).expect("authority must open");

        fs::rename(&executable, fixture.path("qualified-docker"))
            .expect("qualified path must move");
        copy_executable("/bin/false", &executable);

        let error = authority
            .process_command()
            .err()
            .expect("swapped path must be rejected");
        assert_eq!(error.code(), LocalInitErrorCode::EngineUnavailable);
    }

    #[test]
    fn executable_with_multiple_names_is_rejected() {
        let fixture = FixtureDirectory::new();
        let executable = fixture.path("docker");
        copy_executable("/bin/true", &executable);
        fs::hard_link(&executable, fixture.path("docker-alias"))
            .expect("fixture hard link must succeed");

        assert_eq!(
            ExecutableAuthority::open(&executable).unwrap_err().code(),
            LocalInitErrorCode::EngineUnavailable
        );
    }

    #[test]
    fn compose_plugin_selection_requires_one_exact_reported_authority() {
        let valid = br#"[{"SchemaVersion":"0.1.0","Vendor":"Docker Inc.","Version":"5.4.0","ShortDescription":"Docker Compose","Name":"compose","Path":"/usr/lib/docker/cli-plugins/docker-compose"}]"#;
        let selected = selected_compose_plugin(valid, "5.4.0").expect("plugin must select");
        assert_eq!(selected.path, "/usr/lib/docker/cli-plugins/docker-compose");

        assert_eq!(
            selected_compose_plugin(valid, "5.4.1").unwrap_err().code(),
            LocalInitErrorCode::EngineUnavailable
        );
        let duplicate = br#"[{"SchemaVersion":"0.1.0","Vendor":"Docker Inc.","Version":"5.4.0","ShortDescription":"Docker Compose","Name":"compose","Path":"/first"},{"SchemaVersion":"0.1.0","Vendor":"Docker Inc.","Version":"5.4.0","ShortDescription":"Docker Compose","Name":"compose","Path":"/second"}]"#;
        assert_eq!(
            selected_compose_plugin(duplicate, "5.4.0")
                .unwrap_err()
                .code(),
            LocalInitErrorCode::EngineUnavailable
        );
    }
}
