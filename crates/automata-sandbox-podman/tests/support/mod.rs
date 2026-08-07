#![allow(dead_code)]

use std::{
    collections::BTreeMap,
    ffi::OsString,
    fs,
    path::{Path, PathBuf},
    sync::{
        Arc, Mutex,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};

use automata_execution::{
    EnvironmentProfile, EnvironmentProfileId, ExecutionArgv, ExecutionEnvironment, ImmutableImage,
    NetworkPolicy, OperationId, ResourceLimits, RootFilesystemPolicy, SandboxEnvironment,
    SandboxGeneration, SandboxSpec, Sha256Digest, TargetPath,
};
use automata_sandbox_podman::{
    CommandOutput, CommandRequest, CommandTermination, PodmanBinary, PodmanCommandExecutor,
    PodmanOptions, PodmanProcessEnvironment, PodmanStateRoot, RootlessPodmanProvider,
};

const OWNER: &str = "io.automata.owner";
const SANDBOX: &str = "io.automata.sandbox";
const GENERATION: &str = "io.automata.generation";
const PROFILE: &str = "io.automata.profile";
const PROFILE_DIGEST: &str = "io.automata.profile-sha256";
const SPEC: &str = "io.automata.spec-sha256";

#[derive(Debug)]
pub(crate) struct ScratchRoot {
    path: PathBuf,
}

impl ScratchRoot {
    pub(crate) fn new(_label: &str) -> Self {
        static NEXT_SCRATCH: AtomicU64 = AtomicU64::new(0);
        let identifier = format!(
            "{}-{}",
            std::process::id(),
            NEXT_SCRATCH.fetch_add(1, Ordering::Relaxed)
        );
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../target/podman-tests")
            .join(identifier);
        fs::create_dir_all(&path).expect("repo-local test scratch must be creatable");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            fs::set_permissions(&path, fs::Permissions::from_mode(0o700))
                .expect("test scratch permissions must be settable");
        }
        let path = fs::canonicalize(path).expect("test scratch must canonicalize");
        Self { path }
    }

    pub(crate) fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for ScratchRoot {
    fn drop(&mut self) {
        let _ignored = fs::remove_dir_all(&self.path);
    }
}

#[derive(Clone, Debug, Default)]
struct Resource {
    labels: BTreeMap<String, String>,
    state: Option<String>,
}

#[derive(Default)]
struct FakeState {
    commands: Vec<Vec<String>>,
    exec_requests: Vec<CapturedExecRequest>,
    child_environments: Vec<BTreeMap<String, String>>,
    dynamic_environment_names: Vec<Vec<String>>,
    process_homes: Vec<PathBuf>,
    process_temporary_directories: Vec<Option<PathBuf>>,
    network: Option<Resource>,
    pod: Option<Resource>,
    container: Option<Resource>,
    fail_once: Option<Vec<String>>,
    cancel_once: Option<Vec<String>>,
    exec_output: Option<CommandOutput>,
    copied_to: Option<Vec<u8>>,
    copy_from: Vec<u8>,
    copy_attack: Option<CopyAttack>,
    staged_input_mode: Option<u32>,
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct CapturedExecRequest {
    pub(crate) timeout: Duration,
    pub(crate) aggregate_deadline: Instant,
    pub(crate) output_limit: usize,
}

#[derive(Clone, Debug)]
pub(crate) enum CopyAttack {
    Symlink(PathBuf),
    Directory,
}

#[derive(Default)]
pub(crate) struct FakePodman {
    state: Mutex<FakeState>,
}

impl std::fmt::Debug for FakePodman {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("FakePodman")
            .field("captured_values", &"[REDACTED]")
            .finish_non_exhaustive()
    }
}

impl FakePodman {
    pub(crate) fn commands(&self) -> Vec<Vec<String>> {
        self.state.lock().expect("fake lock").commands.clone()
    }

    pub(crate) fn fail_once(&self, command: &[&str]) {
        self.state.lock().expect("fake lock").fail_once = Some(
            command
                .iter()
                .map(|component| (*component).to_owned())
                .collect(),
        );
    }

    pub(crate) fn cancel_once(&self, command: &[&str]) {
        self.state.lock().expect("fake lock").cancel_once = Some(
            command
                .iter()
                .map(|component| (*component).to_owned())
                .collect(),
        );
    }

    pub(crate) fn replace_owner(&self, owner: &str) {
        let mut state = self.state.lock().expect("fake lock");
        if let Some(resource) = state.network.as_mut() {
            resource.labels.insert(OWNER.to_owned(), owner.to_owned());
        }
        if let Some(resource) = state.pod.as_mut() {
            resource.labels.insert(OWNER.to_owned(), owner.to_owned());
        }
        if let Some(resource) = state.container.as_mut() {
            resource.labels.insert(OWNER.to_owned(), owner.to_owned());
        }
    }

    pub(crate) fn set_exec_output(&self, output: CommandOutput) {
        self.state.lock().expect("fake lock").exec_output = Some(output);
    }

    pub(crate) fn last_exec_environment(&self) -> BTreeMap<String, String> {
        self.state
            .lock()
            .expect("fake lock")
            .child_environments
            .last()
            .cloned()
            .unwrap_or_default()
    }

    pub(crate) fn last_exec_request(&self) -> Option<CapturedExecRequest> {
        self.state
            .lock()
            .expect("fake lock")
            .exec_requests
            .last()
            .copied()
    }

    pub(crate) fn last_dynamic_environment_names(&self) -> Vec<String> {
        self.state
            .lock()
            .expect("fake lock")
            .dynamic_environment_names
            .last()
            .cloned()
            .unwrap_or_default()
    }

    pub(crate) fn last_process_home(&self) -> Option<PathBuf> {
        self.state
            .lock()
            .expect("fake lock")
            .process_homes
            .last()
            .cloned()
    }

    pub(crate) fn last_process_temporary_directory(&self) -> Option<PathBuf> {
        self.state
            .lock()
            .expect("fake lock")
            .process_temporary_directories
            .last()
            .cloned()
            .flatten()
    }

    pub(crate) fn set_copy_from(&self, content: Vec<u8>) {
        self.state.lock().expect("fake lock").copy_from = content;
    }

    pub(crate) fn set_copy_attack(&self, attack: CopyAttack) {
        self.state.lock().expect("fake lock").copy_attack = Some(attack);
    }

    pub(crate) fn copied_to(&self) -> Option<Vec<u8>> {
        self.state.lock().expect("fake lock").copied_to.clone()
    }

    pub(crate) fn staged_input_mode(&self) -> Option<u32> {
        self.state.lock().expect("fake lock").staged_input_mode
    }

    pub(crate) fn is_empty(&self) -> bool {
        let state = self.state.lock().expect("fake lock");
        state.network.is_none() && state.pod.is_none() && state.container.is_none()
    }
}

impl PodmanCommandExecutor for FakePodman {
    fn execute(
        &self,
        request: &CommandRequest,
        environment: &PodmanProcessEnvironment,
        cancellation: &dyn automata_execution::Cancellation,
    ) -> CommandOutput {
        if cancellation.is_cancelled() {
            return CommandOutput::terminated(CommandTermination::Cancelled);
        }
        let arguments = request
            .arguments()
            .iter()
            .map(|value| value.to_string_lossy().into_owned())
            .collect::<Vec<_>>();
        let command = arguments
            .iter()
            .skip_while(|value| value.starts_with("--"))
            .cloned()
            .collect::<Vec<_>>();
        let child_environment = collect_exec_environment(request, &arguments);
        let mut state = self.state.lock().expect("fake lock");
        state.commands.push(arguments);
        if command.first().is_some_and(|value| value == "exec") {
            state.exec_requests.push(CapturedExecRequest {
                timeout: request.timeout(),
                aggregate_deadline: request.aggregate_deadline(),
                output_limit: request.output_limit(),
            });
        }
        state.child_environments.push(child_environment);
        state.dynamic_environment_names.push(
            request
                .child_environment()
                .values()
                .iter()
                .map(|variable| variable.name().as_str().to_owned())
                .collect(),
        );
        state.process_homes.push(environment.home().to_path_buf());
        state
            .process_temporary_directories
            .push(environment.temporary_directory().map(Path::to_path_buf));
        if state
            .fail_once
            .as_ref()
            .is_some_and(|expected| command.starts_with(expected))
        {
            state.fail_once = None;
            return CommandOutput::failure(125, b"redacted backend rejection".to_vec());
        }
        if state
            .cancel_once
            .as_ref()
            .is_some_and(|expected| command.starts_with(expected))
        {
            state.cancel_once = None;
            return CommandOutput::terminated(CommandTermination::Cancelled);
        }
        execute_fake(&mut state, &command)
    }
}

fn collect_exec_environment(
    request: &CommandRequest,
    arguments: &[String],
) -> BTreeMap<String, String> {
    let mut values = request
        .child_environment()
        .values()
        .iter()
        .map(|variable| {
            (
                variable.name().as_str().to_owned(),
                variable.value().expose().to_owned(),
            )
        })
        .collect::<BTreeMap<_, _>>();
    for window in arguments.windows(2) {
        if window[0] != "--env-file" {
            continue;
        }
        let Ok(content) = fs::read_to_string(&window[1]) else {
            continue;
        };
        for line in content.lines() {
            if let Some((name, value)) = line.split_once('=') {
                values.insert(name.to_owned(), value.to_owned());
            }
        }
    }
    values
}

fn execute_fake(state: &mut FakeState, command: &[String]) -> CommandOutput {
    match command {
        [first, ..] if first == "info" => CommandOutput::success(b"true\nv2\n".to_vec()),
        [action, program, arguments @ ..] if action == "unshare" && program == "/usr/bin/rm" => {
            let Some(path) = arguments.last() else {
                return CommandOutput::failure(125, Vec::new());
            };
            match fs::remove_dir_all(path) {
                Ok(()) => CommandOutput::success(Vec::new()),
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                    CommandOutput::success(Vec::new())
                }
                Err(_) => CommandOutput::failure(125, Vec::new()),
            }
        }
        [kind, action, name] if action == "exists" => {
            exists_output(resource(state, kind).is_some() && !name.is_empty())
        }
        [kind, action, rest @ ..] if action == "inspect" => {
            let name = rest.last().map(String::as_str).unwrap_or_default();
            if name.is_empty() {
                return CommandOutput::failure(125, Vec::new());
            }
            resource(state, kind).map_or_else(
                || CommandOutput::failure(1, Vec::new()),
                |resource| CommandOutput::success(inspect_bytes(resource)),
            )
        }
        [kind, action, rest @ ..] if action == "create" && kind == "network" => {
            state.network = Some(new_resource(rest, None));
            CommandOutput::success(Vec::new())
        }
        [kind, action, rest @ ..] if action == "create" && kind == "pod" => {
            state.pod = Some(new_resource(rest, None));
            CommandOutput::success(Vec::new())
        }
        [action, rest @ ..] if action == "create" => {
            state.container = Some(new_resource(rest, Some("created")));
            CommandOutput::success(Vec::new())
        }
        [action, ..] if action == "start" => {
            if let Some(container) = state.container.as_mut() {
                container.state = Some("running".to_owned());
                CommandOutput::success(Vec::new())
            } else {
                CommandOutput::failure(1, Vec::new())
            }
        }
        [kind, action, ..] if action == "rm" && kind == "network" => {
            state.network = None;
            CommandOutput::success(Vec::new())
        }
        [kind, action, ..] if action == "rm" && kind == "pod" => {
            state.pod = None;
            CommandOutput::success(Vec::new())
        }
        [action, ..] if action == "rm" => {
            state.container = None;
            CommandOutput::success(Vec::new())
        }
        [action, ..] if action == "exec" => state
            .exec_output
            .clone()
            .unwrap_or_else(|| CommandOutput::success(b"executed\n".to_vec())),
        [action, ..] if action == "kill" => {
            if let Some(container) = state.container.as_mut() {
                container.state = Some("exited".to_owned());
                CommandOutput::success(Vec::new())
            } else {
                CommandOutput::failure(1, Vec::new())
            }
        }
        [action, ..] if action == "wait" => CommandOutput::success(b"137\n".to_vec()),
        [action, source, destination] if action == "cp" => {
            execute_fake_copy(state, source, destination)
        }
        [action, option, source, destination] if action == "cp" && option == "--overwrite" => {
            execute_fake_copy(state, source, destination)
        }
        _ => CommandOutput::failure(125, Vec::new()),
    }
}

fn execute_fake_copy(state: &mut FakeState, source: &str, destination: &str) -> CommandOutput {
    if destination.contains(':') {
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt as _;
            state.staged_input_mode = fs::symlink_metadata(source)
                .ok()
                .map(|metadata| metadata.mode() & 0o777);
        }
        return match fs::read(source) {
            Ok(content) => {
                state.copied_to = Some(content);
                CommandOutput::success(Vec::new())
            }
            Err(_) => CommandOutput::failure(125, Vec::new()),
        };
    }
    if !source.contains(':') {
        return CommandOutput::failure(125, Vec::new());
    }
    let path = Path::new(destination);
    let result = match state.copy_attack.take() {
        #[cfg(unix)]
        Some(CopyAttack::Symlink(target)) => std::os::unix::fs::symlink(target, path),
        Some(CopyAttack::Directory) => fs::create_dir(path),
        None => fs::write(path, &state.copy_from),
        #[cfg(not(unix))]
        Some(CopyAttack::Symlink(_)) => return CommandOutput::failure(125, Vec::new()),
    };
    if result.is_err() {
        return CommandOutput::failure(125, Vec::new());
    }
    CommandOutput::success(Vec::new())
}

fn resource<'a>(state: &'a FakeState, kind: &str) -> Option<&'a Resource> {
    match kind {
        "network" => state.network.as_ref(),
        "pod" => state.pod.as_ref(),
        "container" => state.container.as_ref(),
        _ => None,
    }
}

fn exists_output(exists: bool) -> CommandOutput {
    if exists {
        CommandOutput::success(Vec::new())
    } else {
        CommandOutput::failure(1, Vec::new())
    }
}

fn new_resource(arguments: &[String], state: Option<&str>) -> Resource {
    let mut labels = BTreeMap::new();
    let mut index = 0;
    while index + 1 < arguments.len() {
        if arguments[index] == "--label" {
            if let Some((key, value)) = arguments[index + 1].split_once('=') {
                labels.insert(key.to_owned(), value.to_owned());
            }
            index += 2;
        } else {
            index += 1;
        }
    }
    Resource {
        labels,
        state: state.map(str::to_owned),
    }
}

fn inspect_bytes(resource: &Resource) -> Vec<u8> {
    let mut values = [OWNER, SANDBOX, GENERATION, PROFILE, PROFILE_DIGEST, SPEC]
        .map(|key| resource.labels.get(key).cloned().unwrap_or_default())
        .to_vec();
    if let Some(state) = &resource.state {
        values.push(state.clone());
    }
    format!("{}\n", values.join("\n")).into_bytes()
}

pub(crate) struct Fixture {
    pub(crate) provider: RootlessPodmanProvider,
    pub(crate) fake: Arc<FakePodman>,
    pub(crate) scratch: ScratchRoot,
}

impl Fixture {
    pub(crate) fn new(label: &str) -> Self {
        Self::new_with_options(label, std::convert::identity)
    }

    pub(crate) fn new_with_options(
        label: &str,
        configure: impl FnOnce(PodmanOptions) -> PodmanOptions,
    ) -> Self {
        let scratch = ScratchRoot::new(label);
        let fake = Arc::new(FakePodman::default());
        let provider = RootlessPodmanProvider::open_with_executor(
            configure(options(scratch.path())),
            Arc::clone(&fake) as Arc<dyn PodmanCommandExecutor>,
        )
        .expect("fake provider must open");
        Self {
            provider,
            fake,
            scratch,
        }
    }
}

pub(crate) fn options(root: &Path) -> PodmanOptions {
    let root = PodmanStateRoot::existing(root).expect("state root");
    let binary = PodmanBinary::new("/usr/bin/podman").expect("binary");
    let environment =
        PodmanProcessEnvironment::new(root.as_path(), None, OsString::from("/usr/bin:/bin"))
            .expect("process environment");
    PodmanOptions::new(binary, root, environment)
}

pub(crate) fn sample_spec(operation_id: OperationId) -> SandboxSpec {
    sample_spec_with(
        operation_id,
        "automata.dev/archlinux-x86-64-v1",
        NetworkPolicy::PrivateEgress,
    )
}

pub(crate) fn sample_spec_with(
    operation_id: OperationId,
    profile_id: &str,
    network: NetworkPolicy,
) -> SandboxSpec {
    sample_spec_with_digest(operation_id, profile_id, [0x11; 32], network)
}

pub(crate) fn sample_spec_with_digest(
    operation_id: OperationId,
    profile_id: &str,
    profile_digest: [u8; 32],
    network: NetworkPolicy,
) -> SandboxSpec {
    let image = ImmutableImage::new(format!(
        "registry.example.invalid/automata/arch@sha256:{}",
        "0".repeat(64)
    ))
    .expect("immutable image");
    let keepalive = ExecutionArgv::new(
        TargetPath::posix("/bin/sleep").expect("program"),
        vec!["infinity".to_owned()],
    )
    .expect("keepalive");
    let profile = SandboxEnvironment::new(
        EnvironmentProfile::new(
            EnvironmentProfileId::new(profile_id).expect("profile id"),
            Sha256Digest::from_bytes(profile_digest),
        ),
        image,
        keepalive,
        TargetPath::posix("/__w").expect("workspace"),
        ExecutionEnvironment::empty(),
    )
    .expect("profile");
    SandboxSpec::new(
        operation_id,
        SandboxGeneration::new(1).expect("generation"),
        profile,
        TargetPath::posix("/__w").expect("workspace"),
        network,
        RootFilesystemPolicy::ReadOnly,
        ResourceLimits::new(512 * 1024 * 1024, 2_000, 512).expect("resources"),
    )
}
