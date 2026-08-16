#![cfg(target_os = "linux")]
#![allow(dead_code)]

use std::{
    collections::BTreeMap,
    fs,
    os::unix::fs::PermissionsExt as _,
    path::{Path, PathBuf},
    sync::{
        Arc, Mutex,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};

use automata_ci_execution::{
    EnvironmentProfile, EnvironmentProfileId, ExecutionArgv, ExecutionEnvironment, ImmutableImage,
    NetworkPolicy, OperationId, ResourceLimits, RootFilesystemPolicy, RunnerId, SandboxCustody,
    SandboxEnvironment, SandboxGeneration, SandboxSpec, Sha256Digest, TargetPath,
};
use automata_ci_sandbox_podman::{
    CommandOutput, CommandRequest, CommandTermination, PodmanBinary, PodmanCommandExecutor,
    PodmanOptions, PodmanProcessEnvironment, PodmanStateRoot, RootlessPodmanProvider,
};

const OWNER: &str = "io.automata.owner";
const RESOURCE_SCHEMA: &str = "io.automata.sandbox-schema";
const SANDBOX: &str = "io.automata.sandbox";
const GENERATION: &str = "io.automata.generation";
const PROFILE: &str = "io.automata.profile";
const PROFILE_DIGEST: &str = "io.automata.profile-sha256";
const SPEC: &str = "io.automata.spec-sha256";
const CUSTODY_KIND: &str = "io.automata.custody-kind";
const CUSTODY_RUNNER: &str = "io.automata.custody-runner";
const CUSTODY_SLOT: &str = "io.automata.custody-slot";
const FAKE_INFRA_ID: &str = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";

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
    identifier: String,
    name: String,
    image_name: String,
    network_mode: String,
    entrypoint: Vec<String>,
    command: Vec<String>,
    network_address: Option<String>,
    logs: Vec<u8>,
    labels: BTreeMap<String, String>,
    state: Option<String>,
    health_configured: bool,
    health_configuration: Vec<u8>,
    health: Option<String>,
    ports: BTreeMap<String, u16>,
}

#[allow(clippy::struct_excessive_bools)]
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
    containers: BTreeMap<String, Resource>,
    next_host_port: u16,
    next_container_id: u64,
    next_service_address: u8,
    keep_health_starting: bool,
    require_active_healthcheck: bool,
    omit_health_configuration: bool,
    port_output: Option<CommandOutput>,
    fail_once: Option<Vec<String>>,
    cancel_once: Option<Vec<String>>,
    buildkit_image_missing: bool,
    buildkit_digest_override: Option<String>,
    buildkit_probe_output: Option<CommandOutput>,
    exec_output: Option<CommandOutput>,
    copied_to: Option<Vec<u8>>,
    copy_from: Vec<u8>,
    copy_archive: Option<Vec<u8>>,
    no_swap_verifications: u32,
    aggregate_pids: Option<u32>,
    fail_no_swap_verification_once: bool,
    fail_delegated_cgroup: bool,
    cancel_service_create_once: bool,
    malformed_service_identifier_once: bool,
    wrong_service_identifier_once: bool,
    wrong_proxy_identifier_once: bool,
    drift_health_configuration_once: bool,
    replace_network_before_remove: bool,
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct CapturedExecRequest {
    pub(crate) timeout: Duration,
    pub(crate) aggregate_deadline: Instant,
    pub(crate) output_limit: usize,
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

    pub(crate) fn make_buildkit_image_missing(&self) {
        self.state.lock().expect("fake lock").buildkit_image_missing = true;
    }

    pub(crate) fn override_buildkit_digest(&self, digest: &str) {
        self.state
            .lock()
            .expect("fake lock")
            .buildkit_digest_override = Some(digest.to_owned());
    }

    pub(crate) fn set_buildkit_probe_output(&self, output: CommandOutput) {
        self.state.lock().expect("fake lock").buildkit_probe_output = Some(output);
    }

    pub(crate) fn replace_owner(&self, owner: &str) {
        let mut state = self.state.lock().expect("fake lock");
        if let Some(resource) = state.network.as_mut() {
            resource.labels.insert(OWNER.to_owned(), owner.to_owned());
        }
        if let Some(resource) = state.pod.as_mut() {
            resource.labels.insert(OWNER.to_owned(), owner.to_owned());
        }
        for resource in state.containers.values_mut() {
            resource.labels.insert(OWNER.to_owned(), owner.to_owned());
        }
    }

    pub(crate) fn replace_custody(&self, kind: &str, runner: RunnerId, slot: u16) {
        let mut state = self.state.lock().expect("fake lock");
        let replace = |resource: &mut Resource| {
            resource
                .labels
                .insert(CUSTODY_KIND.to_owned(), kind.to_owned());
            resource
                .labels
                .insert(CUSTODY_RUNNER.to_owned(), runner.to_string());
            resource
                .labels
                .insert(CUSTODY_SLOT.to_owned(), slot.to_string());
        };
        if let Some(resource) = state.network.as_mut() {
            replace(resource);
        }
        if let Some(resource) = state.pod.as_mut() {
            replace(resource);
        }
        for resource in state.containers.values_mut() {
            replace(resource);
        }
    }

    pub(crate) fn replace_resource_schema(&self, schema: &str) {
        let mut state = self.state.lock().expect("fake lock");
        if let Some(resource) = state.network.as_mut() {
            resource
                .labels
                .insert(RESOURCE_SCHEMA.to_owned(), schema.to_owned());
        }
        if let Some(resource) = state.pod.as_mut() {
            resource
                .labels
                .insert(RESOURCE_SCHEMA.to_owned(), schema.to_owned());
        }
        for resource in state.containers.values_mut() {
            resource
                .labels
                .insert(RESOURCE_SCHEMA.to_owned(), schema.to_owned());
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

    pub(crate) fn child_environments(&self) -> Vec<BTreeMap<String, String>> {
        self.state
            .lock()
            .expect("fake lock")
            .child_environments
            .clone()
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

    pub(crate) fn set_copy_archive(&self, archive: Vec<u8>) {
        self.state.lock().expect("fake lock").copy_archive = Some(archive);
    }

    pub(crate) fn copied_to(&self) -> Option<Vec<u8>> {
        self.state.lock().expect("fake lock").copied_to.clone()
    }

    pub(crate) fn fail_no_swap_verification_once(&self) {
        self.state
            .lock()
            .expect("fake lock")
            .fail_no_swap_verification_once = true;
    }

    pub(crate) fn fail_delegated_cgroup(&self) {
        self.state.lock().expect("fake lock").fail_delegated_cgroup = true;
    }

    pub(crate) fn cancel_service_create_once(&self) {
        self.state
            .lock()
            .expect("fake lock")
            .cancel_service_create_once = true;
    }

    pub(crate) fn malformed_service_identifier_once(&self) {
        self.state
            .lock()
            .expect("fake lock")
            .malformed_service_identifier_once = true;
    }

    pub(crate) fn wrong_service_identifier_once(&self) {
        self.state
            .lock()
            .expect("fake lock")
            .wrong_service_identifier_once = true;
    }

    pub(crate) fn wrong_proxy_identifier_once(&self) {
        self.state
            .lock()
            .expect("fake lock")
            .wrong_proxy_identifier_once = true;
    }

    pub(crate) fn drift_service_proxy_command(&self) -> Vec<String> {
        let mut state = self.state.lock().expect("fake lock");
        let resource = state
            .containers
            .values_mut()
            .find(|resource| resource.entrypoint == ["/usr/libexec/automata-ci-service-proxy"])
            .expect("service proxy exists");
        let original = resource.command.clone();
        let mapping = resource.command.get_mut(1).expect("proxy mapping exists");
        let (_, suffix) = mapping.split_once('|').expect("mapping protocol");
        let (_, suffix) = suffix.split_once('|').expect("mapping address");
        *mapping = format!("tcp|10.89.0.250|{suffix}");
        original
    }

    pub(crate) fn restore_service_proxy_command(&self, command: Vec<String>) {
        let mut state = self.state.lock().expect("fake lock");
        let resource = state
            .containers
            .values_mut()
            .find(|resource| resource.entrypoint == ["/usr/libexec/automata-ci-service-proxy"])
            .expect("service proxy exists");
        resource.command = command;
    }

    pub(crate) fn drift_primary_pod(&self) -> String {
        let mut state = self.state.lock().expect("fake lock");
        let pod_identifier = state
            .pod
            .as_ref()
            .map(|pod| pod.identifier.clone())
            .expect("pod exists");
        let primary = state
            .containers
            .values_mut()
            .find(|resource| {
                resource.network_mode == pod_identifier
                    && resource.entrypoint != ["/usr/libexec/automata-ci-service-proxy"]
            })
            .expect("primary container exists");
        std::mem::replace(
            &mut primary.network_mode,
            "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd".to_owned(),
        )
    }

    pub(crate) fn restore_primary_pod(&self, pod_identifier: String) {
        let mut state = self.state.lock().expect("fake lock");
        let primary = state
            .containers
            .values_mut()
            .find(|resource| {
                resource.network_mode
                    == "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
                    && resource.entrypoint != ["/usr/libexec/automata-ci-service-proxy"]
            })
            .expect("primary container exists");
        primary.network_mode = pod_identifier;
    }

    pub(crate) fn keep_health_starting(&self) {
        self.state.lock().expect("fake lock").keep_health_starting = true;
    }

    pub(crate) fn require_active_healthcheck(&self) {
        self.state
            .lock()
            .expect("fake lock")
            .require_active_healthcheck = true;
    }

    pub(crate) fn omit_health_configuration(&self) {
        self.state
            .lock()
            .expect("fake lock")
            .omit_health_configuration = true;
    }

    pub(crate) fn drift_health_configuration_once(&self) {
        self.state
            .lock()
            .expect("fake lock")
            .drift_health_configuration_once = true;
    }

    pub(crate) fn set_port_output(&self, output: Option<CommandOutput>) {
        self.state.lock().expect("fake lock").port_output = output;
    }

    pub(crate) fn stop_service_proxy(&self) -> String {
        let mut state = self.state.lock().expect("fake lock");
        let (_, proxy) = state
            .containers
            .iter_mut()
            .find(|(name, _)| name.starts_with("automata-job-service-proxy-"))
            .expect("service proxy exists");
        proxy.state = Some("exited".to_owned());
        proxy.identifier.clone()
    }

    pub(crate) fn replace_network_before_remove(&self) {
        self.state
            .lock()
            .expect("fake lock")
            .replace_network_before_remove = true;
    }

    pub(crate) fn only_network_remains(&self) -> bool {
        let state = self.state.lock().expect("fake lock");
        state.network.is_some() && state.pod.is_none() && state.containers.is_empty()
    }

    pub(crate) fn retain_network_only(&self) {
        let mut state = self.state.lock().expect("fake lock");
        state.pod = None;
        state.containers.clear();
    }

    pub(crate) fn no_swap_verifications(&self) -> u32 {
        self.state.lock().expect("fake lock").no_swap_verifications
    }

    pub(crate) fn aggregate_pids(&self) -> Option<u32> {
        self.state.lock().expect("fake lock").aggregate_pids
    }

    pub(crate) fn is_empty(&self) -> bool {
        let state = self.state.lock().expect("fake lock");
        state.network.is_none() && state.pod.is_none() && state.containers.is_empty()
    }
}

impl PodmanCommandExecutor for FakePodman {
    fn execute(
        &self,
        request: &CommandRequest,
        environment: &PodmanProcessEnvironment,
        cancellation: &dyn automata_ci_execution::Cancellation,
    ) -> CommandOutput {
        if cancellation.disposition().requires_termination() {
            return interrupted_before_input(request, CommandTermination::Cancelled);
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
        if command.first().is_some_and(|value| value == "exec") {
            state.exec_requests.push(CapturedExecRequest {
                timeout: request.timeout(),
                aggregate_deadline: request.aggregate_deadline(),
                output_limit: request.output_limit(),
            });
        }
        state.child_environments.push(child_environment);
        state.dynamic_environment_names.push(
            arguments
                .windows(2)
                .filter(|window| window[0] == "--env" && !window[1].contains('='))
                .map(|window| window[1].clone())
                .collect(),
        );
        state.commands.push(arguments);
        state.process_homes.push(environment.home().to_path_buf());
        state.process_temporary_directories.push(Some(
            environment.process_transient_directory().to_path_buf(),
        ));
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
            return interrupted_before_input(request, CommandTermination::Cancelled);
        }
        if state.cancel_service_create_once
            && command.first().is_some_and(|value| value == "create")
            && command.iter().any(|value| value == "--network-alias")
        {
            state.cancel_service_create_once = false;
            return interrupted_before_input(request, CommandTermination::Cancelled);
        }
        execute_fake(&mut state, &command, request.stdin())
    }

    fn delegated_no_swap_cgroup(&self) -> Option<String> {
        (!self.state.lock().expect("fake lock").fail_delegated_cgroup)
            .then(|| "/automata-runner.service".to_owned())
    }

    fn enforces_job_cgroup(&self, _process_id: u32, pod_cgroup: &str, aggregate_pids: u32) -> bool {
        if pod_cgroup != "/automata-runner.service/automata-job-services.slice"
            || aggregate_pids == 0
        {
            return false;
        }
        let Ok(mut state) = self.state.lock() else {
            return false;
        };
        let Some(verifications) = state.no_swap_verifications.checked_add(1) else {
            return false;
        };
        state.no_swap_verifications = verifications;
        if state
            .aggregate_pids
            .is_some_and(|configured| configured != aggregate_pids)
        {
            return false;
        }
        state.aggregate_pids = Some(aggregate_pids);
        !std::mem::take(&mut state.fail_no_swap_verification_once)
    }
}

fn interrupted_before_input(
    request: &CommandRequest<'_>,
    termination: CommandTermination,
) -> CommandOutput {
    if request.stdin_byte_len().is_some() {
        CommandOutput::terminated_with_incomplete_stdin(termination)
    } else {
        CommandOutput::terminated(termination)
    }
}

fn collect_exec_environment(
    request: &CommandRequest,
    arguments: &[String],
) -> BTreeMap<String, String> {
    let mut values = BTreeMap::new();
    for window in arguments.windows(2) {
        if window != ["--env-file", "/dev/stdin"] {
            continue;
        }
        let Some(byte_len) = request.stdin_byte_len() else {
            continue;
        };
        let mut content = Vec::with_capacity(byte_len);
        for segment in request.stdin_segments() {
            content.extend_from_slice(segment);
        }
        let Ok(content) = std::str::from_utf8(&content) else {
            continue;
        };
        for line in content.lines() {
            if let Some((name, value)) = line.split_once('=') {
                values.insert(name.to_owned(), value.to_owned());
            }
        }
    }
    for (name, value) in request.inherited_environment() {
        if arguments
            .windows(2)
            .any(|window| window[0] == "--env" && window[1] == name)
        {
            values.insert(name.to_owned(), value.to_owned());
        }
    }
    values
}

fn execute_fake(state: &mut FakeState, command: &[String], stdin: Option<&[u8]>) -> CommandOutput {
    if let Some(output) = execute_fake_inspection(state, command) {
        return output;
    }
    if let Some(output) = execute_fake_lifecycle(state, command) {
        return output;
    }
    match command {
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
        [action, ..] if action == "exec" => state
            .exec_output
            .clone()
            .unwrap_or_else(|| CommandOutput::success(b"executed\n".to_vec())),
        [action, ..] if action == "wait" => CommandOutput::success(b"137\n".to_vec()),
        [action, arguments @ ..]
            if action == "run"
                && arguments
                    .iter()
                    .any(|value| value == "--entrypoint=buildkitd")
                && arguments.last().is_some_and(|value| value == "--version") =>
        {
            state.buildkit_probe_output.clone().unwrap_or_else(|| {
                CommandOutput::success(b"buildkitd github.com/moby/buildkit v0.0.0-test\n".to_vec())
            })
        }
        [action, source, destination] if action == "cp" => {
            execute_fake_copy(state, source, destination, stdin)
        }
        [action, option, source, destination] if action == "cp" && option == "--overwrite" => {
            execute_fake_copy(state, source, destination, stdin)
        }
        _ => CommandOutput::failure(125, Vec::new()),
    }
}

#[allow(clippy::too_many_lines)]
fn execute_fake_inspection(state: &FakeState, command: &[String]) -> Option<CommandOutput> {
    match command {
        [image, exists, reference]
            if image == "image" && exists == "exists" && reference.contains("@sha256:") =>
        {
            Some(if state.buildkit_image_missing {
                CommandOutput::failure(1, Vec::new())
            } else {
                CommandOutput::success(Vec::new())
            })
        }
        [image, inspect, format, template, reference]
            if image == "image"
                && inspect == "inspect"
                && format == "--format"
                && template
                    == "{{.Digest}}\n{{ index .Labels \"io.automata.service-proxy.protocol-version\" }}" =>
        {
            let digest = reference.rsplit_once('@').map(|(_, value)| value).unwrap_or_default();
            Some(CommandOutput::success(
                format!("{digest}\n1\n").into_bytes(),
            ))
        }
        [image, inspect, format, template, reference]
            if image == "image"
                && inspect == "inspect"
                && format == "--format"
                && template == "{{.Digest}}"
                && reference.contains("@sha256:") =>
        {
            let digest = reference
                .rsplit_once('@')
                .map(|(_, value)| value)
                .unwrap_or_default();
            let digest = state
                .buildkit_digest_override
                .as_deref()
                .unwrap_or(digest);
            Some(CommandOutput::success(format!("{digest}\n").into_bytes()))
        }
        [container, inspect, format, template, name]
            if container == "container"
                && inspect == "inspect"
                && format == "--format"
                && template == "{{.State.Pid}}"
                && !name.is_empty() =>
        {
            Some(CommandOutput::success(
                format!("{}\n", std::process::id()).into_bytes(),
            ))
        }
        [container, inspect, format, template, name]
            if container == "container"
                && inspect == "inspect"
                && format == "--format"
                && template == "{{json .Config.Healthcheck}}" =>
        {
            Some(container_resource(state, name).map_or_else(
                || CommandOutput::failure(1, Vec::new()),
                |resource| {
                    if resource.health_configuration.is_empty() {
                        CommandOutput::success(b"null\n".to_vec())
                    } else {
                        CommandOutput::success(resource.health_configuration.clone())
                    }
                },
            ))
        }
        [container, inspect, format, template, name]
            if container == "container"
                && inspect == "inspect"
                && format == "--format"
                && template.starts_with(
                    "{{.ImageName}}\n{{if .HostConfig.PortBindings}}published{{else}}unpublished{{end}}\n",
                ) =>
        {
            Some(container_resource(state, name).map_or_else(
                || CommandOutput::failure(1, Vec::new()),
                |resource| {
                    let create_command = serde_json::to_string(&[
                        "/usr/bin/podman",
                        "create",
                        "--sysctl",
                        "net.ipv4.ip_unprivileged_port_start=0",
                    ])
                    .expect("fake create-command JSON");
                    CommandOutput::success(
                        format!(
                            "{}\nunpublished\n{}\n{create_command}\n",
                            resource.image_name,
                            if resource.network_address.is_some() {
                                "alias"
                            } else {
                                "missing"
                            }
                        )
                        .into_bytes(),
                    )
                },
            ))
        }
        [pod, inspect, format, template, name]
            if pod == "pod"
                && inspect == "inspect"
                && format == "--format"
                && template == "{{json .CreateCommand}}"
                && resource(state, "pod", name).is_some() =>
        {
            Some(CommandOutput::success(
                serde_json::to_vec(&[
                    "/usr/bin/podman",
                    "pod",
                    "create",
                    "--sysctl",
                    "net.ipv4.ip_unprivileged_port_start=0",
                ])
                .expect("fake pod create-command JSON"),
            ))
        }
        [pod, inspect, format, template, name]
            if pod == "pod"
                && inspect == "inspect"
                && format == "--format"
                && template == "{{.CgroupPath}}"
                && !name.is_empty() =>
        {
            Some(CommandOutput::success(
                b"/automata-runner.service/automata-job-services.slice\n".to_vec(),
            ))
        }
        [pod, inspect, format, template, name]
            if pod == "pod"
                && inspect == "inspect"
                && format == "--format"
                && template == "{{.InfraContainerID}}"
                && resource(state, "pod", name).is_some() =>
        {
            Some(CommandOutput::success(format!("{FAKE_INFRA_ID}\n").into_bytes()))
        }
        [container, inspect, format, template, identifier]
            if container == "container"
                && inspect == "inspect"
                && format == "--format"
                && template
                    == "{{ index .HostConfig.Sysctls \"net.ipv4.ip_unprivileged_port_start\" }}"
                && identifier == FAKE_INFRA_ID =>
        {
            Some(CommandOutput::success(b"0\n".to_vec()))
        }
        [container, inspect, format, template, name]
            if container == "container"
                && inspect == "inspect"
                && format == "--format"
                && template
                    == "{{.ImageName}}\n{{.Pod}}\n{{json .Config.Entrypoint}}\n{{json .Config.Cmd}}" =>
        {
            Some(container_resource(state, name).map_or_else(
                || CommandOutput::failure(1, Vec::new()),
                |resource| {
                    CommandOutput::success(
                        format!(
                            "{}\n{}\n{}\n{}\n",
                            resource.image_name,
                            resource.network_mode,
                            serde_json::to_string(&resource.entrypoint)
                                .expect("fake entrypoint JSON"),
                            serde_json::to_string(&resource.command).expect("fake command JSON")
                        )
                        .into_bytes(),
                    )
                },
            ))
        }
        [container, inspect, format, template, name]
            if container == "container"
                && inspect == "inspect"
                && format == "--format"
                && template == "{{.Pod}}" =>
        {
            Some(container_resource(state, name).map_or_else(
                || CommandOutput::failure(1, Vec::new()),
                |resource| {
                    CommandOutput::success(format!("{}\n", resource.network_mode).into_bytes())
                },
            ))
        }
        [container, inspect, format, template, name]
            if container == "container"
                && inspect == "inspect"
                && format == "--format"
                && template.starts_with("{{with index .NetworkSettings.Networks \"")
                && template.ends_with("\"}}{{.IPAddress}}{{end}}") =>
        {
            Some(container_resource(state, name).map_or_else(
                || CommandOutput::failure(1, Vec::new()),
                |resource| {
                    resource.network_address.as_ref().map_or_else(
                        || CommandOutput::success(Vec::new()),
                        |address| CommandOutput::success(format!("{address}\n").into_bytes()),
                    )
                },
            ))
        }
        [logs, name] if logs == "logs" => Some(state.port_output.clone().unwrap_or_else(|| {
            container_resource(state, name).map_or_else(
                || CommandOutput::failure(1, Vec::new()),
                |resource| CommandOutput::success(resource.logs.clone()),
            )
        })),
        [container, inspect, format, template, name]
            if container == "container"
                && inspect == "inspect"
                && format == "--format"
                && template
                    == "{{.State.Status}}\n{{if .Config.Healthcheck}}configured{{else}}none{{end}}\n{{if .State.Health}}{{.State.Health.Status}}{{else}}none{{end}}"
                && !name.is_empty() =>
        {
            Some(container_resource(state, name).map_or_else(
                || CommandOutput::failure(1, Vec::new()),
                |resource| {
                    CommandOutput::success(
                        format!(
                            "{}\n{}\n{}\n",
                            resource.state.as_deref().unwrap_or("unknown"),
                            if resource.health_configured {
                                "configured"
                            } else {
                                "none"
                            },
                            resource.health.as_deref().unwrap_or("none")
                        )
                        .into_bytes(),
                    )
                },
            ))
        }
        [kind, action, name] if action == "exists" => Some(exists_output(
            resource(state, kind, name).is_some() && !name.is_empty(),
        )),
        [kind, action, rest @ ..] if action == "inspect" => {
            let name = rest.last().map(String::as_str).unwrap_or_default();
            Some(if name.is_empty() {
                CommandOutput::failure(125, Vec::new())
            } else {
                resource(state, kind, name).map_or_else(
                    || CommandOutput::failure(1, Vec::new()),
                    |resource| {
                        let mut bytes = inspect_bytes(resource);
                        if rest.iter().any(|value| {
                            value.starts_with("{{.ID}}\n{{.Name}}\n")
                                || value.starts_with("{{.Id}}\n{{.Name}}\n")
                        }) {
                            bytes = format!(
                                "{}\n{}\n{}",
                                resource.identifier,
                                resource.name,
                                String::from_utf8_lossy(&bytes)
                            )
                            .into_bytes();
                        } else if kind == "container"
                            && rest.iter().any(|value| value.ends_with("\n{{.Id}}"))
                        {
                            bytes.extend_from_slice(resource.identifier.as_bytes());
                            bytes.push(b'\n');
                        }
                        CommandOutput::success(bytes)
                    },
                )
            })
        }
        [action, name, port] if action == "port" => {
            Some(state.port_output.clone().unwrap_or_else(|| {
                state
                    .containers
                    .values()
                    .find(|resource| resource.identifier == *name)
                    .or_else(|| state.containers.get(name))
                    .and_then(|resource| resource.ports.get(port))
                    .map_or_else(
                        || CommandOutput::failure(1, Vec::new()),
                        |host| CommandOutput::success(format!("127.0.0.1:{host}\n").into_bytes()),
                    )
            }))
        }
        _ => None,
    }
}

fn execute_fake_lifecycle(state: &mut FakeState, command: &[String]) -> Option<CommandOutput> {
    let output = match command {
        [healthcheck, run, token] if healthcheck == "healthcheck" && run == "run" => {
            let Some(name) = container_name(state, token) else {
                return Some(CommandOutput::failure(1, Vec::new()));
            };
            let keep_starting = state.keep_health_starting;
            let Some(container) = state.containers.get_mut(&name) else {
                return Some(CommandOutput::failure(1, Vec::new()));
            };
            if !container.health_configured {
                CommandOutput::failure(125, Vec::new())
            } else if keep_starting {
                CommandOutput::failure(1, b"unhealthy\n".to_vec())
            } else {
                container.health = Some("healthy".to_owned());
                CommandOutput::success(b"healthy\n".to_vec())
            }
        }
        [kind, action, rest @ ..] if action == "create" && kind == "network" => {
            let mut resource = new_resource(rest, None);
            state.next_container_id = state.next_container_id.saturating_add(1);
            resource.identifier = format!("{:064x}", state.next_container_id);
            resource.name = rest.last().cloned().unwrap_or_default();
            state.network = Some(resource);
            CommandOutput::success(Vec::new())
        }
        [kind, action, rest @ ..] if action == "create" && kind == "pod" => {
            let mut resource = new_resource(rest, None);
            state.next_container_id = state.next_container_id.saturating_add(1);
            resource.identifier = format!("{:064x}", state.next_container_id);
            state.pod = Some(resource);
            CommandOutput::success(Vec::new())
        }
        [action, rest @ ..] if action == "create" => create_fake_container(state, rest),
        [action, rest @ ..] if action == "start" => {
            let token = rest.last().map(String::as_str).unwrap_or_default();
            let Some(name) = container_name(state, token) else {
                return Some(CommandOutput::failure(1, Vec::new()));
            };
            let Some(container) = state.containers.get_mut(&name) else {
                return Some(CommandOutput::failure(1, Vec::new()));
            };
            container.state = Some("running".to_owned());
            if !state.keep_health_starting
                && !state.require_active_healthcheck
                && container.health.as_deref() == Some("starting")
            {
                container.health = Some("healthy".to_owned());
            }
            CommandOutput::success(Vec::new())
        }
        [kind, action, ..] if kind == "pod" && action == "stop" => {
            for container in state.containers.values_mut() {
                container.state = Some("exited".to_owned());
            }
            CommandOutput::success(Vec::new())
        }
        [kind, action, ..] if action == "rm" && kind == "network" => {
            if std::mem::take(&mut state.replace_network_before_remove) {
                let name = state
                    .network
                    .as_ref()
                    .map(|resource| resource.name.clone())
                    .unwrap_or_default();
                state.network = Some(Resource {
                    identifier: "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
                        .to_owned(),
                    name,
                    ..Resource::default()
                });
            } else {
                state.network = None;
            }
            CommandOutput::success(Vec::new())
        }
        [kind, action, ..] if action == "rm" && kind == "pod" => {
            state.pod = None;
            CommandOutput::success(Vec::new())
        }
        [action, ..] if action == "rm" => {
            let token = command.last().map(String::as_str).unwrap_or_default();
            if let Some(name) = container_name(state, token) {
                state.containers.remove(&name);
            }
            CommandOutput::success(Vec::new())
        }
        [action, ..] if action == "kill" => {
            let token = command.last().map(String::as_str).unwrap_or_default();
            let Some(name) = container_name(state, token) else {
                return Some(CommandOutput::failure(1, Vec::new()));
            };
            let Some(container) = state.containers.get_mut(&name) else {
                return Some(CommandOutput::failure(1, Vec::new()));
            };
            container.state = Some("exited".to_owned());
            CommandOutput::success(Vec::new())
        }
        _ => return None,
    };
    Some(output)
}

#[allow(clippy::too_many_lines)]
fn create_fake_container(state: &mut FakeState, arguments: &[String]) -> CommandOutput {
    let Some(name) = option_value(arguments, "--name") else {
        return CommandOutput::failure(125, Vec::new());
    };
    let mut resource = new_resource(arguments, Some("created"));
    state.next_container_id = state.next_container_id.saturating_add(1);
    resource.identifier = format!("{:064x}", state.next_container_id);
    if let Some(pod) = option_value(arguments, "--pod") {
        resource.network_mode = state
            .pod
            .as_ref()
            .filter(|resource| resource.name == pod || resource.identifier == pod)
            .map_or_else(|| pod.to_owned(), |resource| resource.identifier.clone());
    } else {
        option_value(arguments, "--network")
            .unwrap_or_default()
            .clone_into(&mut resource.network_mode);
    }
    resource.entrypoint = option_value(arguments, "--entrypoint")
        .map(|value| vec![value.to_owned()])
        .unwrap_or_default();
    resource.image_name = arguments
        .iter()
        .find(|value| value.contains("@sha256:"))
        .cloned()
        .unwrap_or_default();
    if arguments.iter().any(|value| value == "--network-alias") {
        state.next_service_address = state.next_service_address.max(10).saturating_add(1);
        resource.network_address = Some(format!("10.89.0.{}", state.next_service_address));
    }
    if let Some(command_index) = arguments.iter().position(|value| value == "serve-v1") {
        resource.command = arguments[command_index..].to_vec();
        resource.image_name = arguments
            .get(command_index.wrapping_sub(1))
            .cloned()
            .unwrap_or_default();
        let mut ports = Vec::new();
        for mapping in &arguments[command_index + 1..] {
            let mut fields = mapping.split('|');
            let _protocol = fields.next();
            let _address = fields.next();
            let _target = fields.next();
            let Some(listen) = fields.next().and_then(|value| value.parse::<u16>().ok()) else {
                return CommandOutput::failure(125, Vec::new());
            };
            if fields.next().is_some() {
                return CommandOutput::failure(125, Vec::new());
            }
            let listen = if listen == 0 {
                state.next_host_port = state.next_host_port.max(40_000).saturating_add(1);
                state.next_host_port
            } else {
                listen
            };
            if ports.contains(&listen) {
                return CommandOutput::failure(125, Vec::new());
            }
            ports.push(listen);
        }
        resource.logs = format!(
            "{{\"version\":1,\"ports\":[{}]}}\n",
            ports
                .iter()
                .map(u16::to_string)
                .collect::<Vec<_>>()
                .join(",")
        )
        .into_bytes();
    }
    if arguments.iter().any(|value| value == "--health-cmd") && !state.omit_health_configuration {
        resource.health_configured = true;
        resource.health = Some("starting".to_owned());
        let command = if std::mem::take(&mut state.drift_health_configuration_once) {
            "drifted"
        } else {
            option_value(arguments, "--health-cmd").unwrap_or_default()
        };
        let interval = fake_duration_nanos(option_value(arguments, "--health-interval"));
        let timeout = fake_duration_nanos(option_value(arguments, "--health-timeout"));
        let start_period = fake_duration_nanos(option_value(arguments, "--health-start-period"));
        let retries = option_value(arguments, "--health-retries")
            .and_then(|value| value.parse::<u64>().ok())
            .unwrap_or_default();
        resource.health_configuration = serde_json::to_vec(&serde_json::json!({
            "Test": ["CMD-SHELL", command],
            "Interval": interval,
            "Timeout": timeout,
            "StartPeriod": start_period,
            "Retries": retries,
        }))
        .expect("fake health JSON");
        resource.health_configuration.push(b'\n');
    }
    for published in option_values(arguments, "--publish") {
        let Some(requested) = published.strip_prefix("127.0.0.1::") else {
            return CommandOutput::failure(125, Vec::new());
        };
        state.next_host_port = state.next_host_port.max(40_000).saturating_add(1);
        resource
            .ports
            .insert(requested.to_owned(), state.next_host_port);
    }
    let identifier = resource.identifier.clone();
    state.containers.insert(name.to_owned(), resource);
    let is_service = arguments.iter().any(|value| value == "--network-alias");
    let is_proxy = arguments.iter().any(|value| value == "serve-v1");
    if is_service && std::mem::take(&mut state.wrong_service_identifier_once) {
        CommandOutput::success(
            b"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc\n".to_vec(),
        )
    } else if is_proxy && std::mem::take(&mut state.wrong_proxy_identifier_once) {
        CommandOutput::success(
            b"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\n".to_vec(),
        )
    } else if is_service && std::mem::take(&mut state.malformed_service_identifier_once) {
        CommandOutput::success(b"malformed\n".to_vec())
    } else {
        CommandOutput::success(format!("{identifier}\n").into_bytes())
    }
}

fn execute_fake_copy(
    state: &mut FakeState,
    source: &str,
    destination: &str,
    stdin: Option<&[u8]>,
) -> CommandOutput {
    if source == "-" && destination.contains(':') {
        return stdin.and_then(test_tar_payload).map_or_else(
            || CommandOutput::failure(125, Vec::new()),
            |content| {
                state.copied_to = Some(content);
                CommandOutput::success(Vec::new())
            },
        );
    }
    if destination != "-" || !source.contains(':') || stdin.is_some() {
        return CommandOutput::failure(125, Vec::new());
    }
    let name = source
        .rsplit_once('/')
        .map(|(_, name)| name)
        .unwrap_or_default();
    let archive = state
        .copy_archive
        .take()
        .unwrap_or_else(|| test_single_file_tar(name, &state.copy_from));
    CommandOutput::success(archive)
}

const TEST_TAR_BLOCK_BYTES: usize = 512;

pub(crate) fn test_single_file_tar(name: &str, content: &[u8]) -> Vec<u8> {
    let padded = content.len().div_ceil(TEST_TAR_BLOCK_BYTES) * TEST_TAR_BLOCK_BYTES;
    let mut archive = vec![0_u8; TEST_TAR_BLOCK_BYTES + padded + 2 * TEST_TAR_BLOCK_BYTES];
    archive[..name.len()].copy_from_slice(name.as_bytes());
    test_write_octal(&mut archive[100..108], 0o600);
    test_write_octal(&mut archive[108..116], 0);
    test_write_octal(&mut archive[116..124], 0);
    test_write_octal(&mut archive[124..136], content.len());
    test_write_octal(&mut archive[136..148], 0);
    archive[148..156].fill(b' ');
    archive[156] = b'0';
    archive[257..263].copy_from_slice(b"ustar\0");
    archive[263..265].copy_from_slice(b"00");
    test_write_octal(&mut archive[329..337], 0);
    test_write_octal(&mut archive[337..345], 0);
    test_write_checksum(&mut archive[..TEST_TAR_BLOCK_BYTES]);
    archive[TEST_TAR_BLOCK_BYTES..TEST_TAR_BLOCK_BYTES + content.len()].copy_from_slice(content);
    archive
}

fn test_tar_payload(archive: &[u8]) -> Option<Vec<u8>> {
    let header = archive.get(..TEST_TAR_BLOCK_BYTES)?;
    if header.get(156).copied() != Some(b'0') || header.get(257..263) != Some(b"ustar\0".as_slice())
    {
        return None;
    }
    let size = test_parse_octal(header.get(124..136)?)?;
    let padded = size.div_ceil(TEST_TAR_BLOCK_BYTES) * TEST_TAR_BLOCK_BYTES;
    let content_end = TEST_TAR_BLOCK_BYTES.checked_add(size)?;
    let expected = TEST_TAR_BLOCK_BYTES
        .checked_add(padded)?
        .checked_add(2 * TEST_TAR_BLOCK_BYTES)?;
    (archive.len() == expected).then(|| archive[TEST_TAR_BLOCK_BYTES..content_end].to_vec())
}

fn test_write_octal(field: &mut [u8], value: usize) {
    let (terminator, digits) = field.split_last_mut().expect("tar numeric field");
    *terminator = 0;
    digits.fill(b'0');
    let mut remaining = value;
    for digit in digits.iter_mut().rev() {
        *digit = b'0' + u8::try_from(remaining % 8).expect("octal digit");
        remaining /= 8;
    }
    assert_eq!(remaining, 0);
}

fn test_parse_octal(field: &[u8]) -> Option<usize> {
    let (terminator, digits) = field.split_last()?;
    (*terminator == 0).then_some(())?;
    digits.iter().try_fold(0_usize, |value, byte| {
        let digit = byte.checked_sub(b'0').filter(|digit| *digit < 8)?;
        value.checked_mul(8)?.checked_add(usize::from(digit))
    })
}

fn test_write_checksum(header: &mut [u8]) {
    let checksum = header.iter().map(|byte| usize::from(*byte)).sum::<usize>();
    let field = &mut header[148..156];
    field.fill(b'0');
    field[6] = 0;
    field[7] = b' ';
    let mut remaining = checksum;
    for digit in field[..6].iter_mut().rev() {
        *digit = b'0' + u8::try_from(remaining % 8).expect("checksum digit");
        remaining /= 8;
    }
    assert_eq!(remaining, 0);
}

fn resource<'a>(state: &'a FakeState, kind: &str, name: &str) -> Option<&'a Resource> {
    match kind {
        "network" => state
            .network
            .as_ref()
            .filter(|resource| resource.name == name || resource.identifier == name),
        "pod" => state
            .pod
            .as_ref()
            .filter(|resource| resource.name == name || resource.identifier == name),
        "container" => container_resource(state, name),
        _ => None,
    }
}

fn container_resource<'a>(state: &'a FakeState, token: &str) -> Option<&'a Resource> {
    state.containers.get(token).or_else(|| {
        state
            .containers
            .values()
            .find(|value| value.identifier == token)
    })
}

fn container_name(state: &FakeState, token: &str) -> Option<String> {
    if state.containers.contains_key(token) {
        return Some(token.to_owned());
    }
    state
        .containers
        .iter()
        .find_map(|(name, resource)| (resource.identifier == token).then(|| name.clone()))
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
        identifier: String::new(),
        name: option_value(arguments, "--name")
            .unwrap_or_default()
            .to_owned(),
        image_name: String::new(),
        network_mode: String::new(),
        entrypoint: Vec::new(),
        command: Vec::new(),
        network_address: None,
        logs: Vec::new(),
        labels,
        state: state.map(str::to_owned),
        health_configured: false,
        health_configuration: Vec::new(),
        health: None,
        ports: BTreeMap::new(),
    }
}

fn fake_duration_nanos(value: Option<&str>) -> u64 {
    value
        .and_then(|value| value.strip_suffix("ns"))
        .and_then(|value| value.parse::<u64>().ok())
        .unwrap_or_default()
}

fn option_value<'a>(arguments: &'a [String], option: &str) -> Option<&'a str> {
    arguments
        .windows(2)
        .find(|window| window[0] == option)
        .map(|window| window[1].as_str())
}

fn option_values<'a>(arguments: &'a [String], option: &'a str) -> impl Iterator<Item = &'a str> {
    arguments
        .windows(2)
        .filter(move |window| window[0] == option)
        .map(|window| window[1].as_str())
}

fn inspect_bytes(resource: &Resource) -> Vec<u8> {
    let mut values = [
        OWNER,
        RESOURCE_SCHEMA,
        SANDBOX,
        GENERATION,
        PROFILE,
        PROFILE_DIGEST,
        SPEC,
        CUSTODY_KIND,
        CUSTODY_RUNNER,
        CUSTODY_SLOT,
    ]
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
        let configured = configure(options(scratch.path()));
        Self::open_with_scratch(scratch, configured)
    }

    pub(crate) fn new_with_service_proxy(label: &str) -> Self {
        Self::new_with_service_proxy_options(label, std::convert::identity)
    }

    pub(crate) fn new_with_service_proxy_options(
        label: &str,
        configure: impl FnOnce(PodmanOptions) -> PodmanOptions,
    ) -> Self {
        let scratch = ScratchRoot::new(label);
        let configured = configure(options_with_service_proxy(scratch.path()));
        Self::open_with_scratch(scratch, configured)
    }

    fn open_with_scratch(scratch: ScratchRoot, configured: PodmanOptions) -> Self {
        let fake = Arc::new(FakePodman::default());
        let provider = RootlessPodmanProvider::open_with_executor(
            configured,
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
    let runtime = root.as_path().join("runtime");
    fs::create_dir_all(&runtime).expect("create rootless runtime directory");
    fs::set_permissions(&runtime, fs::Permissions::from_mode(0o700))
        .expect("make rootless runtime directory private");
    let environment = PodmanProcessEnvironment::new(
        root.as_path(),
        runtime,
        root.as_path(),
        root.as_path().join("private/usr/sbin"),
        "/usr/bin/true",
        "/usr/bin/true",
        "/usr/bin/true",
        "/usr/bin/true",
    )
    .expect("process environment");
    PodmanOptions::new(binary, root, environment).expect("coherent Podman options")
}

pub(crate) fn options_with_service_proxy(root: &Path) -> PodmanOptions {
    options(root).with_service_proxy_image(synthetic_service_proxy_image())
}

pub(crate) fn synthetic_buildkit_image() -> ImmutableImage {
    ImmutableImage::new(format!(
        "registry.example.invalid/buildkit/runtime@sha256:{}",
        "66".repeat(32)
    ))
    .expect("synthetic immutable BuildKit image")
}

fn synthetic_service_proxy_image() -> ImmutableImage {
    ImmutableImage::new(format!(
        "registry.example.invalid/automata/service-proxy@sha256:{}",
        "55".repeat(32)
    ))
    .expect("synthetic immutable service-proxy image")
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
        SandboxCustody::ProfileAdmission {
            runner_id: RunnerId::new(),
        },
        profile,
        TargetPath::posix("/__w").expect("workspace"),
        network,
        RootFilesystemPolicy::ReadOnly,
        ResourceLimits::new(512 * 1024 * 1024, 2_000, 512).expect("resources"),
    )
}
