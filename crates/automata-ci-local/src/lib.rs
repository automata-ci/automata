//! Cross-platform boundary for disposable local Automata installations.
//!
//! The crate owns Docker Engine discovery and exact local workflow inspection
//! without depending on the product CLI. Lifecycle mutation is added in
//! separately reviewed slices; [`inspect`] and [`check_workflow`] are read-only
//! and create no engine resources, admission records, or host state.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

use std::{collections::BTreeMap, fmt, io, process::Stdio, time::Duration};

use serde::{Deserialize, Serialize, de::DeserializeOwned};
use tokio::{
    io::{AsyncRead, AsyncReadExt as _},
    process::{Child, Command as ProcessCommand},
    time::timeout,
};

mod check;
mod engine;
mod installation;
#[cfg(unix)]
mod local_docker;
#[cfg(unix)]
mod snapshot;
#[cfg(not(unix))]
#[path = "snapshot_unsupported.rs"]
mod snapshot;
mod snapshot_limits;

pub use check::{
    LocalCheckDiagnostic, LocalCheckIssue, LocalCheckIssueCode, LocalCheckReport,
    LocalCheckRequest, LocalCheckSource, LocalCheckedJob, LocalCheckedWorkflow, check_workflow,
};
pub use engine::{LocalEngineError, LocalEngineErrorCode};
pub use installation::{
    ComposeProjectName, Installation, InstallationId, InstallationIdError, InstallationName,
    InstallationNameError, InstallationSelectorKey,
};
#[cfg(unix)]
pub use local_docker::LocalDockerProvider;

/// Reserved in-container directory used by the fixed-relay Docker provider's protected client.
pub const LOCAL_DOCKER_CONTROL_DIRECTORY: &str = automata_ci_sandbox_guest::LOCAL_CONTROL_DIRECTORY;

/// Smallest whole-job memory limit accepted by the fixed-relay Docker provider.
pub const MINIMUM_LOCAL_DOCKER_SANDBOX_MEMORY_BYTES: u64 = 256 * 1_024 * 1_024;
/// Smallest CPU quota accepted by the fixed-relay Docker provider, in millicores.
pub const MINIMUM_LOCAL_DOCKER_SANDBOX_CPU_MILLIS: u32 = 1_000;
/// Smallest process limit that can contain PID 1, the protected client, and one workload process.
pub const MINIMUM_LOCAL_DOCKER_SANDBOX_PIDS: u32 = 3;

const COMMAND_TIMEOUT: Duration = Duration::from_secs(5);
const COMMAND_TERMINATION_TIMEOUT: Duration = Duration::from_secs(1);
const MAX_COMMAND_STREAM_BYTES: usize = 64 * 1024;
const MAX_DOCKER_CONTEXT_NAME_BYTES: usize = 128;
const MAX_DOCKER_ENDPOINT_BYTES: usize = 4096;
const MIN_DOCKER_API: ApiVersion = ApiVersion {
    major: 1,
    minor: 44,
};
const MIN_COMPOSE_VERSION: (u64, u64, u64) = (2, 20, 0);

/// Container engine requested by a local-installation operation.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EngineRequest {
    /// Select the portable Docker Engine path.
    #[default]
    Auto,
    /// Require Docker Engine and the Docker Compose CLI plugin.
    Docker,
}

/// Read-only host inspection request.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DoctorRequest {
    engine: EngineRequest,
}

impl DoctorRequest {
    /// Creates a request for one container-engine selection.
    pub const fn new(engine: EngineRequest) -> Self {
        Self { engine }
    }
}

/// Inspects the local host without creating state or containers.
pub async fn inspect(request: DoctorRequest) -> DoctorReport {
    let context = capture_docker(
        DoctorProbe::DockerContext,
        &["context", "inspect", "--format", "{{json .}}"],
    )
    .await;
    let endpoint = validated_context_output(&context, std::env::consts::OS);
    let compose_arguments = ["compose", "version", "--format", "json"];
    let (version, info, compose) = if let Some(endpoint) = endpoint.as_ref() {
        let version_arguments = [
            "--host",
            endpoint.host.as_str(),
            "version",
            "--format",
            "json",
        ];
        let info_arguments = ["--host", endpoint.host.as_str(), "info", "--format", "json"];
        tokio::join!(
            capture_docker(DoctorProbe::DockerVersion, &version_arguments),
            capture_docker(DoctorProbe::DockerInfo, &info_arguments),
            capture_docker(DoctorProbe::DockerCompose, &compose_arguments),
        )
    } else {
        let compose = capture_docker(DoctorProbe::DockerCompose, &compose_arguments).await;
        (ProbeOutput::Skipped, ProbeOutput::Skipped, compose)
    };
    let probes = ProbeSet {
        context,
        version,
        info,
        compose,
    };
    build_report(
        &request,
        std::env::consts::OS,
        std::env::consts::ARCH,
        process_is_root(),
        std::env::var_os("DOCKER_API_VERSION").is_some(),
        &probes,
    )
}

/// Schema-versioned local preflight result.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct DoctorReport {
    schema: u32,
    ready: bool,
    platform: Platform,
    requested_engine: EngineRequest,
    selected_engine: Option<EngineSelection>,
    issues: Vec<DoctorIssue>,
}

impl DoctorReport {
    /// Returns whether every mandatory preflight check passed.
    pub const fn ready(&self) -> bool {
        self.ready
    }

    /// Returns the compiled host operating-system identity.
    pub fn operating_system(&self) -> &str {
        &self.platform.operating_system
    }

    /// Returns the compiled host architecture identity.
    pub fn architecture(&self) -> &str {
        &self.platform.architecture
    }

    /// Returns the validated engine and Compose selection, when available.
    pub const fn selected_engine(&self) -> Option<&EngineSelection> {
        self.selected_engine.as_ref()
    }

    /// Returns every typed preflight issue in deterministic probe order.
    pub fn issues(&self) -> &[DoctorIssue] {
        &self.issues
    }
}

/// Docker probe that owns one preflight issue.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DoctorProbe {
    /// Host process identity.
    ProcessIdentity,
    /// Initially qualified host operating-system and architecture tuple.
    HostPlatform,
    /// Docker context and endpoint inspection.
    DockerContext,
    /// Docker client/server version inspection.
    DockerVersion,
    /// Docker Engine information inspection.
    DockerInfo,
    /// Docker Compose CLI plugin inspection.
    DockerCompose,
}

/// Stable reason code for one failed preflight check.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DoctorIssueCode {
    /// A Unix root process attempted to use the local lifecycle.
    RootProcess,
    /// The Docker command was not found on `PATH`.
    CommandNotFound,
    /// A Docker probe exceeded its deadline.
    CommandTimedOut,
    /// A Docker probe could not start, read, or exit successfully.
    CommandFailed,
    /// A Docker probe emitted more than the bounded output allowance.
    CommandOutputTooLarge,
    /// A Docker probe did not return its required JSON shape.
    MalformedProbeResponse,
    /// `DOCKER_API_VERSION` disabled normal client/server API negotiation.
    DockerApiOverride,
    /// The host operating-system and architecture tuple is not initially qualified.
    UnsupportedHostPlatform,
    /// The selected Docker context could not be inspected.
    DockerContextUnavailable,
    /// The selected Docker daemon was stopped, inaccessible, or otherwise unavailable.
    DockerDaemonUnavailable,
    /// The Docker Compose CLI plugin was absent or could not run.
    DockerComposeUnavailable,
    /// The selected context was not a supported local socket endpoint.
    UntrustedDockerEndpoint,
    /// The server did not identify as Docker Engine.
    NonDockerEngine,
    /// The selected Docker Engine was not in Linux-container mode.
    NonLinuxEngine,
    /// The engine architecture is not supported or differs from the host.
    UnsupportedEngineArchitecture,
    /// The engine cannot negotiate the minimum supported Docker API.
    UnsupportedDockerApi,
    /// The engine did not expose one stable non-secret identity.
    MissingEngineIdentity,
    /// Independently reported engine facts did not agree.
    EngineIdentityMismatch,
    /// The engine lacks a local volume or bridge-network capability.
    MissingEngineCapability,
    /// The Compose plugin version is malformed or below the tested floor.
    UnsupportedComposeVersion,
}

impl DoctorIssueCode {
    /// Returns one static, non-sensitive remediation message.
    pub const fn message(self) -> &'static str {
        match self {
            Self::RootProcess => "run the local lifecycle as an ordinary Unix user",
            Self::CommandNotFound => "install the Docker CLI and make it available on PATH",
            Self::CommandTimedOut => "the Docker probe timed out",
            Self::CommandFailed => "the Docker probe failed",
            Self::CommandOutputTooLarge => "the Docker probe exceeded its output limit",
            Self::MalformedProbeResponse => "the Docker probe returned an unsupported JSON shape",
            Self::DockerApiOverride => "unset DOCKER_API_VERSION so API negotiation is reliable",
            Self::UnsupportedHostPlatform => {
                "the initial local install supports x86-64 Linux, Apple Silicon macOS, and x86-64 Windows"
            }
            Self::DockerContextUnavailable => {
                "select a valid local Docker context and retry the inspection"
            }
            Self::DockerDaemonUnavailable => {
                "start Docker Engine and allow this user to access its local socket"
            }
            Self::DockerComposeUnavailable => {
                "install Docker Compose CLI plugin version 2.20.0 or newer"
            }
            Self::UntrustedDockerEndpoint => {
                "select a local Unix socket or Windows named-pipe Docker context"
            }
            Self::NonDockerEngine => "the selected endpoint is not a supported Docker Engine",
            Self::NonLinuxEngine => "switch Docker Desktop to Linux-container mode",
            Self::UnsupportedEngineArchitecture => {
                "use a native amd64 or arm64 Linux Docker Engine"
            }
            Self::UnsupportedDockerApi => "upgrade Docker Engine to a supported API version",
            Self::MissingEngineIdentity => "the Docker Engine did not report a stable identity",
            Self::EngineIdentityMismatch => "Docker version and info responses disagree",
            Self::MissingEngineCapability => {
                "the Docker Engine requires local volumes and bridge networks"
            }
            Self::UnsupportedComposeVersion => {
                "install Docker Compose plugin version 2.20.0 or newer"
            }
        }
    }
}

/// One typed and probe-scoped preflight issue.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub struct DoctorIssue {
    probe: DoctorProbe,
    code: DoctorIssueCode,
    message: &'static str,
}

impl DoctorIssue {
    const fn new(probe: DoctorProbe, code: DoctorIssueCode) -> Self {
        Self {
            probe,
            code,
            message: code.message(),
        }
    }

    /// Returns the probe that produced this issue.
    pub const fn probe(self) -> DoctorProbe {
        self.probe
    }

    /// Returns the stable machine-readable reason code.
    pub const fn code(self) -> DoctorIssueCode {
        self.code
    }

    /// Returns one static, non-sensitive remediation message.
    pub const fn message(self) -> &'static str {
        self.message
    }
}

impl DoctorProbe {
    const fn sort_key(self) -> u8 {
        match self {
            Self::ProcessIdentity => 0,
            Self::HostPlatform => 1,
            Self::DockerContext => 2,
            Self::DockerVersion => 3,
            Self::DockerInfo => 4,
            Self::DockerCompose => 5,
        }
    }
}

/// Container engine selected by the preflight.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Engine {
    /// Docker Engine.
    Docker,
}

/// Compose frontend selected for lifecycle commands.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ComposeFrontend {
    /// The `docker compose` CLI plugin.
    DockerPlugin,
}

/// Supported local Docker endpoint class.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EngineEndpoint {
    /// Local Unix-domain socket used on Linux and macOS.
    UnixSocket,
    /// Local Windows named pipe.
    WindowsNamedPipe,
}

#[derive(Clone, Eq, PartialEq)]
pub(crate) struct DockerConnection {
    context_name: String,
    host: String,
    endpoint: EngineEndpoint,
}

impl fmt::Debug for DockerConnection {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DockerConnection")
            .field("context_name", &self.context_name)
            .field("endpoint", &self.endpoint)
            .field("host", &"<validated-local-endpoint>")
            .finish()
    }
}

/// Supported Linux engine architecture.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EngineArchitecture {
    /// AMD64/x86-64.
    Amd64,
    /// ARM64/AArch64.
    Arm64,
}

/// Exact validated engine/frontend pair selected for an installation.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct EngineSelection {
    engine: Engine,
    compose: ComposeFrontend,
    context_name: String,
    endpoint: EngineEndpoint,
    engine_id: String,
    server_version: String,
    api_version: String,
    architecture: EngineArchitecture,
    compose_version: String,
}

impl EngineSelection {
    /// Returns the selected container engine.
    pub const fn engine(&self) -> Engine {
        self.engine
    }

    /// Returns the selected Compose frontend.
    pub const fn compose(&self) -> ComposeFrontend {
        self.compose
    }

    /// Returns the exact Docker context name observed during preflight.
    pub fn context_name(&self) -> &str {
        &self.context_name
    }

    /// Returns the validated local endpoint class.
    pub const fn endpoint(&self) -> EngineEndpoint {
        self.endpoint
    }

    /// Returns the exact non-secret engine identity.
    pub fn engine_id(&self) -> &str {
        &self.engine_id
    }

    /// Returns the exact Docker Engine version.
    pub fn server_version(&self) -> &str {
        &self.server_version
    }

    /// Returns the exact Docker API version selected for adapter requests.
    pub fn api_version(&self) -> &str {
        &self.api_version
    }

    /// Returns the normalized Linux engine architecture.
    pub const fn architecture(&self) -> EngineArchitecture {
        self.architecture
    }

    /// Returns the exact Docker Compose plugin version.
    pub fn compose_version(&self) -> &str {
        &self.compose_version
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
struct Platform {
    operating_system: String,
    architecture: String,
}

fn build_report(
    request: &DoctorRequest,
    operating_system: &str,
    host_architecture: &str,
    root_process: bool,
    docker_api_override: bool,
    probes: &ProbeSet,
) -> DoctorReport {
    let mut issues = Vec::new();
    if root_process {
        issues.push(DoctorIssue::new(
            DoctorProbe::ProcessIdentity,
            DoctorIssueCode::RootProcess,
        ));
    }
    if docker_api_override {
        issues.push(DoctorIssue::new(
            DoctorProbe::DockerVersion,
            DoctorIssueCode::DockerApiOverride,
        ));
    }
    if !initial_host_platform_is_supported(operating_system, host_architecture) {
        issues.push(DoctorIssue::new(
            DoctorProbe::HostPlatform,
            DoctorIssueCode::UnsupportedHostPlatform,
        ));
    }
    let selected_engine = evaluate_engine(operating_system, host_architecture, probes, &mut issues);
    issues.sort_by_key(|issue| issue.probe.sort_key());
    DoctorReport {
        schema: 3,
        ready: selected_engine.is_some() && issues.is_empty(),
        platform: Platform {
            operating_system: operating_system.to_owned(),
            architecture: host_architecture.to_owned(),
        },
        requested_engine: request.engine,
        selected_engine,
        issues,
    }
}

fn initial_host_platform_is_supported(operating_system: &str, architecture: &str) -> bool {
    matches!(
        (operating_system, normalize_architecture(architecture)),
        ("linux" | "windows", Some(EngineArchitecture::Amd64))
            | ("macos", Some(EngineArchitecture::Arm64))
    )
}

#[derive(Debug)]
struct ProbeSet {
    context: ProbeOutput,
    version: ProbeOutput,
    info: ProbeOutput,
    compose: ProbeOutput,
}

#[derive(Debug)]
enum ProbeOutput {
    Success(Vec<u8>),
    Failure(CommandFailure),
    Skipped,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CommandFailure {
    NotFound,
    TimedOut,
    Failed,
    OutputTooLarge,
    ContextUnavailable,
    DaemonUnavailable,
    ComposeUnavailable,
}

async fn capture_docker(probe: DoctorProbe, arguments: &[&str]) -> ProbeOutput {
    let mut command = ProcessCommand::new("docker");
    command
        .args(arguments)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    let (mut child, mut containment) = match spawn_contained(command) {
        Ok(spawned) => spawned,
        Err(failure) => return ProbeOutput::Failure(failure),
    };
    let Some(stdout) = child.stdout.take() else {
        terminate_process_tree(&mut child, &mut containment).await;
        return ProbeOutput::Failure(CommandFailure::Failed);
    };
    let Some(stderr) = child.stderr.take() else {
        terminate_process_tree(&mut child, &mut containment).await;
        return ProbeOutput::Failure(CommandFailure::Failed);
    };
    let captured = timeout(COMMAND_TIMEOUT, async {
        tokio::try_join!(
            read_bounded(stdout, MAX_COMMAND_STREAM_BYTES),
            read_bounded(stderr, MAX_COMMAND_STREAM_BYTES),
            async { child.wait().await.map_err(|_error| CaptureFailure::Io) }
        )
    })
    .await;
    let (stdout, stderr, status) = match captured {
        Ok(Ok(captured)) => captured,
        Ok(Err(CaptureFailure::OutputTooLarge)) => {
            terminate_process_tree(&mut child, &mut containment).await;
            return ProbeOutput::Failure(CommandFailure::OutputTooLarge);
        }
        Ok(Err(CaptureFailure::Io)) => {
            terminate_process_tree(&mut child, &mut containment).await;
            return ProbeOutput::Failure(CommandFailure::Failed);
        }
        Err(_) => {
            terminate_process_tree(&mut child, &mut containment).await;
            return ProbeOutput::Failure(CommandFailure::TimedOut);
        }
    };
    terminate_remaining_process_tree(&mut containment);
    drop(stderr);
    if !status.success() {
        return ProbeOutput::Failure(unavailable_failure(probe));
    }
    ProbeOutput::Success(stdout)
}

const fn unavailable_failure(probe: DoctorProbe) -> CommandFailure {
    match probe {
        DoctorProbe::DockerContext => CommandFailure::ContextUnavailable,
        DoctorProbe::DockerVersion | DoctorProbe::DockerInfo => CommandFailure::DaemonUnavailable,
        DoctorProbe::DockerCompose => CommandFailure::ComposeUnavailable,
        DoctorProbe::ProcessIdentity | DoctorProbe::HostPlatform => CommandFailure::Failed,
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CaptureFailure {
    Io,
    OutputTooLarge,
}

async fn read_bounded<R: AsyncRead + Unpin>(
    mut reader: R,
    maximum_bytes: usize,
) -> Result<Vec<u8>, CaptureFailure> {
    let mut bytes = Vec::with_capacity(maximum_bytes.min(4096));
    let mut chunk = [0_u8; 4096];
    loop {
        let count = reader
            .read(&mut chunk)
            .await
            .map_err(|_error| CaptureFailure::Io)?;
        if count == 0 {
            break;
        }
        let remaining = maximum_bytes.saturating_sub(bytes.len());
        if count > remaining {
            return Err(CaptureFailure::OutputTooLarge);
        }
        bytes.extend_from_slice(&chunk[..count]);
    }
    Ok(bytes)
}

#[cfg(unix)]
struct ProcessContainment {
    process_group: Option<u32>,
}

#[cfg(unix)]
impl Drop for ProcessContainment {
    fn drop(&mut self) {
        self.terminate_and_disarm();
    }
}

#[cfg(unix)]
impl ProcessContainment {
    fn signal(&self) {
        if let Some(process_group) = self.process_group {
            signal_process_group(process_group);
        }
    }

    fn terminate_and_disarm(&mut self) {
        if let Some(process_group) = self.process_group.take() {
            signal_process_group(process_group);
        }
    }
}

#[cfg(windows)]
struct ProcessContainment {
    group: processkit::ProcessGroup,
}

#[cfg(unix)]
fn spawn_contained(
    mut command: ProcessCommand,
) -> Result<(Child, ProcessContainment), CommandFailure> {
    command.process_group(0);
    let child = command.spawn().map_err(|error| {
        if error.kind() == io::ErrorKind::NotFound {
            CommandFailure::NotFound
        } else {
            CommandFailure::Failed
        }
    })?;
    let process_group = child.id().ok_or(CommandFailure::Failed)?;
    Ok((
        child,
        ProcessContainment {
            process_group: Some(process_group),
        },
    ))
}

#[cfg(windows)]
fn spawn_contained(command: ProcessCommand) -> Result<(Child, ProcessContainment), CommandFailure> {
    use std::error::Error as _;

    let group = processkit::ProcessGroup::new().map_err(|_error| CommandFailure::Failed)?;
    let child = group.spawn(command).map_err(|error| {
        let mut source = error.source();
        while let Some(current) = source {
            if current
                .downcast_ref::<io::Error>()
                .is_some_and(|error| error.kind() == io::ErrorKind::NotFound)
            {
                return CommandFailure::NotFound;
            }
            source = current.source();
        }
        CommandFailure::Failed
    })?;
    Ok((child, ProcessContainment { group }))
}

#[cfg(unix)]
async fn terminate_process_tree(child: &mut Child, containment: &mut ProcessContainment) {
    containment.signal();
    let _ignored = child.start_kill();
    let _ignored = timeout(COMMAND_TERMINATION_TIMEOUT, child.wait()).await;
    containment.terminate_and_disarm();
}

#[cfg(windows)]
async fn terminate_process_tree(child: &mut Child, containment: &mut ProcessContainment) {
    let _ignored = containment.group.kill_all();
    let _ignored = child.start_kill();
    let _ignored = timeout(COMMAND_TERMINATION_TIMEOUT, child.wait()).await;
    let _ignored = containment.group.kill_all();
}

#[cfg(unix)]
fn terminate_remaining_process_tree(containment: &mut ProcessContainment) {
    containment.terminate_and_disarm();
}

#[cfg(windows)]
fn terminate_remaining_process_tree(containment: &mut ProcessContainment) {
    let _ignored = containment.group.kill_all();
}

#[cfg(unix)]
fn signal_process_group(process_group: u32) {
    let Ok(raw_process_group) = i32::try_from(process_group) else {
        return;
    };
    let Some(process_group) = rustix::process::Pid::from_raw(raw_process_group) else {
        return;
    };
    let _ignored =
        rustix::process::kill_process_group(process_group, rustix::process::Signal::KILL);
}

fn evaluate_engine(
    operating_system: &str,
    host_architecture: &str,
    probes: &ProbeSet,
    issues: &mut Vec<DoctorIssue>,
) -> Option<EngineSelection> {
    if matches!(
        probes.context,
        ProbeOutput::Failure(CommandFailure::NotFound)
    ) {
        issues.push(DoctorIssue::new(
            DoctorProbe::DockerContext,
            DoctorIssueCode::CommandNotFound,
        ));
        return None;
    }

    let context: Option<DockerContextDocument> =
        parse_probe(DoctorProbe::DockerContext, &probes.context, issues);
    let version: Option<DockerVersionDocument> =
        parse_probe(DoctorProbe::DockerVersion, &probes.version, issues);
    let info: Option<DockerInfoDocument> =
        parse_probe(DoctorProbe::DockerInfo, &probes.info, issues);
    let compose: Option<DockerComposeDocument> =
        parse_probe(DoctorProbe::DockerCompose, &probes.compose, issues);

    let connection = context.as_ref().and_then(|context| {
        record_validation(
            DoctorProbe::DockerContext,
            validate_context(context, operating_system),
            issues,
        )
    });
    let version = version.as_ref().and_then(|version| {
        record_validation(
            DoctorProbe::DockerVersion,
            validate_version(version, host_architecture),
            issues,
        )
    });
    let compose_version = compose.as_ref().and_then(|compose| {
        record_validation(
            DoctorProbe::DockerCompose,
            validate_compose(compose),
            issues,
        )
    });
    let engine_id = info.as_ref().and_then(|info| {
        version.as_ref().and_then(|version| {
            record_validation(
                DoctorProbe::DockerInfo,
                validate_info(info, version),
                issues,
            )
        })
    });
    Some(EngineSelection {
        engine: Engine::Docker,
        compose: ComposeFrontend::DockerPlugin,
        context_name: connection.as_ref()?.context_name.clone(),
        endpoint: connection.as_ref()?.endpoint,
        engine_id: engine_id?,
        server_version: version.as_ref()?.server_version.clone(),
        api_version: version.as_ref()?.api_version.clone(),
        architecture: version.as_ref()?.architecture,
        compose_version: compose_version?,
    })
}

fn parse_probe<T: DeserializeOwned>(
    probe: DoctorProbe,
    output: &ProbeOutput,
    issues: &mut Vec<DoctorIssue>,
) -> Option<T> {
    let bytes = match output {
        ProbeOutput::Success(bytes) => bytes,
        ProbeOutput::Failure(failure) => {
            issues.push(DoctorIssue::new(probe, failure.issue_code()));
            return None;
        }
        ProbeOutput::Skipped => return None,
    };
    if let Ok(document) = serde_json::from_slice(bytes) {
        Some(document)
    } else {
        issues.push(DoctorIssue::new(
            probe,
            DoctorIssueCode::MalformedProbeResponse,
        ));
        None
    }
}

impl CommandFailure {
    const fn issue_code(self) -> DoctorIssueCode {
        match self {
            Self::NotFound => DoctorIssueCode::CommandNotFound,
            Self::TimedOut => DoctorIssueCode::CommandTimedOut,
            Self::Failed => DoctorIssueCode::CommandFailed,
            Self::OutputTooLarge => DoctorIssueCode::CommandOutputTooLarge,
            Self::ContextUnavailable => DoctorIssueCode::DockerContextUnavailable,
            Self::DaemonUnavailable => DoctorIssueCode::DockerDaemonUnavailable,
            Self::ComposeUnavailable => DoctorIssueCode::DockerComposeUnavailable,
        }
    }
}

fn record_validation<T>(
    probe: DoctorProbe,
    result: Result<T, DoctorIssueCode>,
    issues: &mut Vec<DoctorIssue>,
) -> Option<T> {
    match result {
        Ok(value) => Some(value),
        Err(code) => {
            issues.push(DoctorIssue::new(probe, code));
            None
        }
    }
}

#[derive(Debug, Default, Deserialize)]
struct DockerContextDocument {
    #[serde(default, rename = "Name")]
    name: String,
    #[serde(default, rename = "Endpoints")]
    endpoints: DockerContextEndpoints,
}

#[derive(Debug, Default, Deserialize)]
struct DockerContextEndpoints {
    #[serde(default)]
    docker: DockerContextEndpoint,
}

#[derive(Debug, Default, Deserialize)]
struct DockerContextEndpoint {
    #[serde(default, rename = "Host")]
    host: String,
    #[serde(default, rename = "SkipTLSVerify")]
    skip_tls_verify: bool,
}

fn validated_context_output(
    output: &ProbeOutput,
    operating_system: &str,
) -> Option<DockerConnection> {
    let ProbeOutput::Success(bytes) = output else {
        return None;
    };
    let document: DockerContextDocument = serde_json::from_slice(bytes).ok()?;
    validate_context(&document, operating_system).ok()
}

fn validate_context(
    context: &DockerContextDocument,
    operating_system: &str,
) -> Result<DockerConnection, DoctorIssueCode> {
    if !valid_context_name(&context.name)
        || context.endpoints.docker.host.len() > MAX_DOCKER_ENDPOINT_BYTES
        || context.endpoints.docker.skip_tls_verify
    {
        return Err(DoctorIssueCode::UntrustedDockerEndpoint);
    }
    let endpoint = local_endpoint(&context.endpoints.docker.host, operating_system)
        .ok_or(DoctorIssueCode::UntrustedDockerEndpoint)?;
    Ok(DockerConnection {
        context_name: context.name.clone(),
        host: context.endpoints.docker.host.clone(),
        endpoint,
    })
}

fn valid_context_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= MAX_DOCKER_CONTEXT_NAME_BYTES
        && name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
}

fn local_endpoint(host: &str, operating_system: &str) -> Option<EngineEndpoint> {
    if matches!(operating_system, "linux" | "macos") {
        let path = host.strip_prefix("unix://")?;
        return (path.starts_with('/') && path.len() > 1 && !path.contains(['\0', '?', '#']))
            .then_some(EngineEndpoint::UnixSocket);
    }
    if operating_system == "windows" {
        let pipe = host.strip_prefix("npipe:////./pipe/")?;
        return (!pipe.is_empty()
            && pipe
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-')))
        .then_some(EngineEndpoint::WindowsNamedPipe);
    }
    None
}

#[derive(Debug, Default, Deserialize)]
struct DockerVersionDocument {
    #[serde(default, rename = "Client")]
    client: Option<DockerClientVersion>,
    #[serde(default, rename = "Server")]
    server: Option<DockerServerVersion>,
}

#[derive(Debug, Default, Deserialize)]
struct DockerClientVersion {
    #[serde(default, rename = "Version")]
    version: String,
    #[serde(default, rename = "ApiVersion")]
    api_version: String,
}

#[derive(Debug, Default, Deserialize)]
struct DockerServerVersion {
    #[serde(default, rename = "Version")]
    version: String,
    #[serde(default, rename = "ApiVersion")]
    api_version: String,
    #[serde(default, rename = "MinAPIVersion")]
    minimum_api_version: String,
    #[serde(default, rename = "Os")]
    operating_system: String,
    #[serde(default, rename = "Arch")]
    architecture: String,
    #[serde(default, rename = "GitCommit")]
    git_commit: String,
    #[serde(default, rename = "Components")]
    components: Vec<DockerComponent>,
}

#[derive(Debug, Default, Deserialize)]
struct DockerComponent {
    #[serde(default, rename = "Name")]
    name: String,
    #[serde(default, rename = "Version")]
    version: String,
    #[serde(default, rename = "Details")]
    details: BTreeMap<String, String>,
}

#[derive(Debug)]
struct ValidatedVersion {
    server_version: String,
    api_version: String,
    architecture: EngineArchitecture,
}

fn validate_version(
    document: &DockerVersionDocument,
    host_architecture: &str,
) -> Result<ValidatedVersion, DoctorIssueCode> {
    let client = document
        .client
        .as_ref()
        .ok_or(DoctorIssueCode::NonDockerEngine)?;
    let server = document
        .server
        .as_ref()
        .ok_or(DoctorIssueCode::NonDockerEngine)?;
    let primary = server
        .components
        .first()
        .filter(|component| component.name == "Engine")
        .ok_or(DoctorIssueCode::NonDockerEngine)?;
    let required_details = [
        "ApiVersion",
        "MinAPIVersion",
        "Arch",
        "Os",
        "GitCommit",
        "GoVersion",
        "KernelVersion",
    ];
    if client.version.is_empty()
        || client.api_version.is_empty()
        || server.version.is_empty()
        || server.git_commit.is_empty()
        || required_details
            .iter()
            .any(|field| primary.details.get(*field).is_none_or(String::is_empty))
        || !["containerd", "runc", "docker-init"].iter().all(|name| {
            server
                .components
                .iter()
                .skip(1)
                .any(|component| component.name == *name)
        })
    {
        return Err(DoctorIssueCode::NonDockerEngine);
    }
    if primary.version != server.version
        || primary.details.get("GitCommit") != Some(&server.git_commit)
    {
        return Err(DoctorIssueCode::EngineIdentityMismatch);
    }
    if server.operating_system != "linux"
        || primary.details.get("Os").map(String::as_str) != Some("linux")
    {
        return Err(DoctorIssueCode::NonLinuxEngine);
    }
    let architecture = normalize_architecture(&server.architecture)
        .ok_or(DoctorIssueCode::UnsupportedEngineArchitecture)?;
    let component_architecture = primary
        .details
        .get("Arch")
        .and_then(|value| normalize_architecture(value))
        .ok_or(DoctorIssueCode::UnsupportedEngineArchitecture)?;
    let host_architecture = normalize_architecture(host_architecture)
        .ok_or(DoctorIssueCode::UnsupportedEngineArchitecture)?;
    if architecture != component_architecture || architecture != host_architecture {
        return Err(DoctorIssueCode::UnsupportedEngineArchitecture);
    }
    let client_api =
        ApiVersion::parse(&client.api_version).ok_or(DoctorIssueCode::UnsupportedDockerApi)?;
    let server_api =
        ApiVersion::parse(&server.api_version).ok_or(DoctorIssueCode::UnsupportedDockerApi)?;
    let minimum_api = ApiVersion::parse(&server.minimum_api_version)
        .ok_or(DoctorIssueCode::UnsupportedDockerApi)?;
    let component_api = primary
        .details
        .get("ApiVersion")
        .and_then(|value| ApiVersion::parse(value))
        .ok_or(DoctorIssueCode::UnsupportedDockerApi)?;
    let component_minimum_api = primary
        .details
        .get("MinAPIVersion")
        .and_then(|value| ApiVersion::parse(value))
        .ok_or(DoctorIssueCode::UnsupportedDockerApi)?;
    let adapter_api = capped_adapter_api(client_api);
    if client_api < MIN_DOCKER_API
        || adapter_api < MIN_DOCKER_API
        || server_api < client_api
        || minimum_api > adapter_api
        || component_api != server_api
        || component_minimum_api != minimum_api
    {
        return Err(DoctorIssueCode::UnsupportedDockerApi);
    }
    Ok(ValidatedVersion {
        server_version: server.version.clone(),
        api_version: format!("{}.{}", adapter_api.major, adapter_api.minor),
        architecture,
    })
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct ApiVersion {
    major: u16,
    minor: u16,
}

impl ApiVersion {
    fn parse(value: &str) -> Option<Self> {
        let (major, minor) = value.split_once('.')?;
        if major.is_empty()
            || minor.is_empty()
            || !major.bytes().all(|byte| byte.is_ascii_digit())
            || !minor.bytes().all(|byte| byte.is_ascii_digit())
        {
            return None;
        }
        Some(Self {
            major: major.parse().ok()?,
            minor: minor.parse().ok()?,
        })
    }
}

fn capped_adapter_api(selected: ApiVersion) -> ApiVersion {
    // Keep this in lockstep with the bounded request/response models in
    // `engine::transport`; raising it requires extending those models first.
    let supported = ApiVersion {
        major: 1,
        minor: 53,
    };
    selected.min(supported)
}

const fn normalize_architecture(value: &str) -> Option<EngineArchitecture> {
    match value.as_bytes() {
        b"amd64" | b"x86_64" => Some(EngineArchitecture::Amd64),
        b"arm64" | b"aarch64" => Some(EngineArchitecture::Arm64),
        _ => None,
    }
}

#[derive(Debug, Default, Deserialize)]
struct DockerInfoDocument {
    #[serde(default, rename = "ID")]
    id: String,
    #[serde(default, rename = "OSType")]
    operating_system: String,
    #[serde(default, rename = "Architecture")]
    architecture: String,
    #[serde(default, rename = "ServerVersion")]
    server_version: String,
    #[serde(default, rename = "Plugins")]
    plugins: DockerPlugins,
}

#[derive(Debug, Default, Deserialize)]
struct DockerPlugins {
    #[serde(default, rename = "Volume")]
    volumes: Vec<String>,
    #[serde(default, rename = "Network")]
    networks: Vec<String>,
}

fn validate_info(
    info: &DockerInfoDocument,
    version: &ValidatedVersion,
) -> Result<String, DoctorIssueCode> {
    if info.operating_system != "linux" {
        return Err(DoctorIssueCode::NonLinuxEngine);
    }
    let architecture = normalize_architecture(&info.architecture)
        .ok_or(DoctorIssueCode::UnsupportedEngineArchitecture)?;
    if architecture != version.architecture || info.server_version != version.server_version {
        return Err(DoctorIssueCode::EngineIdentityMismatch);
    }
    if info.id.is_empty()
        || info.id.len() > 512
        || info.id.trim() != info.id
        || info.id.chars().any(char::is_control)
    {
        return Err(DoctorIssueCode::MissingEngineIdentity);
    }
    if !info.plugins.volumes.iter().any(|plugin| plugin == "local")
        || !info
            .plugins
            .networks
            .iter()
            .any(|plugin| plugin == "bridge")
    {
        return Err(DoctorIssueCode::MissingEngineCapability);
    }
    Ok(info.id.clone())
}

#[derive(Debug, Default, Deserialize)]
struct DockerComposeDocument {
    #[serde(default)]
    version: String,
}

fn validate_compose(document: &DockerComposeDocument) -> Result<String, DoctorIssueCode> {
    let parsed = parse_compose_version(&document.version)
        .ok_or(DoctorIssueCode::UnsupportedComposeVersion)?;
    if parsed < MIN_COMPOSE_VERSION {
        return Err(DoctorIssueCode::UnsupportedComposeVersion);
    }
    Ok(document.version.clone())
}

fn parse_compose_version(value: &str) -> Option<(u64, u64, u64)> {
    let value = value.strip_prefix('v').unwrap_or(value);
    let (version, _build) = value.split_once('+').unwrap_or((value, ""));
    let (core, vendor) = version.split_once('-').unwrap_or((version, ""));
    if !vendor.is_empty() {
        let desktop_revision = vendor.strip_prefix("desktop.")?;
        if desktop_revision.is_empty()
            || desktop_revision.split('.').any(|component| {
                component.is_empty() || !component.bytes().all(|b| b.is_ascii_digit())
            })
        {
            return None;
        }
    } else if version.ends_with('-') {
        return None;
    }
    let mut components = core.split('.');
    let major = components.next()?.parse().ok()?;
    let minor = components.next()?.parse().ok()?;
    let patch = components.next()?.parse().ok()?;
    (components.next().is_none()).then_some((major, minor, patch))
}

#[cfg(unix)]
fn process_is_root() -> bool {
    rustix::process::geteuid().is_root()
}

#[cfg(not(unix))]
const fn process_is_root() -> bool {
    false
}

#[cfg(test)]
mod tests {
    use super::{
        CaptureFailure, CommandFailure, ComposeFrontend, DoctorIssueCode, DoctorProbe,
        DoctorRequest, EngineArchitecture, EngineEndpoint, EngineRequest, MAX_COMMAND_STREAM_BYTES,
        ProbeOutput, ProbeSet, build_report, read_bounded,
    };
    #[cfg(target_os = "linux")]
    use super::{spawn_contained, terminate_process_tree};
    use serde_json::json;
    #[cfg(target_os = "linux")]
    use std::path::PathBuf;
    use tokio::io::AsyncReadExt as _;
    #[cfg(target_os = "linux")]
    use tokio::process::Command as ProcessCommand;

    const CONTEXT_UNIX: &str = r#"{
        "Name":"default",
        "Endpoints":{"docker":{"Host":"unix:///var/run/docker.sock","SkipTLSVerify":false}}
    }"#;
    const CONTEXT_WINDOWS: &str = r#"{
        "Name":"desktop-linux",
        "Endpoints":{"docker":{"Host":"npipe:////./pipe/dockerDesktopLinuxEngine","SkipTLSVerify":false}}
    }"#;
    const VERSION_AMD64: &str = r#"{
        "Client":{"Version":"29.7.2","ApiVersion":"1.55"},
        "Server":{
            "Version":"29.7.2","ApiVersion":"1.55","MinAPIVersion":"1.40",
            "Os":"linux","Arch":"amd64","GitCommit":"server-commit",
            "Components":[
                {"Name":"Engine","Version":"29.7.2","Details":{
                    "ApiVersion":"1.55","MinAPIVersion":"1.40","Arch":"amd64",
                    "Os":"linux","GitCommit":"server-commit","GoVersion":"go1.26",
                    "KernelVersion":"6.12"
                }},
                {"Name":"containerd"},{"Name":"runc"},{"Name":"docker-init"}
            ]
        }
    }"#;
    const PODMAN_COMPAT_VERSION: &str = r#"{
        "Client":{"Version":"29.7.2","ApiVersion":"1.44"},
        "Server":{
            "Version":"6.0.2","ApiVersion":"1.44","MinAPIVersion":"1.24",
            "Os":"linux","Arch":"amd64","GitCommit":"compat",
            "Components":[
                {"Name":"Podman Engine","Version":"6.0.2","Details":{
                    "ApiVersion":"6.0.2","MinAPIVersion":"4.0.0",
                    "Arch":"amd64","Os":"linux"
                }},
                {"Name":"Conmon","Version":"2.1.13"},
                {"Name":"OCI Runtime (crun)","Version":"1.23"},
                {"Name":"Engine","Version":"6.0.2","Details":{
                    "ApiVersion":"1.44","MinAPIVersion":"1.24",
                    "Arch":"amd64","Os":"linux"
                }}
            ]
        }
    }"#;
    const INFO_AMD64: &str = r#"{
        "ID":"engine-identity","OSType":"linux","Architecture":"x86_64",
        "ServerVersion":"29.7.2",
        "Plugins":{"Volume":["local"],"Network":["bridge","host"]}
    }"#;
    const COMPOSE: &str = r#"{"version":"5.4.0"}"#;

    fn success(value: impl Into<Vec<u8>>) -> ProbeOutput {
        ProbeOutput::Success(value.into())
    }

    fn healthy_probes(context: &str) -> ProbeSet {
        ProbeSet {
            context: success(context.as_bytes()),
            version: success(VERSION_AMD64.as_bytes()),
            info: success(INFO_AMD64.as_bytes()),
            compose: success(COMPOSE.as_bytes()),
        }
    }

    fn report(
        operating_system: &str,
        host_architecture: &str,
        probes: &ProbeSet,
    ) -> super::DoctorReport {
        build_report(
            &DoctorRequest::new(EngineRequest::Auto),
            operating_system,
            host_architecture,
            false,
            false,
            probes,
        )
    }

    fn issue_codes(report: &super::DoctorReport) -> Vec<DoctorIssueCode> {
        report.issues().iter().map(|issue| issue.code()).collect()
    }

    #[test]
    fn validates_a_local_docker_engine_and_future_compose_major() {
        let report = report("linux", "x86_64", &healthy_probes(CONTEXT_UNIX));
        assert!(report.ready());
        assert!(report.issues().is_empty());
        let engine = report.selected_engine().expect("validated engine");
        assert_eq!(engine.endpoint(), EngineEndpoint::UnixSocket);
        assert_eq!(engine.context_name(), "default");
        assert_eq!(engine.architecture(), EngineArchitecture::Amd64);
        assert_eq!(engine.compose(), ComposeFrontend::DockerPlugin);
        assert_eq!(engine.engine_id(), "engine-identity");
        assert_eq!(engine.api_version(), "1.53");
        assert_eq!(engine.compose_version(), "5.4.0");
    }

    #[test]
    fn validates_docker_desktop_linux_mode_on_windows() {
        let report = report("windows", "x86_64", &healthy_probes(CONTEXT_WINDOWS));
        assert!(report.ready());
        assert_eq!(
            report
                .selected_engine()
                .map(super::EngineSelection::endpoint),
            Some(EngineEndpoint::WindowsNamedPipe)
        );
    }

    #[test]
    fn validates_native_arm64_engine_on_macos() {
        let probes = ProbeSet {
            context: success(
                CONTEXT_UNIX
                    .replace(
                        "/var/run/docker.sock",
                        "/Users/example/.docker/run/docker.sock",
                    )
                    .into_bytes(),
            ),
            version: success(VERSION_AMD64.replace("amd64", "arm64").into_bytes()),
            info: success(INFO_AMD64.replace("x86_64", "aarch64").into_bytes()),
            compose: success(COMPOSE.as_bytes()),
        };
        let report = report("macos", "aarch64", &probes);
        assert!(report.ready());
        assert_eq!(
            report
                .selected_engine()
                .map(super::EngineSelection::architecture),
            Some(EngineArchitecture::Arm64)
        );
    }

    #[test]
    fn rejects_remote_or_insecure_contexts() {
        for context in [
            CONTEXT_UNIX.replace("unix:///var/run/docker.sock", "tcp://127.0.0.1:2375"),
            CONTEXT_UNIX.replace("\"SkipTLSVerify\":false", "\"SkipTLSVerify\":true"),
            CONTEXT_UNIX.replace("\"default\"", "\"context with spaces\""),
            CONTEXT_UNIX.replace("\"default\"", &format!("\"{}\"", "a".repeat(129))),
        ] {
            let report = report("linux", "x86_64", &healthy_probes(&context));
            assert_eq!(
                issue_codes(&report),
                vec![DoctorIssueCode::UntrustedDockerEndpoint]
            );
        }
    }

    #[test]
    fn rejects_podman_primary_component_and_native_cli_shape() {
        let mut probes = healthy_probes(CONTEXT_UNIX);
        probes.version = success(PODMAN_COMPAT_VERSION.as_bytes());
        assert_eq!(
            issue_codes(&report("linux", "x86_64", &probes)),
            vec![DoctorIssueCode::NonDockerEngine]
        );

        let mut probes = healthy_probes(CONTEXT_UNIX);
        probes.version = success(br#"{"Client":{"Version":"6.0.2"}}"#.as_slice());
        assert_eq!(
            issue_codes(&report("linux", "x86_64", &probes)),
            vec![DoctorIssueCode::NonDockerEngine]
        );
    }

    #[test]
    fn rejects_windows_container_mode_and_unqualified_architecture() {
        let mut windows = healthy_probes(CONTEXT_WINDOWS);
        windows.version = success(
            VERSION_AMD64
                .replace("\"linux\"", "\"windows\"")
                .into_bytes(),
        );
        windows.info = success(INFO_AMD64.replace("\"linux\"", "\"windows\"").into_bytes());
        assert_eq!(
            issue_codes(&report("windows", "x86_64", &windows)),
            vec![DoctorIssueCode::NonLinuxEngine]
        );

        let mut architecture = healthy_probes(CONTEXT_UNIX);
        architecture.version = success(VERSION_AMD64.replace("amd64", "s390x").into_bytes());
        architecture.info = success(INFO_AMD64.replace("x86_64", "s390x").into_bytes());
        assert_eq!(
            issue_codes(&report("linux", "s390x", &architecture)),
            vec![
                DoctorIssueCode::UnsupportedHostPlatform,
                DoctorIssueCode::UnsupportedEngineArchitecture,
            ]
        );
    }

    #[test]
    fn rejects_an_engine_without_the_supported_api_overlap() {
        let mut probes = healthy_probes(CONTEXT_UNIX);
        probes.version = success(
            VERSION_AMD64
                .replacen("\"ApiVersion\":\"1.55\"", "\"ApiVersion\":\"1.43\"", 1)
                .into_bytes(),
        );
        assert_eq!(
            issue_codes(&report("linux", "x86_64", &probes)),
            vec![DoctorIssueCode::UnsupportedDockerApi]
        );
    }

    #[test]
    fn rejects_a_daemon_minimum_above_the_adapter_model_ceiling() {
        let mut probes = healthy_probes(CONTEXT_UNIX);
        probes.version = success(
            VERSION_AMD64
                .replace("\"MinAPIVersion\":\"1.40\"", "\"MinAPIVersion\":\"1.54\"")
                .into_bytes(),
        );
        assert_eq!(
            issue_codes(&report("linux", "x86_64", &probes)),
            vec![DoctorIssueCode::UnsupportedDockerApi]
        );
    }

    #[test]
    fn retains_an_older_negotiated_api_below_the_adapter_ceiling() {
        let mut probes = healthy_probes(CONTEXT_UNIX);
        probes.version = success(
            VERSION_AMD64
                .replacen("\"ApiVersion\":\"1.55\"", "\"ApiVersion\":\"1.44\"", 1)
                .into_bytes(),
        );
        let report = report("linux", "x86_64", &probes);
        assert!(report.ready());
        assert_eq!(
            report
                .selected_engine()
                .map(super::EngineSelection::api_version),
            Some("1.44")
        );
    }

    #[test]
    fn rejects_unqualified_host_platform_tuples() {
        for (operating_system, architecture, expected_engine_architecture) in [
            ("macos", "x86_64", "amd64"),
            ("windows", "aarch64", "arm64"),
        ] {
            let probes = ProbeSet {
                context: success(if operating_system == "windows" {
                    CONTEXT_WINDOWS.as_bytes()
                } else {
                    CONTEXT_UNIX.as_bytes()
                }),
                version: success(
                    VERSION_AMD64
                        .replace("amd64", expected_engine_architecture)
                        .into_bytes(),
                ),
                info: success(INFO_AMD64.replace("x86_64", architecture).into_bytes()),
                compose: success(COMPOSE.as_bytes()),
            };
            assert_eq!(
                issue_codes(&report(operating_system, architecture, &probes)),
                vec![DoctorIssueCode::UnsupportedHostPlatform]
            );
        }
    }

    #[test]
    fn rejects_a_forced_docker_api_version() {
        let report = build_report(
            &DoctorRequest::new(EngineRequest::Auto),
            "linux",
            "x86_64",
            false,
            true,
            &healthy_probes(CONTEXT_UNIX),
        );
        assert!(!report.ready());
        assert_eq!(
            issue_codes(&report),
            vec![DoctorIssueCode::DockerApiOverride]
        );
    }

    #[test]
    fn rejects_mismatched_engine_information_and_missing_capabilities() {
        let mut component = healthy_probes(CONTEXT_UNIX);
        component.version = success(
            VERSION_AMD64
                .replace(
                    "\"Name\":\"Engine\",\"Version\":\"29.7.2\"",
                    "\"Name\":\"Engine\",\"Version\":\"29.7.1\"",
                )
                .into_bytes(),
        );
        assert_eq!(
            issue_codes(&report("linux", "x86_64", &component)),
            vec![DoctorIssueCode::EngineIdentityMismatch]
        );

        let mut mismatch = healthy_probes(CONTEXT_UNIX);
        mismatch.info = success(INFO_AMD64.replace("29.7.2", "29.7.1").into_bytes());
        assert_eq!(
            issue_codes(&report("linux", "x86_64", &mismatch)),
            vec![DoctorIssueCode::EngineIdentityMismatch]
        );

        let mut capability = healthy_probes(CONTEXT_UNIX);
        capability.info = success(INFO_AMD64.replace("\"bridge\",", "").into_bytes());
        assert_eq!(
            issue_codes(&report("linux", "x86_64", &capability)),
            vec![DoctorIssueCode::MissingEngineCapability]
        );
    }

    #[test]
    fn rejects_old_or_malformed_compose_versions() {
        for version in ["1.29.2", "not-a-version", "2.20.0-rc.1", "2.20.0-"] {
            let mut probes = healthy_probes(CONTEXT_UNIX);
            probes.compose = success(format!(r#"{{"version":"{version}"}}"#).into_bytes());
            assert_eq!(
                issue_codes(&report("linux", "x86_64", &probes)),
                vec![DoctorIssueCode::UnsupportedComposeVersion]
            );
        }

        let mut desktop = healthy_probes(CONTEXT_UNIX);
        desktop.compose = success(br#"{"version":"v2.32.4-desktop.1"}"#.as_slice());
        assert!(report("linux", "x86_64", &desktop).ready());
    }

    #[test]
    fn command_and_payload_failures_keep_typed_probe_identity() {
        let cases = [
            (CommandFailure::NotFound, DoctorIssueCode::CommandNotFound),
            (CommandFailure::TimedOut, DoctorIssueCode::CommandTimedOut),
            (CommandFailure::Failed, DoctorIssueCode::CommandFailed),
            (
                CommandFailure::OutputTooLarge,
                DoctorIssueCode::CommandOutputTooLarge,
            ),
        ];
        for (failure, expected) in cases {
            let mut probes = healthy_probes(CONTEXT_UNIX);
            probes.context = ProbeOutput::Failure(failure);
            let report = report("linux", "x86_64", &probes);
            assert_eq!(report.issues().len(), 1);
            assert_eq!(report.issues()[0].probe(), DoctorProbe::DockerContext);
            assert_eq!(report.issues()[0].code(), expected);
        }

        let mut probes = healthy_probes(CONTEXT_UNIX);
        probes.info = success(b"not-json".as_slice());
        assert_eq!(
            issue_codes(&report("linux", "x86_64", &probes)),
            vec![DoctorIssueCode::MalformedProbeResponse]
        );

        let probes = ProbeSet {
            context: ProbeOutput::Failure(CommandFailure::ContextUnavailable),
            version: ProbeOutput::Failure(CommandFailure::DaemonUnavailable),
            info: ProbeOutput::Failure(CommandFailure::DaemonUnavailable),
            compose: ProbeOutput::Failure(CommandFailure::ComposeUnavailable),
        };
        let failure_report = report("linux", "x86_64", &probes);
        assert_eq!(
            issue_codes(&failure_report),
            vec![
                DoctorIssueCode::DockerContextUnavailable,
                DoctorIssueCode::DockerDaemonUnavailable,
                DoctorIssueCode::DockerDaemonUnavailable,
                DoctorIssueCode::DockerComposeUnavailable,
            ]
        );
        let document = serde_json::to_value(failure_report).expect("failure report must serialize");
        assert_eq!(
            document["issues"][3]["message"],
            "install Docker Compose CLI plugin version 2.20.0 or newer"
        );

        let probes = ProbeSet {
            context: success(
                CONTEXT_UNIX
                    .replace("unix:///var/run/docker.sock", "tcp://127.0.0.1:2375")
                    .into_bytes(),
            ),
            version: ProbeOutput::Failure(CommandFailure::DaemonUnavailable),
            info: ProbeOutput::Failure(CommandFailure::DaemonUnavailable),
            compose: ProbeOutput::Failure(CommandFailure::ComposeUnavailable),
        };
        assert_eq!(
            issue_codes(&report("linux", "x86_64", &probes)),
            vec![
                DoctorIssueCode::UntrustedDockerEndpoint,
                DoctorIssueCode::DockerDaemonUnavailable,
                DoctorIssueCode::DockerDaemonUnavailable,
                DoctorIssueCode::DockerComposeUnavailable,
            ],
            "simultaneous failures remain in stable probe order"
        );
    }

    #[tokio::test]
    async fn command_capture_rejects_output_above_the_bound() {
        let input = tokio::io::repeat(7).take((MAX_COMMAND_STREAM_BYTES + 1) as u64);
        assert_eq!(
            read_bounded(input, MAX_COMMAND_STREAM_BYTES).await,
            Err(CaptureFailure::OutputTooLarge)
        );
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn process_containment_terminates_descendants() {
        let mut command = ProcessCommand::new("/bin/sh");
        command
            .args(["-c", "sleep 30 & wait"])
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .kill_on_drop(true);
        let (mut child, mut containment) = spawn_contained(command).expect("contained shell");
        let leader = child.id().expect("shell process ID");
        let children_path = PathBuf::from(format!("/proc/{leader}/task/{leader}/children"));
        let descendant = tokio::time::timeout(std::time::Duration::from_secs(1), async {
            loop {
                if let Ok(children) = std::fs::read_to_string(&children_path)
                    && let Some(pid) = children.split_whitespace().next()
                {
                    break pid.parse::<u32>().expect("descendant process ID");
                }
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("shell must spawn its descendant");

        terminate_process_tree(&mut child, &mut containment).await;
        let descendant_path = PathBuf::from(format!("/proc/{descendant}"));
        tokio::time::timeout(std::time::Duration::from_secs(1), async {
            while descendant_path.exists() {
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("descendant must be reaped after group termination");
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn dropping_process_containment_terminates_descendants() {
        let mut command = ProcessCommand::new("/bin/sh");
        command
            .args(["-c", "sleep 30 & wait"])
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .kill_on_drop(true);
        let (mut child, containment) = spawn_contained(command).expect("contained shell");
        let leader = child.id().expect("shell process ID");
        let children_path = PathBuf::from(format!("/proc/{leader}/task/{leader}/children"));
        let descendant = tokio::time::timeout(std::time::Duration::from_secs(1), async {
            loop {
                if let Ok(children) = std::fs::read_to_string(&children_path)
                    && let Some(pid) = children.split_whitespace().next()
                {
                    break pid.parse::<u32>().expect("descendant process ID");
                }
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("shell must spawn its descendant");

        drop(containment);
        tokio::time::timeout(std::time::Duration::from_secs(1), child.wait())
            .await
            .expect("group leader must exit after containment is dropped")
            .expect("group leader wait must succeed");
        let descendant_path = PathBuf::from(format!("/proc/{descendant}"));
        tokio::time::timeout(std::time::Duration::from_secs(1), async {
            while descendant_path.exists() {
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("descendant must be reaped after containment is dropped");
    }

    #[test]
    fn report_contract_is_schema_versioned_and_actionable() {
        let report = report("linux", "x86_64", &healthy_probes(CONTEXT_UNIX));
        assert_eq!(
            serde_json::to_value(report).expect("doctor report must serialize"),
            json!({
                "schema": 3,
                "ready": true,
                "platform": {
                    "operating_system": "linux",
                    "architecture": "x86_64"
                },
                "requested_engine": "auto",
                "selected_engine": {
                    "engine": "docker",
                    "compose": "docker_plugin",
                    "context_name": "default",
                    "endpoint": "unix_socket",
                    "engine_id": "engine-identity",
                    "server_version": "29.7.2",
                    "api_version": "1.53",
                    "architecture": "amd64",
                    "compose_version": "5.4.0"
                },
                "issues": []
            })
        );
    }
}
