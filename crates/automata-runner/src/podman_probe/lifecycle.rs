use std::{
    ffi::OsString,
    fs::{self, OpenOptions},
    io::Write as _,
    net::SocketAddr,
    path::{Path, PathBuf},
    time::{Duration, Instant},
};

use crate::capability_probe::{
    CapabilityProbe, ProbeReasonCode, ProbeStatus, active_network_probe,
};

use super::{
    ActiveProbeLimits, ActiveProbePlan, CommandExecutor, CommandOutput, CommandRequest,
    CommandTermination, ProbeCancellation, ReadinessProbe, plan::validate_resolved_scratch_root,
};

const OWNER_LABEL_KEY: &str = "io.automata.owner";
const OWNER_LABEL_VALUE: &str = "automata-runner";
const PROBE_LABEL_KEY: &str = "io.automata.probe-id";
const CONTAINER_PORT: u16 = 8080;
const OUTPUT_LIMIT: usize = 16 * 1024;
const QUICK_COMMAND_TIMEOUT: Duration = Duration::from_secs(15);
const BUILD_TIMEOUT: Duration = Duration::from_mins(1);
const CLEANUP_COMMAND_TIMEOUT: Duration = Duration::from_secs(15);
const CONTAINERFILE: &str =
    "FROM scratch\nCOPY automata-runner /automata-runner\nENTRYPOINT [\"/automata-runner\"]\n";

pub(super) struct LifecycleExecution {
    pub(super) outcome: Result<(), ProbeFailure>,
    pub(super) cleanup_errors: Vec<String>,
}

pub(super) fn run_lifecycle(
    plan: &ActiveProbePlan,
    commands: &dyn CommandExecutor,
    readiness: &dyn ReadinessProbe,
    cancellation: &ProbeCancellation,
    limits: ActiveProbeLimits,
) -> LifecycleExecution {
    let mut resources = ProbeResources::new(plan, commands, cancellation, limits.cleanup_timeout());
    let outcome = execute_active_probe(&mut resources, readiness, limits.readiness_timeout());
    let cleanup_errors = resources.cleanup();
    LifecycleExecution {
        outcome,
        cleanup_errors,
    }
}

fn execute_active_probe(
    resources: &mut ProbeResources<'_>,
    readiness: &dyn ReadinessProbe,
    readiness_timeout: Duration,
) -> Result<(), ProbeFailure> {
    resources.ensure_provisioning_allowed()?;
    resources.verify_rootless_podman()?;
    resources.ensure_provisioning_allowed()?;
    resources.prepare_context()?;
    resources.ensure_provisioning_allowed()?;
    resources.create_network()?;
    resources.ensure_provisioning_allowed()?;
    resources.build_image()?;
    resources.ensure_provisioning_allowed()?;
    resources.start_container()?;
    resources.ensure_provisioning_allowed()?;
    let address = resources.published_address()?;
    resources.ensure_provisioning_allowed()?;
    readiness
        .wait_until_ready(
            address,
            resources.plan.identifier(),
            readiness_timeout,
            resources.cancellation,
        )
        .map_err(|detail| {
            if resources.cancellation.is_cancelled() {
                resources.interrupted_failure()
            } else {
                ProbeFailure::degraded(
                    ProbeReasonCode::ActiveProbeHttpFailed,
                    format!("published readiness request failed: {detail}"),
                )
            }
        })?;
    resources.ensure_provisioning_allowed()
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ResourceState {
    NotAttempted,
    MaybeCreated,
    Owned,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ResourceKind {
    Container,
    Network,
    Image,
}

impl ResourceKind {
    const fn description(self) -> &'static str {
        match self {
            Self::Container => "container",
            Self::Network => "network",
            Self::Image => "image",
        }
    }
}

struct ProbeResources<'a> {
    plan: &'a ActiveProbePlan,
    commands: &'a dyn CommandExecutor,
    cancellation: &'a ProbeCancellation,
    cleanup_timeout: Duration,
    cleanup_deadline: Option<Instant>,
    cleanup_finished: bool,
    context_created: bool,
    scratch_root: PathBuf,
    context_path: PathBuf,
    network: ResourceState,
    image: ResourceState,
    container: ResourceState,
}

impl<'a> ProbeResources<'a> {
    fn new(
        plan: &'a ActiveProbePlan,
        commands: &'a dyn CommandExecutor,
        cancellation: &'a ProbeCancellation,
        cleanup_timeout: Duration,
    ) -> Self {
        Self {
            plan,
            commands,
            cancellation,
            cleanup_timeout,
            cleanup_deadline: None,
            cleanup_finished: false,
            context_created: false,
            scratch_root: plan.scratch_root().to_owned(),
            context_path: plan.context_path().to_owned(),
            network: ResourceState::NotAttempted,
            image: ResourceState::NotAttempted,
            container: ResourceState::NotAttempted,
        }
    }

    fn ensure_provisioning_allowed(&self) -> Result<(), ProbeFailure> {
        if self.cancellation.is_cancelled() {
            Err(self.interrupted_failure())
        } else {
            Ok(())
        }
    }

    fn interrupted_failure(&self) -> ProbeFailure {
        ProbeFailure::indeterminate(
            ProbeReasonCode::ActiveProbeInterrupted,
            format!(
                "active Podman probe interrupted after {} shutdown request(s); provisioning stopped and bounded cleanup began",
                self.cancellation.signal_count()
            ),
        )
    }

    fn verify_rootless_podman(&self) -> Result<(), ProbeFailure> {
        self.ensure_provisioning_allowed()?;
        let mut request = podman_request(QUICK_COMMAND_TIMEOUT);
        request
            .arg("info")
            .arg("--format")
            .arg("{{.Host.Security.Rootless}}");
        let output = checked_command(
            self.commands,
            &request,
            self.cancellation,
            "rootless Podman verification",
        )?;
        self.ensure_provisioning_allowed()?;
        if output.stdout().trim() == "true" {
            Ok(())
        } else {
            Err(ProbeFailure::unavailable(
                ProbeReasonCode::ActiveProbeRequiresRootlessUser,
                format!(
                    "Podman did not report a local rootless engine (reported {:?})",
                    output.stdout().trim()
                ),
            ))
        }
    }

    fn prepare_context(&mut self) -> Result<(), ProbeFailure> {
        self.ensure_provisioning_allowed()?;
        self.prepare_scratch_root()?;
        self.ensure_provisioning_allowed()?;

        let mut context_builder = fs::DirBuilder::new();
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt as _;
            context_builder.mode(0o700);
        }
        context_builder
            .create(self.context_path())
            .map_err(|error| {
                ProbeFailure::indeterminate(
                    ProbeReasonCode::ActiveProbePreparationFailed,
                    format!(
                        "failed to create unique probe context {}: {error}",
                        self.context_path().display()
                    ),
                )
            })?;
        self.context_created = true;
        self.ensure_provisioning_allowed()?;

        let target = self.context_path().join("automata-runner");
        fs::copy(self.plan.executable(), &target).map_err(|error| {
            ProbeFailure::indeterminate(
                ProbeReasonCode::ActiveProbePreparationFailed,
                format!("failed to copy the runner into the probe context: {error}"),
            )
        })?;
        self.ensure_provisioning_allowed()?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            fs::set_permissions(&target, fs::Permissions::from_mode(0o555)).map_err(|error| {
                ProbeFailure::indeterminate(
                    ProbeReasonCode::ActiveProbePreparationFailed,
                    format!("failed to make the scratch payload executable: {error}"),
                )
            })?;
        }
        self.ensure_provisioning_allowed()?;

        let containerfile_path = self.context_path().join("Containerfile");
        let mut containerfile = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&containerfile_path)
            .map_err(|error| {
                ProbeFailure::indeterminate(
                    ProbeReasonCode::ActiveProbePreparationFailed,
                    format!("failed to create the scratch Containerfile: {error}"),
                )
            })?;
        containerfile
            .write_all(CONTAINERFILE.as_bytes())
            .map_err(|error| {
                ProbeFailure::indeterminate(
                    ProbeReasonCode::ActiveProbePreparationFailed,
                    format!("failed to write the scratch Containerfile: {error}"),
                )
            })?;
        self.ensure_provisioning_allowed()
    }

    fn prepare_scratch_root(&mut self) -> Result<(), ProbeFailure> {
        match fs::symlink_metadata(&self.scratch_root) {
            Ok(metadata) if metadata.file_type().is_symlink() => {
                return Err(scratch_preparation_failure(
                    "runner scratch root must be a real directory, not a symlink".to_owned(),
                ));
            }
            Ok(_metadata) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => {
                return Err(scratch_preparation_failure(format!(
                    "failed to inspect configured runner scratch root: {error}"
                )));
            }
        }

        let destination = resolve_scratch_destination(&self.scratch_root).map_err(|error| {
            scratch_preparation_failure(format!(
                "failed to resolve runner scratch root {}: {error}",
                self.scratch_root.display()
            ))
        })?;
        validate_resolved_scratch_root(&destination).map_err(scratch_preparation_failure)?;

        let mut root_builder = fs::DirBuilder::new();
        root_builder.recursive(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt as _;
            root_builder.mode(0o700);
        }
        root_builder.create(&destination).map_err(|error| {
            ProbeFailure::indeterminate(
                ProbeReasonCode::ActiveProbePreparationFailed,
                format!(
                    "failed to create runner scratch root {}: {error}",
                    destination.display()
                ),
            )
        })?;
        let metadata = fs::symlink_metadata(&destination).map_err(|error| {
            ProbeFailure::indeterminate(
                ProbeReasonCode::ActiveProbePreparationFailed,
                format!("failed to inspect runner scratch root: {error}"),
            )
        })?;
        if !metadata.is_dir() || metadata.file_type().is_symlink() {
            return Err(ProbeFailure::indeterminate(
                ProbeReasonCode::ActiveProbePreparationFailed,
                "runner scratch root must be a real directory, not a symlink".to_owned(),
            ));
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            fs::set_permissions(&destination, fs::Permissions::from_mode(0o700)).map_err(
                |error| {
                    ProbeFailure::indeterminate(
                        ProbeReasonCode::ActiveProbePreparationFailed,
                        format!("failed to secure runner scratch root permissions: {error}"),
                    )
                },
            )?;
        }
        let resolved = fs::canonicalize(&destination).map_err(|error| {
            scratch_preparation_failure(format!(
                "failed to canonicalize runner scratch root after creation: {error}"
            ))
        })?;
        validate_resolved_scratch_root(&resolved).map_err(scratch_preparation_failure)?;
        self.context_path = self.plan.context_path_in(&resolved);
        self.scratch_root = resolved;
        Ok(())
    }

    fn context_path(&self) -> &Path {
        &self.context_path
    }

    fn create_network(&mut self) -> Result<(), ProbeFailure> {
        self.ensure_provisioning_allowed()?;
        self.network = ResourceState::MaybeCreated;
        let mut request = podman_request(QUICK_COMMAND_TIMEOUT);
        request
            .arg("network")
            .arg("create")
            .arg("--disable-dns")
            .arg("--label")
            .arg(owner_label())
            .arg("--label")
            .arg(self.probe_label())
            .arg(self.plan.network_name());
        checked_command(
            self.commands,
            &request,
            self.cancellation,
            "Podman network creation",
        )?;
        self.network = ResourceState::Owned;
        self.ensure_provisioning_allowed()
    }

    fn build_image(&mut self) -> Result<(), ProbeFailure> {
        self.ensure_provisioning_allowed()?;
        self.image = ResourceState::MaybeCreated;
        let mut request = podman_request(BUILD_TIMEOUT);
        request
            .arg("build")
            .arg("--pull=never")
            .arg("--no-cache")
            .arg("--layers=false")
            .arg("--force-rm=true")
            .arg("--network=none")
            .arg("--label")
            .arg(owner_label())
            .arg("--label")
            .arg(self.probe_label())
            .arg("--tag")
            .arg(self.plan.image_name())
            .arg("--file")
            .arg(self.context_path().join("Containerfile"))
            .arg(self.context_path());
        checked_command(
            self.commands,
            &request,
            self.cancellation,
            "scratch image build",
        )?;
        self.image = ResourceState::Owned;
        self.ensure_provisioning_allowed()
    }

    fn start_container(&mut self) -> Result<(), ProbeFailure> {
        self.ensure_provisioning_allowed()?;
        self.container = ResourceState::MaybeCreated;
        let mut request = podman_request(QUICK_COMMAND_TIMEOUT);
        request
            .arg("run")
            .arg("--detach")
            .arg("--name")
            .arg(self.plan.container_name())
            .arg("--label")
            .arg(owner_label())
            .arg("--label")
            .arg(self.probe_label())
            .arg("--network")
            .arg(self.plan.network_name())
            .arg("--publish")
            .arg(format!("127.0.0.1::{CONTAINER_PORT}/tcp"))
            .arg("--pull=never")
            .arg("--read-only")
            .arg("--cap-drop=all")
            .arg("--security-opt=no-new-privileges")
            .arg("--user=65532:65532")
            .arg(self.plan.image_name())
            .arg("__probe-http-ready")
            .arg("--port")
            .arg(CONTAINER_PORT.to_string())
            .arg("--token")
            .arg(self.plan.identifier());
        checked_command(
            self.commands,
            &request,
            self.cancellation,
            "isolated container start",
        )?;
        self.container = ResourceState::Owned;
        self.ensure_provisioning_allowed()
    }

    fn published_address(&self) -> Result<SocketAddr, ProbeFailure> {
        self.ensure_provisioning_allowed()?;
        let mut request = podman_request(QUICK_COMMAND_TIMEOUT);
        request
            .arg("port")
            .arg(self.plan.container_name())
            .arg(format!("{CONTAINER_PORT}/tcp"));
        let output = checked_command(
            self.commands,
            &request,
            self.cancellation,
            "published-port lookup",
        )?;
        self.ensure_provisioning_allowed()?;
        let mut lines = output
            .stdout()
            .lines()
            .filter(|line| !line.trim().is_empty());
        let address = lines
            .next()
            .and_then(|line| line.trim().parse::<SocketAddr>().ok())
            .filter(|address| address.ip().is_loopback() && address.port() != 0);
        if lines.next().is_some() || address.is_none() {
            return Err(ProbeFailure::degraded(
                ProbeReasonCode::ActiveProbePortInvalid,
                format!(
                    "Podman returned an invalid loopback port mapping: {:?}",
                    output.stdout().trim()
                ),
            ));
        }
        address.ok_or_else(|| {
            ProbeFailure::degraded(
                ProbeReasonCode::ActiveProbePortInvalid,
                "Podman did not return a loopback port mapping".to_owned(),
            )
        })
    }

    fn cleanup(&mut self) -> Vec<String> {
        let now = Instant::now();
        let deadline = *self
            .cleanup_deadline
            .get_or_insert_with(|| now.checked_add(self.cleanup_timeout).unwrap_or(now));
        let mut errors = Vec::new();
        for kind in [
            ResourceKind::Container,
            ResourceKind::Network,
            ResourceKind::Image,
        ] {
            if self.resource_state(kind) == ResourceState::NotAttempted {
                continue;
            }
            if let Some(error) = self.cleanup_budget_error(kind, deadline) {
                errors.push(error);
                break;
            }
            if let Err(error) = self.cleanup_resource(kind, deadline) {
                errors.push(error);
            }
        }
        self.remove_context(&mut errors);
        self.cleanup_finished = true;
        errors
    }

    fn cleanup_budget_error(&self, kind: ResourceKind, deadline: Instant) -> Option<String> {
        if self.cancellation.is_forced() {
            Some(format!(
                "cleanup stopped before {} removal after a second shutdown request",
                kind.description()
            ))
        } else if Instant::now() >= deadline {
            Some(format!(
                "aggregate cleanup deadline expired before {} ownership verification",
                kind.description()
            ))
        } else {
            None
        }
    }

    fn cleanup_resource(&mut self, kind: ResourceKind, deadline: Instant) -> Result<(), String> {
        if !self.resource_is_owned(kind, deadline)? {
            self.set_resource_state(kind, ResourceState::NotAttempted);
            return Ok(());
        }
        if let Some(error) = self.cleanup_budget_error(kind, deadline) {
            return Err(error);
        }

        let mut request = cleanup_podman_request(deadline);
        match kind {
            ResourceKind::Container => {
                request
                    .arg("rm")
                    .arg("--force")
                    .arg("--ignore")
                    .arg(self.plan.container_name());
            }
            ResourceKind::Network => {
                request
                    .arg("network")
                    .arg("rm")
                    .arg("--force")
                    .arg(self.plan.network_name());
            }
            ResourceKind::Image => {
                request
                    .arg("image")
                    .arg("rm")
                    .arg("--force")
                    .arg("--ignore")
                    .arg(self.plan.image_name());
            }
        }
        let output = self.commands.execute(&request, self.cancellation);
        if output.succeeded() {
            self.set_resource_state(kind, ResourceState::NotAttempted);
            Ok(())
        } else {
            Err(format!(
                "failed to remove owned {}: {}",
                kind.description(),
                output.failure_detail()
            ))
        }
    }

    fn resource_is_owned(&self, kind: ResourceKind, deadline: Instant) -> Result<bool, String> {
        let name = self.resource_name(kind);
        let mut exists = cleanup_podman_request(deadline);
        match kind {
            ResourceKind::Container => {
                exists.arg("container").arg("exists").arg(name);
            }
            ResourceKind::Network => {
                exists.arg("network").arg("exists").arg(name);
            }
            ResourceKind::Image => {
                exists.arg("image").arg("exists").arg(name);
            }
        }
        let exists_output = self.commands.execute(&exists, self.cancellation);
        match exists_output.termination() {
            CommandTermination::Exited(Some(1)) => return Ok(false),
            _ if exists_output.succeeded() => {}
            _ => {
                return Err(format!(
                    "could not determine whether probe {} exists: {}",
                    kind.description(),
                    exists_output.failure_detail()
                ));
            }
        }
        if let Some(error) = self.cleanup_budget_error(kind, deadline) {
            return Err(error);
        }

        let mut inspect = cleanup_podman_request(deadline);
        let label_template = match kind {
            ResourceKind::Container => format!(
                "{{{{ index .Config.Labels \"{PROBE_LABEL_KEY}\" }}}}\n{{{{ index .Config.Labels \"{OWNER_LABEL_KEY}\" }}}}"
            ),
            ResourceKind::Network | ResourceKind::Image => format!(
                "{{{{ index .Labels \"{PROBE_LABEL_KEY}\" }}}}\n{{{{ index .Labels \"{OWNER_LABEL_KEY}\" }}}}"
            ),
        };
        match kind {
            ResourceKind::Container => {
                inspect
                    .arg("container")
                    .arg("inspect")
                    .arg("--format")
                    .arg(label_template)
                    .arg(name);
            }
            ResourceKind::Network => {
                inspect
                    .arg("network")
                    .arg("inspect")
                    .arg("--format")
                    .arg(label_template)
                    .arg(name);
            }
            ResourceKind::Image => {
                inspect
                    .arg("image")
                    .arg("inspect")
                    .arg("--format")
                    .arg(label_template)
                    .arg(name);
            }
        }
        let inspect_output = self.commands.execute(&inspect, self.cancellation);
        if !inspect_output.succeeded() {
            return Err(format!(
                "could not inspect possible probe {} ownership: {}",
                kind.description(),
                inspect_output.failure_detail()
            ));
        }
        let mut labels = inspect_output.stdout().lines();
        let probe_identifier = labels.next().unwrap_or_default().trim();
        let owner = labels.next().unwrap_or_default().trim();
        let has_extra_values = labels.any(|line| !line.trim().is_empty());
        if probe_identifier == self.plan.identifier()
            && owner == OWNER_LABEL_VALUE
            && !has_extra_values
        {
            Ok(true)
        } else {
            Err(format!(
                "refusing to remove {} {name}: expected probe ID {} and owner {OWNER_LABEL_VALUE}, found probe ID {probe_identifier:?} and owner {owner:?}",
                kind.description(),
                self.plan.identifier()
            ))
        }
    }

    fn remove_context(&mut self, errors: &mut Vec<String>) {
        if !self.context_created {
            return;
        }
        match fs::remove_dir_all(self.context_path()) {
            Ok(()) => self.context_created = false,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                self.context_created = false;
            }
            Err(error) => errors.push(format!(
                "failed to remove probe context {}: {error}",
                self.context_path().display()
            )),
        }
    }

    const fn resource_state(&self, kind: ResourceKind) -> ResourceState {
        match kind {
            ResourceKind::Container => self.container,
            ResourceKind::Network => self.network,
            ResourceKind::Image => self.image,
        }
    }

    fn set_resource_state(&mut self, kind: ResourceKind, state: ResourceState) {
        match kind {
            ResourceKind::Container => self.container = state,
            ResourceKind::Network => self.network = state,
            ResourceKind::Image => self.image = state,
        }
    }

    fn resource_name(&self, kind: ResourceKind) -> &str {
        match kind {
            ResourceKind::Container => self.plan.container_name(),
            ResourceKind::Network => self.plan.network_name(),
            ResourceKind::Image => self.plan.image_name(),
        }
    }

    fn probe_label(&self) -> String {
        format!("{PROBE_LABEL_KEY}={}", self.plan.identifier())
    }
}

fn resolve_scratch_destination(path: &Path) -> std::io::Result<PathBuf> {
    let mut ancestor = path;
    let mut missing_segments = Vec::<OsString>::new();
    loop {
        match fs::canonicalize(ancestor) {
            Ok(mut resolved) => {
                for segment in missing_segments.iter().rev() {
                    resolved.push(segment);
                }
                return Ok(resolved);
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                let segment = ancestor.file_name().ok_or_else(|| {
                    std::io::Error::new(
                        std::io::ErrorKind::NotFound,
                        "no existing ancestor could be resolved",
                    )
                })?;
                missing_segments.push(segment.to_owned());
                ancestor = ancestor.parent().ok_or_else(|| {
                    std::io::Error::new(
                        std::io::ErrorKind::NotFound,
                        "no existing ancestor could be resolved",
                    )
                })?;
            }
            Err(error) => return Err(error),
        }
    }
}

fn scratch_preparation_failure(detail: String) -> ProbeFailure {
    ProbeFailure::indeterminate(ProbeReasonCode::ActiveProbePreparationFailed, detail)
}

impl Drop for ProbeResources<'_> {
    fn drop(&mut self) {
        if !self.cleanup_finished {
            let _ignored = self.cleanup();
        }
    }
}

pub(super) struct ProbeFailure {
    status: ProbeStatus,
    reason: ProbeReasonCode,
    pub(super) detail: String,
}

impl ProbeFailure {
    fn degraded(reason: ProbeReasonCode, detail: String) -> Self {
        Self {
            status: ProbeStatus::Degraded,
            reason,
            detail,
        }
    }

    fn unavailable(reason: ProbeReasonCode, detail: String) -> Self {
        Self {
            status: ProbeStatus::Unavailable,
            reason,
            detail,
        }
    }

    fn indeterminate(reason: ProbeReasonCode, detail: String) -> Self {
        Self {
            status: ProbeStatus::Indeterminate,
            reason,
            detail,
        }
    }

    pub(super) fn into_probe(self) -> CapabilityProbe {
        active_network_probe(self.status, Some(self.reason), self.detail)
    }
}

fn owner_label() -> String {
    format!("{OWNER_LABEL_KEY}={OWNER_LABEL_VALUE}")
}

fn podman_request(timeout: Duration) -> CommandRequest {
    let mut request = CommandRequest::new("podman", timeout, OUTPUT_LIMIT);
    request.arg("--remote=false");
    request
}

fn cleanup_podman_request(deadline: Instant) -> CommandRequest {
    podman_request(CLEANUP_COMMAND_TIMEOUT).for_cleanup(deadline)
}

fn checked_command(
    executor: &dyn CommandExecutor,
    request: &CommandRequest,
    cancellation: &ProbeCancellation,
    stage: &str,
) -> Result<CommandOutput, ProbeFailure> {
    let output = executor.execute(request, cancellation);
    if output.succeeded() {
        return Ok(output);
    }
    let detail = format!("{stage} {}", output.failure_detail());
    match output.termination() {
        CommandTermination::Cancelled => Err(ProbeFailure::indeterminate(
            ProbeReasonCode::ActiveProbeInterrupted,
            detail,
        )),
        CommandTermination::TimedOut | CommandTermination::CleanupDeadlineExceeded => Err(
            ProbeFailure::degraded(ProbeReasonCode::ActiveProbeCommandTimedOut, detail),
        ),
        CommandTermination::FailedToStart => Err(ProbeFailure::unavailable(
            ProbeReasonCode::PodmanExecutableUnavailable,
            detail,
        )),
        CommandTermination::Exited(_) => Err(ProbeFailure::degraded(
            ProbeReasonCode::ActiveProbeCommandFailed,
            detail,
        )),
    }
}
