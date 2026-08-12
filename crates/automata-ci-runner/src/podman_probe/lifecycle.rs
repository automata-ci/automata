use std::{
    ffi::OsString,
    fs,
    net::SocketAddr,
    path::{Path, PathBuf},
    time::{Duration, Instant},
};

#[cfg(unix)]
use std::os::fd::OwnedFd;
#[cfg(unix)]
use std::{
    fs::File,
    io::{Read as _, Write as _},
};

#[cfg(unix)]
use rustix::fs::{
    AtFlags, Dir, FileType, Mode, OFlags, fchmod, fstat, mkdirat, open, openat, unlinkat,
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
const CLEANUP_COMMAND_TIMEOUT: Duration = Duration::from_secs(15);
const NETWORK_IDENTITY_TEMPLATE: &str = r#"{{printf "%s\t%t\n" .ID .Internal}}"#;
const CONTAINER_NETWORKS_TEMPLATE: &str = r#"{{range $name, $network := .NetworkSettings.Networks}}{{printf "%s\t%s\n" $name $network.NetworkID}}{{end}}"#;
const PAYLOAD_NAME: &str = "automata-runner";
const CONTAINER_PAYLOAD_PATH: &str = "/automata-runner";
// Podman's overlay-rootfs option keeps runtime-created paths out of the one-file source rootfs.
const ROOTFS_OVERLAY_SUFFIX: &str = ":O";

pub(super) struct LifecycleExecution {
    pub(super) outcome: Result<(), ProbeFailure>,
    pub(super) cleanup_errors: Vec<String>,
}

pub(super) fn run_lifecycle(
    plan: &ActiveProbePlan,
    executable: &[u8],
    commands: &dyn CommandExecutor,
    readiness: &dyn ReadinessProbe,
    cancellation: &ProbeCancellation,
    limits: ActiveProbeLimits,
) -> LifecycleExecution {
    let mut resources = ProbeResources::new(
        plan,
        executable,
        commands,
        cancellation,
        limits.cleanup_timeout(),
    );
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
    resources.prepare_context()?;
    resources.ensure_provisioning_allowed()?;
    resources.create_network()?;
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
}

impl ResourceKind {
    const fn description(self) -> &'static str {
        match self {
            Self::Container => "container",
            Self::Network => "network",
        }
    }
}

struct ProbeResources<'a> {
    plan: &'a ActiveProbePlan,
    executable: &'a [u8],
    commands: &'a dyn CommandExecutor,
    cancellation: &'a ProbeCancellation,
    cleanup_timeout: Duration,
    cleanup_deadline: Option<Instant>,
    cleanup_finished: bool,
    context: Option<ProbeContext>,
    scratch_root: PathBuf,
    context_path: PathBuf,
    network: ResourceState,
    network_identifier: Option<String>,
    container: ResourceState,
    container_identifier: Option<String>,
}

impl<'a> ProbeResources<'a> {
    fn new(
        plan: &'a ActiveProbePlan,
        executable: &'a [u8],
        commands: &'a dyn CommandExecutor,
        cancellation: &'a ProbeCancellation,
        cleanup_timeout: Duration,
    ) -> Self {
        Self {
            plan,
            executable,
            commands,
            cancellation,
            cleanup_timeout,
            cleanup_deadline: None,
            cleanup_finished: false,
            context: None,
            scratch_root: plan.scratch_root().to_owned(),
            context_path: plan.context_path().to_owned(),
            network: ResourceState::NotAttempted,
            network_identifier: None,
            container: ResourceState::NotAttempted,
            container_identifier: None,
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

    fn prepare_context(&mut self) -> Result<(), ProbeFailure> {
        self.ensure_provisioning_allowed()?;
        self.prepare_scratch_root()?;
        self.ensure_provisioning_allowed()?;
        let context =
            ProbeContext::create(&self.scratch_root, self.context_path()).map_err(|detail| {
                ProbeFailure::indeterminate(ProbeReasonCode::ActiveProbePreparationFailed, detail)
            })?;
        self.context = Some(context);
        self.ensure_provisioning_allowed()?;
        self.context
            .as_mut()
            .expect("created context must be retained")
            .write_payload(self.executable)
            .map_err(|detail| {
                ProbeFailure::indeterminate(ProbeReasonCode::ActiveProbePreparationFailed, detail)
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
            .arg("--label")
            .arg(owner_label())
            .arg("--label")
            .arg(self.probe_label());
        if self.plan.network_policy() == automata_ci_execution::NetworkPolicy::Disabled {
            request.arg("--internal");
        }
        request.arg(self.plan.network_name());
        let output = checked_command(
            self.commands,
            &request,
            self.cancellation,
            "Podman network creation",
        )?;
        let created_name = parse_exact_single_line(output.stdout());
        if output.was_truncated() || created_name != Some(self.plan.network_name()) {
            return Err(ProbeFailure::degraded(
                ProbeReasonCode::ActiveProbeCommandFailed,
                "Podman network creation returned an unexpected resource name".to_owned(),
            ));
        }
        self.ensure_provisioning_allowed()?;
        self.network_identifier = Some(self.inspect_network_identity(self.plan.network_name())?);
        self.network = ResourceState::Owned;
        self.ensure_provisioning_allowed()
    }

    fn inspect_network_identity(&self, identifier: &str) -> Result<String, ProbeFailure> {
        let mut request = podman_request(QUICK_COMMAND_TIMEOUT);
        request
            .arg("network")
            .arg("inspect")
            .arg("--format")
            .arg(NETWORK_IDENTITY_TEMPLATE)
            .arg(identifier);
        let output = checked_command(
            self.commands,
            &request,
            self.cancellation,
            "created-network identity inspection",
        )?;
        if output.was_truncated() {
            return Err(ProbeFailure::degraded(
                ProbeReasonCode::ActiveProbeCommandFailed,
                "created-network identity output exceeded its capture limit".to_owned(),
            ));
        }
        let line = parse_exact_single_line(output.stdout()).ok_or_else(|| {
            ProbeFailure::degraded(
                ProbeReasonCode::ActiveProbeCommandFailed,
                "Podman returned an invalid created-network identity".to_owned(),
            )
        })?;
        let (identifier, internal) = line.split_once('\t').ok_or_else(|| {
            ProbeFailure::degraded(
                ProbeReasonCode::ActiveProbeCommandFailed,
                "Podman returned an invalid created-network identity".to_owned(),
            )
        })?;
        let expected_internal = match self.plan.network_policy() {
            automata_ci_execution::NetworkPolicy::Disabled => "true",
            automata_ci_execution::NetworkPolicy::PrivateEgress => "false",
            automata_ci_execution::NetworkPolicy::Host => {
                return Err(ProbeFailure::degraded(
                    ProbeReasonCode::ActiveProbeCommandFailed,
                    "Podman cannot probe a host-network native profile".to_owned(),
                ));
            }
        };
        if canonical_podman_identifier(ResourceKind::Network, identifier).is_none()
            || internal != expected_internal
        {
            return Err(ProbeFailure::degraded(
                ProbeReasonCode::ActiveProbeCommandFailed,
                "created network did not match the configured network policy".to_owned(),
            ));
        }
        Ok(identifier.to_owned())
    }

    fn start_container(&mut self) -> Result<(), ProbeFailure> {
        self.ensure_provisioning_allowed()?;
        self.verify_context_binding("before container start")?;
        let network_identifier = self.network_identifier.as_deref().ok_or_else(|| {
            ProbeFailure::indeterminate(
                ProbeReasonCode::ActiveProbePreparationFailed,
                "created-network identity was unavailable before container start".to_owned(),
            )
        })?;
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
            .arg(network_identifier)
            .arg("--publish")
            .arg(format!("127.0.0.1::{CONTAINER_PORT}/tcp"))
            .arg("--read-only")
            .arg("--cap-drop=all")
            .arg("--security-opt=no-new-privileges")
            .arg("--user=65532:65532")
            .arg("--rootfs")
            .arg(self.rootfs_argument())
            .arg(CONTAINER_PAYLOAD_PATH)
            .arg("__probe-http-ready")
            .arg("--port")
            .arg(CONTAINER_PORT.to_string())
            .arg("--token")
            .arg(self.plan.identifier());
        let output = checked_command(
            self.commands,
            &request,
            self.cancellation,
            "isolated container start",
        )?;
        self.container_identifier = Some(parse_created_resource_identifier(
            ResourceKind::Container,
            &output,
            "isolated container start",
        )?);
        self.verify_context_binding("after container start")?;
        self.container = ResourceState::Owned;
        self.ensure_provisioning_allowed()?;
        self.verify_container_network()?;
        self.ensure_provisioning_allowed()
    }

    fn rootfs_argument(&self) -> OsString {
        let mut argument = self.context_path().as_os_str().to_owned();
        argument.push(ROOTFS_OVERLAY_SUFFIX);
        argument
    }

    fn verify_context_binding(&self, stage: &str) -> Result<(), ProbeFailure> {
        let context = self.context.as_ref().ok_or_else(|| {
            ProbeFailure::indeterminate(
                ProbeReasonCode::ActiveProbePreparationFailed,
                format!("probe rootfs was unavailable {stage}"),
            )
        })?;
        verify_probe_context_for_use(context, self.executable).map_err(|detail| {
            ProbeFailure::indeterminate(
                ProbeReasonCode::ActiveProbePreparationFailed,
                format!("probe rootfs integrity failed {stage}: {detail}"),
            )
        })
    }

    fn verify_container_network(&self) -> Result<(), ProbeFailure> {
        let expected_identifier = self.network_identifier.as_deref().ok_or_else(|| {
            ProbeFailure::indeterminate(
                ProbeReasonCode::ActiveProbePreparationFailed,
                "created-network identity was unavailable before container inspection".to_owned(),
            )
        })?;
        let container_identifier = self.container_identifier.as_deref().ok_or_else(|| {
            ProbeFailure::indeterminate(
                ProbeReasonCode::ActiveProbePreparationFailed,
                "started-container identity was unavailable before network inspection".to_owned(),
            )
        })?;
        let mut request = podman_request(QUICK_COMMAND_TIMEOUT);
        request
            .arg("container")
            .arg("inspect")
            .arg("--format")
            .arg(CONTAINER_NETWORKS_TEMPLATE)
            .arg(container_identifier);
        let output = checked_command(
            self.commands,
            &request,
            self.cancellation,
            "probe container network inspection",
        )?;
        if output.was_truncated() {
            return Err(ProbeFailure::degraded(
                ProbeReasonCode::ActiveProbeCommandFailed,
                "probe container network output exceeded its capture limit".to_owned(),
            ));
        }
        let exact_membership = parse_exact_single_line(output.stdout())
            .and_then(|line| line.split_once('\t'))
            .is_some_and(|(name, identifier)| {
                name == self.plan.network_name()
                    && identifier == expected_identifier
                    && !identifier.is_empty()
            });
        if !exact_membership {
            return Err(ProbeFailure::degraded(
                ProbeReasonCode::ActiveProbeCommandFailed,
                "probe container was not attached exclusively to the created network".to_owned(),
            ));
        }
        Ok(())
    }

    fn published_address(&self) -> Result<SocketAddr, ProbeFailure> {
        self.ensure_provisioning_allowed()?;
        let container_identifier = self.container_identifier.as_deref().ok_or_else(|| {
            ProbeFailure::indeterminate(
                ProbeReasonCode::ActiveProbePreparationFailed,
                "started-container identity was unavailable before port lookup".to_owned(),
            )
        })?;
        let mut request = podman_request(QUICK_COMMAND_TIMEOUT);
        request
            .arg("port")
            .arg(container_identifier)
            .arg(format!("{CONTAINER_PORT}/tcp"));
        let output = checked_command(
            self.commands,
            &request,
            self.cancellation,
            "published-port lookup",
        )?;
        if output.was_truncated() {
            return Err(ProbeFailure::degraded(
                ProbeReasonCode::ActiveProbePortInvalid,
                "published-port output exceeded its capture limit".to_owned(),
            ));
        }
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
        for kind in [ResourceKind::Container, ResourceKind::Network] {
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
        let Some(identifier) = self.owned_resource_identifier(kind, deadline)? else {
            self.set_resource_state(kind, ResourceState::NotAttempted);
            return Ok(());
        };
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
                    .arg(&identifier);
            }
            ResourceKind::Network => {
                request.arg("network").arg("rm").arg(&identifier);
            }
        }
        let output = self.commands.execute(&request, self.cancellation);
        if !output.succeeded() {
            return Err(format!(
                "failed to remove owned {}: {}",
                kind.description(),
                output.failure_detail()
            ));
        }
        if let Some(error) = self.cleanup_budget_error(kind, deadline) {
            return Err(error);
        }
        if !self.resource_is_absent(kind, &identifier, deadline)? {
            return Err(format!(
                "owned {} still exists after Podman reported successful removal",
                kind.description()
            ));
        }
        self.set_resource_state(kind, ResourceState::NotAttempted);
        Ok(())
    }

    fn resource_is_absent(
        &self,
        kind: ResourceKind,
        identifier: &str,
        deadline: Instant,
    ) -> Result<bool, String> {
        self.resource_exists(kind, identifier, deadline)
            .map(|exists| !exists)
            .map_err(|error| {
                format!(
                    "could not confirm removal of owned {}: {error}",
                    kind.description()
                )
            })
    }

    fn resource_exists(
        &self,
        kind: ResourceKind,
        identifier: &str,
        deadline: Instant,
    ) -> Result<bool, String> {
        let mut exists = cleanup_podman_request(deadline);
        exists.arg(kind.description()).arg("exists").arg(identifier);
        let output = self.commands.execute(&exists, self.cancellation);
        match output.termination() {
            CommandTermination::Exited(Some(1)) => Ok(false),
            _ if output.succeeded() => Ok(true),
            _ => Err(output.failure_detail()),
        }
    }

    fn owned_resource_identifier(
        &self,
        kind: ResourceKind,
        deadline: Instant,
    ) -> Result<Option<String>, String> {
        let name = self.resource_name(kind);
        let lookup = self.created_resource_identifier(kind).unwrap_or(name);
        if !self
            .resource_exists(kind, lookup, deadline)
            .map_err(|error| {
                format!(
                    "could not determine whether probe {} exists: {error}",
                    kind.description()
                )
            })?
        {
            return Ok(None);
        }
        if let Some(error) = self.cleanup_budget_error(kind, deadline) {
            return Err(error);
        }

        self.inspect_owned_resource_identifier(kind, name, lookup, deadline)
            .map(Some)
    }

    fn inspect_owned_resource_identifier(
        &self,
        kind: ResourceKind,
        name: &str,
        lookup: &str,
        deadline: Instant,
    ) -> Result<String, String> {
        let mut inspect = cleanup_podman_request(deadline);
        let identity_template = match kind {
            ResourceKind::Container => format!(
                "{{{{ .Id }}}}\n{{{{ index .Config.Labels \"{PROBE_LABEL_KEY}\" }}}}\n{{{{ index .Config.Labels \"{OWNER_LABEL_KEY}\" }}}}"
            ),
            ResourceKind::Network => format!(
                "{{{{ .ID }}}}\n{{{{ index .Labels \"{PROBE_LABEL_KEY}\" }}}}\n{{{{ index .Labels \"{OWNER_LABEL_KEY}\" }}}}"
            ),
        };
        match kind {
            ResourceKind::Container => {
                inspect
                    .arg("container")
                    .arg("inspect")
                    .arg("--format")
                    .arg(identity_template)
                    .arg(lookup);
            }
            ResourceKind::Network => {
                inspect
                    .arg("network")
                    .arg("inspect")
                    .arg("--format")
                    .arg(identity_template)
                    .arg(lookup);
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
        if inspect_output.was_truncated() {
            return Err(format!(
                "probe {} ownership output exceeded its capture limit",
                kind.description()
            ));
        }
        let mut identity = inspect_output.stdout().lines();
        let reported_identifier = identity.next().unwrap_or_default().trim();
        let probe_identifier = identity.next().unwrap_or_default().trim();
        let owner = identity.next().unwrap_or_default().trim();
        let has_extra_values = identity.any(|line| !line.trim().is_empty());
        let resource_identifier = canonical_podman_identifier(kind, reported_identifier);
        let valid_resource_identifier = resource_identifier.is_some();
        let matches_created_identifier = self
            .created_resource_identifier(kind)
            .is_none_or(|created| resource_identifier == Some(created));
        if valid_resource_identifier
            && matches_created_identifier
            && probe_identifier == self.plan.identifier()
            && owner == OWNER_LABEL_VALUE
            && !has_extra_values
        {
            Ok(resource_identifier
                .expect("validated identifier")
                .to_owned())
        } else {
            Err(format!(
                "refusing to remove {} {name}: expected the created immutable resource identifier, probe ID {}, and owner {OWNER_LABEL_VALUE}; observed identifier validity {valid_resource_identifier}, created-identifier match {matches_created_identifier}, probe ID {probe_identifier:?}, and owner {owner:?}",
                kind.description(),
                self.plan.identifier()
            ))
        }
    }

    fn remove_context(&mut self, errors: &mut Vec<String>) {
        // The context is the container overlay's lowerdir. Retain it until the
        // container is proven absent so later reconciliation can still remove it.
        if self.container != ResourceState::NotAttempted {
            return;
        }
        let Some(context) = self.context.as_mut() else {
            return;
        };
        match context.remove() {
            Ok(()) => self.context = None,
            Err(error) => errors.push(format!("failed to remove probe context: {error}")),
        }
    }

    const fn resource_state(&self, kind: ResourceKind) -> ResourceState {
        match kind {
            ResourceKind::Container => self.container,
            ResourceKind::Network => self.network,
        }
    }

    fn set_resource_state(&mut self, kind: ResourceKind, state: ResourceState) {
        match kind {
            ResourceKind::Container => self.container = state,
            ResourceKind::Network => self.network = state,
        }
    }

    fn resource_name(&self, kind: ResourceKind) -> &str {
        match kind {
            ResourceKind::Container => self.plan.container_name(),
            ResourceKind::Network => self.plan.network_name(),
        }
    }

    fn created_resource_identifier(&self, kind: ResourceKind) -> Option<&str> {
        match kind {
            ResourceKind::Container => self.container_identifier.as_deref(),
            ResourceKind::Network => self.network_identifier.as_deref(),
        }
    }

    fn probe_label(&self) -> String {
        format!("{PROBE_LABEL_KEY}={}", self.plan.identifier())
    }
}

#[cfg(unix)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct FileIdentity {
    device: rustix::fs::Dev,
    inode: u64,
}

#[cfg(unix)]
impl FileIdentity {
    fn of(descriptor: &impl std::os::fd::AsFd) -> Result<Self, String> {
        let metadata = fstat(descriptor)
            .map_err(|error| format!("could not inspect retained probe context: {error}"))?;
        Ok(Self {
            device: metadata.st_dev,
            inode: metadata.st_ino,
        })
    }
}

#[cfg(unix)]
struct ProbeContext {
    parent: OwnedFd,
    directory: OwnedFd,
    payload: Option<OwnedFd>,
    name: OsString,
    parent_identity: FileIdentity,
    directory_identity: FileIdentity,
    payload_identity: Option<FileIdentity>,
}

#[cfg(unix)]
impl ProbeContext {
    fn create(scratch_root: &Path, context_path: &Path) -> Result<Self, String> {
        let name = direct_child_name(scratch_root, context_path)?;
        let directory_flags =
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW;
        let parent = open(scratch_root, directory_flags, Mode::empty())
            .map_err(|error| format!("could not securely open probe scratch root: {error}"))?;
        ensure_private_directory_descriptor(&parent, "probe scratch root")?;
        let parent_identity = FileIdentity::of(&parent)?;
        mkdirat(&parent, &name, Mode::from_raw_mode(0o700)).map_err(|error| {
            format!(
                "failed to create unique probe context {}: {error}",
                context_path.display()
            )
        })?;
        let directory = match openat(&parent, &name, directory_flags, Mode::empty()) {
            Ok(directory) => directory,
            Err(error) => {
                let _ignored = unlinkat(&parent, &name, AtFlags::REMOVEDIR);
                return Err(format!(
                    "could not securely open the created probe context: {error}"
                ));
            }
        };
        // The 0700 parent keeps the context private; the rootfs itself needs
        // search permission so the deliberately unprivileged uid can exec the payload.
        if let Err(error) = fchmod(&directory, Mode::from_raw_mode(0o711)) {
            drop(directory);
            let _ignored = unlinkat(&parent, &name, AtFlags::REMOVEDIR);
            return Err(format!(
                "could not make the probe rootfs traversable by its unprivileged process: {error}"
            ));
        }
        if let Err(error) = ensure_owned_directory_descriptor(&directory, "probe context", 0o711) {
            drop(directory);
            let _ignored = unlinkat(&parent, &name, AtFlags::REMOVEDIR);
            return Err(error);
        }
        let directory_identity = match FileIdentity::of(&directory) {
            Ok(identity) => identity,
            Err(error) => {
                drop(directory);
                let _ignored = unlinkat(&parent, &name, AtFlags::REMOVEDIR);
                return Err(error);
            }
        };
        Ok(Self {
            parent,
            directory,
            payload: None,
            name,
            parent_identity,
            directory_identity,
            payload_identity: None,
        })
    }

    fn write_payload(&mut self, executable: &[u8]) -> Result<(), String> {
        let payload = openat(
            &self.directory,
            PAYLOAD_NAME,
            OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::CLOEXEC | OFlags::NOFOLLOW,
            Mode::from_raw_mode(0o700),
        )
        .map_err(|error| format!("failed to create the snapshotted runner payload: {error}"))?;
        let payload_identity = ensure_owned_regular_payload(&payload)?;
        self.payload_identity = Some(payload_identity);
        let mut payload = File::from(payload);
        let result = (|| {
            payload.write_all(executable).map_err(|error| {
                format!("failed to write the snapshotted runner payload: {error}")
            })?;
            fchmod(&payload, Mode::from_raw_mode(0o555)).map_err(|error| {
                format!("failed to make the scratch payload executable: {error}")
            })?;
            payload.sync_all().map_err(|error| {
                format!("failed to sync the snapshotted runner payload: {error}")
            })?;
            rustix::fs::fsync(&self.directory)
                .map_err(|error| format!("failed to sync the probe context: {error}"))
        })();
        self.payload = Some(OwnedFd::from(payload));
        result
    }

    fn verify_for_use(&self, expected_payload: &[u8]) -> Result<(), String> {
        if FileIdentity::of(&self.parent)? != self.parent_identity {
            return Err("retained probe scratch-root identity changed".to_owned());
        }
        ensure_private_directory_descriptor(&self.parent, "probe scratch root")?;
        if FileIdentity::of(&self.directory)? != self.directory_identity {
            return Err("retained probe context identity changed".to_owned());
        }
        ensure_owned_directory_descriptor(&self.directory, "probe context", 0o711)?;
        let named_context = openat(
            &self.parent,
            &self.name,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
            Mode::empty(),
        )
        .map_err(|error| format!("could not reopen the probe rootfs by name: {error}"))?;
        if FileIdentity::of(&named_context)? != self.directory_identity {
            return Err("probe context name no longer identifies the owned directory".to_owned());
        }
        ensure_owned_directory_descriptor(&named_context, "named probe context", 0o711)?;
        self.verify_exact_entries(&named_context)?;

        let expected_payload_identity = self
            .payload_identity
            .ok_or_else(|| "probe payload identity was unavailable".to_owned())?;
        let retained_payload = self
            .payload
            .as_ref()
            .ok_or_else(|| "probe payload descriptor was not retained".to_owned())?;
        if ensure_executable_payload_descriptor(retained_payload, expected_payload.len())?
            != expected_payload_identity
        {
            return Err("retained probe payload identity changed".to_owned());
        }
        let named_payload = openat(
            &named_context,
            PAYLOAD_NAME,
            OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::NONBLOCK,
            Mode::empty(),
        )
        .map_err(|error| format!("could not reopen the probe payload by name: {error}"))?;
        if ensure_executable_payload_descriptor(&named_payload, expected_payload.len())?
            != expected_payload_identity
        {
            return Err("probe payload name no longer identifies the owned file".to_owned());
        }
        let read_limit = u64::try_from(expected_payload.len())
            .ok()
            .and_then(|length| length.checked_add(1))
            .ok_or_else(|| "probe payload length cannot be represented by the host".to_owned())?;
        let mut observed_payload = Vec::with_capacity(expected_payload.len().min(16 * 1024 * 1024));
        File::from(named_payload)
            .take(read_limit)
            .read_to_end(&mut observed_payload)
            .map_err(|error| format!("could not verify probe payload bytes: {error}"))?;
        if observed_payload != expected_payload {
            return Err("probe payload bytes changed".to_owned());
        }
        Ok(())
    }

    fn remove(&mut self) -> Result<(), String> {
        if FileIdentity::of(&self.parent)? != self.parent_identity {
            return Err("retained probe scratch-root identity changed".to_owned());
        }
        if FileIdentity::of(&self.directory)? != self.directory_identity {
            return Err("retained probe context identity changed".to_owned());
        }
        let named_context = openat(
            &self.parent,
            &self.name,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
            Mode::empty(),
        )
        .map_err(|error| format!("could not reopen the owned probe context by name: {error}"))?;
        if FileIdentity::of(&named_context)? != self.directory_identity {
            return Err("probe context name no longer identifies the owned directory".to_owned());
        }
        self.verify_exact_entries(&named_context)?;
        self.remove_payload()?;
        let named_context = openat(
            &self.parent,
            &self.name,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
            Mode::empty(),
        )
        .map_err(|error| {
            format!("could not revalidate the owned probe context before removal: {error}")
        })?;
        if FileIdentity::of(&named_context)? != self.directory_identity {
            return Err("probe context name changed before directory removal".to_owned());
        }
        unlinkat(&self.parent, &self.name, AtFlags::REMOVEDIR)
            .map_err(|error| format!("could not remove the exact owned probe context: {error}"))?;
        let metadata = fstat(&self.directory)
            .map_err(|error| format!("could not confirm probe context unlink: {error}"))?;
        if metadata.st_nlink != 0 {
            return Err("owned probe context retained a filesystem name after unlink".to_owned());
        }
        match openat(
            &self.parent,
            &self.name,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
            Mode::empty(),
        ) {
            Err(rustix::io::Errno::NOENT) => {}
            Ok(_replacement) => {
                return Err("a probe context name appeared after directory removal".to_owned());
            }
            Err(error) => {
                return Err(format!(
                    "could not confirm probe context removal by name: {error}"
                ));
            }
        }
        rustix::fs::fsync(&self.parent)
            .map_err(|error| format!("could not sync probe context removal: {error}"))
    }

    fn verify_exact_entries(&self, directory: &OwnedFd) -> Result<(), String> {
        let mut entries = Dir::read_from(directory)
            .map_err(|error| format!("could not scan the owned probe context: {error}"))?;
        let mut payload_seen = false;
        while let Some(entry) = entries.read() {
            let entry = entry
                .map_err(|error| format!("could not read the owned probe context: {error}"))?;
            let name = entry.file_name().to_bytes();
            if matches!(name, b"." | b"..") {
                continue;
            }
            if name != PAYLOAD_NAME.as_bytes() || payload_seen || self.payload_identity.is_none() {
                return Err("probe context contains an unexpected entry".to_owned());
            }
            payload_seen = true;
        }
        if payload_seen == self.payload_identity.is_some() {
            Ok(())
        } else {
            Err("probe context payload is missing".to_owned())
        }
    }

    fn remove_payload(&mut self) -> Result<(), String> {
        let Some(expected_identity) = self.payload_identity else {
            return Ok(());
        };
        let retained_payload = self
            .payload
            .as_ref()
            .ok_or_else(|| "probe payload descriptor was not retained".to_owned())?;
        if ensure_owned_regular_payload(retained_payload)? != expected_identity {
            return Err("retained probe payload identity changed".to_owned());
        }
        let named_payload = openat(
            &self.directory,
            PAYLOAD_NAME,
            OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::NONBLOCK,
            Mode::empty(),
        )
        .map_err(|error| format!("could not reopen the owned probe payload by name: {error}"))?;
        if ensure_owned_regular_payload(&named_payload)? != expected_identity {
            return Err("probe payload name no longer identifies the owned file".to_owned());
        }
        unlinkat(&self.directory, PAYLOAD_NAME, AtFlags::empty())
            .map_err(|error| format!("could not remove the exact owned probe payload: {error}"))?;
        let metadata = fstat(retained_payload)
            .map_err(|error| format!("could not confirm probe payload unlink: {error}"))?;
        if metadata.st_nlink != 0 {
            return Err("probe payload retained another filesystem link after unlink".to_owned());
        }
        self.payload = None;
        self.payload_identity = None;
        Ok(())
    }
}

#[cfg(unix)]
fn direct_child_name(scratch_root: &Path, context_path: &Path) -> Result<OsString, String> {
    if context_path.parent() != Some(scratch_root) {
        return Err("probe context must be a direct scratch-root child".to_owned());
    }
    context_path
        .file_name()
        .filter(|name| !name.is_empty())
        .map(ToOwned::to_owned)
        .ok_or_else(|| "probe context name is unavailable".to_owned())
}

#[cfg(unix)]
fn ensure_private_directory_descriptor(
    descriptor: &impl std::os::fd::AsFd,
    description: &str,
) -> Result<(), String> {
    ensure_owned_directory_descriptor(descriptor, description, 0o700)
}

#[cfg(unix)]
fn ensure_owned_directory_descriptor(
    descriptor: &impl std::os::fd::AsFd,
    description: &str,
    expected_mode: rustix::fs::RawMode,
) -> Result<(), String> {
    let metadata =
        fstat(descriptor).map_err(|error| format!("could not inspect {description}: {error}"))?;
    if FileType::from_raw_mode(metadata.st_mode).is_dir()
        && metadata.st_uid == rustix::process::geteuid().as_raw()
        && metadata.st_mode & 0o777 == expected_mode
    {
        Ok(())
    } else {
        Err(format!(
            "{description} must be owned by the effective user with mode {expected_mode:o}"
        ))
    }
}

#[cfg(unix)]
fn ensure_owned_regular_payload(
    descriptor: &impl std::os::fd::AsFd,
) -> Result<FileIdentity, String> {
    let metadata =
        fstat(descriptor).map_err(|error| format!("could not inspect probe payload: {error}"))?;
    if !FileType::from_raw_mode(metadata.st_mode).is_file()
        || metadata.st_uid != rustix::process::geteuid().as_raw()
        || metadata.st_nlink != 1
    {
        return Err("probe payload is not one owned regular file".to_owned());
    }
    FileIdentity::of(descriptor)
}

#[cfg(unix)]
fn ensure_executable_payload_descriptor(
    descriptor: &impl std::os::fd::AsFd,
    expected_length: usize,
) -> Result<FileIdentity, String> {
    let identity = ensure_owned_regular_payload(descriptor)?;
    let metadata =
        fstat(descriptor).map_err(|error| format!("could not inspect probe payload: {error}"))?;
    let expected_length = u64::try_from(expected_length)
        .map_err(|_| "probe payload length cannot be represented by the host".to_owned())?;
    if metadata.st_mode & 0o777 != 0o555
        || u64::try_from(metadata.st_size).ok() != Some(expected_length)
    {
        return Err("probe payload mode or length changed".to_owned());
    }
    Ok(identity)
}

#[cfg(not(unix))]
struct ProbeContext {
    path: PathBuf,
    payload_created: bool,
}

#[cfg(not(unix))]
impl ProbeContext {
    fn create(scratch_root: &Path, context_path: &Path) -> Result<Self, String> {
        if context_path.parent() != Some(scratch_root) {
            return Err("probe context must be a direct scratch-root child".to_owned());
        }
        fs::create_dir(context_path)
            .map_err(|error| format!("failed to create unique probe context: {error}"))?;
        Ok(Self {
            path: context_path.to_owned(),
            payload_created: false,
        })
    }

    fn write_payload(&mut self, executable: &[u8]) -> Result<(), String> {
        fs::write(self.path.join(PAYLOAD_NAME), executable)
            .map_err(|error| format!("failed to write the snapshotted runner payload: {error}"))?;
        self.payload_created = true;
        Ok(())
    }

    fn remove(&mut self) -> Result<(), String> {
        let entries = fs::read_dir(&self.path)
            .map_err(|error| format!("could not scan the owned probe context: {error}"))?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|error| format!("could not read the owned probe context: {error}"))?;
        if entries.len() != usize::from(self.payload_created)
            || entries
                .first()
                .is_some_and(|entry| entry.file_name() != PAYLOAD_NAME)
        {
            return Err("probe context contains an unexpected entry".to_owned());
        }
        if self.payload_created {
            fs::remove_file(self.path.join(PAYLOAD_NAME))
                .map_err(|error| format!("could not remove the probe payload: {error}"))?;
            self.payload_created = false;
        }
        fs::remove_dir(&self.path)
            .map_err(|error| format!("could not remove the exact probe context: {error}"))
    }
}

#[cfg(unix)]
fn verify_probe_context_for_use(
    context: &ProbeContext,
    expected_payload: &[u8],
) -> Result<(), String> {
    context.verify_for_use(expected_payload)
}

#[cfg(not(unix))]
fn verify_probe_context_for_use(
    _context: &ProbeContext,
    _expected_payload: &[u8],
) -> Result<(), String> {
    Err("active Podman probing is unsupported on this platform".to_owned())
}

fn canonical_podman_identifier(kind: ResourceKind, value: &str) -> Option<&str> {
    let value = match kind {
        ResourceKind::Container | ResourceKind::Network => value,
    };
    (value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f')))
    .then_some(value)
}

fn parse_created_resource_identifier(
    kind: ResourceKind,
    output: &CommandOutput,
    stage: &str,
) -> Result<String, ProbeFailure> {
    if output.was_truncated() {
        return Err(ProbeFailure::degraded(
            ProbeReasonCode::ActiveProbeCommandFailed,
            format!("{stage} identifier output exceeded its capture limit"),
        ));
    }
    let identifier = parse_exact_single_line(output.stdout())
        .and_then(|identifier| canonical_podman_identifier(kind, identifier));
    identifier.map(str::to_owned).ok_or_else(|| {
        ProbeFailure::degraded(
            ProbeReasonCode::ActiveProbeCommandFailed,
            format!("{stage} returned a non-canonical resource identifier"),
        )
    })
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

fn parse_exact_single_line(output: &str) -> Option<&str> {
    let line = output.strip_suffix('\n')?;
    (!line.is_empty() && !line.bytes().any(|byte| matches!(byte, b'\n' | b'\r'))).then_some(line)
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
        CommandTermination::ExecutionIntegrityFailed | CommandTermination::Exited(_) => Err(
            ProbeFailure::degraded(ProbeReasonCode::ActiveProbeCommandFailed, detail),
        ),
    }
}
