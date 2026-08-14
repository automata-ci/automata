use std::{
    collections::{BTreeMap, BTreeSet},
    error::Error,
    fmt,
    time::Duration,
};

use automata_ci_core::JobResourceAllocation;
use automata_ci_execution::{
    Cancellation, CopyToRequest, DestroyDisposition, DestroySandbox, EnvironmentProfile,
    ExecutionArgv, ExecutionCommand, ExecutionError, ExecutionErrorKind, ExecutionStage,
    ExecutionTermination, NetworkPolicy, OperationId, OperationOutcome, ProviderError,
    ResourceLimits, RootFilesystemPolicy, SandboxCapability, SandboxEnvironment, SandboxGeneration,
    SandboxHandle, SandboxPrivilegePolicy, SandboxProvider, SandboxSpec, SandboxState, TargetPath,
    TargetPlatform,
};
use automata_ci_job_executor_github::{WindowsScriptShell, windows_script_arguments};
use uuid::Uuid;

use crate::podman_probe::ProbeCancellation;

const ADMISSION_GENERATION: u64 = 1;
const OPERATION_DOMAIN: [u8; 16] = *b"automata-profile";
const SHELL_PROBE_TIMEOUT: Duration = Duration::from_secs(15);
const SHELL_PROBE_OUTPUT_BYTES: usize = 4 * 1024;
const WINDOWS_SHELL_PROBE_COUNT: usize = 3;
const MAX_SHELL_PROBE_COUNT: usize = WINDOWS_SHELL_PROBE_COUNT + 1;
const POWERSHELL_PROBE_SCRIPT: &[u8] = b"$ErrorActionPreference = 'Stop'\r\nexit 0\r\n";
const CMD_PROBE_SCRIPT: &[u8] = b"@echo off\r\nexit /B 0\r\n";
const PYTHON_PROBE_SCRIPT: &[u8] = b"raise SystemExit(0)\r\n";
const POSIX_PROBE_SCRIPT: &[u8] = b"set -eu\nexit 0\n";

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct ProfileAdmissionPolicy {
    network: NetworkPolicy,
    root_filesystem: RootFilesystemPolicy,
    privilege: SandboxPrivilegePolicy,
    resources: ResourceLimits,
    resource_allocation: JobResourceAllocation,
    shell_probes: Option<ShellProbePolicy>,
}
#[derive(Clone, Debug, Eq, PartialEq)]
struct ShellProbePolicy {
    scratch_root: Option<TargetPath>,
    probes: Vec<ShellProbe>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ShellProbe {
    kind: ShellKind,
    program: TargetPath,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ShellKind {
    Bash,
    Sh,
    Pwsh,
    WindowsPowerShell,
    Cmd,
    Python,
}

impl ShellProbe {
    const fn new(kind: ShellKind, program: TargetPath) -> Self {
        Self { kind, program }
    }

    const fn script_name(&self) -> &'static str {
        match self.kind {
            ShellKind::Bash => "profile admission bash.sh",
            ShellKind::Sh => "profile admission sh.sh",
            ShellKind::Pwsh => "profile admission pwsh.ps1",
            ShellKind::WindowsPowerShell => "profile admission powershell.ps1",
            ShellKind::Cmd => "profile admission cmd.cmd",
            ShellKind::Python => "profile admission python.py",
        }
    }

    const fn script_content(&self) -> &'static [u8] {
        match self.kind {
            ShellKind::Bash | ShellKind::Sh => POSIX_PROBE_SCRIPT,
            ShellKind::Pwsh | ShellKind::WindowsPowerShell => POWERSHELL_PROBE_SCRIPT,
            ShellKind::Cmd => CMD_PROBE_SCRIPT,
            ShellKind::Python => PYTHON_PROBE_SCRIPT,
        }
    }

    fn argv(&self, script: &TargetPath) -> Result<ExecutionArgv, ProfileAdmissionError> {
        let arguments = match (self.kind, script.platform()) {
            (ShellKind::Bash, TargetPlatform::Posix) => vec![
                "--noprofile".to_owned(),
                "--norc".to_owned(),
                "-e".to_owned(),
                script.as_str().to_owned(),
            ],
            (ShellKind::Sh, TargetPlatform::Posix) => {
                vec!["-e".to_owned(), script.as_str().to_owned()]
            }
            (ShellKind::Pwsh, TargetPlatform::Posix) => vec![
                "-command".to_owned(),
                format!(". '{}'", script.as_str().replace('\'', "''")),
            ],
            (ShellKind::Python, TargetPlatform::Posix) => {
                vec![script.as_str().to_owned()]
            }
            (ShellKind::Pwsh | ShellKind::WindowsPowerShell, TargetPlatform::Windows) => {
                windows_script_arguments(WindowsScriptShell::PowerShell, script)
                    .ok_or_else(invalid_catalog)?
            }
            (ShellKind::Cmd, TargetPlatform::Windows) => {
                windows_script_arguments(WindowsScriptShell::Cmd, script)
                    .ok_or_else(invalid_catalog)?
            }
            (ShellKind::Python, TargetPlatform::Windows) => vec![script.as_str().to_owned()],
            _ => return Err(invalid_catalog()),
        };
        ExecutionArgv::new(self.program.clone(), arguments).map_err(|_| invalid_catalog())
    }
}

impl ProfileAdmissionPolicy {
    pub(super) const fn new(
        network: NetworkPolicy,
        root_filesystem: RootFilesystemPolicy,
        privilege: SandboxPrivilegePolicy,
        resources: ResourceLimits,
        resource_allocation: JobResourceAllocation,
    ) -> Self {
        Self {
            network,
            root_filesystem,
            privilege,
            resources,
            resource_allocation,
            shell_probes: None,
        }
    }

    pub(super) fn with_windows_hyperv_shells(
        mut self,
        pwsh: TargetPath,
        powershell: TargetPath,
        cmd: TargetPath,
        python: Option<TargetPath>,
    ) -> Result<Self, ProfileAdmissionError> {
        if self.shell_probes.is_some()
            || [pwsh.platform(), powershell.platform(), cmd.platform()]
                .into_iter()
                .any(|platform| platform != automata_ci_execution::TargetPlatform::Windows)
            || python.as_ref().is_some_and(|python| {
                python.platform() != automata_ci_execution::TargetPlatform::Windows
            })
        {
            return Err(invalid_catalog());
        }
        let mut shell_probes = vec![
            ShellProbe::new(ShellKind::Pwsh, pwsh),
            ShellProbe::new(ShellKind::WindowsPowerShell, powershell),
            ShellProbe::new(ShellKind::Cmd, cmd),
        ];
        if let Some(python) = python {
            shell_probes.push(ShellProbe::new(ShellKind::Python, python));
        }
        self.shell_probes = Some(ShellProbePolicy {
            scratch_root: None,
            probes: shell_probes,
        });
        Ok(self)
    }

    pub(super) fn with_virtualized_macos_shells(
        mut self,
        scratch_root: TargetPath,
        bash: TargetPath,
        sh: TargetPath,
        python: Option<TargetPath>,
        pwsh: Option<TargetPath>,
    ) -> Result<Self, ProfileAdmissionError> {
        if self.shell_probes.is_some()
            || [scratch_root.platform(), bash.platform(), sh.platform()]
                .into_iter()
                .any(|platform| platform != TargetPlatform::Posix)
            || python
                .as_ref()
                .is_some_and(|python| python.platform() != TargetPlatform::Posix)
            || pwsh
                .as_ref()
                .is_some_and(|pwsh| pwsh.platform() != TargetPlatform::Posix)
        {
            return Err(invalid_catalog());
        }
        let mut shell_probes = vec![
            ShellProbe::new(ShellKind::Bash, bash),
            ShellProbe::new(ShellKind::Sh, sh),
        ];
        if let Some(python) = python {
            shell_probes.push(ShellProbe::new(ShellKind::Python, python));
        }
        if let Some(pwsh) = pwsh {
            shell_probes.push(ShellProbe::new(ShellKind::Pwsh, pwsh));
        }
        self.shell_probes = Some(ShellProbePolicy {
            scratch_root: Some(scratch_root),
            probes: shell_probes,
        });
        Ok(self)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum ProfileAdmissionOutcome {
    Admitted,
    Cancelled,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum ProfileAdmissionErrorKind {
    InvalidCatalog,
    InvalidProviderEvidence,
    CreateFailed,
    InvalidCreateEvidence,
    InspectFailed,
    InvalidInspectionEvidence,
    AttachFailed,
    InvalidAttachEvidence,
    CopyFailed,
    InvalidCopyEvidence,
    ExecutionFailed,
    InvalidExecutionEvidence,
    DestroyFailed,
    InvalidDestroyEvidence,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum ProfileAdmissionCleanupStatus {
    NotRequired,
    Complete,
    Failed,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct ProfileAdmissionError {
    kind: ProfileAdmissionErrorKind,
    cleanup: ProfileAdmissionCleanupStatus,
    provider_error: Option<ProviderError>,
    execution_error: Option<ExecutionError>,
    cleanup_error: Option<ProviderError>,
}

impl ProfileAdmissionError {
    const fn evidence(
        kind: ProfileAdmissionErrorKind,
        cleanup: ProfileAdmissionCleanupStatus,
        cleanup_error: Option<ProviderError>,
    ) -> Self {
        Self {
            kind,
            cleanup,
            provider_error: None,
            execution_error: None,
            cleanup_error,
        }
    }

    const fn provider(
        kind: ProfileAdmissionErrorKind,
        provider_error: ProviderError,
        cleanup: ProfileAdmissionCleanupStatus,
        cleanup_error: Option<ProviderError>,
    ) -> Self {
        Self {
            kind,
            cleanup,
            provider_error: Some(provider_error),
            execution_error: None,
            cleanup_error,
        }
    }

    const fn execution(
        kind: ProfileAdmissionErrorKind,
        execution_error: ExecutionError,
        cleanup: ProfileAdmissionCleanupStatus,
        cleanup_error: Option<ProviderError>,
    ) -> Self {
        Self {
            kind,
            cleanup,
            provider_error: None,
            execution_error: Some(execution_error),
            cleanup_error,
        }
    }

    pub(super) const fn kind(&self) -> ProfileAdmissionErrorKind {
        self.kind
    }

    pub(super) const fn cleanup_status(&self) -> ProfileAdmissionCleanupStatus {
        self.cleanup
    }

    pub(super) const fn provider_error(&self) -> Option<&ProviderError> {
        self.provider_error.as_ref()
    }

    pub(super) const fn execution_error(&self) -> Option<&ExecutionError> {
        self.execution_error.as_ref()
    }

    pub(super) const fn cleanup_error(&self) -> Option<&ProviderError> {
        self.cleanup_error.as_ref()
    }

    fn is_clean_cancellation(&self, cancellation: &ProbeCancellation) -> bool {
        let provider_cancelled = self.provider_error.as_ref().is_some_and(|error| {
            error.kind() == automata_ci_execution::ProviderErrorKind::Cancelled
        });
        let execution_cancelled = self
            .execution_error
            .is_some_and(|error| error.kind() == ExecutionErrorKind::Cancelled);
        cancellation.is_cancelled()
            && self.cleanup != ProfileAdmissionCleanupStatus::Failed
            && (provider_cancelled || execution_cancelled)
    }
}

impl fmt::Display for ProfileAdmissionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("runner environment-profile admission failed")
    }
}

impl Error for ProfileAdmissionError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        self.cleanup_error
            .as_ref()
            .or(self.provider_error.as_ref())
            .map(|error| error as &(dyn Error + 'static))
            .or_else(|| {
                self.execution_error
                    .as_ref()
                    .map(|error| error as &(dyn Error + 'static))
            })
    }
}

pub(super) fn admit_environment_profiles(
    provider: &dyn SandboxProvider,
    environments: &BTreeMap<EnvironmentProfile, SandboxEnvironment>,
    policy: ProfileAdmissionPolicy,
    cancellation: &ProbeCancellation,
) -> Result<ProfileAdmissionOutcome, ProfileAdmissionError> {
    validate_provider_policy(provider, &policy)?;
    let probe_attempt = policy.shell_probes.as_ref().map(|_| OperationId::new());
    validate_catalog(environments, probe_attempt)?;
    let generation = SandboxGeneration::new(ADMISSION_GENERATION).map_err(|_| {
        ProfileAdmissionError::evidence(
            ProfileAdmissionErrorKind::InvalidCatalog,
            ProfileAdmissionCleanupStatus::NotRequired,
            None,
        )
    })?;
    let context = ProfileAdmissionContext {
        provider,
        policy,
        generation,
        probe_attempt,
        provisioning_cancellation: ProvisioningCancellation(cancellation),
        cleanup_cancellation: CleanupCancellation(cancellation),
    };

    for environment in environments.values() {
        if cancellation.is_cancelled() {
            return Ok(ProfileAdmissionOutcome::Cancelled);
        }
        if let Err(error) = context.admit(environment) {
            if error.is_clean_cancellation(cancellation) {
                return Ok(ProfileAdmissionOutcome::Cancelled);
            }
            return Err(error);
        }
    }

    Ok(if cancellation.is_cancelled() {
        ProfileAdmissionOutcome::Cancelled
    } else {
        ProfileAdmissionOutcome::Admitted
    })
}

struct ProfileAdmissionContext<'context> {
    provider: &'context dyn SandboxProvider,
    policy: ProfileAdmissionPolicy,
    generation: SandboxGeneration,
    probe_attempt: Option<OperationId>,
    provisioning_cancellation: ProvisioningCancellation<'context>,
    cleanup_cancellation: CleanupCancellation<'context>,
}

impl ProfileAdmissionContext<'_> {
    fn admit(&self, environment: &SandboxEnvironment) -> Result<(), ProfileAdmissionError> {
        let operation_ids =
            AdmissionOperationIds::for_profile(environment.attestation(), self.probe_attempt);
        let (workspace, scratch) = self.admission_paths(environment, operation_ids.create)?;
        let shell_script_paths = self
            .policy
            .shell_probes
            .as_ref()
            .map(|policy| {
                let script_root = scratch.as_ref().unwrap_or(&workspace);
                policy
                    .probes
                    .iter()
                    .map(|probe| target_child(script_root, probe.script_name()))
                    .collect::<Result<Vec<_>, _>>()
            })
            .transpose()?;
        let resources = self.policy.resources;
        let mut spec = SandboxSpec::new(
            operation_ids.create,
            self.generation,
            environment.clone(),
            workspace.clone(),
            self.policy.network,
            self.policy.root_filesystem,
            resources,
        )
        .with_privilege(self.policy.privilege)
        .with_resource_allocation(self.policy.resource_allocation);
        if let Some(scratch) = &scratch {
            spec = spec.with_scratch(scratch.clone());
        }
        let record = self.create(environment, &spec, operation_ids.destroy)?;
        self.inspect(environment, &record, operation_ids.destroy)?;
        if let (Some(shell_probes), Some(script_paths)) =
            (&self.policy.shell_probes, shell_script_paths.as_ref())
        {
            self.attach_and_probe(
                environment,
                &record,
                &workspace,
                shell_probes,
                script_paths,
                operation_ids,
            )?;
        }
        self.destroy(&record, operation_ids.destroy)
    }

    fn admission_paths(
        &self,
        environment: &SandboxEnvironment,
        create_operation_id: OperationId,
    ) -> Result<(TargetPath, Option<TargetPath>), ProfileAdmissionError> {
        let Some(shell_probes) = &self.policy.shell_probes else {
            return Ok((environment.workspace().clone(), None));
        };
        let platform = environment.workspace().platform();
        if shell_probes
            .scratch_root
            .as_ref()
            .is_some_and(|root| root.platform() != platform)
            || (platform == TargetPlatform::Windows
                && (environment.workspace().as_str().contains(['%', '"'])
                    || shell_probes
                        .scratch_root
                        .as_ref()
                        .is_some_and(|root| root.as_str().contains(['%', '"']))))
        {
            return Err(invalid_catalog());
        }
        let suffix = format!("profile-admission-{create_operation_id}");
        let workspace = target_child(environment.workspace(), &suffix)?;
        let scratch = shell_probes
            .scratch_root
            .as_ref()
            .map(|root| target_child(root, &suffix))
            .transpose()?;
        Ok((workspace, scratch))
    }

    fn create(
        &self,
        environment: &SandboxEnvironment,
        spec: &SandboxSpec,
        destroy_operation_id: OperationId,
    ) -> Result<automata_ci_execution::SandboxRecord, ProfileAdmissionError> {
        let record = match self.provider.create(spec, &self.provisioning_cancellation) {
            Ok(record) => record,
            Err(error) => {
                let recovery_handle = error.recovery_handle().cloned();
                let (cleanup, cleanup_error) = cleanup_after_create_failure(
                    self.provider,
                    recovery_handle.as_ref(),
                    self.generation,
                    destroy_operation_id,
                    error.outcome(),
                    &self.cleanup_cancellation,
                );
                return Err(ProfileAdmissionError::provider(
                    ProfileAdmissionErrorKind::CreateFailed,
                    error,
                    cleanup,
                    cleanup_error,
                ));
            }
        };

        if record.handle().provider() != self.provider.provider_id()
            || record.generation() != self.generation
            || record.profile() != environment.attestation()
            || record.state() != SandboxState::Running
        {
            let (cleanup, cleanup_error) = cleanup_handle(
                self.provider,
                record.handle(),
                self.generation,
                destroy_operation_id,
                &self.cleanup_cancellation,
            );
            return Err(ProfileAdmissionError::evidence(
                ProfileAdmissionErrorKind::InvalidCreateEvidence,
                cleanup,
                cleanup_error,
            ));
        }
        Ok(record)
    }

    fn inspect(
        &self,
        environment: &SandboxEnvironment,
        record: &automata_ci_execution::SandboxRecord,
        destroy_operation_id: OperationId,
    ) -> Result<(), ProfileAdmissionError> {
        let inspection = match self
            .provider
            .inspect(record.handle(), &self.provisioning_cancellation)
        {
            Ok(inspection) => inspection,
            Err(error) => {
                let (cleanup, cleanup_error) = cleanup_handle(
                    self.provider,
                    record.handle(),
                    self.generation,
                    destroy_operation_id,
                    &self.cleanup_cancellation,
                );
                return Err(ProfileAdmissionError::provider(
                    ProfileAdmissionErrorKind::InspectFailed,
                    error,
                    cleanup,
                    cleanup_error,
                ));
            }
        };
        if inspection.handle() != record.handle()
            || inspection.handle().provider() != self.provider.provider_id()
            || inspection.generation() != self.generation
            || inspection.profile() != environment.attestation()
            || inspection.state() != SandboxState::Running
        {
            let (cleanup, cleanup_error) = cleanup_handle(
                self.provider,
                record.handle(),
                self.generation,
                destroy_operation_id,
                &self.cleanup_cancellation,
            );
            return Err(ProfileAdmissionError::evidence(
                ProfileAdmissionErrorKind::InvalidInspectionEvidence,
                cleanup,
                cleanup_error,
            ));
        }
        Ok(())
    }

    #[allow(clippy::too_many_lines)]
    fn attach_and_probe(
        &self,
        environment: &SandboxEnvironment,
        record: &automata_ci_execution::SandboxRecord,
        workspace: &TargetPath,
        shell_probes: &ShellProbePolicy,
        script_paths: &[TargetPath],
        operation_ids: AdmissionOperationIds,
    ) -> Result<(), ProfileAdmissionError> {
        let endpoint = match self
            .provider
            .attach(record.handle(), &self.provisioning_cancellation)
        {
            Ok(endpoint) => endpoint,
            Err(error) => {
                let (cleanup, cleanup_error) = cleanup_handle(
                    self.provider,
                    record.handle(),
                    self.generation,
                    operation_ids.destroy,
                    &self.cleanup_cancellation,
                );
                return Err(ProfileAdmissionError::provider(
                    ProfileAdmissionErrorKind::AttachFailed,
                    error,
                    cleanup,
                    cleanup_error,
                ));
            }
        };
        if endpoint.handle() != record.handle()
            || ![
                SandboxCapability::CopyTo,
                SandboxCapability::Exec,
                SandboxCapability::EnvironmentInjection,
            ]
            .into_iter()
            .all(|capability| endpoint.capabilities().contains(&capability))
        {
            let (cleanup, cleanup_error) = cleanup_handle(
                self.provider,
                record.handle(),
                self.generation,
                operation_ids.destroy,
                &self.cleanup_cancellation,
            );
            return Err(ProfileAdmissionError::evidence(
                ProfileAdmissionErrorKind::InvalidAttachEvidence,
                cleanup,
                cleanup_error,
            ));
        }

        for ((probe, script), operation_id) in shell_probes
            .probes
            .iter()
            .zip(script_paths)
            .zip(operation_ids.copy)
        {
            let Ok(request) = CopyToRequest::new(
                operation_id,
                script.clone(),
                probe.script_content().to_vec(),
            ) else {
                let (cleanup, cleanup_error) = cleanup_handle(
                    self.provider,
                    record.handle(),
                    self.generation,
                    operation_ids.destroy,
                    &self.cleanup_cancellation,
                );
                return Err(ProfileAdmissionError::evidence(
                    ProfileAdmissionErrorKind::InvalidCopyEvidence,
                    cleanup,
                    cleanup_error,
                ));
            };
            if let Err(error) = endpoint.copy_to(&request, &self.provisioning_cancellation) {
                let (cleanup, cleanup_error) = cleanup_handle(
                    self.provider,
                    record.handle(),
                    self.generation,
                    operation_ids.destroy,
                    &self.cleanup_cancellation,
                );
                return Err(ProfileAdmissionError::execution(
                    ProfileAdmissionErrorKind::CopyFailed,
                    error,
                    cleanup,
                    cleanup_error,
                ));
            }
        }

        for ((probe, script), operation_id) in shell_probes
            .probes
            .iter()
            .zip(script_paths)
            .zip(operation_ids.exec)
        {
            let Ok(argv) = probe.argv(script) else {
                let (cleanup, cleanup_error) = cleanup_handle(
                    self.provider,
                    record.handle(),
                    self.generation,
                    operation_ids.destroy,
                    &self.cleanup_cancellation,
                );
                return Err(ProfileAdmissionError::evidence(
                    ProfileAdmissionErrorKind::InvalidExecutionEvidence,
                    cleanup,
                    cleanup_error,
                ));
            };
            let Ok(command) = ExecutionCommand::new(
                operation_id,
                argv,
                workspace.clone(),
                environment.default_environment().clone(),
                SHELL_PROBE_TIMEOUT,
                SHELL_PROBE_OUTPUT_BYTES,
            ) else {
                let (cleanup, cleanup_error) = cleanup_handle(
                    self.provider,
                    record.handle(),
                    self.generation,
                    operation_ids.destroy,
                    &self.cleanup_cancellation,
                );
                return Err(ProfileAdmissionError::evidence(
                    ProfileAdmissionErrorKind::InvalidExecutionEvidence,
                    cleanup,
                    cleanup_error,
                ));
            };
            let output = match endpoint.exec(&command, &self.provisioning_cancellation) {
                Ok(output) => output,
                Err(error) => {
                    let (cleanup, cleanup_error) = cleanup_handle(
                        self.provider,
                        record.handle(),
                        self.generation,
                        operation_ids.destroy,
                        &self.cleanup_cancellation,
                    );
                    return Err(ProfileAdmissionError::execution(
                        ProfileAdmissionErrorKind::ExecutionFailed,
                        error,
                        cleanup,
                        cleanup_error,
                    ));
                }
            };
            if output.termination() != ExecutionTermination::Exited(0) || output.was_truncated() {
                let (cleanup, cleanup_error) = cleanup_handle(
                    self.provider,
                    record.handle(),
                    self.generation,
                    operation_ids.destroy,
                    &self.cleanup_cancellation,
                );
                if output.termination() == ExecutionTermination::Cancelled
                    && self.provisioning_cancellation.is_cancelled()
                {
                    return Err(ProfileAdmissionError::execution(
                        ProfileAdmissionErrorKind::ExecutionFailed,
                        ExecutionError::new(ExecutionErrorKind::Cancelled, ExecutionStage::Exec),
                        cleanup,
                        cleanup_error,
                    ));
                }
                return Err(ProfileAdmissionError::evidence(
                    ProfileAdmissionErrorKind::InvalidExecutionEvidence,
                    cleanup,
                    cleanup_error,
                ));
            }
        }
        Ok(())
    }

    fn destroy(
        &self,
        record: &automata_ci_execution::SandboxRecord,
        operation_id: OperationId,
    ) -> Result<(), ProfileAdmissionError> {
        match destroy_with_reconciliation(
            self.provider,
            record.handle(),
            self.generation,
            operation_id,
            &self.cleanup_cancellation,
        ) {
            Ok(DestroyEvidence::Destroyed | DestroyEvidence::ReconciledAbsent) => Ok(()),
            Ok(DestroyEvidence::InitiallyAbsent) => Err(ProfileAdmissionError::evidence(
                ProfileAdmissionErrorKind::InvalidDestroyEvidence,
                ProfileAdmissionCleanupStatus::Complete,
                None,
            )),
            Err(error) => Err(ProfileAdmissionError::provider(
                ProfileAdmissionErrorKind::DestroyFailed,
                error.clone(),
                ProfileAdmissionCleanupStatus::Failed,
                Some(error),
            )),
        }
    }
}

fn target_child(root: &TargetPath, child: &str) -> Result<TargetPath, ProfileAdmissionError> {
    if child.is_empty() || child.contains(['/', '\\', ':']) || matches!(child, "." | "..") {
        return Err(invalid_catalog());
    }
    match root.platform() {
        TargetPlatform::Posix => {
            TargetPath::posix(format!("{}/{child}", root.as_str().trim_end_matches('/')))
        }
        TargetPlatform::Windows => {
            TargetPath::windows(format!("{}\\{child}", root.as_str().trim_end_matches('\\')))
        }
    }
    .map_err(|_| invalid_catalog())
}

fn invalid_catalog() -> ProfileAdmissionError {
    ProfileAdmissionError::evidence(
        ProfileAdmissionErrorKind::InvalidCatalog,
        ProfileAdmissionCleanupStatus::NotRequired,
        None,
    )
}

fn validate_provider_policy(
    provider: &dyn SandboxProvider,
    policy: &ProfileAdmissionPolicy,
) -> Result<(), ProfileAdmissionError> {
    if policy.shell_probes.is_some() {
        let common_capabilities = [
            SandboxCapability::WholeJob,
            SandboxCapability::Attach,
            SandboxCapability::Inspect,
            SandboxCapability::CopyTo,
            SandboxCapability::Exec,
            SandboxCapability::EnvironmentInjection,
            SandboxCapability::ResourceLimits,
            SandboxCapability::ProcessLimits,
        ];
        let common_valid = common_capabilities
            .into_iter()
            .all(|capability| provider.capabilities().supports(capability));
        let boundary_valid = policy.network == NetworkPolicy::Disabled
            && policy.root_filesystem == RootFilesystemPolicy::Writable
            && policy.privilege == SandboxPrivilegePolicy::Unprivileged
            && provider
                .capabilities()
                .supports(SandboxCapability::WritableRootFilesystem)
            && provider
                .capabilities()
                .supports(SandboxCapability::NetworkDisabled);
        if !common_valid || !boundary_valid {
            return Err(ProfileAdmissionError::evidence(
                ProfileAdmissionErrorKind::InvalidProviderEvidence,
                ProfileAdmissionCleanupStatus::NotRequired,
                None,
            ));
        }
    }
    Ok(())
}

fn validate_catalog(
    environments: &BTreeMap<EnvironmentProfile, SandboxEnvironment>,
    probe_attempt: Option<OperationId>,
) -> Result<(), ProfileAdmissionError> {
    let mut operation_ids = BTreeSet::new();
    if environments.is_empty()
        || environments.iter().any(|(profile, environment)| {
            profile != environment.attestation()
                || !AdmissionOperationIds::for_profile(profile, probe_attempt)
                    .values()
                    .into_iter()
                    .all(|operation_id| operation_ids.insert(operation_id))
        })
    {
        return Err(ProfileAdmissionError::evidence(
            ProfileAdmissionErrorKind::InvalidCatalog,
            ProfileAdmissionCleanupStatus::NotRequired,
            None,
        ));
    }
    Ok(())
}

fn cleanup_after_create_failure(
    provider: &dyn SandboxProvider,
    recovery_handle: Option<&SandboxHandle>,
    generation: SandboxGeneration,
    operation_id: OperationId,
    outcome: OperationOutcome,
    cancellation: &dyn Cancellation,
) -> (ProfileAdmissionCleanupStatus, Option<ProviderError>) {
    match recovery_handle {
        Some(handle) => cleanup_handle(provider, handle, generation, operation_id, cancellation),
        None if outcome == OperationOutcome::KnownNoEffect => {
            (ProfileAdmissionCleanupStatus::NotRequired, None)
        }
        None => (ProfileAdmissionCleanupStatus::Failed, None),
    }
}

fn cleanup_handle(
    provider: &dyn SandboxProvider,
    handle: &SandboxHandle,
    generation: SandboxGeneration,
    operation_id: OperationId,
    cancellation: &dyn Cancellation,
) -> (ProfileAdmissionCleanupStatus, Option<ProviderError>) {
    match destroy_with_reconciliation(provider, handle, generation, operation_id, cancellation) {
        Ok(_) => (ProfileAdmissionCleanupStatus::Complete, None),
        Err(error) => (ProfileAdmissionCleanupStatus::Failed, Some(error)),
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum DestroyEvidence {
    Destroyed,
    ReconciledAbsent,
    InitiallyAbsent,
}

fn destroy_with_reconciliation(
    provider: &dyn SandboxProvider,
    handle: &SandboxHandle,
    generation: SandboxGeneration,
    operation_id: OperationId,
    cancellation: &dyn Cancellation,
) -> Result<DestroyEvidence, ProviderError> {
    let request = DestroySandbox::new(operation_id, handle.clone(), generation);
    match provider.destroy(&request, cancellation) {
        Ok(DestroyDisposition::Destroyed) => Ok(DestroyEvidence::Destroyed),
        Ok(DestroyDisposition::AlreadyAbsent) => Ok(DestroyEvidence::InitiallyAbsent),
        Err(error)
            if error.outcome() == OperationOutcome::Uncertain
                && error
                    .recovery_handle()
                    .is_none_or(|recovery_handle| recovery_handle == handle) =>
        {
            match provider.destroy(&request, cancellation)? {
                DestroyDisposition::Destroyed => Ok(DestroyEvidence::Destroyed),
                DestroyDisposition::AlreadyAbsent => Ok(DestroyEvidence::ReconciledAbsent),
            }
        }
        Err(error) => Err(error),
    }
}

#[derive(Clone, Copy)]
struct AdmissionOperationIds {
    create: OperationId,
    destroy: OperationId,
    copy: [OperationId; MAX_SHELL_PROBE_COUNT],
    exec: [OperationId; MAX_SHELL_PROBE_COUNT],
}

impl AdmissionOperationIds {
    fn for_profile(profile: &EnvironmentProfile, probe_attempt: Option<OperationId>) -> Self {
        Self {
            create: operation_id(profile, probe_attempt, 0x43),
            destroy: operation_id(profile, probe_attempt, 0x44),
            copy: [
                operation_id(profile, probe_attempt, 0x60),
                operation_id(profile, probe_attempt, 0x61),
                operation_id(profile, probe_attempt, 0x62),
                operation_id(profile, probe_attempt, 0x63),
            ],
            exec: [
                operation_id(profile, probe_attempt, 0x50),
                operation_id(profile, probe_attempt, 0x51),
                operation_id(profile, probe_attempt, 0x52),
                operation_id(profile, probe_attempt, 0x53),
            ],
        }
    }

    const fn values(self) -> [OperationId; 2 + MAX_SHELL_PROBE_COUNT * 2] {
        [
            self.create,
            self.destroy,
            self.copy[0],
            self.copy[1],
            self.copy[2],
            self.copy[3],
            self.exec[0],
            self.exec[1],
            self.exec[2],
            self.exec[3],
        ]
    }
}

fn operation_id(
    profile: &EnvironmentProfile,
    probe_attempt: Option<OperationId>,
    purpose: u8,
) -> OperationId {
    let digest = profile.digest().into_bytes();
    let mut bytes = [0_u8; 16];
    for index in 0..bytes.len() {
        bytes[index] = digest[index] ^ digest[index + bytes.len()] ^ OPERATION_DOMAIN[index];
    }
    let mut ordinal = 0_u8;
    for (index, byte) in profile.id().as_str().bytes().enumerate() {
        let lane = index % bytes.len();
        bytes[lane] = bytes[lane].rotate_left(5) ^ byte ^ ordinal.wrapping_mul(0x9d);
        ordinal = ordinal.wrapping_add(1);
    }
    if let Some(probe_attempt) = probe_attempt {
        for (index, byte) in probe_attempt
            .as_uuid()
            .as_bytes()
            .iter()
            .copied()
            .enumerate()
        {
            bytes[index] = bytes[index].rotate_left(3) ^ byte ^ 0xa7;
        }
    }
    bytes[15] ^= purpose;
    bytes[6] = (bytes[6] & 0x0f) | 0x80;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    OperationId::from_uuid(Uuid::from_bytes(bytes))
}

struct ProvisioningCancellation<'cancellation>(&'cancellation ProbeCancellation);

impl Cancellation for ProvisioningCancellation<'_> {
    fn is_cancelled(&self) -> bool {
        self.0.is_cancelled()
    }
}

struct CleanupCancellation<'cancellation>(&'cancellation ProbeCancellation);

impl Cancellation for CleanupCancellation<'_> {
    fn is_cancelled(&self) -> bool {
        self.0.is_forced()
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use automata_ci_execution::{
        CopyFromRequest, ExecutionEndpoint, ExecutionEnvironment, ExecutionOutput,
        ExecutionOutputRecord, ExecutionOutputStream, ImmutableImage, ProviderCapabilities,
        ProviderErrorKind, ProviderId, ProviderStage, SandboxInspection, SandboxRecord,
        SignalRequest, WaitRequest,
    };

    use super::*;

    #[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
    enum FakeBehavior {
        #[default]
        Happy,
        CreateFailureWithRecovery,
        CreateState(SandboxState),
        InspectState(SandboxState),
        DestroyInitiallyAbsent,
        DestroyUncertainOnce,
        CancelAfterCreate(u8),
        InspectAndDestroyFailure,
        ExecTermination(ExecutionTermination),
        ExecTruncated,
    }

    #[derive(Clone, Debug, Eq, PartialEq)]
    enum Call {
        Create(Box<SandboxSpec>),
        Inspect(SandboxHandle),
        Attach(SandboxHandle),
        CopyTo(CopyToRequest),
        Exec(Box<ExecutionCommand>),
        Destroy(DestroySandbox, bool),
    }

    #[derive(Debug)]
    struct FakeState {
        calls: Vec<Call>,
        resources: BTreeMap<SandboxHandle, (SandboxGeneration, EnvironmentProfile)>,
    }

    #[derive(Debug)]
    struct FakeProvider {
        id: ProviderId,
        capabilities: ProviderCapabilities,
        behavior: FakeBehavior,
        signals: ProbeCancellation,
        state: Arc<Mutex<FakeState>>,
    }

    impl FakeProvider {
        fn new(behavior: FakeBehavior, signals: ProbeCancellation) -> Self {
            Self {
                id: ProviderId::new("profile-admission-test").expect("provider id"),
                capabilities: ProviderCapabilities::new([
                    SandboxCapability::WholeJob,
                    SandboxCapability::Attach,
                    SandboxCapability::Inspect,
                    SandboxCapability::CopyTo,
                    SandboxCapability::Exec,
                    SandboxCapability::EnvironmentInjection,
                    SandboxCapability::HostNetwork,
                    SandboxCapability::HostFilesystem,
                    SandboxCapability::HostIdentity,
                    SandboxCapability::NetworkDisabled,
                    SandboxCapability::WritableRootFilesystem,
                    SandboxCapability::ResourceLimits,
                    SandboxCapability::ProcessLimits,
                ])
                .expect("capabilities"),
                behavior,
                signals,
                state: Arc::new(Mutex::new(FakeState {
                    calls: Vec::new(),
                    resources: BTreeMap::new(),
                })),
            }
        }

        fn calls(&self) -> Vec<Call> {
            self.state.lock().expect("fake state").calls.clone()
        }

        fn resource_count(&self) -> usize {
            self.state.lock().expect("fake state").resources.len()
        }
    }

    impl SandboxProvider for FakeProvider {
        fn provider_id(&self) -> &ProviderId {
            &self.id
        }

        fn capabilities(&self) -> &ProviderCapabilities {
            &self.capabilities
        }

        fn create(
            &self,
            spec: &SandboxSpec,
            cancellation: &dyn Cancellation,
        ) -> Result<SandboxRecord, ProviderError> {
            if cancellation.is_cancelled() {
                return Err(cancelled(ProviderStage::CreateSandbox));
            }
            let handle =
                SandboxHandle::new(self.id.clone(), format!("profile-{}", spec.operation_id()))
                    .expect("handle");
            let mut state = self.state.lock().expect("fake state");
            state.calls.push(Call::Create(Box::new(spec.clone())));
            state.resources.insert(
                handle.clone(),
                (spec.generation(), spec.profile().attestation().clone()),
            );
            drop(state);
            let cancel_after_create = match self.behavior {
                FakeBehavior::CancelAfterCreate(count) => count,
                _ => 0,
            };
            for _ in 0..cancel_after_create {
                self.signals.cancel();
            }
            if self.behavior == FakeBehavior::CreateFailureWithRecovery {
                return Err(ProviderError::new(
                    ProviderErrorKind::AdapterUnavailable,
                    ProviderStage::Start,
                    OperationOutcome::Uncertain,
                    Some(handle),
                ));
            }
            Ok(SandboxRecord::new(
                handle,
                spec.generation(),
                spec.profile().attestation().clone(),
                match self.behavior {
                    FakeBehavior::CreateState(state) => state,
                    _ => SandboxState::Running,
                },
            ))
        }

        fn attach(
            &self,
            handle: &SandboxHandle,
            cancellation: &dyn Cancellation,
        ) -> Result<Box<dyn ExecutionEndpoint>, ProviderError> {
            if cancellation.is_cancelled() {
                return Err(cancelled(ProviderStage::Attach));
            }
            let mut state = self.state.lock().expect("fake state");
            if !state.resources.contains_key(handle) {
                return Err(ProviderError::new(
                    ProviderErrorKind::NotFound,
                    ProviderStage::Attach,
                    OperationOutcome::KnownNoEffect,
                    None,
                ));
            }
            state.calls.push(Call::Attach(handle.clone()));
            Ok(Box::new(FakeEndpoint {
                handle: handle.clone(),
                state: Arc::clone(&self.state),
                behavior: self.behavior,
            }))
        }

        fn inspect(
            &self,
            handle: &SandboxHandle,
            cancellation: &dyn Cancellation,
        ) -> Result<SandboxInspection, ProviderError> {
            self.state
                .lock()
                .expect("fake state")
                .calls
                .push(Call::Inspect(handle.clone()));
            if cancellation.is_cancelled() {
                return Err(cancelled(ProviderStage::Inspect));
            }
            if self.behavior == FakeBehavior::InspectAndDestroyFailure {
                return Err(ProviderError::new(
                    ProviderErrorKind::AdapterUnavailable,
                    ProviderStage::Inspect,
                    OperationOutcome::KnownNoEffect,
                    None,
                ));
            }
            let state = self.state.lock().expect("fake state");
            let (generation, profile) = state.resources.get(handle).expect("owned resource");
            Ok(SandboxInspection::new(
                handle.clone(),
                *generation,
                profile.clone(),
                match self.behavior {
                    FakeBehavior::InspectState(state) => state,
                    _ => SandboxState::Running,
                },
            ))
        }

        fn destroy(
            &self,
            request: &DestroySandbox,
            cancellation: &dyn Cancellation,
        ) -> Result<DestroyDisposition, ProviderError> {
            let cancelled = cancellation.is_cancelled();
            let mut state = self.state.lock().expect("fake state");
            let first_destroy = !state
                .calls
                .iter()
                .any(|call| matches!(call, Call::Destroy(_, _)));
            state.calls.push(Call::Destroy(request.clone(), cancelled));
            if cancelled {
                return Err(super::tests::cancelled(ProviderStage::DestroySandbox));
            }
            if self.behavior == FakeBehavior::InspectAndDestroyFailure {
                return Err(ProviderError::new(
                    ProviderErrorKind::BackendRejected,
                    ProviderStage::DestroySandbox,
                    OperationOutcome::KnownNoEffect,
                    None,
                ));
            }
            if self.behavior == FakeBehavior::DestroyInitiallyAbsent {
                state.resources.remove(request.handle());
                return Ok(DestroyDisposition::AlreadyAbsent);
            }
            if self.behavior == FakeBehavior::DestroyUncertainOnce && first_destroy {
                state.resources.remove(request.handle());
                return Err(ProviderError::new(
                    ProviderErrorKind::AdapterUnavailable,
                    ProviderStage::DestroySandbox,
                    OperationOutcome::Uncertain,
                    Some(request.handle().clone()),
                ));
            }
            Ok(if state.resources.remove(request.handle()).is_some() {
                DestroyDisposition::Destroyed
            } else {
                DestroyDisposition::AlreadyAbsent
            })
        }
    }

    #[derive(Debug)]
    struct FakeEndpoint {
        handle: SandboxHandle,
        state: Arc<Mutex<FakeState>>,
        behavior: FakeBehavior,
    }

    impl ExecutionEndpoint for FakeEndpoint {
        fn handle(&self) -> &SandboxHandle {
            &self.handle
        }

        fn capabilities(&self) -> &[SandboxCapability] {
            &[
                SandboxCapability::CopyTo,
                SandboxCapability::Exec,
                SandboxCapability::EnvironmentInjection,
            ]
        }

        fn exec(
            &self,
            request: &ExecutionCommand,
            cancellation: &dyn Cancellation,
        ) -> Result<ExecutionOutput, ExecutionError> {
            self.state
                .lock()
                .expect("fake state")
                .calls
                .push(Call::Exec(Box::new(request.clone())));
            let termination = if cancellation.is_cancelled() {
                ExecutionTermination::Cancelled
            } else if let FakeBehavior::ExecTermination(termination) = self.behavior {
                termination
            } else {
                ExecutionTermination::Exited(0)
            };
            ExecutionOutput::new(
                termination,
                vec![
                    ExecutionOutputRecord::end_of_stream(ExecutionOutputStream::Stdout),
                    ExecutionOutputRecord::end_of_stream(ExecutionOutputStream::Stderr),
                ],
                self.behavior == FakeBehavior::ExecTruncated,
            )
            .map_err(|_| {
                ExecutionError::new(ExecutionErrorKind::LocalStorage, ExecutionStage::Exec)
            })
        }

        fn signal(
            &self,
            _request: SignalRequest,
            _cancellation: &dyn Cancellation,
        ) -> Result<(), ExecutionError> {
            Err(unsupported_execution(ExecutionStage::Signal))
        }

        fn wait(
            &self,
            _request: WaitRequest,
            _cancellation: &dyn Cancellation,
        ) -> Result<i32, ExecutionError> {
            Err(unsupported_execution(ExecutionStage::Wait))
        }

        fn copy_to(
            &self,
            request: &CopyToRequest,
            cancellation: &dyn Cancellation,
        ) -> Result<(), ExecutionError> {
            self.state
                .lock()
                .expect("fake state")
                .calls
                .push(Call::CopyTo(request.clone()));
            if cancellation.is_cancelled() {
                Err(ExecutionError::new(
                    ExecutionErrorKind::Cancelled,
                    ExecutionStage::CopyTo,
                ))
            } else {
                Ok(())
            }
        }

        fn copy_from(
            &self,
            _request: &CopyFromRequest,
            _cancellation: &dyn Cancellation,
        ) -> Result<Vec<u8>, ExecutionError> {
            Err(unsupported_execution(ExecutionStage::CopyFrom))
        }
    }

    const fn unsupported_execution(stage: ExecutionStage) -> ExecutionError {
        ExecutionError::new(ExecutionErrorKind::UnsupportedCapability, stage)
    }

    fn cancelled(stage: ProviderStage) -> ProviderError {
        ProviderError::new(
            ProviderErrorKind::Cancelled,
            stage,
            OperationOutcome::KnownNoEffect,
            None,
        )
    }

    fn environment(
        id: &str,
        profile_digest: [u8; 32],
        image_digest_byte: u8,
    ) -> (EnvironmentProfile, SandboxEnvironment) {
        let profile_id = format!("test.local/{id}");
        let attestation = EnvironmentProfile::new(
            automata_ci_execution::EnvironmentProfileId::new(profile_id).expect("profile id"),
            automata_ci_execution::Sha256Digest::from_bytes(profile_digest),
        );
        let image_digest = format!("{image_digest_byte:02x}").repeat(32);
        let image = ImmutableImage::new(format!(
            "registry.example.test/automata/{id}@sha256:{image_digest}"
        ))
        .expect("immutable image");
        let keepalive = ExecutionArgv::new(
            TargetPath::posix("/bin/sleep").expect("keepalive path"),
            vec!["infinity".to_owned()],
        )
        .expect("keepalive");
        let environment = SandboxEnvironment::new(
            attestation.clone(),
            image,
            keepalive,
            TargetPath::posix(format!("/work/{id}")).expect("workspace"),
            ExecutionEnvironment::empty(),
        )
        .expect("environment");
        (attestation, environment)
    }

    fn resource_allocation(resources: ResourceLimits) -> JobResourceAllocation {
        let capacity = automata_ci_core::ResourceCapacity::new(
            resources.cpu_millis(),
            resources.memory_bytes(),
            0,
            0,
        );
        JobResourceAllocation::new(capacity, capacity).expect("allocation")
    }

    fn policy() -> ProfileAdmissionPolicy {
        let resources = ResourceLimits::new(256 * 1024 * 1024, 1_750, 321).expect("resources");
        ProfileAdmissionPolicy::new(
            NetworkPolicy::Disabled,
            RootFilesystemPolicy::Writable,
            SandboxPrivilegePolicy::Administrator,
            resources,
            resource_allocation(resources),
        )
    }

    fn profile_digest(seed: u8) -> [u8; 32] {
        let mut value = seed;
        std::array::from_fn(|_| {
            let byte = value;
            value = value.wrapping_add(0x1d);
            byte
        })
    }

    fn windows_hyperv_fixture() -> (
        BTreeMap<EnvironmentProfile, SandboxEnvironment>,
        ProfileAdmissionPolicy,
    ) {
        let attestation = EnvironmentProfile::new(
            automata_ci_execution::EnvironmentProfileId::new("test.local/windows-fixture")
                .expect("profile id"),
            automata_ci_execution::Sha256Digest::from_bytes(profile_digest(0x2a)),
        );
        let environment = SandboxEnvironment::windows_hyperv_container(
            attestation.clone(),
            ImmutableImage::new(concat!(
                "mcr.microsoft.com/windows/servercore@sha256:",
                "1111111111111111111111111111111111111111111111111111111111111111"
            ))
            .expect("pinned Windows image"),
            ExecutionArgv::new(
                TargetPath::windows(r"C:\automata\guest\automata-ci-sandbox-guest.exe")
                    .expect("guest agent path"),
                vec!["keepalive".to_owned()],
            )
            .expect("keepalive argv"),
            TargetPath::windows(r"D:\automata\profiles").expect("profile workspace"),
            ExecutionEnvironment::empty(),
        )
        .expect("Hyper-V container environment");
        let resources = ResourceLimits::new(256 * 1024 * 1024, 1_000, 16).expect("resources");
        let policy = ProfileAdmissionPolicy::new(
            NetworkPolicy::Disabled,
            RootFilesystemPolicy::Writable,
            SandboxPrivilegePolicy::Unprivileged,
            resources,
            resource_allocation(resources),
        )
        .with_windows_hyperv_shells(
            TargetPath::windows(r"C:\Program Files\PowerShell\7\pwsh.exe").expect("pwsh path"),
            TargetPath::windows(r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe")
                .expect("powershell path"),
            TargetPath::windows(r"C:\Windows\System32\cmd.exe").expect("cmd path"),
            Some(
                TargetPath::windows(r"C:\hostedtoolcache\Python\3.13\x64\python.exe")
                    .expect("python path"),
            ),
        )
        .expect("Hyper-V container admission policy");
        (BTreeMap::from([(attestation, environment)]), policy)
    }

    #[test]
    fn windows_python_probe_is_present_only_when_the_tool_is_configured() {
        let resources = ResourceLimits::new(256 * 1024 * 1024, 1_000, 16).expect("resources");
        let without_python = ProfileAdmissionPolicy::new(
            NetworkPolicy::Disabled,
            RootFilesystemPolicy::Writable,
            SandboxPrivilegePolicy::Unprivileged,
            resources,
            resource_allocation(resources),
        )
        .with_windows_hyperv_shells(
            TargetPath::windows(r"C:\Program Files\PowerShell\7\pwsh.exe").expect("pwsh path"),
            TargetPath::windows(r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe")
                .expect("powershell path"),
            TargetPath::windows(r"C:\Windows\System32\cmd.exe").expect("cmd path"),
            None,
        )
        .expect("Hyper-V container policy without Python");
        let probes = &without_python
            .shell_probes
            .as_ref()
            .expect("shell probe policy")
            .probes;
        assert_eq!(probes.len(), WINDOWS_SHELL_PROBE_COUNT);
        assert!(probes.iter().all(|probe| probe.kind != ShellKind::Python));

        let (_, with_python) = windows_hyperv_fixture();
        let probes = &with_python
            .shell_probes
            .as_ref()
            .expect("shell probe policy")
            .probes;
        assert_eq!(probes.len(), MAX_SHELL_PROBE_COUNT);
        assert_eq!(
            probes.last().map(|probe| probe.kind),
            Some(ShellKind::Python)
        );
    }

    #[test]
    fn every_profile_uses_exact_policy_and_full_lifecycle() {
        let signals = ProbeCancellation::default();
        let provider = FakeProvider::new(FakeBehavior::default(), signals.clone());
        let profiles = BTreeMap::from([
            environment("linux-b", profile_digest(0x22), 0xb2),
            environment("linux-a", profile_digest(0x11), 0xa1),
        ]);

        assert_eq!(
            admit_environment_profiles(&provider, &profiles, policy(), &signals),
            Ok(ProfileAdmissionOutcome::Admitted)
        );
        assert_eq!(provider.resource_count(), 0);
        let calls = provider.calls();
        assert_eq!(calls.len(), profiles.len() * 3);
        for (calls, environment) in calls.chunks_exact(3).zip(profiles.values()) {
            let Call::Create(spec) = &calls[0] else {
                panic!("profile must begin with create")
            };
            assert_eq!(spec.profile(), environment);
            assert_eq!(spec.workspace(), environment.workspace());
            assert_eq!(spec.network(), NetworkPolicy::Disabled);
            assert_eq!(spec.root_filesystem(), RootFilesystemPolicy::Writable);
            assert_eq!(spec.privilege(), SandboxPrivilegePolicy::Administrator);
            assert_eq!(spec.resources(), policy().resources);
            assert_eq!(spec.generation().get(), ADMISSION_GENERATION);
            let Call::Inspect(inspected) = &calls[1] else {
                panic!("profile create must be inspected")
            };
            let Call::Destroy(destroyed, cleanup_cancelled) = &calls[2] else {
                panic!("profile inspection must be destroyed")
            };
            assert!(!cleanup_cancelled);
            assert_eq!(inspected, destroyed.handle());
            assert_eq!(destroyed.generation(), spec.generation());
            assert_ne!(destroyed.operation_id(), spec.operation_id());
        }

        let first_ids: Vec<_> = calls
            .iter()
            .filter_map(|call| match call {
                Call::Create(spec) => Some(spec.operation_id()),
                Call::Destroy(request, _) => Some(request.operation_id()),
                Call::Inspect(_) | Call::Attach(_) | Call::CopyTo(_) | Call::Exec(_) => None,
            })
            .collect();
        assert_eq!(
            admit_environment_profiles(&provider, &profiles, policy(), &signals),
            Ok(ProfileAdmissionOutcome::Admitted)
        );
        let second_ids: Vec<_> = provider.calls()[calls.len()..]
            .iter()
            .filter_map(|call| match call {
                Call::Create(spec) => Some(spec.operation_id()),
                Call::Destroy(request, _) => Some(request.operation_id()),
                Call::Inspect(_) | Call::Attach(_) | Call::CopyTo(_) | Call::Exec(_) => None,
            })
            .collect();
        assert_eq!(first_ids, second_ids);
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn windows_hyperv_admission_uses_only_an_isolated_container_workspace() {
        let signals = ProbeCancellation::default();
        let provider = FakeProvider::new(FakeBehavior::default(), signals.clone());
        let attestation = EnvironmentProfile::new(
            automata_ci_execution::EnvironmentProfileId::new("test.local/windows")
                .expect("profile id"),
            automata_ci_execution::Sha256Digest::from_bytes(profile_digest(0x29)),
        );
        let environment = SandboxEnvironment::windows_hyperv_container(
            attestation.clone(),
            ImmutableImage::new(concat!(
                "mcr.microsoft.com/windows/servercore@sha256:",
                "2222222222222222222222222222222222222222222222222222222222222222"
            ))
            .expect("pinned Windows image"),
            ExecutionArgv::new(
                TargetPath::windows(r"C:\automata\guest\automata-ci-sandbox-guest.exe")
                    .expect("guest agent path"),
                vec!["keepalive".to_owned()],
            )
            .expect("keepalive argv"),
            TargetPath::windows(r"D:\automata\profiles").expect("profile workspace"),
            ExecutionEnvironment::empty(),
        )
        .expect("Hyper-V container environment");
        let expected_environment = environment.default_environment().clone();
        let profiles = BTreeMap::from([(attestation, environment)]);
        let pwsh =
            TargetPath::windows(r"C:\Program Files\PowerShell\7\pwsh.exe").expect("pwsh path");
        let powershell =
            TargetPath::windows(r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe")
                .expect("powershell path");
        let cmd = TargetPath::windows(r"C:\Windows\System32\cmd.exe").expect("cmd path");
        let python = TargetPath::windows(r"C:\hostedtoolcache\Python\3.13\x64\python.exe")
            .expect("python path");
        let resources = ResourceLimits::new(256 * 1024 * 1024, 1_750, 321).expect("resources");
        let policy = ProfileAdmissionPolicy::new(
            NetworkPolicy::Disabled,
            RootFilesystemPolicy::Writable,
            SandboxPrivilegePolicy::Unprivileged,
            resources,
            resource_allocation(resources),
        )
        .with_windows_hyperv_shells(
            pwsh.clone(),
            powershell.clone(),
            cmd.clone(),
            Some(python.clone()),
        )
        .expect("Hyper-V container admission policy");

        assert_eq!(
            admit_environment_profiles(&provider, &profiles, policy, &signals),
            Ok(ProfileAdmissionOutcome::Admitted)
        );
        let calls = provider.calls();
        assert_eq!(calls.len(), 12);
        let Call::Create(spec) = &calls[0] else {
            panic!("profile must begin with create")
        };
        assert!(
            spec.scratch().is_none(),
            "host scratch must not be attached"
        );
        let workspace_suffix = spec
            .workspace()
            .as_str()
            .strip_prefix(r"D:\automata\profiles\profile-admission-")
            .expect("isolated workspace child");
        assert_eq!(workspace_suffix, spec.operation_id().to_string());
        assert_eq!(spec.network(), NetworkPolicy::Disabled);
        assert_eq!(spec.root_filesystem(), RootFilesystemPolicy::Writable);
        assert_eq!(spec.privilege(), SandboxPrivilegePolicy::Unprivileged);
        let Call::Inspect(inspected) = &calls[1] else {
            panic!("Hyper-V container must be inspected")
        };
        let Call::Attach(attached) = &calls[2] else {
            panic!("Hyper-V container must be attached")
        };
        assert_eq!(inspected, attached);
        let expected_scripts = [
            ("profile admission pwsh.ps1", POWERSHELL_PROBE_SCRIPT),
            ("profile admission powershell.ps1", POWERSHELL_PROBE_SCRIPT),
            ("profile admission cmd.cmd", CMD_PROBE_SCRIPT),
            ("profile admission python.py", PYTHON_PROBE_SCRIPT),
        ];
        let mut operation_ids = BTreeSet::from([spec.operation_id()]);
        let copied_scripts = calls[3..7]
            .iter()
            .zip(expected_scripts)
            .map(|(call, (name, content))| {
                let Call::CopyTo(request) = call else {
                    panic!("every shell probe script must be copied before execution")
                };
                assert_eq!(
                    request.target(),
                    &target_child(spec.workspace(), name).expect("expected script target")
                );
                assert_eq!(request.content(), content);
                assert!(operation_ids.insert(request.operation_id()));
                request.target().clone()
            })
            .collect::<Vec<_>>();
        let expected_programs = [&pwsh, &powershell, &cmd, &python];
        for ((call, expected_program), script) in calls[7..11]
            .iter()
            .zip(expected_programs)
            .zip(&copied_scripts)
        {
            let Call::Exec(command) = call else {
                panic!("container shell probe must execute")
            };
            assert_eq!(command.argv().program(), expected_program);
            assert_eq!(command.working_directory(), spec.workspace());
            assert_eq!(command.environment(), &expected_environment);
            assert_eq!(command.timeout(), SHELL_PROBE_TIMEOUT);
            assert_eq!(command.output_limit(), SHELL_PROBE_OUTPUT_BYTES);
            assert!(operation_ids.insert(command.operation_id()));
            assert!(!script.as_str().contains('%'));
        }
        let Call::Exec(pwsh_probe) = &calls[7] else {
            unreachable!()
        };
        let Call::Exec(powershell_probe) = &calls[8] else {
            unreachable!()
        };
        let Call::Exec(cmd_probe) = &calls[9] else {
            unreachable!()
        };
        let Call::Exec(python_probe) = &calls[10] else {
            unreachable!()
        };
        for (command, script) in [pwsh_probe, powershell_probe]
            .into_iter()
            .zip(&copied_scripts)
        {
            let expected = vec!["-command".to_owned(), format!(". '{}'", script.as_str())];
            assert_eq!(command.argv().arguments(), expected.as_slice());
        }
        let expected_cmd_arguments = vec![
            "/D".to_owned(),
            "/E:ON".to_owned(),
            "/V:OFF".to_owned(),
            "/C".to_owned(),
            copied_scripts[2].as_str().to_owned(),
        ];
        assert_eq!(
            cmd_probe.argv().arguments(),
            expected_cmd_arguments.as_slice()
        );
        assert_eq!(
            python_probe.argv().arguments(),
            &[copied_scripts[3].as_str().to_owned()]
        );
        let Call::Destroy(destroyed, false) = &calls[11] else {
            panic!("Hyper-V container must be destroyed after every probe")
        };
        assert!(operation_ids.insert(destroyed.operation_id()));
    }

    #[test]
    fn isolated_shell_admission_requires_every_boundary_capability_before_mutation() {
        let required = [
            SandboxCapability::WholeJob,
            SandboxCapability::Attach,
            SandboxCapability::Inspect,
            SandboxCapability::CopyTo,
            SandboxCapability::Exec,
            SandboxCapability::EnvironmentInjection,
            SandboxCapability::NetworkDisabled,
            SandboxCapability::WritableRootFilesystem,
            SandboxCapability::ResourceLimits,
            SandboxCapability::ProcessLimits,
        ];
        for missing in [
            SandboxCapability::NetworkDisabled,
            SandboxCapability::CopyTo,
            SandboxCapability::WritableRootFilesystem,
            SandboxCapability::ProcessLimits,
        ] {
            let signals = ProbeCancellation::default();
            let mut provider = FakeProvider::new(FakeBehavior::Happy, signals.clone());
            provider.capabilities = ProviderCapabilities::new(
                required
                    .into_iter()
                    .filter(|capability| *capability != missing),
            )
            .expect("capabilities with one required boundary omitted");
            let (profiles, policy) = windows_hyperv_fixture();

            let error = admit_environment_profiles(&provider, &profiles, policy, &signals)
                .expect_err("every isolated boundary must be explicitly advertised");
            assert_eq!(
                error.kind(),
                ProfileAdmissionErrorKind::InvalidProviderEvidence
            );
            assert_eq!(
                error.cleanup_status(),
                ProfileAdmissionCleanupStatus::NotRequired
            );
            assert!(provider.calls().is_empty(), "missing {missing:?}");
        }
    }

    #[test]
    fn shell_admission_rejects_nonzero_or_truncated_probe() {
        for behavior in [
            FakeBehavior::ExecTermination(ExecutionTermination::Exited(7)),
            FakeBehavior::ExecTruncated,
        ] {
            let signals = ProbeCancellation::default();
            let provider = FakeProvider::new(behavior, signals.clone());
            let (profiles, policy) = windows_hyperv_fixture();

            let error = admit_environment_profiles(&provider, &profiles, policy, &signals)
                .expect_err("invalid shell evidence must reject admission");
            assert_eq!(
                error.kind(),
                ProfileAdmissionErrorKind::InvalidExecutionEvidence
            );
            assert_eq!(
                error.cleanup_status(),
                ProfileAdmissionCleanupStatus::Complete
            );
            assert_eq!(provider.resource_count(), 0);
            assert!(matches!(
                provider.calls().as_slice(),
                [
                    Call::Create(_),
                    Call::Inspect(_),
                    Call::Attach(_),
                    Call::CopyTo(_),
                    Call::CopyTo(_),
                    Call::CopyTo(_),
                    Call::CopyTo(_),
                    Call::Exec(_),
                    Call::Destroy(_, false)
                ]
            ));
        }
    }

    #[test]
    fn execution_cancellation_is_clean_only_with_a_signal_and_complete_cleanup() {
        let signals = ProbeCancellation::default();
        let complete = ProfileAdmissionError::execution(
            ProfileAdmissionErrorKind::ExecutionFailed,
            ExecutionError::new(ExecutionErrorKind::Cancelled, ExecutionStage::Exec),
            ProfileAdmissionCleanupStatus::Complete,
            None,
        );
        assert!(!complete.is_clean_cancellation(&signals));

        signals.cancel();
        assert!(complete.is_clean_cancellation(&signals));
        let failed = ProfileAdmissionError::execution(
            ProfileAdmissionErrorKind::ExecutionFailed,
            ExecutionError::new(ExecutionErrorKind::Cancelled, ExecutionStage::Exec),
            ProfileAdmissionCleanupStatus::Failed,
            None,
        );
        assert!(!failed.is_clean_cancellation(&signals));
    }

    #[test]
    fn uncertain_create_recovery_handle_is_destroyed() {
        let signals = ProbeCancellation::default();
        let provider = FakeProvider::new(FakeBehavior::CreateFailureWithRecovery, signals.clone());
        let profiles = BTreeMap::from([environment("linux", profile_digest(0x31), 0x41)]);

        let error = admit_environment_profiles(&provider, &profiles, policy(), &signals)
            .expect_err("create failure cannot admit profile");
        assert_eq!(error.kind(), ProfileAdmissionErrorKind::CreateFailed);
        assert_eq!(
            error.cleanup_status(),
            ProfileAdmissionCleanupStatus::Complete
        );
        assert_eq!(provider.resource_count(), 0);
        assert!(matches!(
            provider.calls().as_slice(),
            [Call::Create(_), Call::Destroy(_, false)]
        ));
    }

    #[test]
    fn invalid_create_and_inspection_evidence_are_cleaned() {
        for behavior in [
            FakeBehavior::CreateState(SandboxState::Created),
            FakeBehavior::InspectState(SandboxState::Degraded),
        ] {
            let signals = ProbeCancellation::default();
            let provider = FakeProvider::new(behavior, signals.clone());
            let profiles = BTreeMap::from([environment("linux", profile_digest(0x51), 0x61)]);
            let error = admit_environment_profiles(&provider, &profiles, policy(), &signals)
                .expect_err("invalid lifecycle evidence cannot admit profile");
            assert!(matches!(
                error.kind(),
                ProfileAdmissionErrorKind::InvalidCreateEvidence
                    | ProfileAdmissionErrorKind::InvalidInspectionEvidence
            ));
            assert_eq!(
                error.cleanup_status(),
                ProfileAdmissionCleanupStatus::Complete
            );
            assert_eq!(provider.resource_count(), 0);
        }
    }

    #[test]
    fn first_shutdown_request_cancels_provisioning_but_not_cleanup() {
        let signals = ProbeCancellation::default();
        let provider = FakeProvider::new(FakeBehavior::CancelAfterCreate(1), signals.clone());
        let profiles = BTreeMap::from([environment("linux", profile_digest(0x71), 0x81)]);

        assert_eq!(
            admit_environment_profiles(&provider, &profiles, policy(), &signals),
            Ok(ProfileAdmissionOutcome::Cancelled)
        );
        assert_eq!(provider.resource_count(), 0);
        assert!(matches!(
            provider.calls().as_slice(),
            [Call::Create(_), Call::Inspect(_), Call::Destroy(_, false)]
        ));
    }

    #[test]
    fn forced_shutdown_reports_failed_cleanup() {
        let signals = ProbeCancellation::default();
        let provider = FakeProvider::new(FakeBehavior::CancelAfterCreate(2), signals.clone());
        let profiles = BTreeMap::from([environment("linux", profile_digest(0x91), 0xa1)]);

        let error = admit_environment_profiles(&provider, &profiles, policy(), &signals)
            .expect_err("forced cancellation may interrupt cleanup but cannot hide it");
        assert_eq!(error.kind(), ProfileAdmissionErrorKind::InspectFailed);
        assert_eq!(
            error.cleanup_status(),
            ProfileAdmissionCleanupStatus::Failed
        );
        assert_eq!(provider.resource_count(), 1);
        assert!(matches!(
            provider.calls().last(),
            Some(Call::Destroy(_, true))
        ));
    }

    #[test]
    fn cleanup_failure_preserves_primary_inspection_failure() {
        let signals = ProbeCancellation::default();
        let provider = FakeProvider::new(FakeBehavior::InspectAndDestroyFailure, signals.clone());
        let profiles = BTreeMap::from([environment("linux", profile_digest(0xb1), 0xc1)]);

        let error = admit_environment_profiles(&provider, &profiles, policy(), &signals)
            .expect_err("cleanup failure cannot admit profile");
        assert_eq!(error.kind(), ProfileAdmissionErrorKind::InspectFailed);
        assert_eq!(
            error.cleanup_status(),
            ProfileAdmissionCleanupStatus::Failed
        );
        assert_eq!(
            error.provider_error().map(ProviderError::kind),
            Some(ProviderErrorKind::AdapterUnavailable)
        );
        assert_eq!(
            error.cleanup_error().map(ProviderError::kind),
            Some(ProviderErrorKind::BackendRejected)
        );
    }

    #[test]
    fn disappearance_before_initial_destroy_fails_admission() {
        let signals = ProbeCancellation::default();
        let provider = FakeProvider::new(FakeBehavior::DestroyInitiallyAbsent, signals.clone());
        let profiles = BTreeMap::from([environment("linux", profile_digest(0xc1), 0xd1)]);

        let error = admit_environment_profiles(&provider, &profiles, policy(), &signals)
            .expect_err("an initially absent destroy target invalidates lifecycle evidence");
        assert_eq!(
            error.kind(),
            ProfileAdmissionErrorKind::InvalidDestroyEvidence
        );
        assert_eq!(
            error.cleanup_status(),
            ProfileAdmissionCleanupStatus::Complete
        );
        assert_eq!(provider.resource_count(), 0);
    }

    #[test]
    fn uncertain_destroy_is_replayed_and_reconciled_absent() {
        let signals = ProbeCancellation::default();
        let provider = FakeProvider::new(FakeBehavior::DestroyUncertainOnce, signals.clone());
        let profiles = BTreeMap::from([environment("linux", profile_digest(0xc7), 0xd7)]);

        assert_eq!(
            admit_environment_profiles(&provider, &profiles, policy(), &signals),
            Ok(ProfileAdmissionOutcome::Admitted)
        );
        assert_eq!(provider.resource_count(), 0);
        let calls = provider.calls();
        assert!(matches!(
            calls.as_slice(),
            [Call::Create(_), Call::Inspect(_), Call::Destroy(first, false), Call::Destroy(second, false)]
                if first == second
        ));
    }

    #[test]
    fn deterministic_operation_collision_fails_before_mutation() {
        let signals = ProbeCancellation::default();
        let provider = FakeProvider::new(FakeBehavior::default(), signals.clone());
        let first_digest = profile_digest(0xd1);
        let mut colliding_digest = first_digest;
        colliding_digest[0] ^= 0x5a;
        colliding_digest[16] ^= 0x5a;
        let profiles = BTreeMap::from([
            environment("linux", first_digest, 0xe1),
            environment("linux", colliding_digest, 0xf1),
        ]);

        let error = admit_environment_profiles(&provider, &profiles, policy(), &signals)
            .expect_err("colliding replay coordinates must fail before create");
        assert_eq!(error.kind(), ProfileAdmissionErrorKind::InvalidCatalog);
        assert_eq!(
            error.cleanup_status(),
            ProfileAdmissionCleanupStatus::NotRequired
        );
        assert!(provider.calls().is_empty());
    }

    #[test]
    fn replay_coordinates_bind_full_digest_and_profile_identity() {
        let (first, _) = environment("linux", profile_digest(0x17), 0x27);
        let mut changed_lower_half = profile_digest(0x17);
        changed_lower_half[16] ^= 0x80;
        let (changed_digest, _) = environment("linux", changed_lower_half, 0x27);
        let (changed_id, _) = environment("linux-other", profile_digest(0x17), 0x27);

        assert_ne!(
            AdmissionOperationIds::for_profile(&first, None).values(),
            AdmissionOperationIds::for_profile(&changed_digest, None).values()
        );
        assert_ne!(
            AdmissionOperationIds::for_profile(&first, None).values(),
            AdmissionOperationIds::for_profile(&changed_id, None).values()
        );
    }
}
