use std::{
    collections::{BTreeMap, BTreeSet},
    error::Error,
    fmt,
    time::Duration,
};

use automata_ci_core::{JobResourceAllocation, RunnerId};
use automata_ci_execution::{
    Cancellation, CopyToRequest, DestroyDisposition, DestroySandbox, EnvironmentProfile,
    ExecutionArgv, ExecutionCommand, ExecutionError, ExecutionErrorKind, ExecutionStage,
    ExecutionTermination, NetworkPolicy, OperationId, OperationOutcome, ProviderError,
    ResourceLimits, RootFilesystemPolicy, SandboxCapability, SandboxCustody, SandboxEnvironment,
    SandboxGeneration, SandboxHandle, SandboxPrivilegePolicy, SandboxProvider, SandboxSpec,
    SandboxState, TargetPath, TargetPlatform,
};
use automata_ci_job_executor_actions::{WindowsScriptShell, windows_script_arguments};
use sha2::{Digest as _, Sha256};
use uuid::Uuid;

use crate::podman_probe::ProbeCancellation;

const ADMISSION_GENERATION: u64 = 1;
const OPERATION_DOMAIN: [u8; 16] = *b"automata-profile";
const SHELL_PROBE_TIMEOUT: Duration = Duration::from_secs(15);
const SHELL_PROBE_OUTPUT_BYTES: usize = 4 * 1024;
#[cfg(test)]
const WINDOWS_SHELL_PROBE_COUNT: usize = 3;
const MAX_SHELL_PROBE_COUNT: usize = 11;
pub(super) const WINDOWS_PROFILE_PROBE_SCHEMA_VERSION: u16 = 1;
// This canonical descriptor is the compatibility boundary for the shared
// enrollment/runtime probe below. Any semantic change to the lifecycle,
// command construction, or acceptance rules must update this descriptor and
// increment the schema version so retained enrollment receipts fail closed.
const WINDOWS_PROFILE_PROBE_CONTRACT_V1: &[u8] = b"automata.windows-profile-probe/v1\n\
lifecycle=validate-provider-policy,create,inspect-running,attach,copy-script,exec,destroy,inspect-absent\n\
cleanup=signal-on-cancel,destroy-with-reconciliation,inspect-absent\n\
pwsh-script=ErrorActionPreference-Stop,Console.Out.Write-exact-operation-marker\n\
powershell-script=ErrorActionPreference-Stop,Console.Out.Write-exact-operation-marker\n\
pwsh-argv=-command,dot-source-single-quoted-exact-script-path\n\
powershell-argv=-command,dot-source-single-quoted-exact-script-path\n\
cmd-script=echo-off,nul-set-p-exact-operation-marker,exit-B-0\n\
cmd-argv=/D,/E:ON,/V:OFF,/C,exact-script-path\n\
python-script=sys.stdout.write-exact-operation-marker,SystemExit-0\n\
python-argv=exact-script-path\n\
tar-argv=--version;stdout-prefix=tar (GNU tar) \n\
sha256-argv=--version;stdout-prefix=automata-sha256 \n\
node12-argv=--input-type=commonjs,--eval,exact-major-12,exact-operation-marker\n\
node16-argv=--input-type=commonjs,--eval,exact-major-16,exact-operation-marker\n\
node20-argv=--input-type=commonjs,--eval,exact-major-20,exact-operation-marker\n\
node24-argv=--input-type=commonjs,--eval,exact-major-24,exact-operation-marker\n\
exec=workspace,default-environment,timeout-15-seconds,output-limit-4096\n\
accept=exit-0,complete-not-truncated,stdout-exact-or-version-prefix,stderr-empty";

pub(super) fn windows_profile_probe_contract_sha256() -> automata_ci_core::Sha256Digest {
    automata_ci_core::Sha256Digest::from_bytes(
        Sha256::digest(WINDOWS_PROFILE_PROBE_CONTRACT_V1).into(),
    )
}

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

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
enum ShellKind {
    Bash,
    Sh,
    Pwsh,
    WindowsPowerShell,
    Cmd,
    Python,
    Install,
    Tar,
    Sha256sum,
    Node12,
    Node16,
    Node20,
    Node24,
}

impl ShellProbe {
    const fn new(kind: ShellKind, program: TargetPath) -> Self {
        Self { kind, program }
    }

    const fn script_name(&self) -> Option<&'static str> {
        Some(match self.kind {
            ShellKind::Bash => "profile admission bash.sh",
            ShellKind::Sh => "profile admission sh.sh",
            ShellKind::Pwsh => "profile admission pwsh.ps1",
            ShellKind::WindowsPowerShell => "profile admission powershell.ps1",
            ShellKind::Cmd => "profile admission cmd.cmd",
            ShellKind::Python => "profile admission python.py",
            ShellKind::Install
            | ShellKind::Tar
            | ShellKind::Sha256sum
            | ShellKind::Node12
            | ShellKind::Node16
            | ShellKind::Node20
            | ShellKind::Node24 => return None,
        })
    }

    fn marker(&self, operation_id: OperationId) -> String {
        let kind = match self.kind {
            ShellKind::Bash => "bash",
            ShellKind::Sh => "sh",
            ShellKind::Pwsh => "pwsh",
            ShellKind::WindowsPowerShell => "powershell",
            ShellKind::Cmd => "cmd",
            ShellKind::Python => "python",
            ShellKind::Install => "install",
            ShellKind::Tar => "tar",
            ShellKind::Sha256sum => "sha256sum",
            ShellKind::Node12 => "node12",
            ShellKind::Node16 => "node16",
            ShellKind::Node20 => "node20",
            ShellKind::Node24 => "node24",
        };
        format!("automata-profile-{kind}-{operation_id}")
    }

    fn script_content(&self, operation_id: OperationId) -> Option<Vec<u8>> {
        let marker = self.marker(operation_id);
        Some(match self.kind {
            ShellKind::Bash | ShellKind::Sh => {
                format!("set -eu\nprintf '%s' '{marker}'\n").into_bytes()
            }
            ShellKind::Pwsh | ShellKind::WindowsPowerShell => {
                format!("$ErrorActionPreference = 'Stop'\r\n[Console]::Out.Write('{marker}')\r\n")
                    .into_bytes()
            }
            ShellKind::Cmd => {
                format!("@echo off\r\n<nul set /p \"={marker}\"\r\nexit /B 0\r\n").into_bytes()
            }
            ShellKind::Python => {
                format!("import sys\r\nsys.stdout.write(\"{marker}\")\r\nraise SystemExit(0)\r\n")
                    .into_bytes()
            }
            ShellKind::Install
            | ShellKind::Tar
            | ShellKind::Sha256sum
            | ShellKind::Node12
            | ShellKind::Node16
            | ShellKind::Node20
            | ShellKind::Node24 => return None,
        })
    }

    fn argv(
        &self,
        script: Option<&TargetPath>,
        operation_id: OperationId,
    ) -> Result<ExecutionArgv, ProfileAdmissionError> {
        let script_platform = script.map(TargetPath::platform);
        let arguments = match (self.kind, script_platform) {
            (ShellKind::Bash, Some(TargetPlatform::Posix)) => vec![
                "--noprofile".to_owned(),
                "--norc".to_owned(),
                "-e".to_owned(),
                script.expect("matched script").as_str().to_owned(),
            ],
            (ShellKind::Sh, Some(TargetPlatform::Posix)) => {
                vec![
                    "-e".to_owned(),
                    script.expect("matched script").as_str().to_owned(),
                ]
            }
            (ShellKind::Pwsh, Some(TargetPlatform::Posix)) => vec![
                "-command".to_owned(),
                format!(
                    ". '{}'",
                    script.expect("matched script").as_str().replace('\'', "''")
                ),
            ],
            (ShellKind::Python, Some(TargetPlatform::Posix | TargetPlatform::Windows)) => {
                vec![script.expect("matched script").as_str().to_owned()]
            }
            (ShellKind::Pwsh | ShellKind::WindowsPowerShell, Some(TargetPlatform::Windows)) => {
                windows_script_arguments(
                    WindowsScriptShell::PowerShell,
                    script.expect("matched script"),
                )
                .ok_or_else(invalid_catalog)?
            }
            (ShellKind::Cmd, Some(TargetPlatform::Windows)) => {
                windows_script_arguments(WindowsScriptShell::Cmd, script.expect("matched script"))
                    .ok_or_else(invalid_catalog)?
            }
            (ShellKind::Install | ShellKind::Tar | ShellKind::Sha256sum, None) => {
                vec!["--version".to_owned()]
            }
            (
                ShellKind::Node12 | ShellKind::Node16 | ShellKind::Node20 | ShellKind::Node24,
                None,
            ) => {
                let major = match self.kind {
                    ShellKind::Node12 => 12,
                    ShellKind::Node16 => 16,
                    ShellKind::Node20 => 20,
                    ShellKind::Node24 => 24,
                    _ => unreachable!(),
                };
                let marker = self.marker(operation_id);
                vec![
                    "--input-type=commonjs".to_owned(),
                    "--eval".to_owned(),
                    format!(
                        "if (process.versions.node.split('.')[0] !== '{major}') process.exit(64); process.stdout.write('{marker}')"
                    ),
                ]
            }
            _ => return Err(invalid_catalog()),
        };
        ExecutionArgv::new(self.program.clone(), arguments).map_err(|_| invalid_catalog())
    }

    fn expected_stdout_matches(&self, operation_id: OperationId, stdout: &[u8]) -> bool {
        match self.kind {
            ShellKind::Install => stdout.starts_with(b"install (GNU coreutils) "),
            ShellKind::Tar => stdout.starts_with(b"tar (GNU tar) "),
            ShellKind::Sha256sum if self.program.platform() == TargetPlatform::Windows => {
                stdout.starts_with(b"automata-sha256 ")
            }
            ShellKind::Sha256sum => stdout.starts_with(b"sha256sum (GNU coreutils) "),
            _ => stdout == self.marker(operation_id).as_bytes(),
        }
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

    #[allow(clippy::too_many_arguments)]
    pub(super) fn with_linux_tools(
        mut self,
        bash: TargetPath,
        sh: TargetPath,
        python: Option<TargetPath>,
        pwsh: Option<TargetPath>,
        install: TargetPath,
        tar: TargetPath,
        sha256sum: TargetPath,
        node12: Option<TargetPath>,
        node16: Option<TargetPath>,
        node20: Option<TargetPath>,
        node24: Option<TargetPath>,
    ) -> Result<Self, ProfileAdmissionError> {
        let mut probes = vec![
            ShellProbe::new(ShellKind::Bash, bash),
            ShellProbe::new(ShellKind::Sh, sh),
        ];
        if let Some(python) = python {
            probes.push(ShellProbe::new(ShellKind::Python, python));
        }
        if let Some(pwsh) = pwsh {
            probes.push(ShellProbe::new(ShellKind::Pwsh, pwsh));
        }
        probes.extend([
            ShellProbe::new(ShellKind::Install, install),
            ShellProbe::new(ShellKind::Tar, tar),
            ShellProbe::new(ShellKind::Sha256sum, sha256sum),
        ]);
        for (kind, program) in [
            (ShellKind::Node12, node12),
            (ShellKind::Node16, node16),
            (ShellKind::Node20, node20),
            (ShellKind::Node24, node24),
        ] {
            if let Some(program) = program {
                probes.push(ShellProbe::new(kind, program));
            }
        }
        if self.shell_probes.is_some()
            || probes.len() > MAX_SHELL_PROBE_COUNT
            || probes.iter().any(|probe| !valid_linux_probe(probe))
        {
            return Err(invalid_catalog());
        }
        self.shell_probes = Some(ShellProbePolicy {
            scratch_root: None,
            probes,
        });
        Ok(self)
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

    #[allow(clippy::too_many_arguments)]
    pub(super) fn with_windows_hyperv_tools(
        self,
        pwsh: TargetPath,
        powershell: TargetPath,
        cmd: TargetPath,
        python: Option<TargetPath>,
        tar: TargetPath,
        sha256: TargetPath,
        node12: Option<TargetPath>,
        node16: Option<TargetPath>,
        node20: Option<TargetPath>,
        node24: Option<TargetPath>,
    ) -> Result<Self, ProfileAdmissionError> {
        let mut policy = self.with_windows_hyperv_shells(pwsh, powershell, cmd, python)?;
        let probes = &mut policy
            .shell_probes
            .as_mut()
            .ok_or_else(invalid_catalog)?
            .probes;
        probes.extend([
            ShellProbe::new(ShellKind::Tar, tar),
            ShellProbe::new(ShellKind::Sha256sum, sha256),
        ]);
        for (kind, program) in [
            (ShellKind::Node12, node12),
            (ShellKind::Node16, node16),
            (ShellKind::Node20, node20),
            (ShellKind::Node24, node24),
        ] {
            if let Some(program) = program {
                probes.push(ShellProbe::new(kind, program));
            }
        }
        if probes.len() > MAX_SHELL_PROBE_COUNT
            || probes.iter().any(|probe| !valid_windows_probe(probe))
        {
            return Err(invalid_catalog());
        }
        Ok(policy)
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

fn valid_linux_probe(probe: &ShellProbe) -> bool {
    if probe.program.platform() != TargetPlatform::Posix || !probe.program.as_str().starts_with('/')
    {
        return false;
    }
    let Some(basename) = probe.program.as_str().rsplit('/').next() else {
        return false;
    };
    match probe.kind {
        ShellKind::Bash => basename == "bash",
        ShellKind::Sh => basename == "sh",
        ShellKind::Pwsh => basename == "pwsh",
        ShellKind::Python => {
            basename == "python"
                || basename == "python3"
                || basename.strip_prefix("python3.").is_some_and(|version| {
                    !version.is_empty() && version.bytes().all(|byte| byte.is_ascii_digit())
                })
        }
        ShellKind::Install => basename == "install",
        ShellKind::Tar => basename == "tar",
        ShellKind::Sha256sum => basename == "sha256sum",
        ShellKind::Node12 | ShellKind::Node16 | ShellKind::Node20 | ShellKind::Node24 => {
            basename == "node"
        }
        ShellKind::WindowsPowerShell | ShellKind::Cmd => false,
    }
}

fn valid_windows_probe(probe: &ShellProbe) -> bool {
    if probe.program.platform() != TargetPlatform::Windows {
        return false;
    }
    let Some(basename) = probe.program.as_str().rsplit('\\').next() else {
        return false;
    };
    match probe.kind {
        ShellKind::Pwsh => basename.eq_ignore_ascii_case("pwsh.exe"),
        ShellKind::WindowsPowerShell => basename.eq_ignore_ascii_case("powershell.exe"),
        ShellKind::Cmd => basename.eq_ignore_ascii_case("cmd.exe"),
        ShellKind::Python => basename.eq_ignore_ascii_case("python.exe"),
        ShellKind::Tar => basename.eq_ignore_ascii_case("tar.exe"),
        ShellKind::Sha256sum => basename.eq_ignore_ascii_case("automata-sha256.exe"),
        ShellKind::Node12 | ShellKind::Node16 | ShellKind::Node20 | ShellKind::Node24 => {
            basename.eq_ignore_ascii_case("node.exe")
        }
        ShellKind::Bash | ShellKind::Sh | ShellKind::Install => false,
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
    runner_id: RunnerId,
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
        runner_id,
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
    runner_id: RunnerId,
    policy: ProfileAdmissionPolicy,
    generation: SandboxGeneration,
    probe_attempt: Option<OperationId>,
    provisioning_cancellation: ProvisioningCancellation<'context>,
    cleanup_cancellation: CleanupCancellation<'context>,
}

impl ProfileAdmissionContext<'_> {
    const fn custody(&self) -> SandboxCustody {
        SandboxCustody::ProfileAdmission {
            runner_id: self.runner_id,
        }
    }

    fn cleanup_after_create_failure(
        &self,
        recovery_handle: Option<&SandboxHandle>,
        operation_id: OperationId,
        outcome: OperationOutcome,
    ) -> (ProfileAdmissionCleanupStatus, Option<ProviderError>) {
        match recovery_handle {
            Some(handle) => self.cleanup_handle(handle, operation_id),
            None if outcome == OperationOutcome::KnownNoEffect => {
                (ProfileAdmissionCleanupStatus::NotRequired, None)
            }
            None => (ProfileAdmissionCleanupStatus::Failed, None),
        }
    }

    fn cleanup_handle(
        &self,
        handle: &SandboxHandle,
        operation_id: OperationId,
    ) -> (ProfileAdmissionCleanupStatus, Option<ProviderError>) {
        match self.destroy_with_reconciliation(handle, operation_id) {
            Ok(_) => (ProfileAdmissionCleanupStatus::Complete, None),
            Err(error) => (ProfileAdmissionCleanupStatus::Failed, Some(error)),
        }
    }

    fn destroy_with_reconciliation(
        &self,
        handle: &SandboxHandle,
        operation_id: OperationId,
    ) -> Result<DestroyEvidence, ProviderError> {
        let request = DestroySandbox::new(
            operation_id,
            handle.clone(),
            self.generation,
            self.custody(),
        );
        match self.provider.destroy(&request, &self.cleanup_cancellation) {
            Ok(DestroyDisposition::Destroyed) => Ok(DestroyEvidence::Destroyed),
            Ok(DestroyDisposition::AlreadyAbsent) => Ok(DestroyEvidence::InitiallyAbsent),
            Err(error)
                if error.outcome() == OperationOutcome::Uncertain
                    && error
                        .recovery_handle()
                        .is_none_or(|recovery_handle| recovery_handle == handle) =>
            {
                match self
                    .provider
                    .destroy(&request, &self.cleanup_cancellation)?
                {
                    DestroyDisposition::Destroyed => Ok(DestroyEvidence::Destroyed),
                    DestroyDisposition::AlreadyAbsent => Ok(DestroyEvidence::ReconciledAbsent),
                }
            }
            Err(error) => Err(error),
        }
    }

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
                    .map(|probe| {
                        probe
                            .script_name()
                            .map(|name| target_child(script_root, name))
                            .transpose()
                    })
                    .collect::<Result<Vec<_>, _>>()
            })
            .transpose()?;
        let resources = self.policy.resources;
        let mut spec = SandboxSpec::new(
            operation_ids.create,
            self.generation,
            self.custody(),
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
                &operation_ids,
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
                let (cleanup, cleanup_error) = self.cleanup_after_create_failure(
                    recovery_handle.as_ref(),
                    destroy_operation_id,
                    error.outcome(),
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
            let (cleanup, cleanup_error) =
                self.cleanup_handle(record.handle(), destroy_operation_id);
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
                let (cleanup, cleanup_error) =
                    self.cleanup_handle(record.handle(), destroy_operation_id);
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
            || inspection.custody() != self.custody()
            || inspection.profile() != environment.attestation()
            || inspection.state() != SandboxState::Running
        {
            let (cleanup, cleanup_error) =
                self.cleanup_handle(record.handle(), destroy_operation_id);
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
        script_paths: &[Option<TargetPath>],
        operation_ids: &AdmissionOperationIds,
    ) -> Result<(), ProfileAdmissionError> {
        let endpoint = match self
            .provider
            .attach(record.handle(), &self.provisioning_cancellation)
        {
            Ok(endpoint) => endpoint,
            Err(error) => {
                let (cleanup, cleanup_error) =
                    self.cleanup_handle(record.handle(), operation_ids.destroy);
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
            let (cleanup, cleanup_error) =
                self.cleanup_handle(record.handle(), operation_ids.destroy);
            return Err(ProfileAdmissionError::evidence(
                ProfileAdmissionErrorKind::InvalidAttachEvidence,
                cleanup,
                cleanup_error,
            ));
        }

        for (((probe, script), operation_id), execution_operation_id) in shell_probes
            .probes
            .iter()
            .zip(script_paths)
            .zip(operation_ids.copy)
            .zip(operation_ids.exec)
        {
            let (Some(script), Some(content)) = (
                script.as_ref(),
                probe.script_content(execution_operation_id),
            ) else {
                if script.is_some() || probe.script_name().is_some() {
                    let (cleanup, cleanup_error) =
                        self.cleanup_handle(record.handle(), operation_ids.destroy);
                    return Err(ProfileAdmissionError::evidence(
                        ProfileAdmissionErrorKind::InvalidCopyEvidence,
                        cleanup,
                        cleanup_error,
                    ));
                }
                continue;
            };
            let Ok(request) = CopyToRequest::new(operation_id, script.clone(), content) else {
                let (cleanup, cleanup_error) =
                    self.cleanup_handle(record.handle(), operation_ids.destroy);
                return Err(ProfileAdmissionError::evidence(
                    ProfileAdmissionErrorKind::InvalidCopyEvidence,
                    cleanup,
                    cleanup_error,
                ));
            };
            if let Err(error) = endpoint.copy_to(&request, &self.provisioning_cancellation) {
                let (cleanup, cleanup_error) =
                    self.cleanup_handle(record.handle(), operation_ids.destroy);
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
            let Ok(argv) = probe.argv(script.as_ref(), operation_id) else {
                let (cleanup, cleanup_error) =
                    self.cleanup_handle(record.handle(), operation_ids.destroy);
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
                let (cleanup, cleanup_error) =
                    self.cleanup_handle(record.handle(), operation_ids.destroy);
                return Err(ProfileAdmissionError::evidence(
                    ProfileAdmissionErrorKind::InvalidExecutionEvidence,
                    cleanup,
                    cleanup_error,
                ));
            };
            let output = match endpoint.exec(
                &command,
                &self.provisioning_cancellation,
                automata_ci_execution::discard_execution_output(),
            ) {
                Ok(output) => output,
                Err(error) => {
                    let (cleanup, cleanup_error) =
                        self.cleanup_handle(record.handle(), operation_ids.destroy);
                    return Err(ProfileAdmissionError::execution(
                        ProfileAdmissionErrorKind::ExecutionFailed,
                        error,
                        cleanup,
                        cleanup_error,
                    ));
                }
            };
            if output.termination() != ExecutionTermination::Exited(0)
                || output.was_truncated()
                || !probe.expected_stdout_matches(operation_id, output.stdout())
                || !output.stderr().is_empty()
            {
                let (cleanup, cleanup_error) =
                    self.cleanup_handle(record.handle(), operation_ids.destroy);
                if output.termination() == ExecutionTermination::Cancelled
                    && self
                        .provisioning_cancellation
                        .disposition()
                        .requires_termination()
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
        match self.destroy_with_reconciliation(record.handle(), operation_id) {
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
        let capabilities = provider.capabilities();
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
            .all(|capability| capabilities.supports(capability));
        let network_valid = match policy.network {
            NetworkPolicy::Disabled => capabilities.supports(SandboxCapability::NetworkDisabled),
            NetworkPolicy::PrivateEgress => capabilities.supports(SandboxCapability::PrivateEgress),
            NetworkPolicy::Host => false,
        };
        let root_valid = match policy.root_filesystem {
            RootFilesystemPolicy::ReadOnly => {
                capabilities.supports(SandboxCapability::ReadOnlyRootFilesystem)
            }
            RootFilesystemPolicy::Writable => {
                capabilities.supports(SandboxCapability::WritableRootFilesystem)
            }
            RootFilesystemPolicy::Host => false,
        };
        let privilege_valid = match policy.privilege {
            SandboxPrivilegePolicy::Unprivileged => true,
            SandboxPrivilegePolicy::Administrator => {
                capabilities.supports(SandboxCapability::Administrator)
                    && capabilities.supports(SandboxCapability::UserNamespace)
            }
            SandboxPrivilegePolicy::Host => false,
        };
        let boundary_valid = network_valid && root_valid && privilege_valid;
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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum DestroyEvidence {
    Destroyed,
    ReconciledAbsent,
    InitiallyAbsent,
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
            copy: std::array::from_fn(|index| {
                let index = u8::try_from(index).expect("profile probe count fits in u8");
                operation_id(profile, probe_attempt, 0x60 + index)
            }),
            exec: std::array::from_fn(|index| {
                let index = u8::try_from(index).expect("profile probe count fits in u8");
                operation_id(profile, probe_attempt, 0x50 + index)
            }),
        }
    }

    fn values(self) -> Vec<OperationId> {
        let mut values = Vec::with_capacity(2 + MAX_SHELL_PROBE_COUNT * 2);
        values.extend([self.create, self.destroy]);
        values.extend(self.copy);
        values.extend(self.exec);
        values
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
    fn disposition(&self) -> automata_ci_execution::CancellationDisposition {
        if self.0.is_cancelled() {
            automata_ci_execution::CancellationDisposition::Terminate
        } else {
            automata_ci_execution::CancellationDisposition::Active
        }
    }
}

struct CleanupCancellation<'cancellation>(&'cancellation ProbeCancellation);

impl Cancellation for CleanupCancellation<'_> {
    fn disposition(&self) -> automata_ci_execution::CancellationDisposition {
        if self.0.is_forced() {
            automata_ci_execution::CancellationDisposition::Terminate
        } else {
            automata_ci_execution::CancellationDisposition::Active
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{
        num::NonZeroU16,
        sync::{Arc, Mutex},
    };

    use automata_ci_execution::{
        CopyFromRequest, ExecutionEndpoint, ExecutionEnvironment, ExecutionOutput,
        ExecutionOutputRecord, ExecutionOutputStream, ImmutableImage, ProviderCapabilities,
        ProviderErrorKind, ProviderId, ProviderStage, SandboxInspection, SandboxRecord,
        SignalRequest, WaitRequest,
    };

    use super::*;

    fn runner_id() -> RunnerId {
        RunnerId::from_uuid(Uuid::from_u128(0x8fe5_8afb_3922_4299_a540_4da9_bfa4_25d6))
    }

    #[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
    enum FakeBehavior {
        #[default]
        Happy,
        CreateFailureWithRecovery,
        CreateState(SandboxState),
        InspectState(SandboxState),
        InspectCustody(SandboxCustody),
        DestroyInitiallyAbsent,
        DestroyUncertainOnce,
        CancelAfterCreate(u8),
        InspectAndDestroyFailure,
        ExecTermination(ExecutionTermination),
        ExecTruncated,
        ExecWrongOutput,
        ExecStderr,
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
        resources: BTreeMap<SandboxHandle, (SandboxGeneration, SandboxCustody, EnvironmentProfile)>,
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
                    SandboxCapability::PrivateEgress,
                    SandboxCapability::ReadOnlyRootFilesystem,
                    SandboxCapability::WritableRootFilesystem,
                    SandboxCapability::Administrator,
                    SandboxCapability::UserNamespace,
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
            if cancellation.disposition().requires_termination() {
                return Err(cancelled(ProviderStage::CreateSandbox));
            }
            let handle =
                SandboxHandle::new(self.id.clone(), format!("profile-{}", spec.operation_id()))
                    .expect("handle");
            let mut state = self.state.lock().expect("fake state");
            state.calls.push(Call::Create(Box::new(spec.clone())));
            state.resources.insert(
                handle.clone(),
                (
                    spec.generation(),
                    spec.custody(),
                    spec.profile().attestation().clone(),
                ),
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
            if cancellation.disposition().requires_termination() {
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
            if cancellation.disposition().requires_termination() {
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
            let (generation, custody, profile) =
                state.resources.get(handle).expect("owned resource");
            let custody = match self.behavior {
                FakeBehavior::InspectCustody(custody) => custody,
                _ => *custody,
            };
            Ok(SandboxInspection::new(
                handle.clone(),
                *generation,
                custody,
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
            let cancelled = cancellation.disposition().requires_termination();
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

    fn fake_shell_kind(request: &ExecutionCommand) -> Option<ShellKind> {
        let program = request.argv().program();
        let basename = program.as_str().rsplit(['/', '\\']).next()?;
        if basename.eq_ignore_ascii_case("bash") {
            Some(ShellKind::Bash)
        } else if basename.eq_ignore_ascii_case("sh") {
            Some(ShellKind::Sh)
        } else if basename.eq_ignore_ascii_case("pwsh") || basename.eq_ignore_ascii_case("pwsh.exe")
        {
            Some(ShellKind::Pwsh)
        } else if basename.eq_ignore_ascii_case("powershell.exe") {
            Some(ShellKind::WindowsPowerShell)
        } else if basename.eq_ignore_ascii_case("cmd.exe") {
            Some(ShellKind::Cmd)
        } else if basename.eq_ignore_ascii_case("python")
            || basename.eq_ignore_ascii_case("python3")
            || basename.eq_ignore_ascii_case("python.exe")
        {
            Some(ShellKind::Python)
        } else if basename == "install" {
            Some(ShellKind::Install)
        } else if basename.eq_ignore_ascii_case("tar") || basename.eq_ignore_ascii_case("tar.exe") {
            Some(ShellKind::Tar)
        } else if basename.eq_ignore_ascii_case("sha256sum")
            || basename.eq_ignore_ascii_case("automata-sha256.exe")
        {
            Some(ShellKind::Sha256sum)
        } else if basename.eq_ignore_ascii_case("node") || basename.eq_ignore_ascii_case("node.exe")
        {
            let evaluation = request.argv().arguments().last()?;
            [
                ("!== '12'", ShellKind::Node12),
                ("!== '16'", ShellKind::Node16),
                ("!== '20'", ShellKind::Node20),
                ("!== '24'", ShellKind::Node24),
            ]
            .into_iter()
            .find_map(|(needle, kind)| evaluation.contains(needle).then_some(kind))
        } else {
            None
        }
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
            output: Arc<dyn automata_ci_execution::ExecutionOutputSink>,
        ) -> Result<ExecutionOutput, ExecutionError> {
            self.state
                .lock()
                .expect("fake state")
                .calls
                .push(Call::Exec(Box::new(request.clone())));
            let termination = if cancellation.disposition().requires_termination() {
                ExecutionTermination::Cancelled
            } else if let FakeBehavior::ExecTermination(termination) = self.behavior {
                termination
            } else {
                ExecutionTermination::Exited(0)
            };
            let kind = fake_shell_kind(request).ok_or_else(|| {
                ExecutionError::new(ExecutionErrorKind::InvalidEnvironment, ExecutionStage::Exec)
            })?;
            let stdout = if self.behavior == FakeBehavior::ExecWrongOutput {
                b"wrong-shell-probe-output".to_vec()
            } else {
                match kind {
                    ShellKind::Install => b"install (GNU coreutils) 9.4\n".to_vec(),
                    ShellKind::Tar => b"tar (GNU tar) 1.35\n".to_vec(),
                    ShellKind::Sha256sum
                        if request.argv().program().platform() == TargetPlatform::Windows =>
                    {
                        b"automata-sha256 1.0.0\n".to_vec()
                    }
                    ShellKind::Sha256sum => b"sha256sum (GNU coreutils) 9.4\n".to_vec(),
                    _ => ShellProbe::new(kind, request.argv().program().clone())
                        .marker(request.operation_id())
                        .into_bytes(),
                }
            };
            let stdout = ExecutionOutputRecord::data(ExecutionOutputStream::Stdout, stdout)
                .map_err(|_| {
                    ExecutionError::new(ExecutionErrorKind::LocalStorage, ExecutionStage::Exec)
                })?;
            let mut records = vec![
                stdout,
                ExecutionOutputRecord::end_of_stream(ExecutionOutputStream::Stdout),
            ];
            if self.behavior == FakeBehavior::ExecStderr {
                records.push(
                    ExecutionOutputRecord::data(
                        ExecutionOutputStream::Stderr,
                        b"unexpected-shell-probe-stderr".to_vec(),
                    )
                    .map_err(|_| {
                        ExecutionError::new(ExecutionErrorKind::LocalStorage, ExecutionStage::Exec)
                    })?,
                );
            }
            records.push(ExecutionOutputRecord::end_of_stream(
                ExecutionOutputStream::Stderr,
            ));
            let result = ExecutionOutput::new(
                termination,
                records,
                self.behavior == FakeBehavior::ExecTruncated,
            )
            .map_err(|_| {
                ExecutionError::new(ExecutionErrorKind::LocalStorage, ExecutionStage::Exec)
            })?;
            for record in result.records() {
                output.observe(record).map_err(|_| {
                    ExecutionError::new(ExecutionErrorKind::OutputRejected, ExecutionStage::Exec)
                })?;
            }
            Ok(result)
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
            if cancellation.disposition().requires_termination() {
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

    fn linux_tool_policy() -> ProfileAdmissionPolicy {
        let resources = ResourceLimits::new(512 * 1024 * 1024, 2_000, 128).expect("resources");
        ProfileAdmissionPolicy::new(
            NetworkPolicy::PrivateEgress,
            RootFilesystemPolicy::Writable,
            SandboxPrivilegePolicy::Administrator,
            resources,
            resource_allocation(resources),
        )
        .with_linux_tools(
            TargetPath::posix("/usr/bin/bash").expect("bash path"),
            TargetPath::posix("/usr/bin/sh").expect("sh path"),
            Some(TargetPath::posix("/usr/bin/python3").expect("python path")),
            None,
            TargetPath::posix("/usr/bin/install").expect("install path"),
            TargetPath::posix("/usr/bin/tar").expect("tar path"),
            TargetPath::posix("/usr/bin/sha256sum").expect("sha256sum path"),
            None,
            None,
            None,
            Some(TargetPath::posix("/opt/externals/node24/bin/node").expect("node path")),
        )
        .expect("Linux tool admission policy")
    }

    #[test]
    fn linux_profile_admission_proves_every_configured_tool_in_the_exact_sandbox() {
        let signals = ProbeCancellation::default();
        let provider = FakeProvider::new(FakeBehavior::Happy, signals.clone());
        let (attestation, environment) = environment("linux-toolchain", profile_digest(0x35), 0x46);
        let expected_environment = environment.default_environment().clone();
        let profiles = BTreeMap::from([(attestation, environment)]);

        assert_eq!(
            admit_environment_profiles(
                &provider,
                runner_id(),
                &profiles,
                linux_tool_policy(),
                &signals,
            ),
            Ok(ProfileAdmissionOutcome::Admitted)
        );
        let calls = provider.calls();
        let Call::Create(spec) = &calls[0] else {
            panic!("Linux tool admission must begin with create")
        };
        assert_eq!(spec.network(), NetworkPolicy::PrivateEgress);
        assert_eq!(spec.root_filesystem(), RootFilesystemPolicy::Writable);
        assert_eq!(spec.privilege(), SandboxPrivilegePolicy::Administrator);
        assert!(spec.scratch().is_none());
        assert!(
            spec.workspace()
                .as_str()
                .starts_with("/work/linux-toolchain/profile-admission-")
        );
        assert!(matches!(calls[1], Call::Inspect(_)));
        assert!(matches!(calls[2], Call::Attach(_)));

        let copied = calls[3..6]
            .iter()
            .map(|call| match call {
                Call::CopyTo(request) => request.target().as_str(),
                _ => panic!("only script probes copy input"),
            })
            .collect::<Vec<_>>();
        assert_eq!(
            copied,
            [
                format!("{}/profile admission bash.sh", spec.workspace().as_str()),
                format!("{}/profile admission sh.sh", spec.workspace().as_str()),
                format!("{}/profile admission python.py", spec.workspace().as_str()),
            ]
        );

        let expected_programs = [
            "/usr/bin/bash",
            "/usr/bin/sh",
            "/usr/bin/python3",
            "/usr/bin/install",
            "/usr/bin/tar",
            "/usr/bin/sha256sum",
            "/opt/externals/node24/bin/node",
        ];
        let executions = &calls[6..13];
        for (call, expected_program) in executions.iter().zip(expected_programs) {
            let Call::Exec(command) = call else {
                panic!("every configured Linux tool must execute")
            };
            assert_eq!(command.argv().program().as_str(), expected_program);
            assert_eq!(command.working_directory(), spec.workspace());
            assert_eq!(command.environment(), &expected_environment);
            assert_eq!(command.timeout(), SHELL_PROBE_TIMEOUT);
            assert_eq!(command.output_limit(), SHELL_PROBE_OUTPUT_BYTES);
        }
        for call in &executions[3..6] {
            let Call::Exec(command) = call else {
                unreachable!()
            };
            assert_eq!(command.argv().arguments(), &["--version".to_owned()]);
        }
        let Call::Exec(node) = &executions[6] else {
            unreachable!()
        };
        assert_eq!(node.argv().arguments()[0], "--input-type=commonjs");
        assert!(node.argv().arguments()[2].contains("!== '24'"));
        assert!(matches!(calls[13], Call::Destroy(_, false)));
        assert_eq!(provider.resource_count(), 0);
    }

    #[test]
    fn linux_profile_tool_policy_rejects_aliased_paths_before_provider_mutation() {
        let resources = ResourceLimits::new(512 * 1024 * 1024, 2_000, 128).expect("resources");
        let invalid = ProfileAdmissionPolicy::new(
            NetworkPolicy::PrivateEgress,
            RootFilesystemPolicy::Writable,
            SandboxPrivilegePolicy::Administrator,
            resources,
            resource_allocation(resources),
        )
        .with_linux_tools(
            TargetPath::posix("/usr/bin/true").expect("literal path"),
            TargetPath::posix("/usr/bin/sh").expect("sh path"),
            None,
            None,
            TargetPath::posix("/usr/bin/install").expect("install path"),
            TargetPath::posix("/usr/bin/tar").expect("tar path"),
            TargetPath::posix("/usr/bin/sha256sum").expect("sha256sum path"),
            None,
            None,
            None,
            None,
        )
        .expect_err("a generic successful program cannot stand in for Bash");
        assert_eq!(invalid.kind(), ProfileAdmissionErrorKind::InvalidCatalog);
        assert_eq!(
            invalid.cleanup_status(),
            ProfileAdmissionCleanupStatus::NotRequired
        );
    }

    #[test]
    fn linux_profile_tool_admission_requires_confined_administrator_evidence() {
        for missing in [
            SandboxCapability::PrivateEgress,
            SandboxCapability::Administrator,
            SandboxCapability::UserNamespace,
        ] {
            let signals = ProbeCancellation::default();
            let mut provider = FakeProvider::new(FakeBehavior::Happy, signals.clone());
            provider.capabilities = ProviderCapabilities::new(
                provider
                    .capabilities
                    .values()
                    .iter()
                    .copied()
                    .filter(|capability| *capability != missing),
            )
            .expect("capabilities with one Linux boundary omitted");
            let (profile, sandbox) = environment("linux-tools", profile_digest(0x57), 0x68);
            let profiles = BTreeMap::from([(profile, sandbox)]);

            let error = admit_environment_profiles(
                &provider,
                runner_id(),
                &profiles,
                linux_tool_policy(),
                &signals,
            )
            .expect_err("Linux profile tools require the complete sandbox boundary");
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
    fn fixed_relay_local_docker_capabilities_reach_linux_profile_admission() {
        let signals = ProbeCancellation::default();
        let mut provider = FakeProvider::new(FakeBehavior::Happy, signals.clone());
        provider.capabilities = ProviderCapabilities::new([
            SandboxCapability::WholeJob,
            SandboxCapability::Attach,
            SandboxCapability::Inspect,
            SandboxCapability::Exec,
            SandboxCapability::CopyTo,
            SandboxCapability::CopyFrom,
            SandboxCapability::EnvironmentInjection,
            SandboxCapability::PrivateEgress,
            SandboxCapability::WritableRootFilesystem,
            SandboxCapability::Administrator,
            SandboxCapability::UserNamespace,
            SandboxCapability::ResourceLimits,
            SandboxCapability::ProcessLimits,
        ])
        .expect("exact LocalDocker provider capabilities");
        let (profile, sandbox) = environment("local-docker-tools", profile_digest(0x69), 0x7a);
        let profiles = BTreeMap::from([(profile, sandbox)]);
        let policy = linux_tool_policy();

        assert_eq!(
            admit_environment_profiles(&provider, runner_id(), &profiles, policy, &signals,),
            Ok(ProfileAdmissionOutcome::Admitted)
        );
        assert!(matches!(provider.calls().first(), Some(Call::Create(_))));
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
        assert_eq!(probes.len(), WINDOWS_SHELL_PROBE_COUNT + 1);
        assert_eq!(
            probes.last().map(|probe| probe.kind),
            Some(ShellKind::Python)
        );
    }

    #[test]
    fn windows_action_tools_and_every_configured_node_generation_are_probed() {
        let resources = ResourceLimits::new(256 * 1024 * 1024, 1_000, 16).expect("resources");
        let policy = ProfileAdmissionPolicy::new(
            NetworkPolicy::Disabled,
            RootFilesystemPolicy::Writable,
            SandboxPrivilegePolicy::Unprivileged,
            resources,
            resource_allocation(resources),
        )
        .with_windows_hyperv_tools(
            TargetPath::windows(r"C:\Program Files\PowerShell\7\pwsh.exe").expect("pwsh"),
            TargetPath::windows(r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe")
                .expect("powershell"),
            TargetPath::windows(r"C:\Windows\System32\cmd.exe").expect("cmd"),
            None,
            TargetPath::windows(r"C:\automata\tools\tar\tar.exe").expect("tar"),
            TargetPath::windows(r"C:\automata\tools\hash\automata-sha256.exe").expect("hash"),
            Some(TargetPath::windows(r"C:\automata\externals\node12\node.exe").expect("node12")),
            Some(TargetPath::windows(r"C:\automata\externals\node16\node.exe").expect("node16")),
            Some(TargetPath::windows(r"C:\automata\externals\node20\node.exe").expect("node20")),
            Some(TargetPath::windows(r"C:\automata\externals\node24\node.exe").expect("node24")),
        )
        .expect("complete Windows tool policy");
        let kinds = policy
            .shell_probes
            .expect("tool probes")
            .probes
            .into_iter()
            .map(|probe| probe.kind)
            .collect::<BTreeSet<_>>();
        assert_eq!(
            kinds,
            BTreeSet::from([
                ShellKind::Pwsh,
                ShellKind::WindowsPowerShell,
                ShellKind::Cmd,
                ShellKind::Tar,
                ShellKind::Sha256sum,
                ShellKind::Node12,
                ShellKind::Node16,
                ShellKind::Node20,
                ShellKind::Node24,
            ])
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
            admit_environment_profiles(&provider, runner_id(), &profiles, policy(), &signals),
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
            assert_eq!(
                spec.custody(),
                SandboxCustody::ProfileAdmission {
                    runner_id: runner_id(),
                }
            );
            let Call::Inspect(inspected) = &calls[1] else {
                panic!("profile create must be inspected")
            };
            let Call::Destroy(destroyed, cleanup_cancelled) = &calls[2] else {
                panic!("profile inspection must be destroyed")
            };
            assert!(!cleanup_cancelled);
            assert_eq!(inspected, destroyed.handle());
            assert_eq!(destroyed.generation(), spec.generation());
            assert_eq!(destroyed.custody(), spec.custody());
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
            admit_environment_profiles(&provider, runner_id(), &profiles, policy(), &signals),
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
            admit_environment_profiles(&provider, runner_id(), &profiles, policy, &signals),
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
            "profile admission pwsh.ps1",
            "profile admission powershell.ps1",
            "profile admission cmd.cmd",
            "profile admission python.py",
        ];
        let mut operation_ids = BTreeSet::from([spec.operation_id()]);
        let copied_scripts = calls[3..7]
            .iter()
            .zip(expected_scripts)
            .map(|(call, name)| {
                let Call::CopyTo(request) = call else {
                    panic!("every shell probe script must be copied before execution")
                };
                assert_eq!(
                    request.target(),
                    &target_child(spec.workspace(), name).expect("expected script target")
                );
                assert!(operation_ids.insert(request.operation_id()));
                request.target().clone()
            })
            .collect::<Vec<_>>();
        let expected_programs = [&pwsh, &powershell, &cmd, &python];
        let expected_kinds = [
            ShellKind::Pwsh,
            ShellKind::WindowsPowerShell,
            ShellKind::Cmd,
            ShellKind::Python,
        ];
        for (index, ((call, expected_program), script)) in calls[7..11]
            .iter()
            .zip(expected_programs)
            .zip(&copied_scripts)
            .enumerate()
        {
            let Call::Exec(command) = call else {
                panic!("container shell probe must execute")
            };
            let Call::CopyTo(copy) = &calls[3 + index] else {
                unreachable!()
            };
            assert_eq!(
                copy.content(),
                ShellProbe::new(expected_kinds[index], (*expected_program).clone())
                    .script_content(command.operation_id())
                    .expect("shell probe payload")
            );
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

            let error =
                admit_environment_profiles(&provider, runner_id(), &profiles, policy, &signals)
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
    fn shell_admission_requires_exact_clean_success_evidence() {
        for behavior in [
            FakeBehavior::ExecTermination(ExecutionTermination::Exited(7)),
            FakeBehavior::ExecTruncated,
            FakeBehavior::ExecWrongOutput,
            FakeBehavior::ExecStderr,
        ] {
            let signals = ProbeCancellation::default();
            let provider = FakeProvider::new(behavior, signals.clone());
            let (profiles, policy) = windows_hyperv_fixture();

            let error =
                admit_environment_profiles(&provider, runner_id(), &profiles, policy, &signals)
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

        let error =
            admit_environment_profiles(&provider, runner_id(), &profiles, policy(), &signals)
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
        let expected_runner = runner_id();
        for behavior in [
            FakeBehavior::CreateState(SandboxState::Created),
            FakeBehavior::InspectState(SandboxState::Degraded),
            FakeBehavior::InspectCustody(SandboxCustody::ProfileAdmission {
                runner_id: RunnerId::new(),
            }),
            FakeBehavior::InspectCustody(SandboxCustody::Job {
                runner_id: expected_runner,
                slot_ordinal: NonZeroU16::new(1).expect("non-zero slot"),
            }),
        ] {
            let signals = ProbeCancellation::default();
            let provider = FakeProvider::new(behavior, signals.clone());
            let profiles = BTreeMap::from([environment("linux", profile_digest(0x51), 0x61)]);
            let error = admit_environment_profiles(
                &provider,
                expected_runner,
                &profiles,
                policy(),
                &signals,
            )
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
            admit_environment_profiles(&provider, runner_id(), &profiles, policy(), &signals),
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

        let error =
            admit_environment_profiles(&provider, runner_id(), &profiles, policy(), &signals)
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

        let error =
            admit_environment_profiles(&provider, runner_id(), &profiles, policy(), &signals)
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

        let error =
            admit_environment_profiles(&provider, runner_id(), &profiles, policy(), &signals)
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
            admit_environment_profiles(&provider, runner_id(), &profiles, policy(), &signals),
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

        let error =
            admit_environment_profiles(&provider, runner_id(), &profiles, policy(), &signals)
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
