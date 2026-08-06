use std::{
    collections::BTreeSet,
    path::PathBuf,
    process::{Command, Stdio},
};

#[cfg(target_os = "linux")]
use std::{fs, path::Path};

use serde::Serialize;

pub const PROCESS_EXECUTION: &str = "core.process-exec/v1";
pub const CGROUP_V2: &str = "linux.cgroup-v2/v1";
pub const USER_NAMESPACE: &str = "linux.user-namespace/v1";
pub const PODMAN_NETWORK_ISOLATION: &str = "linux.podman-network-isolation/v1";

#[cfg(target_os = "linux")]
const REQUIRED_NFT_MODULES: [&str; 6] = [
    "nft_ct",
    "nft_masq",
    "nft_fib_inet",
    "nft_nat",
    "nft_reject_inet",
    "nft_numgen",
];

/// Strength of the evidence collected for a capability.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProbeStatus {
    /// An active probe demonstrated that the capability can be used.
    Usable,
    /// A supporting interface exists, but usability or enforceability was not proven.
    Detected,
    /// A known prerequisite is missing from an otherwise relevant capability.
    Degraded,
    /// The expected interface or behavior is absent.
    Unavailable,
    /// The host did not allow the probe to determine a result.
    Indeterminate,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProbeReasonCode {
    PodmanExecutableUnavailable,
    KernelReleaseUnavailable,
    KernelModuleInspectionFailed,
    KernelModuleTreeMissing,
    ModuleDependencyIndexMissing,
    RequiredKernelModulesUnavailable,
    ActiveNetworkVerificationNotPerformed,
    ActiveProbeUnsupportedPlatform,
    ActiveProbeRequiresRootlessUser,
    ProbeExecutableNotStatic,
    ProbeExecutableInspectionFailed,
    ActiveProbePreparationFailed,
    ActiveProbeCommandFailed,
    ActiveProbeCommandTimedOut,
    ActiveProbePortInvalid,
    ActiveProbeHttpFailed,
    ActiveProbeCleanupFailed,
    ActiveProbeInterrupted,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ProbeReason {
    code: ProbeReasonCode,
    detail: String,
}

impl ProbeReason {
    pub const fn code(&self) -> ProbeReasonCode {
        self.code
    }

    pub fn detail(&self) -> &str {
        &self.detail
    }
}

/// Read-only facts about kernel-module support for rootless container networking.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum KernelModuleReadiness {
    Ready {
        release: String,
    },
    ModuleTreeMissing {
        release: String,
        path: PathBuf,
    },
    DependencyIndexMissing {
        path: PathBuf,
    },
    RequiredModulesMissing {
        modules: Vec<&'static str>,
    },
    Indeterminate {
        reason: ProbeReasonCode,
        detail: String,
    },
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct CapabilityProbe {
    capability: &'static str,
    status: ProbeStatus,
    detail: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    reason: Option<ProbeReason>,
}

impl CapabilityProbe {
    pub fn capability(&self) -> &'static str {
        self.capability
    }

    pub const fn status(&self) -> ProbeStatus {
        self.status
    }

    pub fn detail(&self) -> &str {
        &self.detail
    }

    pub const fn reason(&self) -> Option<&ProbeReason> {
        self.reason.as_ref()
    }

    pub const fn is_usable(&self) -> bool {
        matches!(self.status, ProbeStatus::Usable)
    }
}

/// Probes host facts without treating mere interface presence as enforceable support.
pub fn probe_capabilities() -> Vec<CapabilityProbe> {
    let mut probes = vec![probe_process_execution()];

    #[cfg(target_os = "linux")]
    {
        probes.push(probe_interface_presence(
            CGROUP_V2,
            Path::new("/sys/fs/cgroup/cgroup.controllers"),
            "cgroup v2 is mounted, but writable delegation and limit enforcement were not verified",
        ));
        probes.push(probe_podman_network_isolation());
        probes.push(probe_interface_presence(
            USER_NAMESPACE,
            Path::new("/proc/self/ns/user"),
            "the user-namespace interface exists, but creating a new user namespace was not verified",
        ));
    }

    probes
}

/// Returns only capabilities supported by an active successful probe.
pub fn usable_capabilities(probes: &[CapabilityProbe]) -> BTreeSet<&'static str> {
    probes
        .iter()
        .filter(|probe| probe.is_usable())
        .map(CapabilityProbe::capability)
        .collect()
}

fn probe_process_execution() -> CapabilityProbe {
    let executable = match std::env::current_exe() {
        Ok(executable) => executable,
        Err(error) => {
            return CapabilityProbe {
                capability: PROCESS_EXECUTION,
                status: ProbeStatus::Indeterminate,
                detail: format!("could not resolve the current executable: {error}"),
                reason: None,
            };
        }
    };

    match Command::new(executable)
        .arg("--help")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
    {
        Ok(status) if status.success() => CapabilityProbe {
            capability: PROCESS_EXECUTION,
            status: ProbeStatus::Usable,
            detail: "successfully launched and waited for a child process".to_owned(),
            reason: None,
        },
        Ok(status) => CapabilityProbe {
            capability: PROCESS_EXECUTION,
            status: ProbeStatus::Unavailable,
            detail: format!("the child-process probe exited with {status}"),
            reason: None,
        },
        Err(error) => CapabilityProbe {
            capability: PROCESS_EXECUTION,
            status: ProbeStatus::Unavailable,
            detail: format!("could not launch the child-process probe: {error}"),
            reason: None,
        },
    }
}

#[cfg(target_os = "linux")]
fn probe_interface_presence(
    capability: &'static str,
    path: &Path,
    detected_detail: &'static str,
) -> CapabilityProbe {
    match path.try_exists() {
        Ok(true) => CapabilityProbe {
            capability,
            status: ProbeStatus::Detected,
            detail: detected_detail.to_owned(),
            reason: None,
        },
        Ok(false) => CapabilityProbe {
            capability,
            status: ProbeStatus::Unavailable,
            detail: format!("{} is not present", path.display()),
            reason: None,
        },
        Err(error) => CapabilityProbe {
            capability,
            status: ProbeStatus::Indeterminate,
            detail: format!("could not inspect {}: {error}", path.display()),
            reason: None,
        },
    }
}

/// Assesses read-only Podman networking prerequisites without creating a network or loading modules.
pub fn assess_podman_network_isolation(
    podman_available: bool,
    module_readiness: KernelModuleReadiness,
) -> CapabilityProbe {
    if !podman_available {
        return network_probe(
            ProbeStatus::Unavailable,
            ProbeReasonCode::PodmanExecutableUnavailable,
            "the Podman executable could not be run",
        );
    }

    match module_readiness {
        KernelModuleReadiness::Ready { release } => network_probe(
            ProbeStatus::Detected,
            ProbeReasonCode::ActiveNetworkVerificationNotPerformed,
            &format!(
                "Podman and nftables module prerequisites are present for kernel {release}; network creation was not attempted"
            ),
        ),
        KernelModuleReadiness::ModuleTreeMissing { release, path } => network_probe(
            ProbeStatus::Degraded,
            ProbeReasonCode::KernelModuleTreeMissing,
            &format!(
                "the running kernel {release} has no matching module tree at {}",
                path.display()
            ),
        ),
        KernelModuleReadiness::DependencyIndexMissing { path } => network_probe(
            ProbeStatus::Degraded,
            ProbeReasonCode::ModuleDependencyIndexMissing,
            &format!(
                "the running kernel module index is missing at {}",
                path.display()
            ),
        ),
        KernelModuleReadiness::RequiredModulesMissing { modules } => network_probe(
            ProbeStatus::Degraded,
            ProbeReasonCode::RequiredKernelModulesUnavailable,
            &format!(
                "required nftables modules are neither loaded nor available for autoload: {}",
                modules.join(", ")
            ),
        ),
        KernelModuleReadiness::Indeterminate { reason, detail } => {
            network_probe(ProbeStatus::Indeterminate, reason, &detail)
        }
    }
}

fn network_probe(
    status: ProbeStatus,
    reason_code: ProbeReasonCode,
    detail: &str,
) -> CapabilityProbe {
    CapabilityProbe {
        capability: PODMAN_NETWORK_ISOLATION,
        status,
        detail: detail.to_owned(),
        reason: Some(ProbeReason {
            code: reason_code,
            detail: detail.to_owned(),
        }),
    }
}

pub(crate) fn active_network_probe(
    status: ProbeStatus,
    reason_code: Option<ProbeReasonCode>,
    detail: String,
) -> CapabilityProbe {
    CapabilityProbe {
        capability: PODMAN_NETWORK_ISOLATION,
        status,
        reason: reason_code.map(|code| ProbeReason {
            code,
            detail: detail.clone(),
        }),
        detail,
    }
}

#[cfg(target_os = "linux")]
fn probe_podman_network_isolation() -> CapabilityProbe {
    let podman_available = executable_is_in_path("podman");
    assess_podman_network_isolation(podman_available, inspect_kernel_module_readiness())
}

#[cfg(target_os = "linux")]
fn executable_is_in_path(name: &str) -> bool {
    use std::os::unix::fs::PermissionsExt as _;

    std::env::var_os("PATH").is_some_and(|path| {
        std::env::split_paths(&path).any(|directory| {
            fs::metadata(directory.join(name)).is_ok_and(|metadata| {
                metadata.is_file() && metadata.permissions().mode() & 0o111 != 0
            })
        })
    })
}

#[cfg(target_os = "linux")]
fn inspect_kernel_module_readiness() -> KernelModuleReadiness {
    let release = match fs::read_to_string("/proc/sys/kernel/osrelease") {
        Ok(release) if !release.trim().is_empty() => release.trim().to_owned(),
        Ok(_) => {
            return KernelModuleReadiness::Indeterminate {
                reason: ProbeReasonCode::KernelReleaseUnavailable,
                detail: "the running kernel release file is empty".to_owned(),
            };
        }
        Err(error) => {
            return KernelModuleReadiness::Indeterminate {
                reason: ProbeReasonCode::KernelReleaseUnavailable,
                detail: format!("could not read the running kernel release: {error}"),
            };
        }
    };

    let module_tree = PathBuf::from("/usr/lib/modules").join(&release);
    match module_tree.try_exists() {
        Ok(true) => {}
        Ok(false) => {
            return KernelModuleReadiness::ModuleTreeMissing {
                release,
                path: module_tree,
            };
        }
        Err(error) => {
            return KernelModuleReadiness::Indeterminate {
                reason: ProbeReasonCode::KernelModuleInspectionFailed,
                detail: format!("could not inspect {}: {error}", module_tree.display()),
            };
        }
    }

    let dependency_index = module_tree.join("modules.dep");
    let dependencies = match fs::read_to_string(&dependency_index) {
        Ok(dependencies) => dependencies,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return KernelModuleReadiness::DependencyIndexMissing {
                path: dependency_index,
            };
        }
        Err(error) => {
            return KernelModuleReadiness::Indeterminate {
                reason: ProbeReasonCode::KernelModuleInspectionFailed,
                detail: format!("could not read {}: {error}", dependency_index.display()),
            };
        }
    };

    let missing_modules = REQUIRED_NFT_MODULES
        .iter()
        .copied()
        .filter(|module| !module_is_loaded(module) && !module_is_indexed(&dependencies, module))
        .collect::<Vec<_>>();
    if missing_modules.is_empty() {
        KernelModuleReadiness::Ready { release }
    } else {
        KernelModuleReadiness::RequiredModulesMissing {
            modules: missing_modules,
        }
    }
}

#[cfg(target_os = "linux")]
fn module_is_loaded(module: &str) -> bool {
    Path::new("/sys/module").join(module).is_dir()
}

#[cfg(target_os = "linux")]
fn module_is_indexed(dependencies: &str, module: &str) -> bool {
    dependencies.lines().any(|line| {
        let Some((path, _dependencies)) = line.split_once(':') else {
            return false;
        };
        let Some(file_name) = Path::new(path).file_name().and_then(|name| name.to_str()) else {
            return false;
        };
        file_name == format!("{module}.ko") || file_name.starts_with(&format!("{module}.ko."))
    })
}
