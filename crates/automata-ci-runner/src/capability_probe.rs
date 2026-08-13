use std::{
    collections::BTreeSet,
    path::PathBuf,
    process::{Command, Stdio},
};

#[cfg(target_os = "linux")]
use std::{fs, io::Read as _, path::Path};

use serde::Serialize;

/// Capability identifier for successfully spawning and waiting for a child process.
// foundation-governance: derived-contract owner=runner-contract kind=wire-discriminator
pub const PROCESS_EXECUTION: &str = "core.process-exec/v1";
/// Capability identifier for the presence of the Linux cgroup-v2 interface.
// foundation-governance: derived-contract owner=runner-contract kind=wire-discriminator
pub const CGROUP_V2: &str = "linux.cgroup-v2/v1";
/// Capability identifier for the presence of the Linux user-namespace interface.
// foundation-governance: derived-contract owner=runner-contract kind=wire-discriminator
pub const USER_NAMESPACE: &str = "linux.user-namespace/v1";
/// Capability identifier for verified rootless-Podman network isolation.
// foundation-governance: derived-contract owner=runner-contract kind=wire-discriminator
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
#[cfg(target_os = "linux")]
const MAX_MODULE_DEPENDENCY_INDEX_BYTES: usize = 16 * 1024 * 1024;

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

/// Cleanup outcome for resources created while collecting active evidence.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProbeCleanupStatus {
    /// The probe did not create resources that required cleanup.
    NotApplicable,
    /// Cleanup completed or proved that no probe-owned resources remained.
    Complete,
    /// One or more probe-owned resources could not be proved absent.
    Failed,
}

/// Stable machine-readable reason for a non-usable or qualified probe result.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProbeReasonCode {
    /// The configured Podman executable could not be found or executed.
    PodmanExecutableUnavailable,
    /// The running Linux kernel release could not be determined.
    KernelReleaseUnavailable,
    /// Loaded or available kernel modules could not be inspected.
    KernelModuleInspectionFailed,
    /// No module tree exists for the running kernel release.
    KernelModuleTreeMissing,
    /// The running kernel's module dependency index is absent.
    ModuleDependencyIndexMissing,
    /// One or more required nftables modules are neither loaded nor available.
    RequiredKernelModulesUnavailable,
    /// Static prerequisites were found, but an isolated network was not created.
    ActiveNetworkVerificationNotPerformed,
    /// The active rootless-Podman probe is unavailable on this operating system.
    ActiveProbeUnsupportedPlatform,
    /// The active probe was invoked as root or could not verify a non-root identity.
    ActiveProbeRequiresRootlessUser,
    /// The probe executable requires a loader or shared library unavailable in the minimal rootfs.
    ProbeExecutableNotStatic,
    /// The probe executable could not be safely inspected for minimal-rootfs compatibility.
    ProbeExecutableInspectionFailed,
    /// Probe-owned names, paths, signals, or rootfs context could not be prepared.
    ActiveProbePreparationFailed,
    /// A Podman lifecycle command failed or lost post-start execution integrity.
    ActiveProbeCommandFailed,
    /// A Podman lifecycle command exceeded its deadline.
    ActiveProbeCommandTimedOut,
    /// Podman did not publish one valid loopback readiness port.
    ActiveProbePortInvalid,
    /// The isolated readiness endpoint could not be verified.
    ActiveProbeHttpFailed,
    /// Probe resources could not all be removed within the cleanup policy.
    ActiveProbeCleanupFailed,
    /// Shutdown interrupted provisioning or forced cleanup to stop.
    ActiveProbeInterrupted,
}

/// A stable reason category paired with operator-facing diagnostic detail.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ProbeReason {
    code: ProbeReasonCode,
    detail: String,
}

impl ProbeReason {
    /// Returns the machine-readable reason category.
    pub const fn code(&self) -> ProbeReasonCode {
        self.code
    }

    /// Returns the operator-facing explanation collected at the host boundary.
    pub fn detail(&self) -> &str {
        &self.detail
    }
}

/// Read-only facts about kernel-module support for rootless container networking.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum KernelModuleReadiness {
    /// The running kernel has every required loaded or loadable module.
    Ready {
        /// Running kernel release used to select the module tree.
        release: String,
    },
    /// The running kernel has no matching module tree on disk.
    ModuleTreeMissing {
        /// Running kernel release whose module tree was requested.
        release: String,
        /// Expected absolute module-tree path.
        path: PathBuf,
    },
    /// The module tree exists without its dependency index.
    DependencyIndexMissing {
        /// Expected dependency-index path.
        path: PathBuf,
    },
    /// Required nftables modules are neither loaded nor listed as loadable.
    RequiredModulesMissing {
        /// Stable names of the missing modules.
        modules: Vec<&'static str>,
    },
    /// Host inspection could not safely produce a readiness decision.
    Indeterminate {
        /// Stable category for the inspection failure.
        reason: ProbeReasonCode,
        /// Operator-facing explanation of the failure.
        detail: String,
    },
}

/// Evidence and diagnostic detail for one advertised runner capability.
///
/// Only [`ProbeStatus::Usable`] evidence is eligible for capability
/// advertisement; detected interfaces alone are deliberately insufficient.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct CapabilityProbe {
    capability: &'static str,
    status: ProbeStatus,
    cleanup: ProbeCleanupStatus,
    detail: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    reason: Option<ProbeReason>,
}

impl CapabilityProbe {
    /// Returns the versioned capability identifier assessed by this probe.
    pub fn capability(&self) -> &'static str {
        self.capability
    }

    /// Returns the strength or failure class of the collected evidence.
    pub const fn status(&self) -> ProbeStatus {
        self.status
    }

    /// Returns the structured cleanup outcome for active probe resources.
    pub const fn cleanup_status(&self) -> ProbeCleanupStatus {
        self.cleanup
    }

    /// Returns the operator-facing probe explanation.
    pub fn detail(&self) -> &str {
        &self.detail
    }

    /// Returns the structured qualification or failure reason, when present.
    pub const fn reason(&self) -> Option<&ProbeReason> {
        self.reason.as_ref()
    }

    /// Reports whether this evidence is strong enough to advertise the capability.
    pub const fn is_usable(&self) -> bool {
        matches!(self.status, ProbeStatus::Usable)
    }
}

/// Probes host facts without treating mere interface presence as enforceable support.
pub fn probe_capabilities() -> Vec<CapabilityProbe> {
    #[cfg(target_os = "linux")]
    let mut probes = vec![probe_process_execution()];

    #[cfg(not(target_os = "linux"))]
    let probes = vec![probe_process_execution()];

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
                cleanup: ProbeCleanupStatus::NotApplicable,
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
            cleanup: ProbeCleanupStatus::NotApplicable,
            detail: "successfully launched and waited for a child process".to_owned(),
            reason: None,
        },
        Ok(status) => CapabilityProbe {
            capability: PROCESS_EXECUTION,
            status: ProbeStatus::Unavailable,
            cleanup: ProbeCleanupStatus::NotApplicable,
            detail: format!("the child-process probe exited with {status}"),
            reason: None,
        },
        Err(error) => CapabilityProbe {
            capability: PROCESS_EXECUTION,
            status: ProbeStatus::Unavailable,
            cleanup: ProbeCleanupStatus::NotApplicable,
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
            cleanup: ProbeCleanupStatus::NotApplicable,
            detail: detected_detail.to_owned(),
            reason: None,
        },
        Ok(false) => CapabilityProbe {
            capability,
            status: ProbeStatus::Unavailable,
            cleanup: ProbeCleanupStatus::NotApplicable,
            detail: format!("{} is not present", path.display()),
            reason: None,
        },
        Err(error) => CapabilityProbe {
            capability,
            status: ProbeStatus::Indeterminate,
            cleanup: ProbeCleanupStatus::NotApplicable,
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
        cleanup: ProbeCleanupStatus::NotApplicable,
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
        cleanup: ProbeCleanupStatus::NotApplicable,
        reason: reason_code.map(|code| ProbeReason {
            code,
            detail: detail.clone(),
        }),
        detail,
    }
}

impl CapabilityProbe {
    pub(crate) const fn with_cleanup_status(mut self, cleanup: ProbeCleanupStatus) -> Self {
        self.cleanup = cleanup;
        self
    }
}

#[cfg(target_os = "linux")]
fn probe_podman_network_isolation() -> CapabilityProbe {
    let podman_available = executable_is_in_path("podman");
    assess_podman_network_isolation(podman_available, inspect_kernel_module_readiness())
}

/// Assesses passive networking prerequisites for one exact configured Podman binary.
///
/// This check does not create resources. Production admission must additionally
/// run the active rootless-network probe before advertising isolation support.
#[cfg(target_os = "linux")]
pub(crate) fn assess_configured_podman_network_isolation(binary: &Path) -> CapabilityProbe {
    assess_podman_network_isolation(
        executable_path_is_runnable(binary),
        inspect_kernel_module_readiness(),
    )
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
fn executable_path_is_runnable(path: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt as _;

    fs::metadata(path)
        .is_ok_and(|metadata| metadata.is_file() && metadata.permissions().mode() & 0o111 != 0)
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

    inspect_kernel_module_readiness_at(
        release,
        Path::new("/usr/lib/modules"),
        Path::new("/sys/module"),
    )
}

#[cfg(target_os = "linux")]
fn inspect_kernel_module_readiness_at(
    release: String,
    module_trees: &Path,
    loaded_modules: &Path,
) -> KernelModuleReadiness {
    let unloaded_modules = REQUIRED_NFT_MODULES
        .iter()
        .copied()
        .filter(|module| !module_is_loaded_at(loaded_modules, module))
        .collect::<Vec<_>>();
    if unloaded_modules.is_empty() {
        return KernelModuleReadiness::Ready { release };
    }

    let module_tree = module_trees.join(&release);
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
    let dependencies = match read_bounded_text(&dependency_index, MAX_MODULE_DEPENDENCY_INDEX_BYTES)
    {
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

    let missing_modules = unloaded_modules
        .into_iter()
        .filter(|module| !module_is_indexed(&dependencies, module))
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
fn read_bounded_text(path: &Path, maximum_bytes: usize) -> std::io::Result<String> {
    let file = fs::File::open(path)?;
    let limit = u64::try_from(maximum_bytes)
        .unwrap_or(u64::MAX)
        .saturating_add(1);
    let mut bytes = Vec::with_capacity(maximum_bytes.min(64 * 1024));
    file.take(limit).read_to_end(&mut bytes)?;
    if bytes.len() > maximum_bytes {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "kernel module dependency index exceeds its byte limit",
        ));
    }
    String::from_utf8(bytes).map_err(|_| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "kernel module dependency index is not UTF-8",
        )
    })
}

#[cfg(target_os = "linux")]
fn module_is_loaded_at(loaded_modules: &Path, module: &str) -> bool {
    loaded_modules.join(module).is_dir()
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

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use std::fs;

    use uuid::Uuid;

    use super::*;

    #[test]
    fn loaded_modules_are_sufficient_without_an_on_disk_module_tree() {
        let fixture = ModuleFixture::new();
        for module in REQUIRED_NFT_MODULES {
            fs::create_dir_all(fixture.loaded_modules.join(module))
                .expect("loaded-module fixture must be creatable");
        }

        assert_eq!(
            inspect_kernel_module_readiness_at(
                fixture.release.clone(),
                &fixture.module_trees,
                &fixture.loaded_modules,
            ),
            KernelModuleReadiness::Ready {
                release: fixture.release.clone(),
            }
        );
    }

    #[test]
    fn dependency_index_reads_are_bounded_before_text_decoding() {
        let fixture = ModuleFixture::new();
        let path = fixture.root.join("bounded-dependency-index");
        fs::write(&path, b"0123456789abcdefX").expect("dependency fixture must be writable");

        let error = read_bounded_text(&path, 16).expect_err("oversized index must fail closed");

        assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
        assert!(error.to_string().contains("byte limit"));
    }

    struct ModuleFixture {
        root: PathBuf,
        release: String,
        module_trees: PathBuf,
        loaded_modules: PathBuf,
    }

    impl ModuleFixture {
        fn new() -> Self {
            let workspace_root = Path::new(env!("CARGO_MANIFEST_DIR"))
                .parent()
                .and_then(Path::parent)
                .expect("runner crate must be nested beneath the workspace root");
            let root = workspace_root
                .join("target/agent-scratch/runner")
                .join(format!("module-fixture-{}", Uuid::new_v4().simple()));
            let module_trees = root.join("module-trees");
            let loaded_modules = root.join("loaded-modules");
            fs::create_dir_all(&module_trees).expect("module root fixture must be creatable");
            fs::create_dir_all(&loaded_modules).expect("loaded root fixture must be creatable");
            Self {
                root,
                release: "7.1.5-arch1-1".to_owned(),
                module_trees,
                loaded_modules,
            }
        }
    }

    impl Drop for ModuleFixture {
        fn drop(&mut self) {
            let _ignored = fs::remove_dir_all(&self.root);
        }
    }
}
