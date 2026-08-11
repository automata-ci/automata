mod command;
mod control;
mod elf;
mod http;
mod lifecycle;
mod plan;

#[cfg(target_os = "linux")]
use std::fs;
use std::sync::Arc;

use automata_ci_execution::NetworkPolicy;
use automata_ci_sandbox_podman::PodmanOptions;
#[cfg(target_os = "linux")]
use command::ConfiguredSystemCommandExecutor;
pub use command::{
    CommandExecutor, CommandOutput, CommandRequest, CommandTermination, SystemCommandExecutor,
};
pub use control::{ActiveProbeLimits, ProbeCancellation};
pub use elf::{ElfScratchExecutableInspector, ScratchCompatibility, ScratchExecutableInspector};
pub use http::{ReadinessProbe, SystemReadinessProbe};
pub use plan::ActiveProbePlan;
#[cfg(target_os = "linux")]
use uuid::Uuid;

#[cfg(target_os = "linux")]
use crate::capability_probe::assess_configured_podman_network_isolation;
use crate::capability_probe::{
    CapabilityProbe, ProbeCleanupStatus, ProbeReasonCode, ProbeStatus, active_network_probe,
};
use elf::load_executable_snapshot;
#[cfg(target_os = "linux")]
use elf::load_running_executable_snapshot;
use lifecycle::run_lifecycle;

/// Runs the opt-in active Podman/Netavark probe with system adapters.
pub async fn probe_current_executable() -> CapabilityProbe {
    probe_current_executable_with_control(
        Arc::new(SystemCommandExecutor),
        None,
        NetworkPolicy::PrivateEgress,
        &ProbeCancellation::default(),
    )
    .await
}

pub(crate) async fn probe_current_executable_with_cancellation(
    cancellation: &ProbeCancellation,
) -> CapabilityProbe {
    probe_current_executable_with_control(
        Arc::new(SystemCommandExecutor),
        None,
        NetworkPolicy::PrivateEgress,
        cancellation,
    )
    .await
}

pub(crate) async fn probe_configured_current_executable_with_control(
    options: &PodmanOptions,
    network_policy: NetworkPolicy,
    cancellation: &ProbeCancellation,
) -> CapabilityProbe {
    #[cfg(not(target_os = "linux"))]
    {
        let _ = options;
        let _ = network_policy;
        let _ = cancellation;
        return active_network_probe(
            ProbeStatus::Unavailable,
            Some(ProbeReasonCode::ActiveProbeUnsupportedPlatform),
            "the active Podman network probe is currently supported only on Linux".to_owned(),
        );
    }

    #[cfg(target_os = "linux")]
    {
        if cancellation.is_cancelled() {
            return interrupted_probe(cancellation, None, &[], ProbeCleanupStatus::NotApplicable);
        }
        let passive = assess_configured_podman_network_isolation(options.binary().as_path());
        if passive.status() != ProbeStatus::Detected {
            return passive;
        }
        probe_current_executable_with_control(
            Arc::new(ConfiguredSystemCommandExecutor::from_options(options)),
            Some(options.state_root().as_path().join("active-probe")),
            network_policy,
            cancellation,
        )
        .await
    }
}

async fn probe_current_executable_with_control(
    commands: Arc<dyn CommandExecutor>,
    scratch_root: Option<std::path::PathBuf>,
    network_policy: NetworkPolicy,
    cancellation: &ProbeCancellation,
) -> CapabilityProbe {
    #[cfg(not(target_os = "linux"))]
    {
        let _ = commands;
        let _ = scratch_root;
        let _ = network_policy;
        let _ = cancellation;
        active_network_probe(
            ProbeStatus::Unavailable,
            Some(ProbeReasonCode::ActiveProbeUnsupportedPlatform),
            "the active Podman network probe is currently supported only on Linux".to_owned(),
        )
    }

    #[cfg(target_os = "linux")]
    {
        let plan = match current_probe_plan(scratch_root, network_policy) {
            Ok(plan) => plan,
            Err(probe) => return probe,
        };
        run_system_active_probe_with_control(plan, commands, cancellation.clone()).await
    }
}

#[cfg(target_os = "linux")]
fn current_probe_plan(
    scratch_root: Option<std::path::PathBuf>,
    network_policy: NetworkPolicy,
) -> Result<ActiveProbePlan, CapabilityProbe> {
    match effective_user_id() {
        Ok(0) => {
            return Err(active_network_probe(
                ProbeStatus::Unavailable,
                Some(ProbeReasonCode::ActiveProbeRequiresRootlessUser),
                "the active network probe must run as a non-root user so it exercises rootless Podman"
                    .to_owned(),
            ));
        }
        Ok(_) => {}
        Err(error) => {
            return Err(active_network_probe(
                ProbeStatus::Indeterminate,
                Some(ProbeReasonCode::ActiveProbeRequiresRootlessUser),
                error,
            ));
        }
    }
    let executable = std::path::PathBuf::from("/proc/self/exe");
    let identifier = Uuid::new_v4().simple().to_string();
    match scratch_root {
        Some(scratch_root) => {
            ActiveProbePlan::new_in(executable, identifier, scratch_root, network_policy)
        }
        None => ActiveProbePlan::new(executable, identifier, network_policy),
    }
    .map_err(|error| {
        active_network_probe(
            ProbeStatus::Indeterminate,
            Some(ProbeReasonCode::ActiveProbePreparationFailed),
            error,
        )
    })
}

#[cfg(target_os = "linux")]
async fn run_system_active_probe_with_control(
    plan: ActiveProbePlan,
    commands: Arc<dyn CommandExecutor>,
    cancellation: ProbeCancellation,
) -> CapabilityProbe {
    let task = tokio::task::spawn_blocking(move || {
        if cancellation.is_cancelled() {
            return interrupted_probe(&cancellation, None, &[], ProbeCleanupStatus::NotApplicable);
        }
        let executable = match load_running_executable_snapshot() {
            Ok(executable) => executable,
            Err(detail) => {
                return active_network_probe(
                    ProbeStatus::Indeterminate,
                    Some(ProbeReasonCode::ProbeExecutableInspectionFailed),
                    detail,
                );
            }
        };
        run_active_podman_probe_from_snapshot_with_control(
            &plan,
            &executable,
            commands.as_ref(),
            &SystemReadinessProbe,
            &ElfScratchExecutableInspector,
            &cancellation,
            ActiveProbeLimits::default(),
        )
    });
    joined_probe(task.await)
}

#[cfg(target_os = "linux")]
fn joined_probe(result: Result<CapabilityProbe, tokio::task::JoinError>) -> CapabilityProbe {
    match result {
        Ok(probe) => probe,
        Err(error) => active_network_probe(
            ProbeStatus::Indeterminate,
            Some(ProbeReasonCode::ActiveProbeCommandFailed),
            format!("active Podman probe task failed: {error}"),
        ),
    }
}

/// Runs an active probe using injected process, HTTP, and executable-inspection adapters.
pub fn run_active_podman_probe_with(
    plan: &ActiveProbePlan,
    commands: &dyn CommandExecutor,
    readiness: &dyn ReadinessProbe,
    executable_inspector: &dyn ScratchExecutableInspector,
) -> CapabilityProbe {
    run_active_podman_probe_with_control(
        plan,
        commands,
        readiness,
        executable_inspector,
        &ProbeCancellation::default(),
        ActiveProbeLimits::default(),
    )
}

/// Runs an active probe with explicit cancellation and aggregate time limits.
pub fn run_active_podman_probe_with_control(
    plan: &ActiveProbePlan,
    commands: &dyn CommandExecutor,
    readiness: &dyn ReadinessProbe,
    executable_inspector: &dyn ScratchExecutableInspector,
    cancellation: &ProbeCancellation,
    limits: ActiveProbeLimits,
) -> CapabilityProbe {
    if cancellation.is_cancelled() {
        return interrupted_probe(cancellation, None, &[], ProbeCleanupStatus::NotApplicable);
    }
    let executable = match load_executable_snapshot(plan.executable()) {
        Ok(executable) => executable,
        Err(detail) => {
            return active_network_probe(
                ProbeStatus::Indeterminate,
                Some(ProbeReasonCode::ProbeExecutableInspectionFailed),
                detail,
            );
        }
    };
    run_active_podman_probe_from_snapshot_with_control(
        plan,
        &executable,
        commands,
        readiness,
        executable_inspector,
        cancellation,
        limits,
    )
}

fn run_active_podman_probe_from_snapshot_with_control(
    plan: &ActiveProbePlan,
    executable: &[u8],
    commands: &dyn CommandExecutor,
    readiness: &dyn ReadinessProbe,
    executable_inspector: &dyn ScratchExecutableInspector,
    cancellation: &ProbeCancellation,
    limits: ActiveProbeLimits,
) -> CapabilityProbe {
    match executable_inspector.inspect(executable) {
        ScratchCompatibility::Compatible => {}
        ScratchCompatibility::Incompatible(detail) => {
            return active_network_probe(
                ProbeStatus::Degraded,
                Some(ProbeReasonCode::ProbeExecutableNotStatic),
                detail,
            );
        }
        ScratchCompatibility::Indeterminate(detail) => {
            return active_network_probe(
                ProbeStatus::Indeterminate,
                Some(ProbeReasonCode::ProbeExecutableInspectionFailed),
                detail,
            );
        }
    }
    if cancellation.is_cancelled() {
        return interrupted_probe(cancellation, None, &[], ProbeCleanupStatus::NotApplicable);
    }

    let execution = run_lifecycle(plan, executable, commands, readiness, cancellation, limits);
    let cleanup = if execution.cleanup_errors.is_empty() {
        ProbeCleanupStatus::Complete
    } else {
        ProbeCleanupStatus::Failed
    };
    if cancellation.is_cancelled() {
        let outcome_detail = execution.outcome.err().map(|failure| failure.detail);
        return interrupted_probe(
            cancellation,
            outcome_detail.as_deref(),
            &execution.cleanup_errors,
            cleanup,
        );
    }
    match (execution.outcome, execution.cleanup_errors.is_empty()) {
        (Ok(()), true) => active_network_probe(
            ProbeStatus::Usable,
            None,
            "created an isolated rootless Podman network and reached a scratch-container readiness endpoint through a random loopback host port"
                .to_owned(),
        )
        .with_cleanup_status(cleanup),
        (Ok(()), false) => active_network_probe(
            ProbeStatus::Degraded,
            Some(ProbeReasonCode::ActiveProbeCleanupFailed),
            format!(
                "network verification succeeded, but owned probe resources could not be fully removed: {}",
                execution.cleanup_errors.join("; ")
            ),
        )
        .with_cleanup_status(cleanup),
        (Err(mut failure), _) => {
            if !execution.cleanup_errors.is_empty() {
                failure.detail.push_str("; cleanup: ");
                failure.detail.push_str(&execution.cleanup_errors.join("; "));
            }
            failure.into_probe().with_cleanup_status(cleanup)
        }
    }
}

fn interrupted_probe(
    cancellation: &ProbeCancellation,
    outcome_detail: Option<&str>,
    cleanup_errors: &[String],
    cleanup: ProbeCleanupStatus,
) -> CapabilityProbe {
    let mut detail = format!(
        "active Podman probe stopped after {} shutdown request(s); no further provisioning was started",
        cancellation.signal_count()
    );
    if let Some(outcome_detail) = outcome_detail {
        detail.push_str("; probe: ");
        detail.push_str(outcome_detail);
    }
    if cleanup_errors.is_empty() {
        detail.push_str("; bounded cleanup completed");
    } else {
        detail.push_str("; cleanup: ");
        detail.push_str(&cleanup_errors.join("; "));
    }
    active_network_probe(
        ProbeStatus::Indeterminate,
        Some(ProbeReasonCode::ActiveProbeInterrupted),
        detail,
    )
    .with_cleanup_status(cleanup)
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use std::{ffi::OsString, fs, os::unix::fs::PermissionsExt as _, path::PathBuf};

    use automata_ci_sandbox_podman::{
        PodmanBinary, PodmanLaunchTrust, PodmanLaunchTrustHandle, PodmanProcessEnvironment,
        PodmanStateRoot,
    };

    use super::*;

    #[derive(Debug)]
    struct TestLaunchTrust;

    impl PodmanLaunchTrust for TestLaunchTrust {
        fn revalidate(&self) -> bool {
            true
        }
    }

    fn admit_test_launch(options: PodmanOptions) -> PodmanOptions {
        options.with_launch_trust(PodmanLaunchTrustHandle::new(Arc::new(TestLaunchTrust)))
    }

    #[tokio::test]
    async fn configured_probe_stops_before_passive_inspection_when_cancelled() {
        let workspace_root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .and_then(std::path::Path::parent)
            .expect("runner crate must be beneath the workspace root");
        let root = workspace_root
            .join("target/agent-scratch/runner")
            .join(format!(
                "cancelled-configured-probe-{}",
                Uuid::new_v4().simple()
            ));
        fs::create_dir_all(&root).expect("probe fixture root must be creatable");
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700))
            .expect("probe fixture root must be private");
        let options = admit_test_launch(
            PodmanOptions::new(
                PodmanBinary::new(root.join("intentionally-missing-podman"))
                    .expect("absolute binary path"),
                PodmanStateRoot::existing(root.clone()).expect("existing state root"),
                PodmanProcessEnvironment::new(
                    root.join("home"),
                    root.join("runtime"),
                    root.clone(),
                    root.join("private/usr/sbin"),
                    "/usr/bin/conmon",
                    "/usr/bin/crun",
                    "/usr/bin/catatonit",
                    "/usr/share/containers/seccomp.json",
                )
                .expect("syntactic process environment"),
            )
            .expect("coherent Podman options"),
        );
        let cancellation = ProbeCancellation::default();
        cancellation.cancel();

        let probe = probe_configured_current_executable_with_control(
            &options,
            NetworkPolicy::PrivateEgress,
            &cancellation,
        )
        .await;

        assert_eq!(probe.status(), ProbeStatus::Indeterminate);
        assert_eq!(
            probe.reason().expect("cancelled probe reason").code(),
            ProbeReasonCode::ActiveProbeInterrupted
        );
        assert_eq!(probe.cleanup_status(), ProbeCleanupStatus::NotApplicable);
        fs::remove_dir_all(root).expect("probe fixture must be removable");
    }

    #[test]
    #[ignore = "requires an explicit rootless Podman host and static runner executable"]
    fn configured_rootless_lifecycle_matches_both_production_network_policies() {
        let executable = required_live_path("AUTOMATA_TEST_STATIC_RUNNER");
        let binary = required_live_path("AUTOMATA_TEST_PODMAN_BINARY");
        let state_root = required_live_path("AUTOMATA_TEST_PODMAN_STATE_ROOT");
        let home = required_live_path("AUTOMATA_TEST_PODMAN_HOME");
        let runtime_directory = required_live_path("AUTOMATA_TEST_PODMAN_RUNTIME");
        let helper_directory = required_live_path("AUTOMATA_TEST_PODMAN_APPROVED_HELPERS");
        let conmon = required_live_path("AUTOMATA_TEST_CONMON");
        let oci_runtime = required_live_path("AUTOMATA_TEST_OCI_RUNTIME");
        let init = required_live_path("AUTOMATA_TEST_CATATONIT");
        let seccomp = required_live_path("AUTOMATA_TEST_SECCOMP_PROFILE");
        let environment = PodmanProcessEnvironment::new(
            home,
            runtime_directory,
            state_root.clone(),
            helper_directory,
            conmon,
            oci_runtime,
            init,
            seccomp,
        )
        .expect("live Podman environment must satisfy the production contract");
        let options = admit_test_launch(
            PodmanOptions::new(
                PodmanBinary::new(binary).expect("live Podman binary must satisfy the contract"),
                PodmanStateRoot::existing(state_root.clone())
                    .expect("live Podman state root must already exist"),
                environment,
            )
            .expect("coherent live Podman options"),
        );
        options
            .prepare_state()
            .expect("materialize exact live Podman state");
        let commands = ConfiguredSystemCommandExecutor::from_options(&options);

        for network_policy in [NetworkPolicy::PrivateEgress, NetworkPolicy::Disabled] {
            let identifier = Uuid::new_v4().simple().to_string();
            let plan = ActiveProbePlan::new_in(
                executable.clone(),
                identifier,
                state_root.join("active-probe-live-test"),
                network_policy,
            )
            .expect("live active-probe plan must be valid");
            let probe = run_active_podman_probe_with_control(
                &plan,
                &commands,
                &SystemReadinessProbe,
                &ElfScratchExecutableInspector,
                &ProbeCancellation::default(),
                ActiveProbeLimits::default(),
            );

            assert_eq!(probe.status(), ProbeStatus::Usable, "{probe:?}");
        }
    }

    fn required_live_path(variable: &str) -> PathBuf {
        canonical_live_path(
            variable,
            std::env::var_os(variable)
                .unwrap_or_else(|| panic!("{variable} must name an explicit live-test path")),
        )
    }

    fn canonical_live_path(variable: &str, value: OsString) -> PathBuf {
        let path = std::fs::canonicalize(PathBuf::from(value))
            .unwrap_or_else(|error| panic!("{variable} must resolve exactly: {error}"));
        reject_system_temporary_path(&path);
        path
    }

    fn reject_system_temporary_path(path: &std::path::Path) {
        assert!(
            !path.starts_with("/tmp"),
            "live Podman tests must not use host /tmp: {}",
            path.display()
        );
    }
}

#[cfg(target_os = "linux")]
fn effective_user_id() -> Result<u32, String> {
    let status = fs::read_to_string("/proc/self/status")
        .map_err(|error| format!("could not inspect the effective user ID: {error}"))?;
    let uid_line = status
        .lines()
        .find(|line| line.starts_with("Uid:"))
        .ok_or_else(|| "could not find the effective user ID in /proc/self/status".to_owned())?;
    uid_line
        .split_ascii_whitespace()
        .nth(2)
        .ok_or_else(|| "effective user ID field is missing from /proc/self/status".to_owned())?
        .parse::<u32>()
        .map_err(|error| format!("effective user ID is invalid: {error}"))
}
