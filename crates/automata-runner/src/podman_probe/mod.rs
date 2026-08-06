mod command;
mod control;
mod elf;
mod http;
mod lifecycle;
mod plan;

#[cfg(target_os = "linux")]
use std::fs;

pub use command::{
    CommandExecutor, CommandOutput, CommandRequest, CommandTermination, SystemCommandExecutor,
};
pub use control::{ActiveProbeLimits, ProbeCancellation};
pub use elf::{ElfScratchExecutableInspector, ScratchCompatibility, ScratchExecutableInspector};
pub use http::{ReadinessProbe, SystemReadinessProbe};
pub use plan::ActiveProbePlan;
use uuid::Uuid;

use crate::capability_probe::{
    CapabilityProbe, ProbeReasonCode, ProbeStatus, active_network_probe,
};
use lifecycle::run_lifecycle;

/// Runs the opt-in active Podman/Netavark probe with system adapters.
pub async fn probe_current_executable() -> CapabilityProbe {
    #[cfg(not(target_os = "linux"))]
    {
        active_network_probe(
            ProbeStatus::Unavailable,
            Some(ProbeReasonCode::ActiveProbeUnsupportedPlatform),
            "the active Podman network probe is currently supported only on Linux".to_owned(),
        )
    }

    #[cfg(target_os = "linux")]
    {
        match effective_user_id() {
            Ok(0) => {
                return active_network_probe(
                    ProbeStatus::Unavailable,
                    Some(ProbeReasonCode::ActiveProbeRequiresRootlessUser),
                    "the active network probe must run as a non-root user so it exercises rootless Podman"
                        .to_owned(),
                );
            }
            Ok(_) => {}
            Err(error) => {
                return active_network_probe(
                    ProbeStatus::Indeterminate,
                    Some(ProbeReasonCode::ActiveProbeRequiresRootlessUser),
                    error,
                );
            }
        }
        let executable = match std::env::current_exe() {
            Ok(executable) => executable,
            Err(error) => {
                return active_network_probe(
                    ProbeStatus::Indeterminate,
                    Some(ProbeReasonCode::ProbeExecutableInspectionFailed),
                    format!("could not resolve the current runner executable: {error}"),
                );
            }
        };
        let identifier = Uuid::new_v4().simple().to_string();
        let plan = match ActiveProbePlan::new(executable, identifier) {
            Ok(plan) => plan,
            Err(error) => {
                return active_network_probe(
                    ProbeStatus::Indeterminate,
                    Some(ProbeReasonCode::ActiveProbePreparationFailed),
                    error,
                );
            }
        };

        run_system_active_probe(plan).await
    }
}

#[cfg(target_os = "linux")]
async fn run_system_active_probe(plan: ActiveProbePlan) -> CapabilityProbe {
    use tokio::signal::unix::{SignalKind, signal};

    let mut interrupt = match signal(SignalKind::interrupt()) {
        Ok(signal) => signal,
        Err(error) => return signal_registration_failure("SIGINT", &error),
    };
    let mut terminate = match signal(SignalKind::terminate()) {
        Ok(signal) => signal,
        Err(error) => return signal_registration_failure("SIGTERM", &error),
    };
    let cancellation = ProbeCancellation::default();
    let observer_cancellation = cancellation.clone();
    let observer = tokio::spawn(async move {
        loop {
            let received = tokio::select! {
                received = interrupt.recv() => received,
                received = terminate.recv() => received,
            };
            if received.is_none() {
                break;
            }
            observer_cancellation.cancel();
        }
    });

    let probe_cancellation = cancellation.clone();
    let task = tokio::task::spawn_blocking(move || {
        run_active_podman_probe_with_control(
            &plan,
            &SystemCommandExecutor,
            &SystemReadinessProbe,
            &ElfScratchExecutableInspector,
            &probe_cancellation,
            ActiveProbeLimits::default(),
        )
    });
    let probe = joined_probe(task.await);
    observer.abort();
    let _observer_result = observer.await;
    probe
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

#[cfg(target_os = "linux")]
fn signal_registration_failure(signal: &str, error: &std::io::Error) -> CapabilityProbe {
    active_network_probe(
        ProbeStatus::Indeterminate,
        Some(ProbeReasonCode::ActiveProbePreparationFailed),
        format!("could not install the active-probe {signal} observer: {error}"),
    )
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
        return interrupted_probe(cancellation, None, &[]);
    }
    match executable_inspector.inspect(plan.executable()) {
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
        return interrupted_probe(cancellation, None, &[]);
    }

    let execution = run_lifecycle(plan, commands, readiness, cancellation, limits);
    if cancellation.is_cancelled() {
        let outcome_detail = execution.outcome.err().map(|failure| failure.detail);
        return interrupted_probe(
            cancellation,
            outcome_detail.as_deref(),
            &execution.cleanup_errors,
        );
    }
    match (execution.outcome, execution.cleanup_errors.is_empty()) {
        (Ok(()), true) => active_network_probe(
            ProbeStatus::Usable,
            None,
            "created an isolated rootless Podman network and reached a scratch-container readiness endpoint through a random loopback host port"
                .to_owned(),
        ),
        (Ok(()), false) => active_network_probe(
            ProbeStatus::Degraded,
            Some(ProbeReasonCode::ActiveProbeCleanupFailed),
            format!(
                "network verification succeeded, but owned probe resources could not be fully removed: {}",
                execution.cleanup_errors.join("; ")
            ),
        ),
        (Err(mut failure), _) => {
            if !execution.cleanup_errors.is_empty() {
                failure.detail.push_str("; cleanup: ");
                failure.detail.push_str(&execution.cleanup_errors.join("; "));
            }
            failure.into_probe()
        }
    }
}

fn interrupted_probe(
    cancellation: &ProbeCancellation,
    outcome_detail: Option<&str>,
    cleanup_errors: &[String],
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
