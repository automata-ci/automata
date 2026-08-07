use std::{
    fmt,
    sync::{
        Arc,
        atomic::{AtomicI64, Ordering},
    },
    time::{Duration, SystemTime},
};

use automata_core::UnixMillis;
use automata_store::{
    ControlPlaneMaintenanceRepository, ControlPlaneMaintenanceRequest, LeaseFailureLimit,
    MaintenanceBatchSize, StaleSessionTimeoutMillis,
};
use thiserror::Error;
use tokio_util::sync::CancellationToken;

/// Trusted wall-clock source for replica maintenance observations.
pub trait MaintenanceClock: fmt::Debug + Send + Sync {
    /// Returns a control-plane wall-clock observation.
    fn now(&self) -> UnixMillis;
}

/// Host wall-clock adapter that never regresses within one process lifetime.
#[derive(Debug, Default)]
pub struct SystemMaintenanceClock {
    last_observation: AtomicI64,
}

impl MaintenanceClock for SystemMaintenanceClock {
    fn now(&self) -> UnixMillis {
        let wall_clock = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .map_or(0, |duration| {
                i64::try_from(duration.as_millis()).unwrap_or(i64::MAX)
            });
        let previous = self
            .last_observation
            .fetch_max(wall_clock, Ordering::AcqRel);
        UnixMillis::new(previous.max(wall_clock))
    }
}

/// Non-overlapping, bounded maintenance loop for one control-plane replica.
pub struct ControlPlaneMaintenanceLoop {
    repository: Arc<dyn ControlPlaneMaintenanceRepository>,
    clock: Arc<dyn MaintenanceClock>,
    interval: Duration,
    maximum_lease_failures: LeaseFailureLimit,
    batch_size: MaintenanceBatchSize,
    stale_session_timeout: StaleSessionTimeoutMillis,
}

impl ControlPlaneMaintenanceLoop {
    /// Composes one replica control loop from neutral ports and validated policy.
    ///
    /// # Errors
    ///
    /// Rejects a sub-millisecond interval or a session timeout no longer than one pass interval.
    pub fn new(
        repository: Arc<dyn ControlPlaneMaintenanceRepository>,
        clock: Arc<dyn MaintenanceClock>,
        interval: Duration,
        maximum_lease_failures: LeaseFailureLimit,
        batch_size: MaintenanceBatchSize,
        stale_session_timeout: StaleSessionTimeoutMillis,
    ) -> Result<Self, MaintenanceLoopConfigError> {
        if interval.is_zero() || interval.as_millis() == 0 {
            return Err(MaintenanceLoopConfigError::IntervalTooShort);
        }
        let interval_millis = u64::try_from(interval.as_millis()).unwrap_or(u64::MAX);
        if stale_session_timeout.get() <= interval_millis {
            return Err(MaintenanceLoopConfigError::SessionTimeoutTooShort);
        }
        Ok(Self {
            repository,
            clock,
            interval,
            maximum_lease_failures,
            batch_size,
            stale_session_timeout,
        })
    }

    /// Performs passes until cancellation, waiting one full interval after each pass.
    ///
    /// A transient repository failure is logged as a sanitized category and retried
    /// after the normal interval. Cancellation can interrupt an in-flight pass.
    pub async fn run(&self, cancellation: CancellationToken) {
        loop {
            let Ok(request) = ControlPlaneMaintenanceRequest::new(
                self.clock.now(),
                self.maximum_lease_failures,
                self.batch_size,
                self.stale_session_timeout,
            ) else {
                tracing::error!(
                    error_kind = "invalid-observation",
                    "control-plane maintenance pass could not be constructed"
                );
                break;
            };
            let result = tokio::select! {
                biased;
                () = cancellation.cancelled() => break,
                result = self.repository.maintain_control_plane(request) => result,
            };
            match result {
                Ok(report) if !report.is_empty() => {
                    let requeued = report
                        .expired_attempts()
                        .iter()
                        .filter(|attempt| {
                            attempt.disposition()
                                == automata_store::ExpiredAttemptDisposition::Requeued
                        })
                        .count();
                    let lost = report.expired_attempts().len().saturating_sub(requeued);
                    tracing::info!(
                        expired_attempts = report.expired_attempts().len(),
                        requeued_attempts = requeued,
                        lost_attempts = lost,
                        skipped_blocked_attempts = report.skipped_blocked_attempts(),
                        closed_stale_sessions = report.closed_stale_sessions(),
                        "control-plane maintenance pass completed"
                    );
                }
                Ok(_) => {}
                Err(_) => tracing::warn!(
                    error_kind = "repository",
                    "control-plane maintenance pass failed"
                ),
            }

            tokio::select! {
                biased;
                () = cancellation.cancelled() => break,
                () = tokio::time::sleep(self.interval) => {}
            }
        }
    }
}

impl fmt::Debug for ControlPlaneMaintenanceLoop {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ControlPlaneMaintenanceLoop")
            .field("interval", &self.interval)
            .field("maximum_lease_failures", &self.maximum_lease_failures)
            .field("batch_size", &self.batch_size)
            .field("stale_session_timeout", &self.stale_session_timeout)
            .finish_non_exhaustive()
    }
}

/// Invalid replica maintenance-loop policy.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum MaintenanceLoopConfigError {
    /// A sub-millisecond delay could create an effective busy loop.
    #[error("control-plane maintenance interval must be at least one millisecond")]
    IntervalTooShort,
    /// Stale sessions must remain resumable for more than one loop interval.
    #[error("stale runner-session timeout must exceed the maintenance interval")]
    SessionTimeoutTooShort,
}
