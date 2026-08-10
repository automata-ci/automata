use std::{
    sync::{
        Arc,
        atomic::{AtomicU8, Ordering},
    },
    time::Duration,
};

const FIRST_SIGNAL: u8 = 1;
const SECOND_SIGNAL: u8 = 2;

/// Shared cancellation state for an active Podman probe.
///
/// The first request stops provisioning and allows bounded cleanup. A second
/// request also interrupts cleanup commands so shutdown can finish promptly.
#[derive(Clone, Debug, Default)]
pub struct ProbeCancellation {
    signal_count: Arc<AtomicU8>,
}

impl ProbeCancellation {
    /// Records a shutdown request. Counts are saturated because only the first
    /// and second requests have distinct semantics.
    pub fn cancel(&self) {
        let _previous =
            self.signal_count
                .fetch_update(Ordering::AcqRel, Ordering::Acquire, |count| {
                    Some(count.saturating_add(1).min(SECOND_SIGNAL))
                });
    }

    /// Reports whether provisioning must stop and bounded cleanup must begin.
    pub fn is_cancelled(&self) -> bool {
        self.signal_count.load(Ordering::Acquire) >= FIRST_SIGNAL
    }

    /// Reports whether cleanup commands must also be interrupted.
    pub fn is_forced(&self) -> bool {
        self.signal_count.load(Ordering::Acquire) >= SECOND_SIGNAL
    }

    /// Returns the saturated shutdown-request count (`0`, `1`, or `2`).
    pub fn signal_count(&self) -> u8 {
        self.signal_count.load(Ordering::Acquire)
    }
}

/// Time limits that span adapter boundaries during an active probe.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ActiveProbeLimits {
    readiness_timeout: Duration,
    cleanup_timeout: Duration,
}

impl ActiveProbeLimits {
    /// Creates explicit readiness and aggregate-cleanup deadlines.
    pub const fn new(readiness_timeout: Duration, cleanup_timeout: Duration) -> Self {
        Self {
            readiness_timeout,
            cleanup_timeout,
        }
    }

    /// Returns the maximum time allowed for isolated HTTP readiness.
    pub const fn readiness_timeout(self) -> Duration {
        self.readiness_timeout
    }

    /// Returns the aggregate deadline shared by all cleanup commands.
    pub const fn cleanup_timeout(self) -> Duration {
        self.cleanup_timeout
    }
}

impl Default for ActiveProbeLimits {
    fn default() -> Self {
        Self::new(Duration::from_secs(10), Duration::from_secs(30))
    }
}
