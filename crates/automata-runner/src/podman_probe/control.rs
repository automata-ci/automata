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

    pub fn is_cancelled(&self) -> bool {
        self.signal_count.load(Ordering::Acquire) >= FIRST_SIGNAL
    }

    pub fn is_forced(&self) -> bool {
        self.signal_count.load(Ordering::Acquire) >= SECOND_SIGNAL
    }

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
    pub const fn new(readiness_timeout: Duration, cleanup_timeout: Duration) -> Self {
        Self {
            readiness_timeout,
            cleanup_timeout,
        }
    }

    pub const fn readiness_timeout(self) -> Duration {
        self.readiness_timeout
    }

    pub const fn cleanup_timeout(self) -> Duration {
        self.cleanup_timeout
    }
}

impl Default for ActiveProbeLimits {
    fn default() -> Self {
        Self::new(Duration::from_secs(10), Duration::from_secs(30))
    }
}
