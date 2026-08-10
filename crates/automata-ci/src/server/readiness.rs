use std::{
    fmt,
    sync::{
        Arc,
        atomic::{AtomicU8, Ordering},
    },
    time::{Duration, Instant},
};

use async_trait::async_trait;
use thiserror::Error;
use tokio_util::sync::CancellationToken;

use super::metrics::ControlPlaneMetrics;

const DATABASE_READY: u8 = 1 << 0;
const OBJECT_STORE_READY: u8 = 1 << 1;
const AUTONOMOUS_WORKFLOW_READY: u8 = 1 << 2;
const ALL_READY: u8 = DATABASE_READY | OBJECT_STORE_READY | AUTONOMOUS_WORKFLOW_READY;

/// Sanitized readiness snapshot for the replica's mandatory shared services.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReadinessSnapshot {
    database: bool,
    object_store: bool,
    autonomous_workflow: bool,
}

impl ReadinessSnapshot {
    /// Whether migrations and the database probe succeeded most recently.
    #[must_use]
    pub const fn database(self) -> bool {
        self.database
    }

    /// Whether the immutable object-store round trip succeeded most recently.
    #[must_use]
    pub const fn object_store(self) -> bool {
        self.object_store
    }

    /// Whether the autonomous workflow worker has reached its first poll.
    #[must_use]
    pub const fn autonomous_workflow(self) -> bool {
        self.autonomous_workflow
    }

    /// Whether this replica can safely accept orchestration traffic.
    #[must_use]
    pub const fn is_ready(self) -> bool {
        self.database && self.object_store && self.autonomous_workflow
    }
}

/// Lock-free aggregate readiness shared with the human-facing HTTP router.
#[derive(Clone, Default)]
pub struct Readiness {
    bits: Arc<AtomicU8>,
}

impl Readiness {
    /// Creates an initializing, non-ready state.
    #[must_use]
    pub fn initializing() -> Self {
        Self::default()
    }

    /// Creates a state in which every mandatory dependency and worker is ready.
    ///
    /// Standalone router tests and embedding adapters can use this explicitly;
    /// production wiring starts with [`Self::initializing`].
    #[must_use]
    pub fn all_ready() -> Self {
        Self {
            bits: Arc::new(AtomicU8::new(ALL_READY)),
        }
    }

    /// Returns the latest aggregate snapshot.
    #[must_use]
    pub fn snapshot(&self) -> ReadinessSnapshot {
        let bits = self.bits.load(Ordering::Acquire);
        ReadinessSnapshot {
            database: bits & DATABASE_READY != 0,
            object_store: bits & OBJECT_STORE_READY != 0,
            autonomous_workflow: bits & AUTONOMOUS_WORKFLOW_READY != 0,
        }
    }

    pub(crate) fn update_dependencies(&self, database: bool, object_store: bool) {
        let mut dependency_bits = 0;
        if database {
            dependency_bits |= DATABASE_READY;
        }
        if object_store {
            dependency_bits |= OBJECT_STORE_READY;
        }
        self.bits
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |bits| {
                Some((bits & AUTONOMOUS_WORKFLOW_READY) | dependency_bits)
            })
            .expect("readiness update is infallible");
    }

    /// Publishes whether the mandatory autonomous workflow worker is polling.
    ///
    /// Dependency readiness bits are preserved atomically so a concurrent
    /// monitor refresh cannot erase the worker's first-poll signal.
    pub fn set_autonomous_workflow_ready(&self, ready: bool) {
        if ready {
            self.bits
                .fetch_or(AUTONOMOUS_WORKFLOW_READY, Ordering::AcqRel);
        } else {
            self.bits
                .fetch_and(!AUTONOMOUS_WORKFLOW_READY, Ordering::AcqRel);
        }
    }
}

impl fmt::Debug for Readiness {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Readiness")
            .field("snapshot", &self.snapshot())
            .finish()
    }
}

/// Sanitized failure of one dependency probe.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
#[error("dependency readiness probe failed")]
pub struct ReadinessProbeError;

/// Provider-neutral active readiness check.
#[async_trait]
pub trait ReadinessProbe: fmt::Debug + Send + Sync {
    /// Checks one mandatory shared dependency without returning provider details.
    async fn probe(&self) -> Result<(), ReadinessProbeError>;
}

/// Periodically refreshes aggregate readiness from independent dependency ports.
pub struct ReadinessMonitor {
    database: Arc<dyn ReadinessProbe>,
    object_store: Arc<dyn ReadinessProbe>,
    interval: Duration,
    metrics: Option<ControlPlaneMetrics>,
}

impl ReadinessMonitor {
    /// Composes mandatory dependency probes under a positive refresh interval.
    ///
    /// # Errors
    ///
    /// Rejects a zero refresh interval.
    pub fn new(
        database: Arc<dyn ReadinessProbe>,
        object_store: Arc<dyn ReadinessProbe>,
        interval: Duration,
    ) -> Result<Self, ReadinessMonitorError> {
        if interval.is_zero() {
            return Err(ReadinessMonitorError);
        }
        Ok(Self {
            database,
            object_store,
            interval,
            metrics: None,
        })
    }

    /// Attaches control-plane observations without changing probe correctness.
    #[must_use]
    pub fn with_metrics(mut self, metrics: ControlPlaneMetrics) -> Self {
        self.metrics = Some(metrics);
        self
    }

    /// Runs both independent probes and atomically publishes their result.
    pub async fn check_once(&self, readiness: &Readiness) -> ReadinessSnapshot {
        let previous = readiness.snapshot();
        let (database, object_store) = tokio::join!(
            probe_once(&self.database, self.interval),
            probe_once(&self.object_store, self.interval)
        );
        readiness.update_dependencies(database.ready, object_store.ready);
        let current = readiness.snapshot();
        if let Some(metrics) = &self.metrics {
            metrics.observe_dependency_probe(
                "database",
                database.outcome,
                database.duration,
                previous.database(),
                current.database(),
            );
            metrics.observe_dependency_probe(
                "object_store",
                object_store.outcome,
                object_store.duration,
                previous.object_store(),
                current.object_store(),
            );
            metrics.set_ready(current.is_ready());
        }
        current
    }

    /// Refreshes readiness until shared process shutdown is requested.
    pub async fn run(&self, readiness: Readiness, shutdown: CancellationToken) {
        loop {
            tokio::select! {
                () = shutdown.cancelled() => break,
                () = tokio::time::sleep(self.interval) => {
                    let previous = readiness.snapshot();
                    let current = self.check_once(&readiness).await;
                    if previous != current {
                        tracing::info!(
                            database_ready = current.database(),
                            object_store_ready = current.object_store(),
                            autonomous_workflow_ready = current.autonomous_workflow(),
                            "control-plane readiness changed"
                        );
                    }
                }
            }
        }
    }
}

struct ProbeObservation {
    ready: bool,
    outcome: &'static str,
    duration: Duration,
}

async fn probe_once(probe: &Arc<dyn ReadinessProbe>, timeout: Duration) -> ProbeObservation {
    let started = Instant::now();
    let result = tokio::time::timeout(timeout, probe.probe()).await;
    let (ready, outcome) = match result {
        Ok(Ok(())) => (true, "success"),
        Ok(Err(_)) => (false, "error"),
        Err(_) => (false, "timeout"),
    };
    ProbeObservation {
        ready,
        outcome,
        duration: started.elapsed(),
    }
}

impl fmt::Debug for ReadinessMonitor {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ReadinessMonitor")
            .field("interval", &self.interval)
            .finish_non_exhaustive()
    }
}

/// Invalid readiness-monitor configuration.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
#[error("readiness probe interval must be greater than zero")]
pub struct ReadinessMonitorError;
