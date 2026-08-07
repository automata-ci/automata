use std::{
    fmt,
    sync::{
        Arc,
        atomic::{AtomicU8, Ordering},
    },
    time::Duration,
};

use async_trait::async_trait;
use thiserror::Error;
use tokio_util::sync::CancellationToken;

const DATABASE_READY: u8 = 1 << 0;
const OBJECT_STORE_READY: u8 = 1 << 1;
const ALL_READY: u8 = DATABASE_READY | OBJECT_STORE_READY;

/// Sanitized readiness snapshot for the replica's mandatory shared services.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReadinessSnapshot {
    database: bool,
    object_store: bool,
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

    /// Whether this replica can safely accept orchestration traffic.
    #[must_use]
    pub const fn is_ready(self) -> bool {
        self.database && self.object_store
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

    /// Creates a state in which both mandatory dependencies have been probed.
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
        }
    }

    pub(crate) fn update(&self, database: bool, object_store: bool) {
        let mut bits = 0;
        if database {
            bits |= DATABASE_READY;
        }
        if object_store {
            bits |= OBJECT_STORE_READY;
        }
        self.bits.store(bits, Ordering::Release);
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
        })
    }

    /// Runs both independent probes and atomically publishes their result.
    pub async fn check_once(&self, readiness: &Readiness) -> ReadinessSnapshot {
        let (database, object_store) = tokio::join!(
            tokio::time::timeout(self.interval, self.database.probe()),
            tokio::time::timeout(self.interval, self.object_store.probe())
        );
        let database = database.is_ok_and(|result| result.is_ok());
        let object_store = object_store.is_ok_and(|result| result.is_ok());
        readiness.update(database, object_store);
        readiness.snapshot()
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
                            "control-plane readiness changed"
                        );
                    }
                }
            }
        }
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
