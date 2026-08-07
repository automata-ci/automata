use std::{
    fmt,
    future::pending,
    sync::{Arc, Mutex},
    time::Duration,
};

use async_trait::async_trait;
use automata::server::{ControlPlaneMaintenanceLoop, MaintenanceClock, MaintenanceLoopConfigError};
use automata_core::UnixMillis;
use automata_store::{
    ControlPlaneMaintenanceReport, ControlPlaneMaintenanceRepository,
    ControlPlaneMaintenanceRequest, LeaseFailureLimit, MaintenanceBatchSize,
    StaleSessionTimeoutMillis, StoreError,
};
use tokio::sync::oneshot;
use tokio_util::sync::CancellationToken;

#[derive(Debug)]
struct FixedClock;

impl MaintenanceClock for FixedClock {
    fn now(&self) -> UnixMillis {
        UnixMillis::new(100_000)
    }
}

struct BlockingRepository {
    entered: Mutex<Option<oneshot::Sender<ControlPlaneMaintenanceRequest>>>,
}

impl fmt::Debug for BlockingRepository {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BlockingRepository")
            .finish_non_exhaustive()
    }
}

#[async_trait]
impl ControlPlaneMaintenanceRepository for BlockingRepository {
    async fn maintain_control_plane(
        &self,
        request: ControlPlaneMaintenanceRequest,
    ) -> Result<ControlPlaneMaintenanceReport, StoreError> {
        if let Some(entered) = self.entered.lock().expect("test lock").take() {
            let _ = entered.send(request);
        }
        pending().await
    }
}

fn loop_policy(
    repository: Arc<dyn ControlPlaneMaintenanceRepository>,
    interval: Duration,
    stale_millis: u64,
) -> Result<ControlPlaneMaintenanceLoop, MaintenanceLoopConfigError> {
    ControlPlaneMaintenanceLoop::new(
        repository,
        Arc::new(FixedClock),
        interval,
        LeaseFailureLimit::new(3).expect("failure policy"),
        MaintenanceBatchSize::new(10).expect("batch size"),
        StaleSessionTimeoutMillis::new(stale_millis).expect("stale timeout"),
    )
}

#[tokio::test]
async fn cancellation_interrupts_an_in_flight_maintenance_pass() {
    let (entered_tx, entered_rx) = oneshot::channel();
    let repository: Arc<dyn ControlPlaneMaintenanceRepository> = Arc::new(BlockingRepository {
        entered: Mutex::new(Some(entered_tx)),
    });
    let maintenance =
        loop_policy(repository, Duration::from_secs(1), 30_000).expect("valid maintenance loop");
    let cancellation = CancellationToken::new();
    let worker_cancellation = cancellation.clone();
    let worker = tokio::spawn(async move { maintenance.run(worker_cancellation).await });

    let request = entered_rx.await.expect("first pass must start immediately");
    assert_eq!(request.observed_at(), UnixMillis::new(100_000));
    assert_eq!(request.stale_session_cutoff(), UnixMillis::new(70_000));

    cancellation.cancel();
    tokio::time::timeout(Duration::from_secs(1), worker)
        .await
        .expect("cancellation must not wait for the repository future")
        .expect("maintenance task must join");
}

#[test]
fn maintenance_loop_rejects_busy_and_premature_staleness_policies() {
    let (entered_tx, _entered_rx) = oneshot::channel();
    let repository: Arc<dyn ControlPlaneMaintenanceRepository> = Arc::new(BlockingRepository {
        entered: Mutex::new(Some(entered_tx)),
    });
    assert!(matches!(
        loop_policy(Arc::clone(&repository), Duration::ZERO, 30_000),
        Err(MaintenanceLoopConfigError::IntervalTooShort)
    ));
    assert!(matches!(
        loop_policy(Arc::clone(&repository), Duration::from_nanos(1), 30_000),
        Err(MaintenanceLoopConfigError::IntervalTooShort)
    ));
    assert!(matches!(
        loop_policy(repository, Duration::from_secs(30), 30_000),
        Err(MaintenanceLoopConfigError::SessionTimeoutTooShort)
    ));
}
