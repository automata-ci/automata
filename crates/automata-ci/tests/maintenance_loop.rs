use std::{
    fmt,
    future::pending,
    sync::{Arc, Mutex},
    time::Duration,
};

use async_trait::async_trait;
use automata_ci::build_info::BuildInfo;
use automata_ci::server::{
    ControlPlaneMaintenanceLoop, ControlPlaneMetrics, MaintenanceClock, MaintenanceLoopConfigError,
};
use automata_ci_control::maintenance::{
    ControlPlaneMaintenanceReport, ControlPlaneMaintenanceRepository,
    ControlPlaneMaintenanceRequest, LeaseFailureLimit, MaintenanceBatchSize,
    StaleSessionTimeoutMillis,
};
use automata_ci_core::UnixMillis;
use automata_ci_store::StoreError;
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

struct OnePassRepository {
    result: Mutex<Option<Result<ControlPlaneMaintenanceReport, StoreError>>>,
    cancellation: CancellationToken,
}

impl fmt::Debug for OnePassRepository {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OnePassRepository")
            .finish_non_exhaustive()
    }
}

#[async_trait]
impl ControlPlaneMaintenanceRepository for OnePassRepository {
    async fn maintain_control_plane(
        &self,
        _request: ControlPlaneMaintenanceRequest,
    ) -> Result<ControlPlaneMaintenanceReport, StoreError> {
        let result = self
            .result
            .lock()
            .expect("test lock")
            .take()
            .expect("one maintenance pass");
        self.cancellation.cancel();
        result
    }
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

#[tokio::test]
async fn maintenance_metrics_record_successful_empty_passes_and_last_success() {
    let cancellation = CancellationToken::new();
    let repository: Arc<dyn ControlPlaneMaintenanceRepository> = Arc::new(OnePassRepository {
        result: Mutex::new(Some(Ok(ControlPlaneMaintenanceReport::default()))),
        cancellation: cancellation.clone(),
    });
    let metrics = ControlPlaneMetrics::new(BuildInfo::current()).expect("control metrics");
    let maintenance = loop_policy(repository, Duration::from_secs(1), 30_000)
        .expect("valid maintenance loop")
        .with_metrics(metrics.clone());

    maintenance.run(cancellation).await;
    let exposition = metrics
        .exporter()
        .encode_openmetrics()
        .expect("bounded exposition");
    let exposition = exposition.as_str();
    assert!(
        exposition
            .contains("automata_ci_control_plane_maintenance_passes_total{outcome=\"success\"} 1")
    );
    assert!(exposition.contains(
        "automata_ci_control_plane_maintenance_work_items_total{kind=\"requeued_attempt\"} 0"
    ));
    assert!(
        exposition
            .contains("automata_ci_control_plane_maintenance_last_success_timestamp_seconds ")
    );
    assert!(exposition.contains("automata_ci_control_plane_maintenance_batch_saturated 0"));
}

#[tokio::test]
async fn maintenance_metrics_close_repository_errors_without_leaking_diagnostics() {
    let cancellation = CancellationToken::new();
    let repository: Arc<dyn ControlPlaneMaintenanceRepository> = Arc::new(OnePassRepository {
        result: Mutex::new(Some(Err(StoreError::corrupt_data(
            "private-maintenance-error-marker",
        )))),
        cancellation: cancellation.clone(),
    });
    let metrics = ControlPlaneMetrics::new(BuildInfo::current()).expect("control metrics");
    let maintenance = loop_policy(repository, Duration::from_secs(1), 30_000)
        .expect("valid maintenance loop")
        .with_metrics(metrics.clone());

    maintenance.run(cancellation).await;
    let exposition = metrics
        .exporter()
        .encode_openmetrics()
        .expect("bounded exposition");
    let exposition = exposition.as_str();
    assert!(
        exposition
            .contains("automata_ci_control_plane_maintenance_passes_total{outcome=\"error\"} 1")
    );
    assert!(!exposition.contains("private-maintenance-error-marker"));
}
