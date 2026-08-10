use std::sync::{
    Arc,
    atomic::{AtomicBool, AtomicUsize, Ordering},
};
use std::time::Duration;
use std::{fmt, future::pending};

use async_trait::async_trait;
use automata_ci::build_info::BuildInfo;
use automata_ci::server::{
    ControlPlaneMetrics, Readiness, ReadinessMonitor, ReadinessMonitorError, ReadinessProbe,
    ReadinessProbeError,
};

#[derive(Debug)]
struct ToggleProbe {
    healthy: AtomicBool,
    calls: AtomicUsize,
}

impl ToggleProbe {
    const fn new(healthy: bool) -> Self {
        Self {
            healthy: AtomicBool::new(healthy),
            calls: AtomicUsize::new(0),
        }
    }

    fn set_healthy(&self, healthy: bool) {
        self.healthy.store(healthy, Ordering::Release);
    }
}

#[async_trait]
impl ReadinessProbe for ToggleProbe {
    async fn probe(&self) -> Result<(), ReadinessProbeError> {
        self.calls.fetch_add(1, Ordering::AcqRel);
        self.healthy
            .load(Ordering::Acquire)
            .then_some(())
            .ok_or(ReadinessProbeError)
    }
}

#[tokio::test]
async fn readiness_requires_fresh_success_from_both_dependency_ports() {
    let database = Arc::new(ToggleProbe::new(true));
    let object_store = Arc::new(ToggleProbe::new(false));
    let metrics = ControlPlaneMetrics::new(BuildInfo::current()).expect("control metrics");
    let monitor = ReadinessMonitor::new(
        database.clone(),
        object_store.clone(),
        Duration::from_secs(1),
    )
    .expect("positive interval must be valid")
    .with_metrics(metrics.clone());
    let readiness = Readiness::initializing();

    let first = monitor.check_once(&readiness).await;
    assert!(first.database());
    assert!(!first.object_store());
    assert!(!first.autonomous_workflow());
    assert!(!first.is_ready());

    object_store.set_healthy(true);
    let second = monitor.check_once(&readiness).await;
    assert!(!second.is_ready());
    readiness.set_autonomous_workflow_ready(true);
    assert!(readiness.snapshot().is_ready());

    let worker_ready_after_refresh = monitor.check_once(&readiness).await;
    assert!(worker_ready_after_refresh.autonomous_workflow());
    assert!(worker_ready_after_refresh.is_ready());

    database.set_healthy(false);
    let third = monitor.check_once(&readiness).await;
    assert!(!third.database());
    assert!(third.object_store());
    assert!(!third.is_ready());
    assert_eq!(database.calls.load(Ordering::Acquire), 4);
    assert_eq!(object_store.calls.load(Ordering::Acquire), 4);

    let exposition = metrics
        .exporter()
        .encode_openmetrics()
        .expect("bounded exposition");
    let exposition = exposition.as_str();
    assert!(exposition.contains(
        "automata_ci_control_plane_dependency_probes_total{dependency=\"database\",outcome=\"success\"} 3"
    ));
    assert!(exposition.contains(
        "automata_ci_control_plane_dependency_probes_total{dependency=\"database\",outcome=\"error\"} 1"
    ));
    assert!(exposition.contains(
        "automata_ci_control_plane_dependency_readiness_transitions_total{dependency=\"database\",state=\"ready\"} 1"
    ));
    assert!(exposition.contains(
        "automata_ci_control_plane_dependency_readiness_transitions_total{dependency=\"database\",state=\"unready\"} 1"
    ));
    assert!(exposition.contains("automata_ci_control_plane_ready 0"));
}

#[test]
fn dependency_and_worker_updates_preserve_each_other() {
    let readiness = Readiness::initializing();
    readiness.set_autonomous_workflow_ready(true);

    // The public snapshot proves the worker bit survives dependency updates;
    // the monitor path exercises the same atomic update above.
    let snapshot = readiness.snapshot();
    assert!(snapshot.autonomous_workflow());
    assert!(!snapshot.is_ready());

    readiness.set_autonomous_workflow_ready(false);
    assert!(!readiness.snapshot().autonomous_workflow());
}

struct PendingProbe;

impl fmt::Debug for PendingProbe {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("PendingProbe")
    }
}

#[async_trait]
impl ReadinessProbe for PendingProbe {
    async fn probe(&self) -> Result<(), ReadinessProbeError> {
        pending().await
    }
}

#[tokio::test]
async fn readiness_metrics_distinguish_timeouts_from_closed_probe_errors() {
    let metrics = ControlPlaneMetrics::new(BuildInfo::current()).expect("control metrics");
    let monitor = ReadinessMonitor::new(
        Arc::new(PendingProbe),
        Arc::new(ToggleProbe::new(false)),
        Duration::from_millis(5),
    )
    .expect("positive interval")
    .with_metrics(metrics.clone());

    let snapshot = monitor.check_once(&Readiness::initializing()).await;
    assert!(!snapshot.is_ready());
    let exposition = metrics
        .exporter()
        .encode_openmetrics()
        .expect("bounded exposition");
    let exposition = exposition.as_str();
    assert!(exposition.contains(
        "automata_ci_control_plane_dependency_probes_total{dependency=\"database\",outcome=\"timeout\"} 1"
    ));
    assert!(exposition.contains(
        "automata_ci_control_plane_dependency_probes_total{dependency=\"object_store\",outcome=\"error\"} 1"
    ));
}

#[test]
fn readiness_monitor_rejects_a_zero_probe_interval() {
    let probe: Arc<dyn ReadinessProbe> = Arc::new(ToggleProbe::new(true));
    let error = ReadinessMonitor::new(Arc::clone(&probe), probe, Duration::ZERO)
        .expect_err("zero interval must be rejected");
    assert_eq!(error, ReadinessMonitorError);
}
