use std::sync::{
    Arc,
    atomic::{AtomicBool, AtomicUsize, Ordering},
};
use std::time::Duration;

use async_trait::async_trait;
use automata::server::{
    Readiness, ReadinessMonitor, ReadinessMonitorError, ReadinessProbe, ReadinessProbeError,
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
    let monitor = ReadinessMonitor::new(
        database.clone(),
        object_store.clone(),
        Duration::from_secs(1),
    )
    .expect("positive interval must be valid");
    let readiness = Readiness::initializing();

    let first = monitor.check_once(&readiness).await;
    assert!(first.database());
    assert!(!first.object_store());
    assert!(!first.is_ready());

    object_store.set_healthy(true);
    let second = monitor.check_once(&readiness).await;
    assert!(second.is_ready());

    database.set_healthy(false);
    let third = monitor.check_once(&readiness).await;
    assert!(!third.database());
    assert!(third.object_store());
    assert!(!third.is_ready());
    assert_eq!(database.calls.load(Ordering::Acquire), 3);
    assert_eq!(object_store.calls.load(Ordering::Acquire), 3);
}

#[test]
fn readiness_monitor_rejects_a_zero_probe_interval() {
    let probe: Arc<dyn ReadinessProbe> = Arc::new(ToggleProbe::new(true));
    let error = ReadinessMonitor::new(Arc::clone(&probe), probe, Duration::ZERO)
        .expect_err("zero interval must be rejected");
    assert_eq!(error, ReadinessMonitorError);
}
