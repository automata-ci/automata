use std::{future, time::Duration};

use automata_ci_metrics::{
    BuildInfo, ExporterLimits, MetricsBuilder, PROCESS_SNAPSHOT_INTERVAL, ProcessRole,
};

fn builder() -> MetricsBuilder {
    MetricsBuilder::new(BuildInfo::new(
        ProcessRole::MetricsFixture,
        "1.2.3-test",
        "unknown",
    ))
    .expect("valid metrics builder")
}

#[test]
fn initial_snapshot_is_exposed_from_cached_standard_metric_handles() {
    let builder = builder();
    let metrics = builder.finish(ExporterLimits::default());
    let exposition = metrics.encode_openmetrics().expect("encode metrics");
    let body = exposition.as_str();

    for name in [
        "process_cpu_seconds_total",
        "process_resident_memory_bytes",
        "process_virtual_memory_bytes",
        "process_threads",
        "process_open_fds",
        "process_max_fds",
        "automata_ci_metrics_process_snapshot_refreshes_total",
        "automata_ci_metrics_process_snapshot_healthy",
        "automata_ci_metrics_process_snapshot_last_success_timestamp_seconds",
    ] {
        assert!(body.contains(name), "missing process family {name}");
    }
    assert!(!body.contains("automata_ci_process_cpu_seconds_total"));
    assert!(body.ends_with("# EOF\n"));
}

#[tokio::test]
async fn sampler_obeys_an_already_resolved_shutdown_future() {
    assert_eq!(PROCESS_SNAPSHOT_INTERVAL, Duration::from_secs(10));
    let builder = builder();
    let sampler = builder.process_sampler();

    tokio::time::timeout(
        Duration::from_millis(100),
        sampler.run_until_cancelled(future::ready(())),
    )
    .await
    .expect("cancelled sampler should return promptly");
}
