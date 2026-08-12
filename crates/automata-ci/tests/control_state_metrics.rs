use std::collections::BTreeSet;

use automata_ci::{build_info::BuildInfo, server::ControlPlaneMetrics};

const STATE_FAMILIES: [&str; 28] = [
    "automata_ci_control_plane_artifact_reservation_oldest_timestamp_seconds",
    "automata_ci_control_plane_artifact_reservations",
    "automata_ci_control_plane_artifacts",
    "automata_ci_control_plane_cancellation_intents_oldest_timestamp_seconds",
    "automata_ci_control_plane_cancellation_intents_pending",
    "automata_ci_control_plane_commands_oldest_timestamp_seconds",
    "automata_ci_control_plane_commands_pending",
    "automata_ci_control_plane_eligible_queue_blocked_jobs",
    "automata_ci_control_plane_eligible_queue_blocked_oldest_timestamp_seconds",
    "automata_ci_control_plane_job_attempts",
    "automata_ci_control_plane_leases",
    "automata_ci_control_plane_logical_activation_oldest_timestamp_seconds",
    "automata_ci_control_plane_logical_activation_publications",
    "automata_ci_control_plane_logical_activations",
    "automata_ci_control_plane_logical_jobs",
    "automata_ci_control_plane_logical_materialized_instances",
    "automata_ci_control_plane_queue_jobs",
    "automata_ci_control_plane_queue_oldest_timestamp_seconds",
    "automata_ci_control_plane_runner_sessions",
    "automata_ci_control_plane_runners",
    "automata_ci_control_plane_state_sampler_duration_seconds",
    "automata_ci_control_plane_state_sampler_healthy",
    "automata_ci_control_plane_state_sampler_last_success_timestamp_seconds",
    "automata_ci_control_plane_state_sampler_runs",
    "automata_ci_control_plane_workflow_runs",
    "automata_ci_control_plane_logical_workflow_runs",
    "automata_ci_postgres_pool_connections",
    "automata_ci_postgres_pool_max_connections",
];

#[test]
fn product_registry_contains_the_exact_bounded_cached_state_schema() {
    let metrics =
        ControlPlaneMetrics::new(BuildInfo::current()).expect("valid embedded build provenance");
    let exposition = metrics
        .exporter()
        .encode_openmetrics()
        .expect("bounded exposition");
    let exposition = exposition.as_str();
    assert!(exposition.ends_with("# EOF\n"));

    let families = exposition
        .lines()
        .filter_map(|line| line.strip_prefix("# TYPE "))
        .filter_map(|line| line.split_once(' ').map(|(name, _kind)| name))
        .filter(|name| is_state_family(name))
        .collect::<BTreeSet<_>>();
    assert_eq!(families, STATE_FAMILIES.into_iter().collect());

    let state_series = exposition
        .lines()
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .filter_map(|line| line.split_once(' ').map(|(sample, _value)| sample))
        .filter(|sample| is_state_family(sample.split('{').next().expect("sample name")))
        .count();
    assert_eq!(state_series, 120);
    for forbidden in [
        "tenant_id=",
        "repository_id=",
        "run_id=",
        "job_id=",
        "attempt_id=",
        "runner_id=",
        "session_id=",
        "operation_id=",
    ] {
        assert!(!exposition.contains(forbidden));
    }
}

fn is_state_family(name: &str) -> bool {
    STATE_FAMILIES.iter().any(|family| {
        name == *family
            || name.strip_suffix("_total") == Some(*family)
            || name.strip_suffix("_bucket") == Some(*family)
            || name.strip_suffix("_sum") == Some(*family)
            || name.strip_suffix("_count") == Some(*family)
    })
}
