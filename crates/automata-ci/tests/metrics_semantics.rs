use std::{collections::BTreeSet, time::Duration};

use automata_ci::{build_info::BuildInfo, server::ControlPlaneMetrics};
use automata_ci_control::{LeasePollObservation, LeasePollObserver};
use automata_ci_runner_control::{
    LeaseOfferObservation, RunnerControlMessageKind, RunnerControlMessageOutcome,
    RunnerControlObserver, RunnerDurableDisposition, RunnerDurableMessageKind,
    RunnerHandshakeOutcome,
};
use automata_ci_runner_transport::{
    RunnerTransportByteDirection, RunnerTransportConnectionEvent, RunnerTransportObserver,
    RunnerTransportRequestObservation, RunnerTransportRoute, RunnerTransportTlsOutcome,
};
use automata_ci_workflow_service::{
    WorkflowAdmissionObservation, WorkflowAdmissionObserver, WorkflowAdmissionStage,
    WorkflowAdmissionStageOutcome,
};

const SEMANTIC_FAMILIES: [&str; 25] = [
    "automata_ci_control_plane_lease_poll_candidates",
    "automata_ci_control_plane_lease_poll_duration_seconds",
    "automata_ci_control_plane_lease_polls",
    "automata_ci_control_plane_lease_queue_wait_seconds",
    "automata_ci_control_plane_runner_control_durable_transitions",
    "automata_ci_control_plane_runner_control_handshake_duration_seconds",
    "automata_ci_control_plane_runner_control_handshakes",
    "automata_ci_control_plane_runner_control_ingress_bytes",
    "automata_ci_control_plane_runner_control_lease_offer_events",
    "automata_ci_control_plane_runner_control_message_duration_seconds",
    "automata_ci_control_plane_runner_control_messages",
    "automata_ci_control_plane_runner_control_receipt_replays",
    "automata_ci_control_plane_runner_transport_bytes",
    "automata_ci_control_plane_runner_transport_connection_events",
    "automata_ci_control_plane_runner_transport_request_duration_seconds",
    "automata_ci_control_plane_runner_transport_requests",
    "automata_ci_control_plane_runner_transport_requests_in_flight",
    "automata_ci_control_plane_runner_transport_tls_handshake_duration_seconds",
    "automata_ci_control_plane_runner_transport_tls_handshakes",
    "automata_ci_control_plane_workflow_admission_duration_seconds",
    "automata_ci_control_plane_workflow_admission_receipt_replays",
    "automata_ci_control_plane_workflow_admission_stage_duration_seconds",
    "automata_ci_control_plane_workflow_admission_stages",
    "automata_ci_control_plane_workflow_admissions",
    "automata_ci_control_plane_workflow_jobs_committed",
];

#[test]
fn semantic_metrics_have_an_exact_bounded_privacy_safe_exposition() {
    let metrics =
        ControlPlaneMetrics::new(BuildInfo::current()).expect("valid embedded build provenance");
    let before = metrics
        .exporter()
        .encode_openmetrics()
        .expect("initial bounded exposition");
    let before_series = series_keys(before.as_str());

    record_semantic_observations(&metrics);

    let exposition = metrics
        .exporter()
        .encode_openmetrics()
        .expect("bounded exposition");
    let exposition = exposition.as_str();
    assert!(exposition.len() < 2 * 1024 * 1024);
    assert!(exposition.ends_with("# EOF\n"));

    let families = exposition
        .lines()
        .filter_map(|line| line.strip_prefix("# TYPE "))
        .filter_map(|line| line.split_once(' ').map(|(family, _kind)| family))
        .filter(|family| is_semantic_metric(family))
        .collect::<BTreeSet<_>>();
    assert_eq!(
        families,
        SEMANTIC_FAMILIES.into_iter().collect::<BTreeSet<_>>()
    );

    let semantic_series = exposition
        .lines()
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .filter_map(|line| line.split_once(' ').map(|(sample, _value)| sample))
        .filter(|sample| is_semantic_metric(sample.split('{').next().expect("sample name")))
        .count();
    assert_eq!(semantic_series, 1_002);
    let all_series = exposition
        .lines()
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .count();
    assert!(all_series <= 5_000, "initial series count was {all_series}");
    assert_eq!(
        series_keys(exposition),
        before_series,
        "typed semantic observations changed the preinitialized series set"
    );

    for expected in [
        "automata_ci_control_plane_lease_polls_total{outcome=\"claimed\",disposition=\"new\",reason=\"none\"} 1",
        "automata_ci_control_plane_workflow_admissions_total{outcome=\"new\"} 1",
        "automata_ci_control_plane_workflow_jobs_committed_total 2",
        "automata_ci_control_plane_runner_control_handshakes_total{outcome=\"opened\"} 1",
        "automata_ci_control_plane_runner_control_messages_total{kind=\"lease_request\",outcome=\"protocol_error\"} 1",
        "automata_ci_control_plane_runner_control_ingress_bytes_total{kind=\"log_batch\"} 13",
        "automata_ci_control_plane_runner_control_lease_offer_events_total{outcome=\"published\"} 1",
        "automata_ci_control_plane_runner_transport_connection_events_total{outcome=\"admitted\"} 1",
        "automata_ci_control_plane_runner_transport_connection_events_total{outcome=\"drain_aborted\"} 1",
        "automata_ci_control_plane_runner_transport_tls_handshakes_total{outcome=\"accepted\"} 1",
        "automata_ci_control_plane_runner_transport_requests_total{route=\"handshake\",stage=\"response\",outcome=\"success\"} 1",
        "automata_ci_control_plane_runner_transport_requests_in_flight{route=\"handshake\"} 0",
        "automata_ci_control_plane_runner_transport_bytes_total{route=\"handshake\",direction=\"request\"} 17",
    ] {
        assert!(exposition.contains(expected), "missing sample: {expected}");
    }

    for impossible_or_private in [
        "kind=\"hello\"",
        "error_stale_session",
        "rejected_unauthenticated",
        "private-runner-marker",
        "private-session-marker",
        "private-operation-marker",
    ] {
        assert!(!exposition.contains(impossible_or_private));
    }
}

fn record_semantic_observations(metrics: &ControlPlaneMetrics) {
    LeasePollObserver::observe_poll(
        metrics,
        LeasePollObservation::Claimed,
        Duration::from_millis(12),
    );
    LeasePollObserver::observe_candidates(metrics, 4);
    LeasePollObserver::observe_queue_wait(metrics, Duration::from_secs(3));
    WorkflowAdmissionObserver::observe_stage(
        metrics,
        WorkflowAdmissionStage::Commit,
        WorkflowAdmissionStageOutcome::Success,
        Duration::from_millis(8),
    );
    WorkflowAdmissionObserver::observe_admission(
        metrics,
        WorkflowAdmissionObservation::New { jobs: 2 },
        Duration::from_millis(30),
    );
    RunnerControlObserver::observe_handshake(
        metrics,
        RunnerHandshakeOutcome::Opened,
        Duration::from_millis(4),
    );
    RunnerControlObserver::observe_message(
        metrics,
        RunnerControlMessageKind::LeaseRequest,
        RunnerControlMessageOutcome::ProtocolError,
        Duration::from_millis(5),
    );
    RunnerControlObserver::observe_durable(
        metrics,
        RunnerDurableMessageKind::LogBatch,
        RunnerDurableDisposition::New,
        13,
    );
    RunnerControlObserver::observe_lease_offer(metrics, LeaseOfferObservation::Published);
    RunnerTransportObserver::observe_connection(metrics, RunnerTransportConnectionEvent::Admitted);
    RunnerTransportObserver::observe_connection(
        metrics,
        RunnerTransportConnectionEvent::DrainAborted,
    );
    RunnerTransportObserver::observe_tls(
        metrics,
        RunnerTransportTlsOutcome::Accepted,
        Duration::from_millis(2),
    );
    RunnerTransportObserver::request_started(metrics, RunnerTransportRoute::Handshake);
    RunnerTransportObserver::observe_bytes(
        metrics,
        RunnerTransportRoute::Handshake,
        RunnerTransportByteDirection::Request,
        17,
    );
    RunnerTransportObserver::observe_request(
        metrics,
        RunnerTransportRequestObservation::Succeeded {
            route: RunnerTransportRoute::Handshake,
        },
        Duration::from_millis(6),
    );
    RunnerTransportObserver::request_finished(metrics, RunnerTransportRoute::Handshake);
}

fn series_keys(exposition: &str) -> BTreeSet<String> {
    exposition
        .lines()
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .map(|line| {
            line.split_once(' ')
                .map_or(line, |(sample, _)| sample)
                .to_owned()
        })
        .collect()
}

fn is_semantic_metric(name: &str) -> bool {
    SEMANTIC_FAMILIES.iter().any(|family| {
        name == *family
            || name.strip_suffix("_total") == Some(*family)
            || name.strip_suffix("_bucket") == Some(*family)
            || name.strip_suffix("_sum") == Some(*family)
            || name.strip_suffix("_count") == Some(*family)
    })
}
