use std::{collections::BTreeSet, time::Duration};

use automata_ci::{build_info::BuildInfo, server::ControlPlaneMetrics};
use automata_ci_results_github::{
    ResultsBlobOperation, ResultsBlobOperationOutcome, ResultsHttpMethod, ResultsHttpRoute,
    ResultsHttpStatusClass, ResultsObserver, ResultsOperation, ResultsOperationOutcome,
    ResultsRepositoryOperation, ResultsRepositoryOperationOutcome, ResultsTransferDirection,
};

const RESULTS_FAMILIES: [&str; 9] = [
    "automata_ci_results_bytes",
    "automata_ci_results_http_request_duration_seconds",
    "automata_ci_results_http_requests",
    "automata_ci_results_http_requests_in_flight",
    "automata_ci_results_operation_duration_seconds",
    "automata_ci_results_operations",
    "automata_ci_storage_bytes",
    "automata_ci_storage_operation_duration_seconds",
    "automata_ci_storage_operations",
];

#[test]
fn results_and_storage_schema_is_exact_bounded_and_identifier_free() {
    let metrics =
        ControlPlaneMetrics::new(BuildInfo::current()).expect("valid embedded build provenance");
    let before = metrics
        .exporter()
        .encode_openmetrics()
        .expect("initial bounded exposition");
    let before_series = series_keys(before.as_str());

    metrics.observe_operation(
        ResultsOperation::Create,
        ResultsOperationOutcome::Success,
        Duration::from_millis(7),
    );
    metrics.observe_transfer_bytes(ResultsTransferDirection::Upload, 17);
    metrics.observe_blob_operation(
        ResultsBlobOperation::Put,
        ResultsBlobOperationOutcome::Created,
        Duration::from_millis(5),
    );
    metrics.observe_blob_bytes(ResultsBlobOperation::Put, 17);
    metrics.observe_repository_operation(
        ResultsRepositoryOperation::Create,
        ResultsRepositoryOperationOutcome::Unavailable,
        Duration::from_millis(3),
    );
    metrics.results_http_request_started(ResultsHttpMethod::Post, ResultsHttpRoute::CreateArtifact);
    metrics.observe_results_http_request(
        ResultsHttpMethod::Post,
        ResultsHttpRoute::CreateArtifact,
        ResultsHttpStatusClass::Cancelled,
        Duration::from_millis(2),
    );
    metrics
        .results_http_request_finished(ResultsHttpMethod::Post, ResultsHttpRoute::CreateArtifact);

    let exposition = metrics
        .exporter()
        .encode_openmetrics()
        .expect("bounded exposition");
    let exposition = exposition.as_str();
    let families = exposition
        .lines()
        .filter_map(|line| line.strip_prefix("# TYPE "))
        .filter_map(|line| line.split_once(' ').map(|(family, _kind)| family))
        .filter(|family| is_results_metric(family))
        .collect::<BTreeSet<_>>();
    assert_eq!(
        families,
        RESULTS_FAMILIES.into_iter().collect::<BTreeSet<_>>()
    );

    let results_series = exposition
        .lines()
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .filter_map(|line| line.split_once(' ').map(|(sample, _value)| sample))
        .filter(|sample| is_results_metric(sample.split('{').next().expect("sample name")))
        .count();
    assert_eq!(results_series, 972);
    let all_series = exposition
        .lines()
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .count();
    assert_eq!(
        all_series, 5_280,
        "the preinitialized series set must match the reviewed cardinality manifest"
    );
    assert_eq!(
        series_keys(exposition),
        before_series,
        "typed Results observations changed the preinitialized series set"
    );

    for expected in [
        "automata_ci_results_operations_total{operation=\"create\",outcome=\"success\"} 1",
        "automata_ci_results_bytes_total{direction=\"upload\"} 17",
        "automata_ci_storage_operations_total{backend=\"object_store\",operation=\"put\",outcome=\"created\"} 1",
        "automata_ci_storage_operations_total{backend=\"postgresql\",operation=\"create\",outcome=\"unavailable\"} 1",
        "automata_ci_storage_bytes_total{backend=\"object_store\",direction=\"write\"} 17",
        "automata_ci_results_http_requests_total{method=\"post\",route=\"create_artifact\",outcome=\"cancelled\"} 1",
        "automata_ci_results_http_requests_in_flight{route=\"create_artifact\"} 0",
        "automata_ci_results_http_requests_in_flight{route=\"create_cache\"} 0",
        "automata_ci_results_http_requests_in_flight{route=\"finalize_cache\"} 0",
        "automata_ci_results_http_requests_in_flight{route=\"get_cache_download_url\"} 0",
        "automata_ci_results_http_requests_in_flight{route=\"cache_upload\"} 0",
        "automata_ci_results_http_requests_in_flight{route=\"cache_download\"} 0",
    ] {
        assert!(exposition.contains(expected), "missing sample: {expected}");
    }
    for private in [
        "private-results-route",
        "private-artifact-name",
        "private-object-key",
        "private-digest",
        "private-provider-error",
    ] {
        assert!(!exposition.contains(private));
    }
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

fn is_results_metric(name: &str) -> bool {
    name.starts_with("automata_ci_results_") || name.starts_with("automata_ci_storage_")
}
