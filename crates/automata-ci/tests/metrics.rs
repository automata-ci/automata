mod support;

use std::{collections::BTreeSet, sync::Arc};

use automata_ci::{
    app::http::{HttpPolicy, router_with_renderer_policy_readiness_and_metrics},
    build_info::BuildInfo,
    server::{ControlPlaneMetrics, Readiness},
};
use automata_ci_metrics::OPENMETRICS_CONTENT_TYPE;
use axum::{
    body::{Body, to_bytes},
    http::{Request, StatusCode, header::CONTENT_TYPE},
};
use tower::ServiceExt as _;

use support::RecordingRenderer;

fn control_metrics() -> ControlPlaneMetrics {
    ControlPlaneMetrics::new(BuildInfo::current()).expect("valid embedded build provenance")
}

#[tokio::test]
async fn metrics_remain_scrapeable_while_application_readiness_is_false() {
    let metrics = control_metrics();
    let renderer = RecordingRenderer::new("unused");
    assert!(renderer.requests().is_empty());
    let application = router_with_renderer_policy_readiness_and_metrics(
        Arc::new(renderer),
        HttpPolicy::default(),
        Readiness::initializing(),
        metrics.clone(),
    );

    let ready_response = application
        .oneshot(
            Request::builder()
                .uri("/readyz")
                .body(Body::empty())
                .expect("readiness request"),
        )
        .await
        .expect("readiness response");
    assert_eq!(ready_response.status(), StatusCode::SERVICE_UNAVAILABLE);

    let metrics_response = metrics
        .exporter()
        .router()
        .oneshot(
            Request::builder()
                .uri("/metrics")
                .body(Body::empty())
                .expect("metrics request"),
        )
        .await
        .expect("metrics response");
    assert_eq!(metrics_response.status(), StatusCode::OK);
    assert_eq!(
        metrics_response.headers().get(CONTENT_TYPE),
        Some(&OPENMETRICS_CONTENT_TYPE.parse().expect("content type"))
    );
    let body = to_bytes(metrics_response.into_body(), 2 * 1024 * 1024)
        .await
        .expect("bounded exposition");
    assert!(body.ends_with(b"# EOF\n"));
    let exposition = std::str::from_utf8(&body).expect("OpenMetrics is UTF-8");
    assert!(exposition.contains("automata_ci_control_plane_ready 0"));
    assert!(exposition.contains(
        "automata_ci_control_plane_http_requests_total{method=\"get\",route=\"/readyz\",status_class=\"5xx\"} 1"
    ));
}

#[tokio::test]
async fn http_metrics_use_a_closed_matched_route_and_never_raw_path_values() {
    let metrics = control_metrics();
    let renderer = RecordingRenderer::new("unused");
    assert!(renderer.requests().is_empty());
    let application = router_with_renderer_policy_readiness_and_metrics(
        Arc::new(renderer),
        HttpPolicy::default(),
        Readiness::all_ready(),
        metrics.clone(),
    );
    let before = metrics
        .exporter()
        .encode_openmetrics()
        .expect("initial bounded exposition");
    let before_series = series_keys(before.as_str());

    let mut forbidden = Vec::new();
    for index in 0..128 {
        let owner = format!("tenant-{index}-secret-marker");
        let repository = format!("repo-{index}-https-example-invalid-private-path-marker");
        let run = format!("run-{index}-image-ghcr-io-private-error-timeout-payload-token-marker");
        let query = format!("credential-{index}-private-query-marker");
        let raw_path = format!("/{owner}/{repository}/actions/runs/{run}?continuation={query}");
        let _response = application
            .clone()
            .oneshot(
                Request::builder()
                    .uri(raw_path)
                    .body(Body::empty())
                    .expect("dynamic route request"),
            )
            .await
            .expect("dynamic route response");
        forbidden.extend([owner, repository, run, query]);

        let unmatched = format!("/unmatched-{index}-private-raw-path-marker");
        let _response = application
            .clone()
            .oneshot(
                Request::builder()
                    .uri(&unmatched)
                    .body(Body::empty())
                    .expect("unmatched route request"),
            )
            .await
            .expect("unmatched route response");
        forbidden.push(unmatched);
    }
    let exposition = metrics
        .exporter()
        .encode_openmetrics()
        .expect("bounded exposition");
    let exposition = exposition.as_str();

    for forbidden in forbidden {
        assert!(
            !exposition.contains(&forbidden),
            "raw request data leaked into metrics: {forbidden}"
        );
    }
    assert!(exposition.contains("route=\"/{owner}/{repository}/actions/runs/{run_id}\""));
    assert_eq!(
        series_keys(exposition),
        before_series,
        "adversarial request values changed the preinitialized series set"
    );
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
