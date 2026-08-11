mod support;

use std::sync::Arc;

use automata_ci::{
    app::http::{HttpPolicy, router_with_renderer, router_with_renderer_policy_and_readiness},
    server::Readiness,
};
use axum::{
    body::{Body, to_bytes},
    http::{
        Request, StatusCode,
        header::{CACHE_CONTROL, CONTENT_TYPE},
    },
};
use tower::ServiceExt as _;

use support::RecordingRenderer;

fn test_router() -> axum::Router {
    let renderer = RecordingRenderer::new("<!doctype html><html><body>test</body></html>");
    assert!(renderer.requests().is_empty());
    router_with_renderer(Arc::new(renderer))
}

#[tokio::test]
async fn health_endpoint_reports_build_provenance() {
    let response = test_router()
        .oneshot(
            Request::builder()
                .uri("/healthz")
                .body(Body::empty())
                .expect("request must be valid"),
        )
        .await
        .expect("health request must succeed");

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.headers()[CACHE_CONTROL], "no-store");
    assert_eq!(response.headers()["referrer-policy"], "no-referrer");
    assert_eq!(response.headers()["x-content-type-options"], "nosniff");
    let body = to_bytes(response.into_body(), 16 * 1024)
        .await
        .expect("health body must be readable");
    let health: serde_json::Value = serde_json::from_slice(&body).expect("health must be JSON");
    assert_eq!(health["status"], "ok");
    assert_eq!(health["version"], env!("CARGO_PKG_VERSION"));
    assert!(health["commit"].is_string());
}

#[tokio::test]
async fn readiness_endpoint_is_available_without_javascript() {
    let response = test_router()
        .oneshot(
            Request::builder()
                .uri("/readyz")
                .body(Body::empty())
                .expect("request must be valid"),
        )
        .await
        .expect("readiness request must succeed");

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.headers()["referrer-policy"], "no-referrer");
    assert_eq!(response.headers()["x-content-type-options"], "nosniff");
    let body = to_bytes(response.into_body(), 1024)
        .await
        .expect("readiness body must be readable");
    assert_eq!(&body[..], b"ready\n");
}

#[tokio::test]
async fn readiness_rejects_traffic_until_mandatory_dependencies_are_probed() {
    let renderer = RecordingRenderer::new("unused");
    let readiness = Readiness::initializing();
    let response = router_with_renderer_policy_and_readiness(
        Arc::new(renderer),
        HttpPolicy::default(),
        readiness,
    )
    .oneshot(
        Request::builder()
            .uri("/readyz")
            .body(Body::empty())
            .expect("readiness request must be valid"),
    )
    .await
    .expect("readiness request must succeed");

    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    let body = to_bytes(response.into_body(), 1024)
        .await
        .expect("readiness body must be readable");
    assert_eq!(&body[..], b"not ready\n");
}

#[tokio::test]
async fn unmatched_human_api_paths_use_the_sanitized_json_envelope() {
    for path in [
        "/api/v1",
        "/api/v1/",
        "/api/v1/missing",
        "/api/v1/local/workflow-runs",
    ] {
        let response = test_router()
            .oneshot(
                Request::builder()
                    .uri(path)
                    .body(Body::empty())
                    .expect("missing API request must be valid"),
            )
            .await
            .expect("missing API request must succeed");

        assert_eq!(response.status(), StatusCode::NOT_FOUND, "path {path}");
        assert_eq!(response.headers()[CACHE_CONTROL], "no-store", "path {path}");
        assert_eq!(
            response.headers()[CONTENT_TYPE],
            "application/json; charset=utf-8",
            "path {path}"
        );
        assert_eq!(
            response.headers()["referrer-policy"],
            "no-referrer",
            "path {path}"
        );
        assert_eq!(
            response.headers()["x-content-type-options"],
            "nosniff",
            "path {path}"
        );
        let body = to_bytes(response.into_body(), 128)
            .await
            .expect("missing API body must be readable");
        assert_eq!(body, r#"{"error":"not_found"}"#, "path {path}");
    }
}

#[tokio::test]
async fn unmatched_browser_paths_retain_the_branded_html_fallback() {
    let response = test_router()
        .oneshot(
            Request::builder()
                .uri("/missing")
                .body(Body::empty())
                .expect("missing browser request must be valid"),
        )
        .await
        .expect("missing browser request must succeed");

    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    assert_eq!(response.headers()[CACHE_CONTROL], "no-store");
    assert_eq!(response.headers()[CONTENT_TYPE], "text/html; charset=utf-8");
    assert!(response.headers().contains_key("content-security-policy"));
    let body = to_bytes(response.into_body(), 16 * 1024)
        .await
        .expect("missing browser body must be readable");
    let body = std::str::from_utf8(&body).expect("browser fallback must be UTF-8");
    assert!(body.contains("Page not found"));
    assert!(body.contains("Automata"));
}
