mod support;

use std::sync::Arc;

use automata::app::http::router_with_renderer;
use axum::{
    body::{Body, to_bytes},
    http::{Request, StatusCode},
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
    let body = to_bytes(response.into_body(), 1024)
        .await
        .expect("readiness body must be readable");
    assert_eq!(&body[..], b"ready\n");
}
