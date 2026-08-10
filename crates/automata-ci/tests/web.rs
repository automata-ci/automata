mod support;

use std::{
    sync::{
        Arc, Barrier,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

use automata_ci::app::http::{
    HttpPolicy, HttpPolicyError, router, router_with_renderer, router_with_renderer_and_policy,
};
use automata_ci_ui_renderer::{
    EmbeddedAsset, RenderError, RenderedPage, Renderer, client_assets, find_asset,
};
use axum::body::{Body, to_bytes};
use axum::http::header::{CACHE_CONTROL, CONTENT_TYPE, ETAG, IF_NONE_MATCH};
use axum::http::{Request, StatusCode};
use serde_json::Value;
use tower::ServiceExt as _;

use support::RecordingRenderer;

#[derive(Debug)]
struct BusyRenderer;

impl Renderer for BusyRenderer {
    fn render(&self, _request_json: &str) -> Result<RenderedPage, RenderError> {
        Err(RenderError::AtCapacity)
    }
}

#[derive(Debug)]
struct GateRenderer {
    entered: AtomicBool,
    release: Barrier,
}

impl GateRenderer {
    fn new() -> Self {
        Self {
            entered: AtomicBool::new(false),
            release: Barrier::new(2),
        }
    }
}

impl Renderer for GateRenderer {
    fn render(&self, _request_json: &str) -> Result<RenderedPage, RenderError> {
        self.entered.store(true, Ordering::Release);
        self.release.wait();
        Ok(RenderedPage::from_complete_html(
            "<!doctype html><html><body>released</body></html>".to_owned(),
        ))
    }
}

#[derive(Debug)]
struct SlowRenderer;

impl Renderer for SlowRenderer {
    fn render(&self, _request_json: &str) -> Result<RenderedPage, RenderError> {
        std::thread::sleep(Duration::from_millis(100));
        Ok(RenderedPage::from_complete_html(
            "<!doctype html><html><body>late</body></html>".to_owned(),
        ))
    }
}

#[tokio::test]
async fn repository_directory_is_rendered_with_a_per_response_csp_nonce() {
    let renderer = Arc::new(RecordingRenderer::new(
        "<!doctype html><html><body>server rendered</body></html>",
    ));
    let response = router_with_renderer(renderer.clone())
        .oneshot(
            Request::builder()
                .uri("/repositories")
                .body(Body::empty())
                .expect("request must be valid"),
        )
        .await
        .expect("repository-directory request must succeed");

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.headers()[CONTENT_TYPE], "text/html; charset=utf-8");
    assert_eq!(response.headers()[CACHE_CONTROL], "no-store");
    assert_eq!(response.headers()["x-content-type-options"], "nosniff");

    let requests = renderer.requests();
    assert_eq!(requests.len(), 1);
    let model: Value = serde_json::from_str(&requests[0]).expect("page model must be JSON");
    assert_eq!(model["schemaVersion"], 1);
    assert_eq!(model["page"]["kind"], "repository-directory");
    assert_eq!(model["page"]["heading"], "Repositories");
    assert_eq!(model["page"]["repositories"], serde_json::json!([]));
    assert!(model["page"].get("repository").is_none());
    assert_eq!(
        model["host"]["assets"]["clientEntry"],
        client_assets().script_path
    );
    let nonce = model["host"]["cspNonce"]
        .as_str()
        .expect("host must provide a CSP nonce");
    assert!(nonce.len() >= 22);
    let csp = response.headers()["content-security-policy"]
        .to_str()
        .expect("CSP must be text");
    assert!(csp.contains(&format!("'nonce-{nonce}'")));
    assert!(csp.contains("font-src data:"));

    let body = to_bytes(response.into_body(), 16 * 1024)
        .await
        .expect("HTML body must be readable");
    assert_eq!(
        &body[..],
        b"<!doctype html><html><body>server rendered</body></html>"
    );
}

#[tokio::test]
async fn production_router_returns_complete_react_html_without_javascript_execution() {
    let app = router().expect("embedded renderer must initialize");
    let redirect = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/")
                .body(Body::empty())
                .expect("request must be valid"),
        )
        .await
        .expect("root redirect must succeed");
    assert_eq!(redirect.status(), StatusCode::PERMANENT_REDIRECT);
    assert_eq!(redirect.headers()["location"], "/repositories");

    let response = app
        .oneshot(
            Request::builder()
                .uri("/repositories")
                .body(Body::empty())
                .expect("request must be valid"),
        )
        .await
        .expect("SSR request must succeed");

    assert_eq!(response.status(), StatusCode::OK);
    let body = to_bytes(response.into_body(), 3 * 1024 * 1024)
        .await
        .expect("SSR body must be readable");
    let html = std::str::from_utf8(&body).expect("SSR output must be UTF-8");
    assert!(html.starts_with("<!doctype html><html lang=\"en\">"));
    assert!(html.contains("<h1>Repositories</h1>"));
    assert!(html.contains("No repositories are available to you."));
    assert!(!html.contains("github.com"));
    assert!(html.contains(client_assets().script_path));
    assert!(!html.contains("automata-server"));
}

#[tokio::test]
async fn renderer_backpressure_is_an_explicit_retryable_response() {
    let response = router_with_renderer(Arc::new(BusyRenderer))
        .oneshot(
            Request::builder()
                .uri("/repositories")
                .body(Body::empty())
                .expect("request must be valid"),
        )
        .await
        .expect("busy renderer response must succeed");

    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(response.headers()["retry-after"], "1");
    assert_eq!(response.headers()[CACHE_CONTROL], "no-store");
}

#[test]
fn http_policy_rejects_zero_limits() {
    assert_eq!(
        HttpPolicy::new(Duration::ZERO, 1),
        Err(HttpPolicyError::ZeroRequestTimeout)
    );
    assert_eq!(
        HttpPolicy::new(Duration::from_secs(1), 0),
        Err(HttpPolicyError::ZeroConcurrentRenders)
    );
}

#[tokio::test]
async fn render_admission_rejects_parallel_work_before_the_blocking_pool() {
    let renderer = Arc::new(GateRenderer::new());
    let policy = HttpPolicy::new(Duration::from_secs(2), 1).expect("valid HTTP policy");
    let app = router_with_renderer_and_policy(renderer.clone(), policy);
    let first_app = app.clone();
    let first = tokio::spawn(async move {
        first_app
            .oneshot(
                Request::builder()
                    .uri("/repositories")
                    .body(Body::empty())
                    .expect("first request must be valid"),
            )
            .await
            .expect("first request must complete")
    });

    for _ in 0..100 {
        if renderer.entered.load(Ordering::Acquire) {
            break;
        }
        tokio::time::sleep(Duration::from_millis(2)).await;
    }
    assert!(renderer.entered.load(Ordering::Acquire));

    let rejected = app
        .oneshot(
            Request::builder()
                .uri("/repositories")
                .body(Body::empty())
                .expect("parallel request must be valid"),
        )
        .await
        .expect("parallel request must produce a response");
    assert_eq!(rejected.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(rejected.headers()["retry-after"], "1");

    renderer.release.wait();
    assert_eq!(
        first.await.expect("first task must join").status(),
        StatusCode::OK
    );
}

#[tokio::test]
async fn request_deadline_returns_a_non_cacheable_gateway_timeout() {
    let policy = HttpPolicy::new(Duration::from_millis(10), 1).expect("valid HTTP policy");
    let response = router_with_renderer_and_policy(Arc::new(SlowRenderer), policy)
        .oneshot(
            Request::builder()
                .uri("/repositories")
                .body(Body::empty())
                .expect("request must be valid"),
        )
        .await
        .expect("timeout must become a response");

    assert_eq!(response.status(), StatusCode::GATEWAY_TIMEOUT);
    assert_eq!(response.headers()[CACHE_CONTROL], "no-store");
}

#[tokio::test]
async fn embedded_assets_are_exact_immutable_and_conditionally_cacheable() {
    let manifest = client_assets();
    let expected = find_asset(manifest.script_path).expect("client script must be embedded");
    let app = router_with_renderer(Arc::new(RecordingRenderer::new("unused")));

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(manifest.script_path)
                .body(Body::empty())
                .expect("asset request must be valid"),
        )
        .await
        .expect("asset request must succeed");
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response.headers()[CONTENT_TYPE],
        expected.content_type.as_str()
    );
    assert_eq!(
        response.headers()[CACHE_CONTROL],
        EmbeddedAsset::CACHE_CONTROL
    );
    let etag = response.headers()[ETAG].clone();
    let body = to_bytes(response.into_body(), 512 * 1024)
        .await
        .expect("asset body must be readable");
    assert_eq!(&body[..], expected.bytes);

    let not_modified = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(manifest.script_path)
                .header(IF_NONE_MATCH, etag)
                .body(Body::empty())
                .expect("conditional request must be valid"),
        )
        .await
        .expect("conditional request must succeed");
    assert_eq!(not_modified.status(), StatusCode::NOT_MODIFIED);
    assert!(
        to_bytes(not_modified.into_body(), 1)
            .await
            .expect("304 body must be readable")
            .is_empty()
    );

    let unknown = app
        .oneshot(
            Request::builder()
                .uri("/assets/not-embedded.js")
                .body(Body::empty())
                .expect("unknown asset request must be valid"),
        )
        .await
        .expect("unknown asset response must succeed");
    assert_eq!(unknown.status(), StatusCode::NOT_FOUND);
}
