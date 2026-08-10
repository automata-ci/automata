//! Bounded human HTTP application, readiness, and fixed-label instrumentation.

use std::{fmt, sync::Arc, time::Duration};

use automata_ci_ui_renderer::{RenderPolicy, Renderer, RendererInitError, WasmtimeRenderer};
use axum::{
    BoxError, Json, Router,
    body::Body,
    error_handling::HandleErrorLayer,
    extract::OriginalUri,
    http::{
        HeaderName, HeaderValue, StatusCode,
        header::{CACHE_CONTROL, CONTENT_ENCODING, CONTENT_LENGTH, CONTENT_TYPE},
    },
    middleware,
    response::{IntoResponse, Response},
    routing::{any, get},
};
use serde::Serialize;
use tower::{ServiceBuilder, timeout::TimeoutLayer};

use super::web;
use crate::{
    build_info::BuildInfo,
    server::{ControlPlaneMetrics, Readiness, metrics::observe_http},
};

const REFERRER_POLICY: HeaderName = HeaderName::from_static("referrer-policy");
const X_CONTENT_TYPE_OPTIONS: HeaderName = HeaderName::from_static("x-content-type-options");
const HUMAN_API_ROOT: &str = "/api/v1";
const HUMAN_API_ROOT_WITH_SLASH: &str = "/api/v1/";
const HUMAN_API_CATCH_ALL: &str = "/api/v1/{*api_path}";

#[derive(Debug, Serialize)]
struct HealthResponse {
    status: &'static str,
    #[serde(flatten)]
    build: BuildInfo,
}

/// Resource policy applied before requests enter application handlers.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HttpPolicy {
    request_timeout: Duration,
    max_concurrent_renders: usize,
}

impl HttpPolicy {
    /// Creates a validated HTTP admission policy.
    ///
    /// # Errors
    ///
    /// Returns an error when either limit is zero.
    pub const fn new(
        request_timeout: Duration,
        max_concurrent_renders: usize,
    ) -> Result<Self, HttpPolicyError> {
        if request_timeout.is_zero() {
            return Err(HttpPolicyError::ZeroRequestTimeout);
        }
        if max_concurrent_renders == 0 {
            return Err(HttpPolicyError::ZeroConcurrentRenders);
        }
        Ok(Self {
            request_timeout,
            max_concurrent_renders,
        })
    }

    /// Returns the deadline applied across middleware and route handling.
    pub const fn request_timeout(self) -> Duration {
        self.request_timeout
    }

    /// Returns the maximum number of renderer calls admitted concurrently.
    pub const fn max_concurrent_renders(self) -> usize {
        self.max_concurrent_renders
    }
}

impl Default for HttpPolicy {
    fn default() -> Self {
        Self {
            request_timeout: Duration::from_secs(30),
            max_concurrent_renders: RenderPolicy::default().max_concurrent_renders(),
        }
    }
}

/// Invalid HTTP admission-policy configuration.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HttpPolicyError {
    /// The whole-request deadline was zero.
    ZeroRequestTimeout,
    /// The concurrent-render limit was zero.
    ZeroConcurrentRenders,
}

impl fmt::Display for HttpPolicyError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ZeroRequestTimeout => formatter.write_str("request timeout must be nonzero"),
            Self::ZeroConcurrentRenders => {
                formatter.write_str("maximum concurrent renders must be nonzero")
            }
        }
    }
}

impl std::error::Error for HttpPolicyError {}

/// Builds the production HTTP application with its isolated UI renderer.
///
/// # Errors
///
/// Returns an error if the embedded renderer component cannot be compiled or
/// linked under the configured isolation policy.
pub fn router() -> Result<Router, RendererInitError> {
    router_with_readiness(Readiness::all_ready())
}

/// Builds the production HTTP application over a shared dependency-readiness state.
///
/// # Errors
///
/// Returns an error if the embedded renderer cannot be initialized.
pub fn router_with_readiness(readiness: Readiness) -> Result<Router, RendererInitError> {
    let policy = RenderPolicy::default();
    let http_policy = HttpPolicy::default();
    let renderer = Arc::new(WasmtimeRenderer::new(policy)?);
    Ok(router_with_renderer_policy_and_readiness(
        renderer,
        http_policy,
        readiness,
    ))
}

/// Builds the production human router before product-specific API routes and
/// fixed-label metrics are attached to the fully combined router.
pub(crate) fn router_with_readiness_web_data(
    readiness: Readiness,
    data: Arc<dyn web::WebData>,
    rbac_data: Option<Arc<dyn web::RbacWebData>>,
    setup_page_availability: Option<Arc<dyn web::SetupPageAvailability>>,
    fallback_context: web::RequestContext,
) -> Result<Router, RendererInitError> {
    let render_policy = RenderPolicy::default();
    let http_policy = HttpPolicy::default();
    let renderer: Arc<dyn Renderer> = Arc::new(WasmtimeRenderer::new(render_policy)?);
    Ok(router_with_renderer_readiness_web_data(
        renderer,
        http_policy,
        readiness,
        data,
        rbac_data,
        setup_page_availability,
        fallback_context,
    ))
}

pub(crate) fn router_with_renderer_readiness_web_data(
    renderer: Arc<dyn Renderer>,
    http_policy: HttpPolicy,
    readiness: Readiness,
    data: Arc<dyn web::WebData>,
    rbac_data: Option<Arc<dyn web::RbacWebData>>,
    setup_page_availability: Option<Arc<dyn web::SetupPageAvailability>>,
    fallback_context: web::RequestContext,
) -> Router {
    let web_router = match (rbac_data, setup_page_availability) {
        (Some(rbac_data), Some(setup_page_availability)) => {
            web::router_with_data_rbac_management_and_setup_availability(
                renderer,
                http_policy.max_concurrent_renders(),
                data,
                rbac_data,
                setup_page_availability,
                fallback_context,
            )
        }
        (Some(rbac_data), None) => web::router_with_data_rbac_and_management(
            renderer,
            http_policy.max_concurrent_renders(),
            data,
            rbac_data,
            fallback_context,
        ),
        (None, Some(setup_page_availability)) => web::router_with_data_and_setup_availability(
            renderer,
            http_policy.max_concurrent_renders(),
            data,
            fallback_context,
            setup_page_availability,
        ),
        (None, None) => web::router_with_data(
            renderer,
            http_policy.max_concurrent_renders(),
            data,
            fallback_context,
        ),
    };
    core_router(web_router, readiness)
}

/// Applies the request deadline and fixed-label RED metrics after every
/// production route and authentication layer has been combined.
pub(crate) fn finalize_combined_router(router: Router, metrics: ControlPlaneMetrics) -> Router {
    finalize_combined_router_with_policy(router, HttpPolicy::default(), metrics)
}

/// Builds an HTTP application around an injected isolated renderer.
///
/// Default request and renderer-admission limits are applied, and dependencies
/// are treated as ready. This constructor is intended for embedding and tests.
pub fn router_with_renderer(renderer: Arc<dyn Renderer>) -> Router {
    router_with_renderer_and_policy(renderer, HttpPolicy::default())
}

/// Builds an HTTP application around an injected renderer and admission policy.
///
/// Dependencies are treated as ready; use
/// [`router_with_renderer_policy_and_readiness`] when readiness must be shared.
pub fn router_with_renderer_and_policy(renderer: Arc<dyn Renderer>, policy: HttpPolicy) -> Router {
    router_with_renderer_policy_and_readiness(renderer, policy, Readiness::all_ready())
}

/// Builds an HTTP router with explicit renderer, policy, and dependency readiness.
pub fn router_with_renderer_policy_and_readiness(
    renderer: Arc<dyn Renderer>,
    policy: HttpPolicy,
    readiness: Readiness,
) -> Router {
    base_router(
        web::router(renderer, policy.max_concurrent_renders()),
        policy,
        readiness,
        None,
    )
}

/// Builds a testable human router with fixed-label HTTP RED instrumentation.
pub fn router_with_renderer_policy_readiness_and_metrics(
    renderer: Arc<dyn Renderer>,
    policy: HttpPolicy,
    readiness: Readiness,
    metrics: ControlPlaneMetrics,
) -> Router {
    base_router(
        web::router(renderer, policy.max_concurrent_renders()),
        policy,
        readiness,
        Some(metrics),
    )
}

fn base_router(
    web_router: Router,
    policy: HttpPolicy,
    readiness: Readiness,
    metrics: Option<ControlPlaneMetrics>,
) -> Router {
    let router = harden_combined_router(normalize_api_routing_errors(apply_request_timeout(
        core_router(web_router, readiness),
        policy,
    )));
    match metrics {
        Some(metrics) => instrument_combined_router(router, metrics),
        None => router,
    }
}

fn core_router(web_router: Router, readiness: Readiness) -> Router {
    Router::new()
        .route("/healthz", get(health))
        .route(
            "/readyz",
            get(move || std::future::ready(ready(&readiness))),
        )
        .route(HUMAN_API_ROOT, any(api_routing_not_found))
        .route(HUMAN_API_ROOT_WITH_SLASH, any(api_routing_not_found))
        .route(HUMAN_API_CATCH_ALL, any(api_routing_not_found))
        .merge(web_router)
}

async fn api_routing_not_found() -> Response {
    api_middleware_error_response(StatusCode::NOT_FOUND, r#"{"error":"not_found"}"#)
}

fn apply_request_timeout(router: Router, policy: HttpPolicy) -> Router {
    router.layer(
        ServiceBuilder::new()
            .layer(HandleErrorLayer::new(handle_middleware_error))
            .layer(TimeoutLayer::new(policy.request_timeout())),
    )
}

fn instrument_combined_router(router: Router, metrics: ControlPlaneMetrics) -> Router {
    router.layer(middleware::from_fn_with_state(metrics, observe_http))
}

fn harden_combined_router(router: Router) -> Router {
    router.layer(middleware::from_fn(harden_http_response))
}

fn normalize_api_routing_errors(router: Router) -> Router {
    router.layer(middleware::from_fn(normalize_api_routing_error))
}

async fn normalize_api_routing_error(
    request: axum::extract::Request,
    next: middleware::Next,
) -> Response {
    let api_path = is_human_api_path(request.uri().path());
    let mut response = next.run(request).await;
    if !api_path || response_has_json_content_type(&response) {
        return response;
    }
    let document = match response.status() {
        StatusCode::NOT_FOUND => r#"{"error":"not_found"}"#,
        StatusCode::METHOD_NOT_ALLOWED => r#"{"error":"method_not_allowed"}"#,
        _ => return response,
    };

    *response.body_mut() = Body::from(document);
    let headers = response.headers_mut();
    headers.insert(CACHE_CONTROL, HeaderValue::from_static("no-store"));
    headers.insert(
        CONTENT_TYPE,
        HeaderValue::from_static("application/json; charset=utf-8"),
    );
    headers.remove(CONTENT_ENCODING);
    headers.remove(CONTENT_LENGTH);
    response
}

fn is_human_api_path(path: &str) -> bool {
    path == HUMAN_API_ROOT
        || path
            .strip_prefix(HUMAN_API_ROOT)
            .is_some_and(|suffix| suffix.starts_with('/'))
}

fn response_has_json_content_type(response: &Response) -> bool {
    let mut values = response.headers().get_all(CONTENT_TYPE).iter();
    let Some(value) = values.next() else {
        return false;
    };
    if values.next().is_some() {
        return false;
    }
    value.to_str().is_ok_and(|value| {
        value
            .split(';')
            .next()
            .is_some_and(|media_type| media_type.trim().eq_ignore_ascii_case("application/json"))
    })
}

fn finalize_combined_router_with_policy(
    router: Router,
    policy: HttpPolicy,
    metrics: ControlPlaneMetrics,
) -> Router {
    instrument_combined_router(
        harden_combined_router(normalize_api_routing_errors(apply_request_timeout(
            router, policy,
        ))),
        metrics,
    )
}

async fn harden_http_response(request: axum::extract::Request, next: middleware::Next) -> Response {
    let mut response = next.run(request).await;
    let headers = response.headers_mut();
    headers.insert(REFERRER_POLICY, HeaderValue::from_static("no-referrer"));
    headers.insert(X_CONTENT_TYPE_OPTIONS, HeaderValue::from_static("nosniff"));
    response
}

async fn handle_middleware_error(OriginalUri(uri): OriginalUri, error: BoxError) -> Response {
    if error.is::<tower::timeout::error::Elapsed>() {
        if is_human_api_path(uri.path()) {
            return api_middleware_error_response(
                StatusCode::GATEWAY_TIMEOUT,
                r#"{"error":"request_timeout"}"#,
            );
        }
        return (
            StatusCode::GATEWAY_TIMEOUT,
            [(CACHE_CONTROL, "no-store")],
            "Request timed out.\n",
        )
            .into_response();
    }

    tracing::error!(%error, "HTTP middleware failed");
    if is_human_api_path(uri.path()) {
        return api_middleware_error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            r#"{"error":"internal_error"}"#,
        );
    }
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        [(CACHE_CONTROL, "no-store")],
        "Internal server error.\n",
    )
        .into_response()
}

fn api_middleware_error_response(status: StatusCode, body: &'static str) -> Response {
    (
        status,
        [
            (CACHE_CONTROL, "no-store"),
            (CONTENT_TYPE, "application/json; charset=utf-8"),
        ],
        body,
    )
        .into_response()
}

async fn health() -> Response {
    (
        [(CACHE_CONTROL, "no-store")],
        Json(HealthResponse {
            status: "ok",
            build: BuildInfo::current(),
        }),
    )
        .into_response()
}

fn ready(readiness: &Readiness) -> Response {
    if readiness.snapshot().is_ready() {
        return (StatusCode::OK, [(CACHE_CONTROL, "no-store")], "ready\n").into_response();
    }
    (
        StatusCode::SERVICE_UNAVAILABLE,
        [(CACHE_CONTROL, "no-store")],
        "not ready\n",
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicBool, Ordering};

    use async_trait::async_trait;
    use automata_ci_auth::{
        human::TenantId, management::RoleDetailRecord, request_auth::AuthenticatedRequestSnapshot,
    };
    use axum::{
        body::{Body, to_bytes},
        http::{Request, header},
        routing::{get, post},
    };
    use tower::ServiceExt as _;

    use super::*;

    #[derive(Debug)]
    struct NeverReadRbacData;

    #[async_trait]
    impl web::RbacWebData for NeverReadRbacData {
        async fn list_users(
            &self,
            _snapshot: &AuthenticatedRequestSnapshot,
            _request: &web::RbacUserListRequest,
        ) -> Result<web::RbacWebReadOutcome<web::RbacUserListPage>, web::RbacWebDataError> {
            unreachable!("unauthenticated route-presence probes must not read RBAC data")
        }

        async fn user_detail(
            &self,
            _snapshot: &AuthenticatedRequestSnapshot,
            _request: &web::RbacUserDetailRequest,
        ) -> Result<web::RbacWebReadOutcome<web::RbacUserDetailPage>, web::RbacWebDataError>
        {
            unreachable!("unauthenticated route-presence probes must not read RBAC data")
        }

        async fn list_roles(
            &self,
            _snapshot: &AuthenticatedRequestSnapshot,
            _request: &web::RbacRoleListRequest,
        ) -> Result<web::RbacWebReadOutcome<web::RbacRoleListPage>, web::RbacWebDataError> {
            unreachable!("unauthenticated route-presence probes must not read RBAC data")
        }

        async fn role_detail(
            &self,
            _snapshot: &AuthenticatedRequestSnapshot,
            _request: &web::RbacRoleDetailRequest,
        ) -> Result<web::RbacWebReadOutcome<RoleDetailRecord>, web::RbacWebDataError> {
            unreachable!("unauthenticated route-presence probes must not read RBAC data")
        }

        async fn list_direct_bindings(
            &self,
            _snapshot: &AuthenticatedRequestSnapshot,
            _request: &web::RbacDirectBindingListRequest,
        ) -> Result<web::RbacWebReadOutcome<web::RbacDirectBindingListPage>, web::RbacWebDataError>
        {
            unreachable!("unauthenticated route-presence probes must not read RBAC data")
        }
    }

    #[derive(Debug)]
    struct MutableSetupAvailability(AtomicBool);

    impl MutableSetupAvailability {
        const fn armed() -> Self {
            Self(AtomicBool::new(true))
        }

        fn withdraw(&self) {
            self.0.store(false, Ordering::SeqCst);
        }
    }

    #[async_trait]
    impl web::SetupPageAvailability for MutableSetupAvailability {
        async fn current(
            &self,
        ) -> Result<web::SetupPageAvailabilityState, web::SetupPageAvailabilityError> {
            Ok(if self.0.load(Ordering::SeqCst) {
                web::SetupPageAvailabilityState::Armed
            } else {
                web::SetupPageAvailabilityState::Absent
            })
        }
    }

    fn composed_web_router(rbac_data: Option<Arc<dyn web::RbacWebData>>) -> Router {
        composed_web_router_with_setup(rbac_data, None)
    }

    fn composed_web_router_with_setup(
        rbac_data: Option<Arc<dyn web::RbacWebData>>,
        setup_page_availability: Option<Arc<dyn web::SetupPageAvailability>>,
    ) -> Router {
        let tenant = TenantId::new("rbac-composition-test").expect("test tenant");
        router_with_readiness_web_data(
            Readiness::all_ready(),
            Arc::new(web::EmptyWebData),
            rbac_data,
            setup_page_availability,
            web::RequestContext::anonymous(tenant),
        )
        .expect("embedded renderer")
    }

    #[tokio::test]
    async fn one_production_router_withdraws_setup_without_losing_rbac_routes() {
        let rbac_data: Arc<dyn web::RbacWebData> = Arc::new(NeverReadRbacData);
        let setup = Arc::new(MutableSetupAvailability::armed());
        let setup_port: Arc<dyn web::SetupPageAvailability> = setup.clone();
        let router = composed_web_router_with_setup(Some(rbac_data), Some(setup_port));

        let response = router
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/setup")
                    .body(Body::empty())
                    .expect("setup request"),
            )
            .await
            .expect("armed setup response");
        assert_eq!(response.status(), StatusCode::OK);

        for _ in 0..2 {
            let response = router
                .clone()
                .oneshot(
                    Request::builder()
                        .uri("/settings/access/users")
                        .body(Body::empty())
                        .expect("RBAC request"),
                )
                .await
                .expect("protected RBAC response");
            assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
            setup.withdraw();
        }

        let response = router
            .oneshot(
                Request::builder()
                    .uri("/setup")
                    .body(Body::empty())
                    .expect("withdrawn setup request"),
            )
            .await
            .expect("withdrawn setup response");
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn production_web_router_composes_exactly_the_rbac_management_surface() {
        let without_rbac = composed_web_router(None);
        let rbac_data: Arc<dyn web::RbacWebData> = Arc::new(NeverReadRbacData);
        let with_rbac = composed_web_router(Some(rbac_data));
        let get_paths = [
            "/settings/access/users",
            "/settings/access/users/aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
            "/settings/access/roles",
            "/settings/access/roles/cccccccc-cccc-4ccc-8ccc-cccccccccccc",
            "/settings/access/direct-bindings",
        ];
        for path in get_paths {
            let response = without_rbac
                .clone()
                .oneshot(
                    Request::builder()
                        .uri(path)
                        .body(Body::empty())
                        .expect("RBAC GET request"),
                )
                .await
                .expect("RBAC-absent response");
            assert_eq!(response.status(), StatusCode::NOT_FOUND, "path {path}");

            let response = with_rbac
                .clone()
                .oneshot(
                    Request::builder()
                        .uri(path)
                        .body(Body::empty())
                        .expect("RBAC GET request"),
                )
                .await
                .expect("RBAC-present response");
            assert_eq!(response.status(), StatusCode::UNAUTHORIZED, "path {path}");
        }

        for path in [
            "/settings/access/users/aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa/status",
            "/settings/access/roles",
            "/settings/access/roles/cccccccc-cccc-4ccc-8ccc-cccccccccccc",
            "/settings/access/roles/cccccccc-cccc-4ccc-8ccc-cccccccccccc/delete",
            "/settings/access/roles/cccccccc-cccc-4ccc-8ccc-cccccccccccc/permissions/jobs:read",
            "/settings/access/direct-bindings",
            "/settings/access/direct-bindings/dddddddd-dddd-4ddd-8ddd-dddddddddddd/revoke",
        ] {
            let response = without_rbac
                .clone()
                .oneshot(
                    Request::builder()
                        .method("POST")
                        .uri(path)
                        .body(Body::empty())
                        .expect("RBAC POST request"),
                )
                .await
                .expect("RBAC-absent response");
            assert_eq!(response.status(), StatusCode::NOT_FOUND, "path {path}");

            let response = with_rbac
                .clone()
                .oneshot(
                    Request::builder()
                        .method("POST")
                        .uri(path)
                        .body(Body::empty())
                        .expect("RBAC POST request"),
                )
                .await
                .expect("RBAC management response");
            assert_eq!(response.status(), StatusCode::UNAUTHORIZED, "path {path}");
        }
    }

    #[tokio::test]
    async fn combined_router_instruments_a_product_route_merged_before_the_layer() {
        let metrics =
            ControlPlaneMetrics::new(BuildInfo::current()).expect("control-plane metrics");
        let router = instrument_combined_router(
            Router::new().route(
                "/api/v1/local/workflow-runs",
                post(|| async { StatusCode::ACCEPTED }),
            ),
            metrics.clone(),
        );

        let response = router
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/local/workflow-runs")
                    .body(Body::empty())
                    .expect("workflow admission request"),
            )
            .await
            .expect("workflow admission response");
        assert_eq!(response.status(), StatusCode::ACCEPTED);

        let exposition = metrics
            .exporter()
            .encode_openmetrics()
            .expect("bounded exposition");
        assert!(exposition.as_str().contains(
            "automata_ci_control_plane_http_requests_total{method=\"post\",route=\"/api/v1/local/workflow-runs\",status_class=\"2xx\"} 1"
        ));
    }

    fn finalized_routing_test_router() -> Router {
        let metrics =
            ControlPlaneMetrics::new(BuildInfo::current()).expect("control-plane metrics");
        finalize_combined_router_with_policy(
            core_router(
                Router::new()
                    .route("/browser", get(|| async { StatusCode::NO_CONTENT }))
                    .fallback(|| async { StatusCode::NOT_FOUND }),
                Readiness::all_ready(),
            )
            .merge(
                Router::new()
                    .route("/api/v1/widgets", get(|| async { StatusCode::NO_CONTENT }))
                    .route(
                        "/api/v1/preserved",
                        get(|| async {
                            (
                                StatusCode::NOT_FOUND,
                                [(CONTENT_TYPE, "application/json; charset=utf-8")],
                                r#"{"error":"route_specific"}"#,
                            )
                        }),
                    ),
            ),
            HttpPolicy::default(),
            metrics,
        )
    }

    #[tokio::test]
    async fn final_router_normalizes_api_method_errors_and_preserves_allow() {
        let response = finalized_routing_test_router()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/widgets")
                    .body(Body::empty())
                    .expect("API method request"),
            )
            .await
            .expect("API method response");
        assert_eq!(response.status(), StatusCode::METHOD_NOT_ALLOWED);
        assert_eq!(response.headers()[header::ALLOW], "GET,HEAD");
        assert_eq!(response.headers()[CACHE_CONTROL], "no-store");
        assert_eq!(
            response.headers()[CONTENT_TYPE],
            "application/json; charset=utf-8"
        );
        assert_eq!(response.headers()[REFERRER_POLICY], "no-referrer");
        assert_eq!(response.headers()[X_CONTENT_TYPE_OPTIONS], "nosniff");
        assert_eq!(
            to_bytes(response.into_body(), 128)
                .await
                .expect("bounded method response"),
            r#"{"error":"method_not_allowed"}"#
        );
    }

    #[tokio::test]
    async fn final_router_normalizes_unmatched_api_routes() {
        let response = finalized_routing_test_router()
            .oneshot(
                Request::builder()
                    .uri("/api/v1/missing")
                    .body(Body::empty())
                    .expect("missing API request"),
            )
            .await
            .expect("missing API response");
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        assert_eq!(response.headers()[CACHE_CONTROL], "no-store");
        assert_eq!(
            response.headers()[CONTENT_TYPE],
            "application/json; charset=utf-8"
        );
        assert_eq!(
            to_bytes(response.into_body(), 128)
                .await
                .expect("bounded missing response"),
            r#"{"error":"not_found"}"#
        );
    }

    #[tokio::test]
    async fn final_router_preserves_route_specific_json_errors() {
        let response = finalized_routing_test_router()
            .oneshot(
                Request::builder()
                    .uri("/api/v1/preserved")
                    .body(Body::empty())
                    .expect("route-specific API request"),
            )
            .await
            .expect("route-specific API response");
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        assert_eq!(
            to_bytes(response.into_body(), 128)
                .await
                .expect("bounded route-specific response"),
            r#"{"error":"route_specific"}"#
        );
    }

    #[tokio::test]
    async fn final_router_leaves_browser_method_errors_unchanged() {
        let response = finalized_routing_test_router()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/browser")
                    .body(Body::empty())
                    .expect("browser method request"),
            )
            .await
            .expect("browser method response");
        assert_eq!(response.status(), StatusCode::METHOD_NOT_ALLOWED);
        assert_ne!(
            response
                .headers()
                .get(CONTENT_TYPE)
                .and_then(|value| value.to_str().ok()),
            Some("application/json; charset=utf-8")
        );
        assert!(
            to_bytes(response.into_body(), 1)
                .await
                .expect("bounded browser method response")
                .is_empty()
        );
    }

    #[tokio::test]
    async fn combined_deadline_covers_authentication_and_merged_human_routes() {
        let metrics =
            ControlPlaneMetrics::new(BuildInfo::current()).expect("control-plane metrics");
        let policy = HttpPolicy::new(Duration::from_millis(10), 1).expect("HTTP policy");
        let router = finalize_combined_router_with_policy(
            Router::new()
                .route("/api/v1/session", get(|| async { StatusCode::OK }))
                .route("/repositories", get(|| async { StatusCode::OK }))
                .layer(middleware::from_fn(
                    |request: axum::extract::Request, next: middleware::Next| async move {
                        // Models the revision-safe session resolver/touch middleware
                        // that production installs before final router finalization.
                        tokio::time::sleep(Duration::from_secs(1)).await;
                        next.run(request).await
                    },
                )),
            policy,
            metrics.clone(),
        );

        let response = router
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/api/v1/session")
                    .body(Body::empty())
                    .expect("session request"),
            )
            .await
            .expect("timeout response");
        assert_eq!(response.status(), StatusCode::GATEWAY_TIMEOUT);
        assert_eq!(response.headers()[CACHE_CONTROL], "no-store");
        assert_eq!(
            response.headers()[CONTENT_TYPE],
            "application/json; charset=utf-8"
        );
        assert_eq!(response.headers()[REFERRER_POLICY], "no-referrer");
        assert_eq!(response.headers()[X_CONTENT_TYPE_OPTIONS], "nosniff");
        assert_eq!(
            to_bytes(response.into_body(), 128)
                .await
                .expect("bounded API timeout body"),
            r#"{"error":"request_timeout"}"#
        );

        let browser = router
            .oneshot(
                Request::builder()
                    .uri("/repositories")
                    .body(Body::empty())
                    .expect("browser request"),
            )
            .await
            .expect("browser timeout response");
        assert_eq!(browser.status(), StatusCode::GATEWAY_TIMEOUT);
        assert_eq!(browser.headers()[CACHE_CONTROL], "no-store");
        assert_eq!(browser.headers()[CONTENT_TYPE], "text/plain; charset=utf-8");
        assert_eq!(
            to_bytes(browser.into_body(), 128)
                .await
                .expect("bounded browser timeout body"),
            "Request timed out.\n"
        );

        let exposition = metrics
            .exporter()
            .encode_openmetrics()
            .expect("bounded exposition");
        assert!(exposition.as_str().contains(
            "automata_ci_control_plane_http_requests_total{method=\"get\",route=\"/api/v1/session\",status_class=\"5xx\"} 1"
        ));
    }
}
