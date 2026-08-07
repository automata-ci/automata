use std::{fmt, sync::Arc, time::Duration};

use automata_ui_renderer::{RenderPolicy, Renderer, RendererInitError, WasmtimeRenderer};
use axum::{
    BoxError, Json, Router,
    error_handling::HandleErrorLayer,
    http::{StatusCode, header::CACHE_CONTROL},
    response::{IntoResponse, Response},
    routing::get,
};
use serde::Serialize;
use tower::{ServiceBuilder, timeout::TimeoutLayer};

use super::web;
use crate::{build_info::BuildInfo, server::Readiness};

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

    pub const fn request_timeout(self) -> Duration {
        self.request_timeout
    }

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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HttpPolicyError {
    ZeroRequestTimeout,
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

pub fn router_with_renderer(renderer: Arc<dyn Renderer>) -> Router {
    router_with_renderer_and_policy(renderer, HttpPolicy::default())
}

pub fn router_with_renderer_and_policy(renderer: Arc<dyn Renderer>, policy: HttpPolicy) -> Router {
    router_with_renderer_policy_and_readiness(renderer, policy, Readiness::all_ready())
}

/// Builds an HTTP router with explicit renderer, policy, and dependency readiness.
pub fn router_with_renderer_policy_and_readiness(
    renderer: Arc<dyn Renderer>,
    policy: HttpPolicy,
    readiness: Readiness,
) -> Router {
    Router::new()
        .route("/healthz", get(health))
        .route(
            "/readyz",
            get(move || std::future::ready(ready(&readiness))),
        )
        .merge(web::router(renderer, policy.max_concurrent_renders()))
        .layer(
            ServiceBuilder::new()
                .layer(HandleErrorLayer::new(handle_middleware_error))
                .layer(TimeoutLayer::new(policy.request_timeout())),
        )
}

async fn handle_middleware_error(error: BoxError) -> Response {
    if error.is::<tower::timeout::error::Elapsed>() {
        return (
            StatusCode::GATEWAY_TIMEOUT,
            [(CACHE_CONTROL, "no-store")],
            "Request timed out.\n",
        )
            .into_response();
    }

    tracing::error!(%error, "HTTP middleware failed");
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        [(CACHE_CONTROL, "no-store")],
        "Internal server error.\n",
    )
        .into_response()
}

async fn health() -> Json<HealthResponse> {
    Json(HealthResponse {
        status: "ok",
        build: BuildInfo::current(),
    })
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
