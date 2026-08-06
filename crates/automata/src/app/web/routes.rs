use std::fmt;
use std::sync::Arc;

use automata_ui_renderer::{EmbeddedAsset, RenderError, Renderer, client_assets, find_asset};
use axum::Router;
use axum::body::Body;
use axum::extract::{Path, Query, State};
use axum::http::header::{CACHE_CONTROL, CONTENT_TYPE, ETAG, IF_NONE_MATCH, RETRY_AFTER};
use axum::http::{HeaderMap, HeaderName, HeaderValue, Response, StatusCode};
use axum::response::{Html, IntoResponse};
use axum::routing::get;
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde::Deserialize;
use tokio::sync::Semaphore;
use tracing::error;

use super::model;

const MAX_BRANCH_FILTER_BYTES: usize = 512;
const PAGE_CACHE_CONTROL: &str = "no-store";

#[derive(Clone)]
struct WebState {
    renderer: Arc<dyn Renderer>,
    render_permits: Arc<Semaphore>,
}

impl fmt::Debug for WebState {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.debug_struct("WebState").finish_non_exhaustive()
    }
}

#[derive(Debug, Default, Deserialize)]
struct RunListQuery {
    status: Option<String>,
    branch: Option<String>,
}

pub fn router(renderer: Arc<dyn Renderer>, max_concurrent_renders: usize) -> Router {
    Router::new()
        .route("/", get(run_list))
        .route("/runs", get(run_list))
        .route("/assets/{*asset_path}", get(asset))
        .with_state(WebState {
            renderer,
            render_permits: Arc::new(Semaphore::new(max_concurrent_renders)),
        })
}

async fn run_list(
    State(state): State<WebState>,
    Query(query): Query<RunListQuery>,
) -> Response<Body> {
    let Ok(permit) = Arc::clone(&state.render_permits).try_acquire_owned() else {
        return renderer_unavailable();
    };
    let status = normalize_status(query.status.as_deref()).to_owned();
    let branch = query
        .branch
        .filter(|value| value.len() <= MAX_BRANCH_FILTER_BYTES)
        .unwrap_or_default();
    let csp_nonce = match new_csp_nonce() {
        Ok(nonce) => nonce,
        Err(error) => {
            error!(%error, "failed to generate a CSP nonce");
            return internal_server_error();
        }
    };
    let request = match model::empty_run_list(client_assets(), csp_nonce.clone(), status, branch) {
        Ok(request) => request,
        Err(error) => {
            error!(%error, "failed to serialize UI page model");
            return internal_server_error();
        }
    };

    let renderer = Arc::clone(&state.renderer);
    match tokio::task::spawn_blocking(move || {
        let _permit = permit;
        renderer.render(&request)
    })
    .await
    {
        Ok(Ok(page)) => html_response(page.into_string(), &csp_nonce),
        Ok(Err(RenderError::AtCapacity | RenderError::ResourceExhausted(_))) => {
            renderer_unavailable()
        }
        Ok(Err(error)) => {
            error!(%error, "isolated UI renderer rejected a page model");
            internal_server_error()
        }
        Err(error) => {
            error!(%error, "isolated UI renderer task failed");
            internal_server_error()
        }
    }
}

async fn asset(Path(asset_path): Path<String>, request_headers: HeaderMap) -> Response<Body> {
    let requested_path = format!("/assets/{asset_path}");
    let Some(asset) = find_asset(&requested_path) else {
        return StatusCode::NOT_FOUND.into_response();
    };

    let etag = format!("\"{}\"", asset.sha256);
    if request_headers
        .get(IF_NONE_MATCH)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| value.split(',').any(|candidate| candidate.trim() == etag))
    {
        return asset_response(StatusCode::NOT_MODIFIED, asset, &etag, Body::empty());
    }

    asset_response(StatusCode::OK, asset, &etag, Body::from(asset.bytes))
}

fn normalize_status(status: Option<&str>) -> &'static str {
    match status {
        Some("queued") => "queued",
        Some("in_progress") => "in_progress",
        Some("completed") => "completed",
        _ => "all",
    }
}

fn new_csp_nonce() -> Result<String, getrandom::Error> {
    let mut bytes = [0_u8; 16];
    getrandom::fill(&mut bytes)?;
    Ok(URL_SAFE_NO_PAD.encode(bytes))
}

fn html_response(html: String, csp_nonce: &str) -> Response<Body> {
    let mut response = Html(html).into_response();
    let headers = response.headers_mut();
    headers.insert(CACHE_CONTROL, HeaderValue::from_static(PAGE_CACHE_CONTROL));
    let csp = format!(
        "default-src 'none'; base-uri 'none'; connect-src 'self'; form-action 'self'; \
         frame-ancestors 'none'; img-src 'self' data:; script-src 'self' 'nonce-{csp_nonce}'; \
         style-src 'self'"
    );
    let Ok(csp) = HeaderValue::from_str(&csp) else {
        error!("failed to construct the page content security policy");
        return internal_server_error();
    };
    headers.insert(HeaderName::from_static("content-security-policy"), csp);
    headers.insert(
        HeaderName::from_static("cross-origin-opener-policy"),
        HeaderValue::from_static("same-origin"),
    );
    headers.insert(
        HeaderName::from_static("referrer-policy"),
        HeaderValue::from_static("no-referrer"),
    );
    headers.insert(
        HeaderName::from_static("x-content-type-options"),
        HeaderValue::from_static("nosniff"),
    );
    headers.insert(
        HeaderName::from_static("x-frame-options"),
        HeaderValue::from_static("DENY"),
    );
    response
}

fn asset_response(
    status: StatusCode,
    asset: EmbeddedAsset,
    etag: &str,
    body: Body,
) -> Response<Body> {
    let mut response = Response::new(body);
    *response.status_mut() = status;
    let headers = response.headers_mut();
    headers.insert(
        CONTENT_TYPE,
        HeaderValue::from_static(asset.content_type.as_str()),
    );
    headers.insert(
        CACHE_CONTROL,
        HeaderValue::from_static(EmbeddedAsset::CACHE_CONTROL),
    );
    if let Ok(value) = HeaderValue::from_str(etag) {
        headers.insert(ETAG, value);
    }
    headers.insert(
        HeaderName::from_static("x-content-type-options"),
        HeaderValue::from_static("nosniff"),
    );
    response
}

fn internal_server_error() -> Response<Body> {
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        [(CACHE_CONTROL, PAGE_CACHE_CONTROL)],
        "Unable to render this page.\n",
    )
        .into_response()
}

fn renderer_unavailable() -> Response<Body> {
    (
        StatusCode::SERVICE_UNAVAILABLE,
        [(CACHE_CONTROL, PAGE_CACHE_CONTROL), (RETRY_AFTER, "1")],
        "The page renderer is temporarily busy.\n",
    )
        .into_response()
}
