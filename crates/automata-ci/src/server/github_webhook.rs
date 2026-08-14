//! Exact public GitHub webhook HTTP ingress.
//!
//! This module deliberately stops at the HTTP-to-delivery-ingress boundary.
//! Product composition must construct the shared verifier and mixed repository
//! registry before calling [`router_with_github_webhook_outside_human_auth`].

use std::{sync::Arc, time::Duration};

use automata_ci_blob::BlobStoreErrorKind;
use automata_ci_github::{
    GithubWebhookError, MAX_GITHUB_WEBHOOK_BODY_BYTES as VERIFIED_GITHUB_WEBHOOK_BODY_BYTES,
    X_GITHUB_DELIVERY, X_GITHUB_EVENT, X_HUB_SIGNATURE_256,
};
use automata_ci_github_delivery::{GithubDeliveryIngress, GithubDeliveryIngressError};
use axum::{
    Router,
    body::Body,
    extract::Request,
    http::{HeaderMap, HeaderValue, Method, StatusCode, header},
    response::Response,
    routing::any,
};
use bytes::Bytes;
use futures::StreamExt as _;
use tokio::{
    sync::Semaphore,
    time::{Instant, timeout_at},
};

const MAX_CONCURRENT_GITHUB_WEBHOOK_REQUESTS: usize = 4;
const MAX_GITHUB_EVENT_HEADER_BYTES: usize = 64;
const MAX_GITHUB_DELIVERY_HEADER_BYTES: usize = 128;
const GITHUB_SIGNATURE_PREFIX: &[u8] = b"sha256=";
const GITHUB_SIGNATURE_HEX_BYTES: usize = 64;

/// Exact public path reserved for signed GitHub webhook delivery.
pub const GITHUB_WEBHOOK_PATH: &str = "/webhooks/github";
/// Maximum raw GitHub webhook body accepted by the product HTTP boundary.
pub const MAX_GITHUB_WEBHOOK_HTTP_BODY_BYTES: usize = VERIFIED_GITHUB_WEBHOOK_BODY_BYTES;
/// Absolute product HTTP deadline for one GitHub webhook request.
pub const GITHUB_WEBHOOK_HTTP_DEADLINE: Duration = Duration::from_secs(7);

/// Merges the exact public GitHub webhook subtree outside a protected human router.
///
/// `human_router` must already have its human-session middleware applied. The
/// independently built webhook subtree is merged afterward, so its exact
/// `POST /webhooks/github` route does not inherit that middleware. No other
/// GitHub provider route is installed.
pub fn router_with_github_webhook_outside_human_auth(
    human_router: Router,
    registry: Arc<GithubDeliveryIngress>,
) -> Router {
    let admission = Arc::new(Semaphore::new(MAX_CONCURRENT_GITHUB_WEBHOOK_REQUESTS));
    let route = any(move |request: Request| {
        let registry = Arc::clone(&registry);
        let admission = Arc::clone(&admission);
        async move { github_webhook(registry, admission, request).await }
    });
    let webhook_subtree = Router::new()
        .route("/github", route)
        .fallback(github_webhook_not_found);

    Router::new()
        .nest("/webhooks", webhook_subtree)
        .merge(human_router)
}

async fn github_webhook(
    registry: Arc<GithubDeliveryIngress>,
    admission: Arc<Semaphore>,
    request: Request,
) -> Response {
    let deadline = Instant::now() + GITHUB_WEBHOOK_HTTP_DEADLINE;
    match timeout_at(
        deadline,
        accept_github_webhook(registry, admission, request, deadline),
    )
    .await
    {
        Ok(Ok(())) => GithubWebhookHttpOutcome::Accepted.response(),
        Ok(Err(outcome)) => outcome.response(),
        Err(_) => GithubWebhookHttpOutcome::TimedOut.response(),
    }
}

async fn accept_github_webhook(
    registry: Arc<GithubDeliveryIngress>,
    admission: Arc<Semaphore>,
    request: Request,
    deadline: Instant,
) -> Result<(), GithubWebhookHttpOutcome> {
    if request.method() != Method::POST {
        return Err(GithubWebhookHttpOutcome::MethodNotAllowed);
    }
    if request.uri().query().is_some() {
        return Err(GithubWebhookHttpOutcome::InvalidRequest);
    }
    require_exact_json(request.headers())?;
    let ingress_route = require_github_header_shapes(request.headers())?;
    let _permit = admission
        .try_acquire_owned()
        .map_err(|_| GithubWebhookHttpOutcome::Unavailable)?;

    let (parts, body) = request.into_parts();
    let raw_body = collect_raw_body(body).await?;
    ensure_before_deadline(deadline)?;
    match ingress_route {
        GithubWebhookIngressRoute::AuthenticatedEvent => {
            registry.accept(&parts.headers, raw_body).await.map(|_| ())
        }
        GithubWebhookIngressRoute::RepositoryDispatch => registry
            .accept_repository_dispatch(&parts.headers, raw_body)
            .await
            .map(|_| ()),
        GithubWebhookIngressRoute::CheckControl => registry
            .accept_check_rerun(&parts.headers, raw_body)
            .await
            .map(|_| ()),
    }
    .map_err(|error| {
        let outcome = GithubWebhookHttpOutcome::from_ingress(error);
        if matches!(
            outcome,
            GithubWebhookHttpOutcome::Internal | GithubWebhookHttpOutcome::Unavailable
        ) {
            tracing::warn!(
                error = %error,
                status = outcome.status().as_u16(),
                "GitHub webhook ingress failed"
            );
        }
        outcome
    })?;
    ensure_before_deadline(deadline)?;
    Ok(())
}

fn ensure_before_deadline(deadline: Instant) -> Result<(), GithubWebhookHttpOutcome> {
    if Instant::now() < deadline {
        Ok(())
    } else {
        Err(GithubWebhookHttpOutcome::TimedOut)
    }
}

fn require_exact_json(headers: &HeaderMap) -> Result<(), GithubWebhookHttpOutcome> {
    let mut values = headers.get_all(header::CONTENT_TYPE).iter();
    let Some(value) = values.next() else {
        return Err(GithubWebhookHttpOutcome::UnsupportedMediaType);
    };
    if value.as_bytes() != b"application/json" || values.next().is_some() {
        return Err(GithubWebhookHttpOutcome::UnsupportedMediaType);
    }
    Ok(())
}

fn require_github_header_shapes(
    headers: &HeaderMap,
) -> Result<GithubWebhookIngressRoute, GithubWebhookHttpOutcome> {
    let signature = unique_header(headers, X_HUB_SIGNATURE_256)?;
    let Some(encoded_signature) = signature.strip_prefix(GITHUB_SIGNATURE_PREFIX) else {
        return Err(GithubWebhookHttpOutcome::AuthenticationFailed);
    };
    if encoded_signature.len() != GITHUB_SIGNATURE_HEX_BYTES
        || !encoded_signature
            .iter()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    {
        return Err(GithubWebhookHttpOutcome::AuthenticationFailed);
    }

    let event = unique_header(headers, X_GITHUB_EVENT)?;
    if event.is_empty()
        || event.len() > MAX_GITHUB_EVENT_HEADER_BYTES
        || !event
            .iter()
            .all(|byte| byte.is_ascii_lowercase() || *byte == b'_')
    {
        return Err(GithubWebhookHttpOutcome::AuthenticationFailed);
    }

    let delivery = unique_header(headers, X_GITHUB_DELIVERY)?;
    if delivery.is_empty()
        || delivery.len() > MAX_GITHUB_DELIVERY_HEADER_BYTES
        || !delivery
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
    {
        return Err(GithubWebhookHttpOutcome::AuthenticationFailed);
    }
    Ok(match event {
        b"repository_dispatch" => GithubWebhookIngressRoute::RepositoryDispatch,
        b"check_run" | b"check_suite" => GithubWebhookIngressRoute::CheckControl,
        _ => GithubWebhookIngressRoute::AuthenticatedEvent,
    })
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum GithubWebhookIngressRoute {
    AuthenticatedEvent,
    RepositoryDispatch,
    CheckControl,
}

fn unique_header<'headers>(
    headers: &'headers HeaderMap,
    name: &str,
) -> Result<&'headers [u8], GithubWebhookHttpOutcome> {
    let mut values = headers.get_all(name).iter();
    let value = values
        .next()
        .ok_or(GithubWebhookHttpOutcome::AuthenticationFailed)?;
    if values.next().is_some() {
        return Err(GithubWebhookHttpOutcome::AuthenticationFailed);
    }
    Ok(value.as_bytes())
}

async fn collect_raw_body(body: Body) -> Result<Bytes, GithubWebhookHttpOutcome> {
    let mut stream = body.into_data_stream();
    let mut raw_body = Vec::new();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|_| GithubWebhookHttpOutcome::InvalidRequest)?;
        let Some(length) = raw_body.len().checked_add(chunk.len()) else {
            return Err(GithubWebhookHttpOutcome::PayloadTooLarge);
        };
        if length > MAX_GITHUB_WEBHOOK_HTTP_BODY_BYTES {
            return Err(GithubWebhookHttpOutcome::PayloadTooLarge);
        }
        raw_body
            .try_reserve_exact(chunk.len())
            .map_err(|_| GithubWebhookHttpOutcome::Internal)?;
        raw_body.extend_from_slice(&chunk);
    }
    Ok(Bytes::from(raw_body))
}

async fn github_webhook_not_found() -> Response {
    GithubWebhookHttpOutcome::NotFound.response()
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum GithubWebhookHttpOutcome {
    Accepted,
    InvalidRequest,
    AuthenticationFailed,
    Forbidden,
    NotFound,
    MethodNotAllowed,
    ReplayConflict,
    PayloadTooLarge,
    UnsupportedMediaType,
    Unavailable,
    TimedOut,
    Internal,
}

impl GithubWebhookHttpOutcome {
    const fn from_ingress(error: GithubDeliveryIngressError) -> Self {
        match error {
            GithubDeliveryIngressError::Webhook(error) => Self::from_webhook(error),
            GithubDeliveryIngressError::ConfiguredIdentityMismatch
            | GithubDeliveryIngressError::CheckRerunAuthorityRejected => Self::Forbidden,
            GithubDeliveryIngressError::RawObject {
                kind: BlobStoreErrorKind::Unavailable | BlobStoreErrorKind::Unauthorized,
            }
            | GithubDeliveryIngressError::InboxUnavailable => Self::Unavailable,
            GithubDeliveryIngressError::ReplayConflict
            | GithubDeliveryIngressError::CheckRerunConflict => Self::ReplayConflict,
            GithubDeliveryIngressError::InvalidTrustedTime
            | GithubDeliveryIngressError::RawObject { .. }
            | GithubDeliveryIngressError::InboxAuthorityRejected
            | GithubDeliveryIngressError::InboxNotFound
            | GithubDeliveryIngressError::InboxCorrupt
            | GithubDeliveryIngressError::InvariantViolation => Self::Internal,
        }
    }

    const fn from_webhook(error: GithubWebhookError) -> Self {
        match error {
            GithubWebhookError::InvalidHeaders
            | GithubWebhookError::InvalidSignature
            | GithubWebhookError::AuthenticationFailed => Self::AuthenticationFailed,
            GithubWebhookError::BodyTooLarge => Self::PayloadTooLarge,
            GithubWebhookError::UnsupportedEvent
            | GithubWebhookError::MalformedPayload
            | GithubWebhookError::InvalidPayload => Self::InvalidRequest,
            GithubWebhookError::InvalidSecret => Self::Internal,
        }
    }

    const fn status(self) -> StatusCode {
        match self {
            Self::Accepted => StatusCode::ACCEPTED,
            Self::InvalidRequest => StatusCode::BAD_REQUEST,
            Self::AuthenticationFailed => StatusCode::UNAUTHORIZED,
            Self::Forbidden => StatusCode::FORBIDDEN,
            Self::NotFound => StatusCode::NOT_FOUND,
            Self::MethodNotAllowed => StatusCode::METHOD_NOT_ALLOWED,
            Self::ReplayConflict => StatusCode::CONFLICT,
            Self::PayloadTooLarge => StatusCode::PAYLOAD_TOO_LARGE,
            Self::UnsupportedMediaType => StatusCode::UNSUPPORTED_MEDIA_TYPE,
            Self::Unavailable => StatusCode::SERVICE_UNAVAILABLE,
            Self::TimedOut => StatusCode::GATEWAY_TIMEOUT,
            Self::Internal => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }

    fn response(self) -> Response {
        let mut response = Response::new(Body::empty());
        *response.status_mut() = self.status();
        response
            .headers_mut()
            .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
        if self == Self::MethodNotAllowed {
            response
                .headers_mut()
                .insert(header::ALLOW, HeaderValue::from_static("POST"));
        }
        response
    }
}

#[cfg(test)]
mod tests {
    use automata_ci_github::{X_GITHUB_DELIVERY, X_GITHUB_EVENT, X_HUB_SIGNATURE_256};
    use axum::http::{HeaderMap, HeaderValue};

    use super::{GithubWebhookIngressRoute, require_github_header_shapes};

    fn shaped_headers(event: &'static str) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(
            X_HUB_SIGNATURE_256,
            HeaderValue::from_static(
                "sha256=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
            ),
        );
        headers.insert(X_GITHUB_EVENT, HeaderValue::from_static(event));
        headers.insert(
            X_GITHUB_DELIVERY,
            HeaderValue::from_static("synthetic-delivery-1"),
        );
        headers
    }

    #[test]
    fn repository_dispatch_uses_the_dedicated_pre_resolution_route() {
        assert_eq!(
            require_github_header_shapes(&shaped_headers("repository_dispatch")),
            Ok(GithubWebhookIngressRoute::RepositoryDispatch)
        );
        assert_eq!(
            require_github_header_shapes(&shaped_headers("pull_request")),
            Ok(GithubWebhookIngressRoute::AuthenticatedEvent)
        );
        assert_eq!(
            require_github_header_shapes(&shaped_headers("push")),
            Ok(GithubWebhookIngressRoute::AuthenticatedEvent)
        );
    }
}
