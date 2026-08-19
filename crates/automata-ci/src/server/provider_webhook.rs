//! Provider-neutral public webhook HTTP ingress.

use std::{str::FromStr as _, sync::Arc, time::Duration};

use automata_ci_provider::{
    ProviderWebhookEndpointId, ProviderWebhookHeaderName, ProviderWebhookHeaders,
    ProviderWebhookMethod,
};
use automata_ci_provider_delivery::{ProviderDeliveryIngress, ProviderDeliveryIngressError};
use axum::{
    Router,
    body::Body,
    extract::{Path, Request},
    http::{HeaderMap, HeaderValue, Method, StatusCode, header},
    response::Response,
    routing::any,
};
use futures::StreamExt as _;
use tokio::{
    sync::Semaphore,
    time::{Instant, timeout_at},
};

const MAX_CONCURRENT_PROVIDER_WEBHOOK_REQUESTS: usize = 4;

/// Public prefix for opaque provider webhook endpoints.
pub const PROVIDER_WEBHOOK_PATH_PREFIX: &str = "/webhooks/providers";
/// Cardinality-safe matched route for every opaque provider webhook endpoint.
pub const PROVIDER_WEBHOOK_ROUTE: &str = "/webhooks/providers/{endpoint_id}";
/// Absolute product HTTP deadline for one provider webhook request.
pub const PROVIDER_WEBHOOK_HTTP_DEADLINE: Duration = Duration::from_secs(7);

/// Merges opaque provider webhook endpoints outside a protected human router.
///
/// `human_router` must already have its human-session middleware applied. The
/// independently built subtree is merged afterward, so only exact
/// `POST /webhooks/providers/{endpoint_id}` requests reach provider ingress.
pub fn router_with_provider_webhooks_outside_human_auth(
    human_router: Router,
    ingress: Arc<ProviderDeliveryIngress>,
) -> Router {
    let admission = Arc::new(Semaphore::new(MAX_CONCURRENT_PROVIDER_WEBHOOK_REQUESTS));
    let route = any(move |Path(endpoint_id): Path<String>, request: Request| {
        let ingress = Arc::clone(&ingress);
        let admission = Arc::clone(&admission);
        async move { provider_webhook(endpoint_id, ingress, admission, request).await }
    });
    let webhook_subtree = Router::new()
        .route("/{endpoint_id}", route)
        .fallback(provider_webhook_not_found);

    Router::new()
        .nest(PROVIDER_WEBHOOK_PATH_PREFIX, webhook_subtree)
        .merge(human_router)
}

async fn provider_webhook(
    endpoint_id: String,
    ingress: Arc<ProviderDeliveryIngress>,
    admission: Arc<Semaphore>,
    request: Request,
) -> Response {
    let deadline = Instant::now() + PROVIDER_WEBHOOK_HTTP_DEADLINE;
    match timeout_at(
        deadline,
        accept_provider_webhook(endpoint_id, ingress, admission, request, deadline),
    )
    .await
    {
        Ok(Ok(())) => ProviderWebhookHttpOutcome::Accepted.response(),
        Ok(Err(outcome)) => outcome.response(),
        Err(_) => ProviderWebhookHttpOutcome::TimedOut.response(),
    }
}

async fn accept_provider_webhook(
    endpoint_id: String,
    ingress: Arc<ProviderDeliveryIngress>,
    admission: Arc<Semaphore>,
    request: Request,
    deadline: Instant,
) -> Result<(), ProviderWebhookHttpOutcome> {
    if request.method() != Method::POST {
        return Err(ProviderWebhookHttpOutcome::MethodNotAllowed);
    }
    if request.uri().query().is_some() {
        return Err(ProviderWebhookHttpOutcome::InvalidRequest);
    }
    require_exact_json(request.headers())?;
    let endpoint_id = ProviderWebhookEndpointId::from_str(&endpoint_id)
        .map_err(|_| ProviderWebhookHttpOutcome::NotFound)?;
    let _permit = admission
        .try_acquire_owned()
        .map_err(|_| ProviderWebhookHttpOutcome::Unavailable)?;
    let received_at = ingress.now().map_err(map_ingress_error)?;
    let prepared = ingress
        .prepare(endpoint_id, received_at)
        .await
        .map_err(map_ingress_error)?;
    let headers = selected_headers(request.headers(), prepared.selected_header_names())?;
    let body = collect_raw_body(request.into_body(), prepared.body_limit()).await?;
    ensure_before_deadline(deadline)?;
    prepared
        .accept(ProviderWebhookMethod::Post, headers, body)
        .await
        .map_err(|error| {
            let outcome = map_ingress_error(error);
            if matches!(
                outcome,
                ProviderWebhookHttpOutcome::Internal | ProviderWebhookHttpOutcome::Unavailable
            ) {
                tracing::warn!(
                    error = %error,
                    status = outcome.status().as_u16(),
                    "provider webhook ingress failed"
                );
            }
            outcome
        })?;
    ensure_before_deadline(deadline)
}

fn require_exact_json(headers: &HeaderMap) -> Result<(), ProviderWebhookHttpOutcome> {
    let mut values = headers.get_all(header::CONTENT_TYPE).iter();
    let Some(value) = values.next() else {
        return Err(ProviderWebhookHttpOutcome::UnsupportedMediaType);
    };
    if value.as_bytes() != b"application/json" || values.next().is_some() {
        return Err(ProviderWebhookHttpOutcome::UnsupportedMediaType);
    }
    Ok(())
}

fn selected_headers(
    headers: &HeaderMap,
    selected: &[ProviderWebhookHeaderName],
) -> Result<ProviderWebhookHeaders, ProviderWebhookHttpOutcome> {
    let mut values = Vec::with_capacity(selected.len());
    for name in selected {
        let mut candidates = headers.get_all(name.as_str()).iter();
        let Some(value) = candidates.next() else {
            return Err(ProviderWebhookHttpOutcome::AuthenticationFailed);
        };
        if candidates.next().is_some() {
            return Err(ProviderWebhookHttpOutcome::AuthenticationFailed);
        }
        values.push((name.clone(), value.as_bytes().to_vec()));
    }
    ProviderWebhookHeaders::new(values)
        .map_err(|_| ProviderWebhookHttpOutcome::AuthenticationFailed)
}

async fn collect_raw_body(
    body: Body,
    body_limit: u64,
) -> Result<Vec<u8>, ProviderWebhookHttpOutcome> {
    let mut stream = body.into_data_stream();
    let mut raw_body = Vec::new();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|_| ProviderWebhookHttpOutcome::InvalidRequest)?;
        let Some(length) = raw_body.len().checked_add(chunk.len()) else {
            return Err(ProviderWebhookHttpOutcome::PayloadTooLarge);
        };
        if u64::try_from(length).map_or(true, |length| length > body_limit) {
            return Err(ProviderWebhookHttpOutcome::PayloadTooLarge);
        }
        raw_body
            .try_reserve_exact(chunk.len())
            .map_err(|_| ProviderWebhookHttpOutcome::Internal)?;
        raw_body.extend_from_slice(&chunk);
    }
    Ok(raw_body)
}

fn ensure_before_deadline(deadline: Instant) -> Result<(), ProviderWebhookHttpOutcome> {
    if Instant::now() < deadline {
        Ok(())
    } else {
        Err(ProviderWebhookHttpOutcome::TimedOut)
    }
}

async fn provider_webhook_not_found() -> Response {
    ProviderWebhookHttpOutcome::NotFound.response()
}

const fn map_ingress_error(error: ProviderDeliveryIngressError) -> ProviderWebhookHttpOutcome {
    match error {
        ProviderDeliveryIngressError::NotFound => ProviderWebhookHttpOutcome::NotFound,
        ProviderDeliveryIngressError::InvalidRequest => ProviderWebhookHttpOutcome::InvalidRequest,
        ProviderDeliveryIngressError::InvalidAuthenticationEvidence
        | ProviderDeliveryIngressError::AuthenticationFailed => {
            ProviderWebhookHttpOutcome::AuthenticationFailed
        }
        ProviderDeliveryIngressError::ReplayConflict => ProviderWebhookHttpOutcome::ReplayConflict,
        ProviderDeliveryIngressError::Storage => ProviderWebhookHttpOutcome::Internal,
        ProviderDeliveryIngressError::Unavailable => ProviderWebhookHttpOutcome::Unavailable,
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ProviderWebhookHttpOutcome {
    Accepted,
    InvalidRequest,
    AuthenticationFailed,
    NotFound,
    MethodNotAllowed,
    ReplayConflict,
    PayloadTooLarge,
    UnsupportedMediaType,
    Unavailable,
    TimedOut,
    Internal,
}

impl ProviderWebhookHttpOutcome {
    const fn status(self) -> StatusCode {
        match self {
            Self::Accepted => StatusCode::ACCEPTED,
            Self::InvalidRequest => StatusCode::BAD_REQUEST,
            Self::AuthenticationFailed => StatusCode::UNAUTHORIZED,
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
    use automata_ci_blob::MemoryBlobStore;
    use automata_ci_provider::{
        AcceptProviderDelivery, DeliveryAdapter, DeliveryAdapterRegistry, ProviderDelivery,
        ProviderDeliveryAcceptOutcome, ProviderDeliveryFuture, ProviderDeliveryId,
        ProviderDeliveryRepository, ProviderSaveOutcome, ProviderWebhookEndpointId,
        ProviderWebhookEndpointManifest, ProviderWebhookEndpointRecord,
        ProviderWebhookEndpointRepository, ProviderWebhookEndpointRevision,
    };
    use automata_ci_provider_delivery::SystemProviderDeliveryClock;
    use automata_ci_provider_github::GithubDeliveryAdapter;
    use axum::{body::Body, http::Request, routing::get};
    use tower::ServiceExt as _;

    use super::*;

    #[derive(Debug)]
    struct MissingProviderRepository;

    impl ProviderWebhookEndpointRepository for MissingProviderRepository {
        fn save_endpoint(
            &self,
            _endpoint: ProviderWebhookEndpointManifest,
        ) -> ProviderDeliveryFuture<'_, ProviderSaveOutcome> {
            Box::pin(async { panic!("save is unused") })
        }

        fn current_endpoint_manifest(
            &self,
            _endpoint_id: ProviderWebhookEndpointId,
        ) -> ProviderDeliveryFuture<'_, Option<ProviderWebhookEndpointManifest>> {
            Box::pin(async { Ok(None) })
        }

        fn resolve_endpoint(
            &self,
            _endpoint_id: ProviderWebhookEndpointId,
        ) -> ProviderDeliveryFuture<'_, Option<ProviderWebhookEndpointRecord>> {
            Box::pin(async { Ok(None) })
        }

        fn load_endpoint(
            &self,
            _endpoint_id: ProviderWebhookEndpointId,
            _revision: ProviderWebhookEndpointRevision,
        ) -> ProviderDeliveryFuture<'_, Option<ProviderWebhookEndpointRecord>> {
            Box::pin(async { Ok(None) })
        }
    }

    impl ProviderDeliveryRepository for MissingProviderRepository {
        fn accept_delivery(
            &self,
            _request: AcceptProviderDelivery,
        ) -> ProviderDeliveryFuture<'_, ProviderDeliveryAcceptOutcome> {
            Box::pin(async { panic!("accept is unused") })
        }

        fn load_delivery(
            &self,
            _delivery_id: ProviderDeliveryId,
        ) -> ProviderDeliveryFuture<'_, Option<ProviderDelivery>> {
            Box::pin(async { Ok(None) })
        }
    }

    #[test]
    fn ingress_failures_have_closed_http_statuses() {
        assert_eq!(
            map_ingress_error(ProviderDeliveryIngressError::NotFound).status(),
            StatusCode::NOT_FOUND
        );
        assert_eq!(
            map_ingress_error(ProviderDeliveryIngressError::AuthenticationFailed).status(),
            StatusCode::UNAUTHORIZED
        );
        assert_eq!(
            map_ingress_error(ProviderDeliveryIngressError::ReplayConflict).status(),
            StatusCode::CONFLICT
        );
        assert_eq!(
            map_ingress_error(ProviderDeliveryIngressError::Storage).status(),
            StatusCode::INTERNAL_SERVER_ERROR
        );
        assert_eq!(
            map_ingress_error(ProviderDeliveryIngressError::Unavailable).status(),
            StatusCode::SERVICE_UNAVAILABLE
        );
    }

    #[tokio::test]
    async fn opaque_provider_route_is_merged_outside_human_authentication() {
        let repository = Arc::new(MissingProviderRepository);
        let endpoints: Arc<dyn ProviderWebhookEndpointRepository> = repository.clone();
        let deliveries: Arc<dyn ProviderDeliveryRepository> = repository;
        let adapter: Arc<dyn DeliveryAdapter> = Arc::new(GithubDeliveryAdapter::new());
        let ingress = Arc::new(ProviderDeliveryIngress::new(
            endpoints,
            deliveries,
            Arc::new(MemoryBlobStore::default()),
            DeliveryAdapterRegistry::new([adapter]).expect("delivery adapters"),
            Arc::new(SystemProviderDeliveryClock),
        ));
        let human = Router::new()
            .route("/human", get(|| async { StatusCode::NO_CONTENT }))
            .layer(axum::middleware::from_fn(
                |_request: Request<Body>, _next: axum::middleware::Next| async {
                    StatusCode::UNAUTHORIZED
                },
            ));
        let router = router_with_provider_webhooks_outside_human_auth(human, ingress);

        let provider = router
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/webhooks/providers/00000000-0000-0000-0000-000000000001")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from("{}"))
                    .expect("provider request"),
            )
            .await
            .expect("provider response");
        assert_eq!(provider.status(), StatusCode::NOT_FOUND);
        let human = router
            .oneshot(
                Request::builder()
                    .uri("/human")
                    .body(Body::empty())
                    .expect("human request"),
            )
            .await
            .expect("human response");
        assert_eq!(human.status(), StatusCode::UNAUTHORIZED);
    }
}
