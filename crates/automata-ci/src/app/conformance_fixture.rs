//! Product adapters for injecting conformance fixtures through real ingress.

use std::{fmt::Write as _, sync::Arc};

use automata_ci_conformance::RawWebhookFixture;
use automata_ci_github::{X_GITHUB_DELIVERY, X_GITHUB_EVENT, X_HUB_SIGNATURE_256};
use automata_ci_github_delivery::GithubDeliveryIngress;
use axum::{Router, body::Body, extract::Request, http::header, response::Response};
use sha2::{Digest as _, Sha256};
use thiserror::Error;
use tower::ServiceExt as _;

use crate::server::{GITHUB_WEBHOOK_PATH, router_with_github_webhook_outside_human_auth};

/// In-process conformance client for Automata's exact production GitHub route.
///
/// This adapter deliberately owns no alternate webhook handler. It constructs
/// the byte-exact public request described by [`RawWebhookFixture`] and sends
/// it through the same Axum router used by the server composition.
#[derive(Clone)]
pub struct GithubWebhookFixtureIngress {
    router: Router,
}

impl GithubWebhookFixtureIngress {
    /// Builds a fixture client around the real product webhook ingress.
    #[must_use]
    pub fn new(ingress: Arc<GithubDeliveryIngress>) -> Self {
        Self {
            router: router_with_github_webhook_outside_human_auth(Router::new(), ingress),
        }
    }

    /// Injects one exact signed fixture through `POST /webhooks/github`.
    ///
    /// The body digest is recomputed immediately before request construction,
    /// preventing a decoded or retained fixture from silently drifting away
    /// from its immutable body lock. Signature verification and all durable
    /// replay decisions remain inside the production ingress.
    ///
    /// # Errors
    ///
    /// Returns an error when the fixture body no longer matches its digest or
    /// its retained header values cannot form an HTTP request.
    pub async fn inject(
        &self,
        fixture: &RawWebhookFixture,
    ) -> Result<Response, GithubWebhookFixtureIngressError> {
        if body_sha256(fixture.body()) != fixture.body_sha256() {
            return Err(GithubWebhookFixtureIngressError::BodyDigestMismatch);
        }
        let request = Request::builder()
            .method("POST")
            .uri(GITHUB_WEBHOOK_PATH)
            .header(header::CONTENT_TYPE, "application/json")
            .header(X_HUB_SIGNATURE_256, fixture.signature_sha256())
            .header(X_GITHUB_EVENT, fixture.event())
            .header(X_GITHUB_DELIVERY, fixture.delivery_id())
            .body(Body::from(fixture.body().to_vec()))?;
        match self.router.clone().oneshot(request).await {
            Ok(response) => Ok(response),
            Err(error) => match error {},
        }
    }
}

impl std::fmt::Debug for GithubWebhookFixtureIngress {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("GithubWebhookFixtureIngress")
            .finish_non_exhaustive()
    }
}

/// Failure to turn an immutable webhook fixture into a product request.
#[derive(Debug, Error)]
pub enum GithubWebhookFixtureIngressError {
    /// The retained raw body differs from the fixture's immutable digest.
    #[error("the webhook fixture body does not match its SHA-256 lock")]
    BodyDigestMismatch,
    /// A retained fixture header could not be represented by the HTTP stack.
    #[error("the webhook fixture cannot form a valid HTTP request")]
    InvalidRequest(#[from] http::Error),
}

fn body_sha256(body: &[u8]) -> String {
    let mut encoded = String::with_capacity(64);
    for byte in Sha256::digest(body) {
        write!(&mut encoded, "{byte:02x}").expect("writing to a string cannot fail");
    }
    encoded
}
