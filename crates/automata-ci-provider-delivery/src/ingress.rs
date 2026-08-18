use std::{fmt, sync::Arc};

use automata_ci_blob::{BlobPayload, BlobStoreErrorKind, ImmutableBlobStore};
use automata_ci_core::UnixMillis;
use automata_ci_provider::{
    AcceptProviderDelivery, DeliveryAdapterRegistry, ProviderDeliveryAcceptOutcome,
    ProviderDeliveryRepository, ProviderDeliveryRepositoryError,
    ProviderWebhookAuthenticationError, ProviderWebhookAuthenticationRequest,
    ProviderWebhookEndpointId, ProviderWebhookEndpointRecord, ProviderWebhookEndpointRepository,
    ProviderWebhookError, ProviderWebhookHeaderName, ProviderWebhookHeaders, ProviderWebhookMethod,
    ProviderWebhookRequest,
};
use bytes::Bytes;
use thiserror::Error;

use crate::ProviderDeliveryClock;

/// Provider-neutral webhook ingress composition.
pub struct ProviderDeliveryIngress {
    endpoints: Arc<dyn ProviderWebhookEndpointRepository>,
    deliveries: Arc<dyn ProviderDeliveryRepository>,
    objects: Arc<dyn ImmutableBlobStore>,
    adapters: DeliveryAdapterRegistry,
    clock: Arc<dyn ProviderDeliveryClock>,
}

impl ProviderDeliveryIngress {
    /// Composes endpoint custody, adapter registry, immutable evidence, and inbox.
    #[must_use]
    pub fn new(
        endpoints: Arc<dyn ProviderWebhookEndpointRepository>,
        deliveries: Arc<dyn ProviderDeliveryRepository>,
        objects: Arc<dyn ImmutableBlobStore>,
        adapters: DeliveryAdapterRegistry,
        clock: Arc<dyn ProviderDeliveryClock>,
    ) -> Self {
        Self {
            endpoints,
            deliveries,
            objects,
            adapters,
            clock,
        }
    }

    /// Returns a trusted receipt timestamp for the HTTP edge.
    ///
    /// # Errors
    ///
    /// Fails when the configured clock cannot produce durable time evidence.
    pub fn now(&self) -> Result<UnixMillis, ProviderDeliveryIngressError> {
        self.clock
            .now()
            .map_err(|_| ProviderDeliveryIngressError::Unavailable)
    }

    /// Resolves one opaque endpoint into request-specific secret custody.
    ///
    /// # Errors
    ///
    /// Fails closed for missing/inactive endpoints, unavailable storage, or an
    /// endpoint whose provider adapter is not statically registered.
    pub async fn prepare(
        &self,
        endpoint_id: ProviderWebhookEndpointId,
        received_at: UnixMillis,
    ) -> Result<PreparedProviderWebhook, ProviderDeliveryIngressError> {
        if received_at.get() < 0 {
            return Err(ProviderDeliveryIngressError::InvalidRequest);
        }
        let record = self
            .endpoints
            .resolve_endpoint(endpoint_id)
            .await
            .map_err(repository_error)?
            .ok_or(ProviderDeliveryIngressError::NotFound)?;
        let header_names = self
            .adapters
            .resolve(record.manifest())
            .map_err(|_| ProviderDeliveryIngressError::Unavailable)?
            .selected_header_names()
            .to_vec();
        Ok(PreparedProviderWebhook {
            record,
            header_names,
            received_at,
            deliveries: Arc::clone(&self.deliveries),
            objects: Arc::clone(&self.objects),
            adapters: self.adapters.clone(),
            clock: Arc::clone(&self.clock),
        })
    }
}

impl fmt::Debug for ProviderDeliveryIngress {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProviderDeliveryIngress")
            .field("endpoints", &self.endpoints)
            .field("deliveries", &self.deliveries)
            .field("objects", &self.objects)
            .field("adapters", &self.adapters)
            .field("clock", &self.clock)
            .finish()
    }
}

/// Endpoint-resolved, move-only webhook authentication context.
pub struct PreparedProviderWebhook {
    record: ProviderWebhookEndpointRecord,
    header_names: Vec<ProviderWebhookHeaderName>,
    received_at: UnixMillis,
    deliveries: Arc<dyn ProviderDeliveryRepository>,
    objects: Arc<dyn ImmutableBlobStore>,
    adapters: DeliveryAdapterRegistry,
    clock: Arc<dyn ProviderDeliveryClock>,
}

impl PreparedProviderWebhook {
    /// Returns the exact adapter-selected headers the HTTP edge may retain.
    #[must_use]
    pub fn selected_header_names(&self) -> &[ProviderWebhookHeaderName] {
        &self.header_names
    }

    /// Returns the exact body limit from the resolved endpoint revision.
    #[must_use]
    pub const fn body_limit(&self) -> u64 {
        self.record.manifest().body_limit()
    }

    /// Authenticates, normalizes, stores raw bytes, and atomically admits replay evidence.
    ///
    /// # Errors
    ///
    /// Returns sanitized request, authentication, immutable-object, or durable
    /// inbox failures. Payload parsing occurs only after adapter authentication.
    pub async fn accept(
        self,
        method: ProviderWebhookMethod,
        headers: ProviderWebhookHeaders,
        body: Vec<u8>,
    ) -> Result<ProviderDeliveryAcceptOutcome, ProviderDeliveryIngressError> {
        let (endpoint, connections, candidates) = self.record.into_parts();
        let adapter = self
            .adapters
            .resolve(&endpoint)
            .map_err(|_| ProviderDeliveryIngressError::Unavailable)?;
        let mut expected_headers = adapter.selected_header_names().to_vec();
        expected_headers.sort();
        let supplied_headers = headers
            .iter()
            .map(|(name, _)| name.clone())
            .collect::<Vec<_>>();
        if supplied_headers != expected_headers {
            return Err(ProviderDeliveryIngressError::InvalidRequest);
        }
        let request = ProviderWebhookRequest::new(
            endpoint,
            connections,
            method,
            headers,
            body,
            self.received_at,
        )
        .map_err(request_error)?;
        let authenticated = adapter
            .authenticate(
                ProviderWebhookAuthenticationRequest::new(request, candidates)
                    .map_err(request_error)?,
            )
            .map_err(authentication_error)?;
        let normalization = adapter.normalize(authenticated).map_err(request_error)?;
        let descriptor = normalization.raw_descriptor().map_err(request_error)?;
        let payload = BlobPayload::verify(
            descriptor.clone(),
            Bytes::copy_from_slice(normalization.raw_body()),
        )
        .map_err(|_| ProviderDeliveryIngressError::InvalidRequest)?;
        self.objects
            .put_if_absent(payload)
            .await
            .map_err(|error| match error.kind() {
                BlobStoreErrorKind::Unavailable => ProviderDeliveryIngressError::Unavailable,
                _ => ProviderDeliveryIngressError::Storage,
            })?;
        let delivery = normalization.seal(descriptor).map_err(request_error)?;
        let accepted_at = self
            .clock
            .now()
            .map_err(|_| ProviderDeliveryIngressError::Unavailable)?;
        self.deliveries
            .accept_delivery(
                AcceptProviderDelivery::new(delivery, accepted_at)
                    .map_err(|_| ProviderDeliveryIngressError::Storage)?,
            )
            .await
            .map_err(repository_error)
    }
}

impl fmt::Debug for PreparedProviderWebhook {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PreparedProviderWebhook")
            .field("record", &self.record)
            .field("header_names", &self.header_names)
            .field("received_at", &self.received_at)
            .field("deliveries", &self.deliveries)
            .field("objects", &self.objects)
            .field("adapters", &self.adapters)
            .field("clock", &self.clock)
            .finish()
    }
}

/// Sanitized provider webhook ingress failure.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum ProviderDeliveryIngressError {
    /// No active endpoint exists for the opaque public identity.
    #[error("provider webhook endpoint was not found")]
    NotFound,
    /// HTTP evidence, bounds, or endpoint binding was invalid.
    #[error("provider webhook request is invalid")]
    InvalidRequest,
    /// Required authentication evidence was malformed.
    #[error("provider webhook authentication evidence is invalid")]
    InvalidAuthenticationEvidence,
    /// No endpoint-selected secret generation authenticated the request.
    #[error("provider webhook authentication failed")]
    AuthenticationFailed,
    /// A replay identity was reused with contradictory immutable evidence.
    #[error("provider webhook replay evidence conflicts")]
    ReplayConflict,
    /// Immutable or relational persistence rejected the evidence.
    #[error("provider webhook storage failed")]
    Storage,
    /// A required clock, adapter, object store, or repository is unavailable.
    #[error("provider webhook ingress is unavailable")]
    Unavailable,
}

const fn authentication_error(
    error: ProviderWebhookAuthenticationError,
) -> ProviderDeliveryIngressError {
    match error {
        ProviderWebhookAuthenticationError::InvalidEvidence => {
            ProviderDeliveryIngressError::InvalidAuthenticationEvidence
        }
        ProviderWebhookAuthenticationError::InvalidSignature => {
            ProviderDeliveryIngressError::AuthenticationFailed
        }
    }
}

const fn request_error(_error: ProviderWebhookError) -> ProviderDeliveryIngressError {
    ProviderDeliveryIngressError::InvalidRequest
}

const fn repository_error(error: ProviderDeliveryRepositoryError) -> ProviderDeliveryIngressError {
    match error {
        ProviderDeliveryRepositoryError::NotFound => ProviderDeliveryIngressError::NotFound,
        ProviderDeliveryRepositoryError::ReplayConflict => {
            ProviderDeliveryIngressError::ReplayConflict
        }
        ProviderDeliveryRepositoryError::Unavailable => ProviderDeliveryIngressError::Unavailable,
        ProviderDeliveryRepositoryError::EndpointConflict
        | ProviderDeliveryRepositoryError::Corrupt => ProviderDeliveryIngressError::Storage,
    }
}
