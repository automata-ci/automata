//! Opaque webhook endpoints and authenticate-before-parse adapter contracts.

use std::{collections::BTreeMap, fmt, num::NonZeroU64, sync::Arc};

use automata_ci_blob::{BlobDescriptor, BlobKey, MediaType};
use automata_ci_core::{Sha256Digest, UnixMillis};
use automata_ci_key_management::SecretBytes;
use sha2::{Digest as _, Sha256};
use thiserror::Error;

use crate::{
    ExternalDeliveryIdentity, ExternalRepositoryIdentity, NormalizedTrigger,
    ProviderConfigurationRevision, ProviderConnectionId, ProviderConnectionManifest,
    ProviderConnectionRevision, ProviderDeliveryId, ProviderEventName, ProviderInstanceId,
    ProviderLifecycleState, ProviderSecret, ProviderSecretGeneration, ProviderSecretName,
    ProviderTriggerError, ProviderTypeId, ProviderWebhookEndpointId, SealedNormalizedTrigger,
};

/// Hard upper bound for any provider webhook body.
pub const MAX_PROVIDER_WEBHOOK_BODY_BYTES: u64 = 32 * 1_024 * 1_024;
/// Maximum retention duration for authenticated raw webhook evidence.
pub const MAX_PROVIDER_RAW_WEBHOOK_RETENTION_MILLIS: u64 = 365 * 24 * 60 * 60 * 1_000;
/// Maximum selected headers passed to a delivery adapter.
pub const MAX_PROVIDER_WEBHOOK_HEADERS: usize = 32;
/// Maximum bytes in one selected header name.
pub const MAX_PROVIDER_WEBHOOK_HEADER_NAME_BYTES: usize = 64;
/// Maximum bytes in one selected header value.
pub const MAX_PROVIDER_WEBHOOK_HEADER_VALUE_BYTES: usize = 4 * 1_024;
/// Maximum total selected header bytes.
pub const MAX_PROVIDER_WEBHOOK_HEADER_BYTES: usize = 16 * 1_024;
/// Maximum simultaneous secret generations accepted by one endpoint.
pub const MAX_PROVIDER_WEBHOOK_SECRET_CANDIDATES: usize = 4;
/// Maximum canonical adapter observations retained with one delivery.
pub const MAX_PROVIDER_DELIVERY_OBSERVATION_BYTES: usize = 16 * 1_024;
/// Media type used for exact authenticated raw webhook bodies.
pub const PROVIDER_RAW_WEBHOOK_MEDIA_TYPE: &str = "application/vnd.automata.provider-webhook-body";
/// Content-addressed object-key prefix for authenticated webhook bodies.
pub const PROVIDER_RAW_WEBHOOK_KEY_PREFIX: &str = "provider-deliveries/raw/sha256";

const MAX_SIGNATURE_SCHEME_BYTES: usize = 64;
const MAX_DELIVERY_ADAPTERS: usize = 32;

/// Positive monotonic revision of one opaque endpoint.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ProviderWebhookEndpointRevision(NonZeroU64);

impl ProviderWebhookEndpointRevision {
    /// Creates a positive revision representable by `PostgreSQL BIGINT`.
    ///
    /// # Errors
    ///
    /// Rejects zero or a value beyond the signed durable range.
    pub const fn new(value: u64) -> Result<Self, ProviderWebhookError> {
        match NonZeroU64::new(value) {
            Some(value) if value.get() <= i64::MAX as u64 => Ok(Self(value)),
            _ => Err(ProviderWebhookError::InvalidEndpointRevision),
        }
    }

    /// Returns the durable positive revision.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0.get()
    }
}

/// Lifecycle of one public webhook endpoint.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum ProviderWebhookEndpointState {
    /// Requests may be authenticated and normalized.
    Active,
    /// The endpoint remains durable but rejects all requests.
    Disabled,
    /// The endpoint is terminal and cannot be reactivated.
    Retired,
}

/// Exact named secret generation eligible for signature verification.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ProviderWebhookSecretReference {
    configuration_revision: ProviderConfigurationRevision,
    name: ProviderSecretName,
    generation: ProviderSecretGeneration,
}

impl ProviderWebhookSecretReference {
    /// Binds a canonical secret name to one exact generation.
    #[must_use]
    pub const fn new(
        configuration_revision: ProviderConfigurationRevision,
        name: ProviderSecretName,
        generation: ProviderSecretGeneration,
    ) -> Self {
        Self {
            configuration_revision,
            name,
            generation,
        }
    }

    /// Returns the exact instance revision that owns the encrypted record.
    #[must_use]
    pub const fn configuration_revision(&self) -> ProviderConfigurationRevision {
        self.configuration_revision
    }

    /// Returns the logical secret name.
    #[must_use]
    pub const fn name(&self) -> &ProviderSecretName {
        &self.name
    }

    /// Returns the exact eligible generation.
    #[must_use]
    pub const fn generation(&self) -> ProviderSecretGeneration {
        self.generation
    }
}

/// Immutable connection-bound webhook endpoint revision.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProviderWebhookEndpointManifest {
    endpoint_id: ProviderWebhookEndpointId,
    revision: ProviderWebhookEndpointRevision,
    state: ProviderWebhookEndpointState,
    provider_type: ProviderTypeId,
    instance_id: ProviderInstanceId,
    provider_revision: ProviderConfigurationRevision,
    connection_id: ProviderConnectionId,
    connection_revision: ProviderConnectionRevision,
    body_limit: NonZeroU64,
    raw_retention_millis: NonZeroU64,
    secret_references: Vec<ProviderWebhookSecretReference>,
    created_at: UnixMillis,
    retired_at: Option<UnixMillis>,
}

impl ProviderWebhookEndpointManifest {
    /// Constructs one exact endpoint routing and verification policy revision.
    ///
    /// # Errors
    ///
    /// Rejects invalid time evidence, body limits, empty/duplicate/excessive
    /// secret references, or inconsistent retirement state.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        endpoint_id: ProviderWebhookEndpointId,
        revision: ProviderWebhookEndpointRevision,
        state: ProviderWebhookEndpointState,
        provider_type: ProviderTypeId,
        instance_id: ProviderInstanceId,
        provider_revision: ProviderConfigurationRevision,
        connection_id: ProviderConnectionId,
        connection_revision: ProviderConnectionRevision,
        body_limit: u64,
        raw_retention_millis: u64,
        mut secret_references: Vec<ProviderWebhookSecretReference>,
        created_at: UnixMillis,
        retired_at: Option<UnixMillis>,
    ) -> Result<Self, ProviderWebhookError> {
        let body_limit = NonZeroU64::new(body_limit)
            .filter(|value| value.get() <= MAX_PROVIDER_WEBHOOK_BODY_BYTES)
            .ok_or(ProviderWebhookError::InvalidBodyLimit)?;
        let raw_retention_millis = NonZeroU64::new(raw_retention_millis)
            .filter(|value| value.get() <= MAX_PROVIDER_RAW_WEBHOOK_RETENTION_MILLIS)
            .ok_or(ProviderWebhookError::InvalidRawRetention)?;
        secret_references.sort();
        if secret_references.is_empty()
            || secret_references.len() > MAX_PROVIDER_WEBHOOK_SECRET_CANDIDATES
        {
            return Err(ProviderWebhookError::InvalidSecretCandidates);
        }
        if secret_references.windows(2).any(|pair| pair[0] == pair[1]) {
            return Err(ProviderWebhookError::DuplicateSecretCandidate);
        }
        if created_at.get() < 0
            || retired_at.is_some_and(|value| value.get() < created_at.get())
            || (state == ProviderWebhookEndpointState::Retired) != retired_at.is_some()
        {
            return Err(ProviderWebhookError::InvalidEndpointLifecycle);
        }
        Ok(Self {
            endpoint_id,
            revision,
            state,
            provider_type,
            instance_id,
            provider_revision,
            connection_id,
            connection_revision,
            body_limit,
            raw_retention_millis,
            secret_references,
            created_at,
            retired_at,
        })
    }

    /// Returns the unguessable public endpoint identity.
    #[must_use]
    pub const fn endpoint_id(&self) -> ProviderWebhookEndpointId {
        self.endpoint_id
    }

    /// Returns the endpoint revision.
    #[must_use]
    pub const fn revision(&self) -> ProviderWebhookEndpointRevision {
        self.revision
    }

    /// Returns endpoint lifecycle state.
    #[must_use]
    pub const fn state(&self) -> ProviderWebhookEndpointState {
        self.state
    }

    /// Returns the exact delivery adapter registry key.
    #[must_use]
    pub const fn provider_type(&self) -> &ProviderTypeId {
        &self.provider_type
    }

    /// Returns the configured provider instance.
    #[must_use]
    pub const fn instance_id(&self) -> ProviderInstanceId {
        self.instance_id
    }

    /// Returns the exact provider configuration revision used by the adapter.
    #[must_use]
    pub const fn provider_revision(&self) -> ProviderConfigurationRevision {
        self.provider_revision
    }

    /// Returns the only connection allowed to use this endpoint.
    #[must_use]
    pub const fn connection_id(&self) -> ProviderConnectionId {
        self.connection_id
    }

    /// Returns the exact connection policy revision bound to ingress.
    #[must_use]
    pub const fn connection_revision(&self) -> ProviderConnectionRevision {
        self.connection_revision
    }

    /// Returns the exact body byte limit applied before adapter invocation.
    #[must_use]
    pub const fn body_limit(&self) -> u64 {
        self.body_limit.get()
    }

    /// Returns how long authenticated raw evidence must remain available.
    #[must_use]
    pub const fn raw_retention_millis(&self) -> u64 {
        self.raw_retention_millis.get()
    }

    /// Returns the bounded exact secret generations eligible for verification.
    #[must_use]
    pub fn secret_references(&self) -> &[ProviderWebhookSecretReference] {
        &self.secret_references
    }

    /// Returns endpoint creation evidence.
    #[must_use]
    pub const fn created_at(&self) -> UnixMillis {
        self.created_at
    }

    /// Returns terminal retirement evidence.
    #[must_use]
    pub const fn retired_at(&self) -> Option<UnixMillis> {
        self.retired_at
    }

    /// Validates a changed contiguous endpoint revision.
    ///
    /// # Errors
    ///
    /// Rejects identity rebinding, reactivation after retirement, time drift,
    /// noncontiguous revisions, or an exact no-op.
    pub fn validate_successor(&self, prior: &Self) -> Result<(), ProviderWebhookError> {
        let next = prior
            .revision
            .get()
            .checked_add(1)
            .ok_or(ProviderWebhookError::InvalidEndpointSuccessor)?;
        if self.endpoint_id != prior.endpoint_id
            || self.revision.get() != next
            || self.provider_type != prior.provider_type
            || self.instance_id != prior.instance_id
            || self.connection_id != prior.connection_id
            || self.created_at != prior.created_at
            || prior.state == ProviderWebhookEndpointState::Retired
            || (self.state == prior.state
                && self.provider_revision == prior.provider_revision
                && self.connection_revision == prior.connection_revision
                && self.body_limit == prior.body_limit
                && self.raw_retention_millis == prior.raw_retention_millis
                && self.secret_references == prior.secret_references
                && self.retired_at == prior.retired_at)
        {
            return Err(ProviderWebhookError::InvalidEndpointSuccessor);
        }
        Ok(())
    }
}

/// One move-only plaintext webhook verification candidate.
pub struct ProviderWebhookSecretCandidate {
    reference: ProviderWebhookSecretReference,
    value: SecretBytes,
}

impl ProviderWebhookSecretCandidate {
    /// Returns the exact named generation without exposing plaintext.
    #[must_use]
    pub const fn reference(&self) -> &ProviderWebhookSecretReference {
        &self.reference
    }

    /// Explicitly exposes secret bytes only at the authentication boundary.
    #[must_use]
    pub fn expose_secret(&self) -> &[u8] {
        self.value.expose_secret()
    }
}

impl fmt::Debug for ProviderWebhookSecretCandidate {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProviderWebhookSecretCandidate")
            .field("reference", &self.reference)
            .field("value", &"[REDACTED]")
            .finish()
    }
}

/// Exact plaintext candidate set resolved for one endpoint request.
pub struct ProviderWebhookSecretCandidates {
    endpoint_id: ProviderWebhookEndpointId,
    endpoint_revision: ProviderWebhookEndpointRevision,
    instance_id: ProviderInstanceId,
    candidates: Vec<ProviderWebhookSecretCandidate>,
}

impl ProviderWebhookSecretCandidates {
    /// Binds move-only plaintext values to the endpoint's exact candidate list.
    ///
    /// # Errors
    ///
    /// Rejects any missing, unexpected, duplicate, or reordered generation.
    pub fn new(
        endpoint: &ProviderWebhookEndpointManifest,
        secrets: impl IntoIterator<Item = (ProviderConfigurationRevision, ProviderSecret)>,
    ) -> Result<Self, ProviderWebhookError> {
        let mut candidates = Vec::new();
        for (configuration_revision, secret) in secrets {
            let (name, generation, value) = secret.into_parts();
            candidates.push(ProviderWebhookSecretCandidate {
                reference: ProviderWebhookSecretReference::new(
                    configuration_revision,
                    name,
                    generation,
                ),
                value,
            });
        }
        candidates.sort_by(|left, right| left.reference.cmp(&right.reference));
        if candidates.len() != endpoint.secret_references.len()
            || candidates
                .iter()
                .zip(&endpoint.secret_references)
                .any(|(candidate, expected)| candidate.reference != *expected)
        {
            return Err(ProviderWebhookError::InvalidSecretCandidates);
        }
        Ok(Self {
            endpoint_id: endpoint.endpoint_id(),
            endpoint_revision: endpoint.revision(),
            instance_id: endpoint.instance_id(),
            candidates,
        })
    }

    /// Returns candidates in canonical name/generation order.
    pub fn iter(&self) -> impl ExactSizeIterator<Item = &ProviderWebhookSecretCandidate> {
        self.candidates.iter()
    }
}

impl fmt::Debug for ProviderWebhookSecretCandidates {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProviderWebhookSecretCandidates")
            .field("endpoint_id", &self.endpoint_id)
            .field("endpoint_revision", &self.endpoint_revision)
            .field("instance_id", &self.instance_id)
            .field(
                "references",
                &self
                    .candidates
                    .iter()
                    .map(ProviderWebhookSecretCandidate::reference)
                    .collect::<Vec<_>>(),
            )
            .finish()
    }
}

/// Exact endpoint request and its endpoint-bound secret custody.
pub struct ProviderWebhookAuthenticationRequest {
    request: ProviderWebhookRequest,
    candidates: ProviderWebhookSecretCandidates,
}

impl fmt::Debug for ProviderWebhookAuthenticationRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProviderWebhookAuthenticationRequest")
            .field("request", &self.request)
            .field("candidates", &self.candidates)
            .finish()
    }
}

impl ProviderWebhookAuthenticationRequest {
    /// Binds raw request bytes to candidates resolved from the same endpoint record.
    ///
    /// # Errors
    ///
    /// Rejects candidates from another endpoint, revision, or provider instance.
    pub fn new(
        request: ProviderWebhookRequest,
        candidates: ProviderWebhookSecretCandidates,
    ) -> Result<Self, ProviderWebhookError> {
        let endpoint = request.endpoint();
        if candidates.endpoint_id != endpoint.endpoint_id()
            || candidates.endpoint_revision != endpoint.revision()
            || candidates.instance_id != endpoint.instance_id()
        {
            return Err(ProviderWebhookError::SecretCandidateEndpointMismatch);
        }
        Ok(Self {
            request,
            candidates,
        })
    }

    /// Returns exact raw request evidence.
    #[must_use]
    pub const fn request(&self) -> &ProviderWebhookRequest {
        &self.request
    }

    /// Returns the only eligible endpoint-bound secret candidates.
    #[must_use]
    pub const fn candidates(&self) -> &ProviderWebhookSecretCandidates {
        &self.candidates
    }

    /// Consumes the authentication input after a candidate verifies.
    #[must_use]
    pub fn into_request(self) -> ProviderWebhookRequest {
        self.request
    }
}

/// Canonical lower-case HTTP header name selected for an adapter.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ProviderWebhookHeaderName(String);

impl ProviderWebhookHeaderName {
    /// Validates an ASCII HTTP token in canonical lower-case form.
    ///
    /// # Errors
    ///
    /// Rejects empty, oversized, uppercase, or non-token names.
    pub fn new(value: impl Into<String>) -> Result<Self, ProviderWebhookError> {
        let value = value.into();
        if value.is_empty()
            || value.len() > MAX_PROVIDER_WEBHOOK_HEADER_NAME_BYTES
            || !value.bytes().all(|byte| {
                byte.is_ascii_lowercase()
                    || byte.is_ascii_digit()
                    || matches!(
                        byte,
                        b'!' | b'#'
                            | b'$'
                            | b'%'
                            | b'&'
                            | b'\''
                            | b'*'
                            | b'+'
                            | b'-'
                            | b'.'
                            | b'^'
                            | b'_'
                            | b'`'
                            | b'|'
                            | b'~'
                    )
            })
        {
            return Err(ProviderWebhookError::InvalidHeaderName);
        }
        Ok(Self(value))
    }

    /// Returns the canonical header name.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Bounded exact selected HTTP headers.
#[derive(Clone, Eq, PartialEq)]
pub struct ProviderWebhookHeaders(BTreeMap<ProviderWebhookHeaderName, Vec<u8>>);

impl ProviderWebhookHeaders {
    /// Builds a duplicate-free selected header set.
    ///
    /// # Errors
    ///
    /// Rejects excessive counts or bytes, duplicate names, or values containing
    /// CR, LF, NUL, or other controls except horizontal tab.
    pub fn new(
        headers: impl IntoIterator<Item = (ProviderWebhookHeaderName, Vec<u8>)>,
    ) -> Result<Self, ProviderWebhookError> {
        let mut selected = BTreeMap::new();
        let mut total = 0usize;
        for (name, value) in headers {
            if selected.len() == MAX_PROVIDER_WEBHOOK_HEADERS {
                return Err(ProviderWebhookError::TooManyHeaders);
            }
            if value.len() > MAX_PROVIDER_WEBHOOK_HEADER_VALUE_BYTES
                || value
                    .iter()
                    .any(|byte| (*byte < 0x20 && *byte != b'\t') || *byte == 0x7f)
            {
                return Err(ProviderWebhookError::InvalidHeaderValue);
            }
            total = total
                .checked_add(name.as_str().len() + value.len())
                .ok_or(ProviderWebhookError::HeadersTooLarge)?;
            if total > MAX_PROVIDER_WEBHOOK_HEADER_BYTES {
                return Err(ProviderWebhookError::HeadersTooLarge);
            }
            if selected.insert(name, value).is_some() {
                return Err(ProviderWebhookError::DuplicateHeader);
            }
        }
        Ok(Self(selected))
    }

    /// Returns one exact selected value.
    #[must_use]
    pub fn get(&self, name: &ProviderWebhookHeaderName) -> Option<&[u8]> {
        self.0.get(name).map(Vec::as_slice)
    }

    /// Iterates selected headers in canonical name order.
    pub fn iter(&self) -> impl ExactSizeIterator<Item = (&ProviderWebhookHeaderName, &[u8])> {
        self.0.iter().map(|(name, value)| (name, value.as_slice()))
    }
}

impl fmt::Debug for ProviderWebhookHeaders {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProviderWebhookHeaders")
            .field("names", &self.0.keys().collect::<Vec<_>>())
            .field("values", &"[REDACTED]")
            .finish()
    }
}

/// Exact webhook method accepted by the public route.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum ProviderWebhookMethod {
    /// HTTP `POST`.
    Post,
}

/// Bounded raw request passed to a delivery adapter before payload parsing.
pub struct ProviderWebhookRequest {
    endpoint: ProviderWebhookEndpointManifest,
    connection: ProviderConnectionManifest,
    method: ProviderWebhookMethod,
    headers: ProviderWebhookHeaders,
    body: Vec<u8>,
    body_digest: Sha256Digest,
    received_at: UnixMillis,
}

impl ProviderWebhookRequest {
    /// Constructs an exact request after endpoint lookup and ingress limits.
    ///
    /// # Errors
    ///
    /// Rejects disabled endpoints, mismatched connection policy, excessive body
    /// bytes, or pre-epoch receipt time.
    pub fn new(
        endpoint: ProviderWebhookEndpointManifest,
        connection: ProviderConnectionManifest,
        method: ProviderWebhookMethod,
        headers: ProviderWebhookHeaders,
        body: Vec<u8>,
        received_at: UnixMillis,
    ) -> Result<Self, ProviderWebhookError> {
        if endpoint.state() != ProviderWebhookEndpointState::Active {
            return Err(ProviderWebhookError::EndpointInactive);
        }
        let configuration = connection.configuration();
        if connection.connection_id() != endpoint.connection_id()
            || connection.revision() != endpoint.connection_revision()
            || connection.state() != ProviderLifecycleState::Active
            || configuration.repository().instance_id() != endpoint.instance_id()
            || configuration.provider_revision() != endpoint.provider_revision()
        {
            return Err(ProviderWebhookError::EndpointConnectionMismatch);
        }
        if body.len() as u64 > endpoint.body_limit() {
            return Err(ProviderWebhookError::BodyTooLarge);
        }
        if received_at.get() < 0 {
            return Err(ProviderWebhookError::InvalidReceivedTime);
        }
        let body_digest = Sha256Digest::from_bytes(Sha256::digest(&body).into());
        Ok(Self {
            endpoint,
            connection,
            method,
            headers,
            body,
            body_digest,
            received_at,
        })
    }

    /// Returns the resolved endpoint binding.
    #[must_use]
    pub const fn endpoint(&self) -> &ProviderWebhookEndpointManifest {
        &self.endpoint
    }

    /// Returns the exact connection and adapter policy bound to this endpoint.
    #[must_use]
    pub const fn connection(&self) -> &ProviderConnectionManifest {
        &self.connection
    }

    /// Returns the exact request method.
    #[must_use]
    pub const fn method(&self) -> ProviderWebhookMethod {
        self.method
    }

    /// Returns selected bounded headers.
    #[must_use]
    pub const fn headers(&self) -> &ProviderWebhookHeaders {
        &self.headers
    }

    /// Returns exact raw body bytes. Adapters must authenticate these before parsing.
    #[must_use]
    pub fn body(&self) -> &[u8] {
        &self.body
    }

    /// Returns the exact raw-body SHA-256 digest.
    #[must_use]
    pub const fn body_digest(&self) -> Sha256Digest {
        self.body_digest
    }

    /// Returns trusted ingress receipt time.
    #[must_use]
    pub const fn received_at(&self) -> UnixMillis {
        self.received_at
    }
}

impl fmt::Debug for ProviderWebhookRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProviderWebhookRequest")
            .field("endpoint", &self.endpoint)
            .field("connection", &self.connection)
            .field("method", &self.method)
            .field("headers", &self.headers)
            .field("body", &"[REDACTED]")
            .field("body_length", &self.body.len())
            .field("body_digest", &self.body_digest)
            .field("received_at", &self.received_at)
            .finish()
    }
}

/// Authenticated signature scheme and exact accepted secret generation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProviderWebhookSignatureEvidence {
    scheme: String,
    secret: ProviderWebhookSecretReference,
}

impl ProviderWebhookSignatureEvidence {
    /// Constructs bounded, non-secret verification evidence.
    ///
    /// # Errors
    ///
    /// Rejects a noncanonical signature-scheme identifier.
    pub fn new(
        scheme: impl Into<String>,
        secret: ProviderWebhookSecretReference,
    ) -> Result<Self, ProviderWebhookError> {
        let scheme = scheme.into();
        if scheme.is_empty()
            || scheme.len() > MAX_SIGNATURE_SCHEME_BYTES
            || !scheme.bytes().all(|byte| {
                byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'-' | b'_')
            })
        {
            return Err(ProviderWebhookError::InvalidSignatureScheme);
        }
        Ok(Self { scheme, secret })
    }

    /// Returns the canonical adapter-owned signature scheme.
    #[must_use]
    pub fn scheme(&self) -> &str {
        &self.scheme
    }

    /// Returns the exact secret generation that verified the body.
    #[must_use]
    pub const fn secret(&self) -> &ProviderWebhookSecretReference {
        &self.secret
    }
}

/// Request typestate proving the raw body was authenticated before parsing.
pub struct AuthenticatedProviderWebhook {
    request: ProviderWebhookRequest,
    signature: ProviderWebhookSignatureEvidence,
}

impl AuthenticatedProviderWebhook {
    /// Marks a request authenticated by an eligible endpoint secret generation.
    ///
    /// This constructor is intended only for trusted adapter implementations,
    /// after constant-time verification over [`ProviderWebhookRequest::body`].
    ///
    /// # Errors
    ///
    /// Rejects signature evidence not selected by the endpoint revision.
    pub fn new(
        request: ProviderWebhookRequest,
        signature: ProviderWebhookSignatureEvidence,
    ) -> Result<Self, ProviderWebhookError> {
        if !request
            .endpoint()
            .secret_references()
            .contains(signature.secret())
        {
            return Err(ProviderWebhookError::UnexpectedVerifiedSecret);
        }
        Ok(Self { request, signature })
    }

    /// Returns the authenticated request for post-verification parsing.
    #[must_use]
    pub const fn request(&self) -> &ProviderWebhookRequest {
        &self.request
    }

    /// Returns non-secret signature evidence.
    #[must_use]
    pub const fn signature(&self) -> &ProviderWebhookSignatureEvidence {
        &self.signature
    }
}

impl fmt::Debug for AuthenticatedProviderWebhook {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AuthenticatedProviderWebhook")
            .field("request", &self.request)
            .field("signature", &self.signature)
            .finish()
    }
}

/// Bounded canonical, non-secret adapter observations used to audit normalization.
#[derive(Clone, Eq, PartialEq)]
pub struct ProviderDeliveryObservations {
    canonical_bytes: Vec<u8>,
    digest: Sha256Digest,
}

impl ProviderDeliveryObservations {
    /// Stores exact canonical adapter bytes.
    ///
    /// # Errors
    ///
    /// Rejects oversized observations.
    pub fn new(canonical_bytes: Vec<u8>) -> Result<Self, ProviderWebhookError> {
        if canonical_bytes.len() > MAX_PROVIDER_DELIVERY_OBSERVATION_BYTES {
            return Err(ProviderWebhookError::ObservationsTooLarge);
        }
        let digest = Sha256Digest::from_bytes(Sha256::digest(&canonical_bytes).into());
        Ok(Self {
            canonical_bytes,
            digest,
        })
    }

    /// Returns exact canonical observation bytes.
    #[must_use]
    pub fn canonical_bytes(&self) -> &[u8] {
        &self.canonical_bytes
    }

    /// Returns the observations digest.
    #[must_use]
    pub const fn digest(&self) -> Sha256Digest {
        self.digest
    }
}

impl fmt::Debug for ProviderDeliveryObservations {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProviderDeliveryObservations")
            .field("canonical_bytes", &"[CANONICAL]")
            .field("byte_length", &self.canonical_bytes.len())
            .field("digest", &self.digest)
            .finish()
    }
}

/// Authenticated and normalized delivery awaiting immutable raw-body storage.
#[derive(Debug)]
pub struct ProviderDeliveryDraft {
    delivery_id: ProviderDeliveryId,
    external_delivery: ExternalDeliveryIdentity,
    event_type: ProviderEventName,
    authenticated: AuthenticatedProviderWebhook,
    trigger: SealedNormalizedTrigger,
    observations: ProviderDeliveryObservations,
}

/// Authenticated non-admission delivery awaiting immutable raw-body storage.
#[derive(Debug)]
pub struct RejectedProviderDeliveryDraft {
    delivery_id: ProviderDeliveryId,
    external_delivery: ExternalDeliveryIdentity,
    event_type: ProviderEventName,
    authenticated: AuthenticatedProviderWebhook,
    repository: Option<ExternalRepositoryIdentity>,
    reason: ProviderDeliveryRejection,
    observations: ProviderDeliveryObservations,
}

impl RejectedProviderDeliveryDraft {
    /// Constructs a bounded authenticated rejection record.
    ///
    /// # Errors
    ///
    /// Rejects delivery or optional repository evidence from another instance.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        delivery_id: ProviderDeliveryId,
        external_delivery: ExternalDeliveryIdentity,
        event_type: ProviderEventName,
        authenticated: AuthenticatedProviderWebhook,
        repository: Option<ExternalRepositoryIdentity>,
        reason: ProviderDeliveryRejection,
        observations: ProviderDeliveryObservations,
    ) -> Result<Self, ProviderWebhookError> {
        let instance_id = authenticated.request().endpoint().instance_id();
        if external_delivery.instance_id() != instance_id
            || repository
                .as_ref()
                .is_some_and(|value| value.instance_id() != instance_id)
        {
            return Err(ProviderWebhookError::PayloadIdentityMismatch);
        }
        Ok(Self {
            delivery_id,
            external_delivery,
            event_type,
            authenticated,
            repository,
            reason,
            observations,
        })
    }
}

impl ProviderDeliveryDraft {
    /// Binds adapter output to exact endpoint, instance, and repository evidence.
    ///
    /// # Errors
    ///
    /// Rejects cross-instance delivery or normalized repository identities.
    pub fn new(
        delivery_id: ProviderDeliveryId,
        external_delivery: ExternalDeliveryIdentity,
        event_type: ProviderEventName,
        authenticated: AuthenticatedProviderWebhook,
        trigger: &NormalizedTrigger,
        observations: ProviderDeliveryObservations,
    ) -> Result<Self, ProviderWebhookError> {
        let endpoint_instance = authenticated.request().endpoint().instance_id();
        if external_delivery.instance_id() != endpoint_instance
            || trigger.target_repository().identity().instance_id() != endpoint_instance
        {
            return Err(ProviderWebhookError::PayloadIdentityMismatch);
        }
        let trigger = trigger.seal().map_err(ProviderWebhookError::Trigger)?;
        Ok(Self {
            delivery_id,
            external_delivery,
            event_type,
            authenticated,
            trigger,
            observations,
        })
    }
}

/// Complete verified delivery with immutable raw-body evidence.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedProviderDelivery {
    delivery_id: ProviderDeliveryId,
    endpoint_id: ProviderWebhookEndpointId,
    endpoint_revision: ProviderWebhookEndpointRevision,
    provider_type: ProviderTypeId,
    instance_id: ProviderInstanceId,
    provider_revision: ProviderConfigurationRevision,
    connection_id: ProviderConnectionId,
    connection_revision: ProviderConnectionRevision,
    external_delivery: ExternalDeliveryIdentity,
    event_type: ProviderEventName,
    received_at: UnixMillis,
    raw_body: BlobDescriptor,
    raw_retain_until: UnixMillis,
    signature: ProviderWebhookSignatureEvidence,
    trigger: SealedNormalizedTrigger,
    observations: ProviderDeliveryObservations,
}

impl VerifiedProviderDelivery {
    /// Rehydrates complete durable verified-delivery evidence.
    ///
    /// # Errors
    ///
    /// Rejects cross-instance identities, negative receipt time, or a raw object
    /// descriptor that is not the canonical content-addressed representation.
    #[allow(clippy::too_many_arguments)]
    pub fn rehydrate(
        delivery_id: ProviderDeliveryId,
        endpoint_id: ProviderWebhookEndpointId,
        endpoint_revision: ProviderWebhookEndpointRevision,
        provider_type: ProviderTypeId,
        instance_id: ProviderInstanceId,
        provider_revision: ProviderConfigurationRevision,
        connection_id: ProviderConnectionId,
        connection_revision: ProviderConnectionRevision,
        external_delivery: ExternalDeliveryIdentity,
        event_type: ProviderEventName,
        received_at: UnixMillis,
        raw_body: BlobDescriptor,
        raw_retain_until: UnixMillis,
        signature: ProviderWebhookSignatureEvidence,
        trigger: SealedNormalizedTrigger,
        observations: ProviderDeliveryObservations,
    ) -> Result<Self, ProviderWebhookError> {
        validate_durable_evidence(
            instance_id,
            &external_delivery,
            received_at,
            &raw_body,
            raw_retain_until,
        )?;
        if trigger
            .trigger()
            .target_repository()
            .identity()
            .instance_id()
            != instance_id
        {
            return Err(ProviderWebhookError::PayloadIdentityMismatch);
        }
        Ok(Self {
            delivery_id,
            endpoint_id,
            endpoint_revision,
            provider_type,
            instance_id,
            provider_revision,
            connection_id,
            connection_revision,
            external_delivery,
            event_type,
            received_at,
            raw_body,
            raw_retain_until,
            signature,
            trigger,
            observations,
        })
    }

    /// Seals normalized output against an immutable content-addressed raw body.
    ///
    /// # Errors
    ///
    /// Rejects a raw descriptor whose digest, size, media type, or key differs
    /// from the authenticated request.
    pub fn seal(
        draft: ProviderDeliveryDraft,
        raw_body: BlobDescriptor,
    ) -> Result<Self, ProviderWebhookError> {
        validate_raw_descriptor(draft.authenticated.request(), &raw_body)?;
        let endpoint = draft.authenticated.request().endpoint();
        let raw_retain_until = retention_deadline(
            draft.authenticated.request().received_at(),
            endpoint.raw_retention_millis(),
        )?;
        Ok(Self {
            delivery_id: draft.delivery_id,
            endpoint_id: endpoint.endpoint_id(),
            endpoint_revision: endpoint.revision(),
            provider_type: endpoint.provider_type().clone(),
            instance_id: endpoint.instance_id(),
            provider_revision: endpoint.provider_revision(),
            connection_id: endpoint.connection_id(),
            connection_revision: endpoint.connection_revision(),
            external_delivery: draft.external_delivery,
            event_type: draft.event_type,
            received_at: draft.authenticated.request().received_at(),
            raw_body,
            raw_retain_until,
            signature: draft.authenticated.signature().clone(),
            trigger: draft.trigger,
            observations: draft.observations,
        })
    }

    /// Returns the durable server-owned delivery identity.
    #[must_use]
    pub const fn delivery_id(&self) -> ProviderDeliveryId {
        self.delivery_id
    }

    /// Returns the exact public endpoint used for ingress.
    #[must_use]
    pub const fn endpoint_id(&self) -> ProviderWebhookEndpointId {
        self.endpoint_id
    }

    /// Returns endpoint policy revision used for authentication.
    #[must_use]
    pub const fn endpoint_revision(&self) -> ProviderWebhookEndpointRevision {
        self.endpoint_revision
    }

    /// Returns the exact provider adapter type.
    #[must_use]
    pub const fn provider_type(&self) -> &ProviderTypeId {
        &self.provider_type
    }

    /// Returns the configured provider instance.
    #[must_use]
    pub const fn instance_id(&self) -> ProviderInstanceId {
        self.instance_id
    }

    /// Returns the exact provider configuration revision used for normalization.
    #[must_use]
    pub const fn provider_revision(&self) -> ProviderConfigurationRevision {
        self.provider_revision
    }

    /// Returns the endpoint-bound connection.
    #[must_use]
    pub const fn connection_id(&self) -> ProviderConnectionId {
        self.connection_id
    }

    /// Returns the exact endpoint-bound connection policy revision.
    #[must_use]
    pub const fn connection_revision(&self) -> ProviderConnectionRevision {
        self.connection_revision
    }

    /// Returns instance-scoped provider replay identity.
    #[must_use]
    pub const fn external_delivery(&self) -> &ExternalDeliveryIdentity {
        &self.external_delivery
    }

    /// Returns provider-native event-name evidence.
    #[must_use]
    pub const fn event_type(&self) -> &ProviderEventName {
        &self.event_type
    }

    /// Returns trusted ingress receipt time.
    #[must_use]
    pub const fn received_at(&self) -> UnixMillis {
        self.received_at
    }

    /// Returns immutable raw request-body evidence.
    #[must_use]
    pub const fn raw_body(&self) -> &BlobDescriptor {
        &self.raw_body
    }

    /// Returns the inclusive raw-evidence retention deadline.
    #[must_use]
    pub const fn raw_retain_until(&self) -> UnixMillis {
        self.raw_retain_until
    }

    /// Returns signature scheme and accepted generation evidence.
    #[must_use]
    pub const fn signature(&self) -> &ProviderWebhookSignatureEvidence {
        &self.signature
    }

    /// Returns the strongly typed normalized trigger.
    #[must_use]
    pub const fn trigger(&self) -> &SealedNormalizedTrigger {
        &self.trigger
    }

    /// Returns bounded adapter audit observations.
    #[must_use]
    pub const fn observations(&self) -> &ProviderDeliveryObservations {
        &self.observations
    }
}

/// Complete authenticated rejection with immutable raw-body evidence.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RejectedProviderDelivery {
    delivery_id: ProviderDeliveryId,
    endpoint_id: ProviderWebhookEndpointId,
    endpoint_revision: ProviderWebhookEndpointRevision,
    provider_type: ProviderTypeId,
    instance_id: ProviderInstanceId,
    provider_revision: ProviderConfigurationRevision,
    connection_id: ProviderConnectionId,
    connection_revision: ProviderConnectionRevision,
    external_delivery: ExternalDeliveryIdentity,
    event_type: ProviderEventName,
    received_at: UnixMillis,
    raw_body: BlobDescriptor,
    raw_retain_until: UnixMillis,
    signature: ProviderWebhookSignatureEvidence,
    repository: Option<ExternalRepositoryIdentity>,
    reason: ProviderDeliveryRejection,
    observations: ProviderDeliveryObservations,
}

impl RejectedProviderDelivery {
    /// Rehydrates complete durable authenticated rejection evidence.
    ///
    /// # Errors
    ///
    /// Rejects cross-instance identities, negative receipt time, or a noncanonical
    /// immutable raw object descriptor.
    #[allow(clippy::too_many_arguments)]
    pub fn rehydrate(
        delivery_id: ProviderDeliveryId,
        endpoint_id: ProviderWebhookEndpointId,
        endpoint_revision: ProviderWebhookEndpointRevision,
        provider_type: ProviderTypeId,
        instance_id: ProviderInstanceId,
        provider_revision: ProviderConfigurationRevision,
        connection_id: ProviderConnectionId,
        connection_revision: ProviderConnectionRevision,
        external_delivery: ExternalDeliveryIdentity,
        event_type: ProviderEventName,
        received_at: UnixMillis,
        raw_body: BlobDescriptor,
        raw_retain_until: UnixMillis,
        signature: ProviderWebhookSignatureEvidence,
        repository: Option<ExternalRepositoryIdentity>,
        reason: ProviderDeliveryRejection,
        observations: ProviderDeliveryObservations,
    ) -> Result<Self, ProviderWebhookError> {
        validate_durable_evidence(
            instance_id,
            &external_delivery,
            received_at,
            &raw_body,
            raw_retain_until,
        )?;
        if repository
            .as_ref()
            .is_some_and(|value| value.instance_id() != instance_id)
        {
            return Err(ProviderWebhookError::PayloadIdentityMismatch);
        }
        Ok(Self {
            delivery_id,
            endpoint_id,
            endpoint_revision,
            provider_type,
            instance_id,
            provider_revision,
            connection_id,
            connection_revision,
            external_delivery,
            event_type,
            received_at,
            raw_body,
            raw_retain_until,
            signature,
            repository,
            reason,
            observations,
        })
    }

    /// Seals an authenticated rejection against immutable raw-body evidence.
    ///
    /// # Errors
    ///
    /// Rejects a descriptor that disagrees with the exact authenticated body.
    pub fn seal(
        draft: RejectedProviderDeliveryDraft,
        raw_body: BlobDescriptor,
    ) -> Result<Self, ProviderWebhookError> {
        validate_raw_descriptor(draft.authenticated.request(), &raw_body)?;
        let endpoint = draft.authenticated.request().endpoint();
        let raw_retain_until = retention_deadline(
            draft.authenticated.request().received_at(),
            endpoint.raw_retention_millis(),
        )?;
        Ok(Self {
            delivery_id: draft.delivery_id,
            endpoint_id: endpoint.endpoint_id(),
            endpoint_revision: endpoint.revision(),
            provider_type: endpoint.provider_type().clone(),
            instance_id: endpoint.instance_id(),
            provider_revision: endpoint.provider_revision(),
            connection_id: endpoint.connection_id(),
            connection_revision: endpoint.connection_revision(),
            external_delivery: draft.external_delivery,
            event_type: draft.event_type,
            received_at: draft.authenticated.request().received_at(),
            raw_body,
            raw_retain_until,
            signature: draft.authenticated.signature().clone(),
            repository: draft.repository,
            reason: draft.reason,
            observations: draft.observations,
        })
    }

    /// Returns the durable server-owned delivery identity.
    #[must_use]
    pub const fn delivery_id(&self) -> ProviderDeliveryId {
        self.delivery_id
    }

    /// Returns the exact public endpoint used for ingress.
    #[must_use]
    pub const fn endpoint_id(&self) -> ProviderWebhookEndpointId {
        self.endpoint_id
    }

    /// Returns the endpoint policy revision used for authentication.
    #[must_use]
    pub const fn endpoint_revision(&self) -> ProviderWebhookEndpointRevision {
        self.endpoint_revision
    }

    /// Returns the exact provider adapter type.
    #[must_use]
    pub const fn provider_type(&self) -> &ProviderTypeId {
        &self.provider_type
    }

    /// Returns the configured provider instance.
    #[must_use]
    pub const fn instance_id(&self) -> ProviderInstanceId {
        self.instance_id
    }

    /// Returns the exact provider configuration revision used for normalization.
    #[must_use]
    pub const fn provider_revision(&self) -> ProviderConfigurationRevision {
        self.provider_revision
    }

    /// Returns the endpoint-bound connection.
    #[must_use]
    pub const fn connection_id(&self) -> ProviderConnectionId {
        self.connection_id
    }

    /// Returns the exact endpoint-bound connection policy revision.
    #[must_use]
    pub const fn connection_revision(&self) -> ProviderConnectionRevision {
        self.connection_revision
    }

    /// Returns instance-scoped provider replay identity.
    #[must_use]
    pub const fn external_delivery(&self) -> &ExternalDeliveryIdentity {
        &self.external_delivery
    }

    /// Returns provider-native event-name evidence.
    #[must_use]
    pub const fn event_type(&self) -> &ProviderEventName {
        &self.event_type
    }

    /// Returns trusted ingress receipt time.
    #[must_use]
    pub const fn received_at(&self) -> UnixMillis {
        self.received_at
    }

    /// Returns immutable raw request-body evidence.
    #[must_use]
    pub const fn raw_body(&self) -> &BlobDescriptor {
        &self.raw_body
    }

    /// Returns the inclusive raw-evidence retention deadline.
    #[must_use]
    pub const fn raw_retain_until(&self) -> UnixMillis {
        self.raw_retain_until
    }

    /// Returns signature scheme and accepted generation evidence.
    #[must_use]
    pub const fn signature(&self) -> &ProviderWebhookSignatureEvidence {
        &self.signature
    }

    /// Returns repository identity when the authenticated shape contained it.
    #[must_use]
    pub const fn repository(&self) -> Option<&ExternalRepositoryIdentity> {
        self.repository.as_ref()
    }

    /// Returns why this event cannot enter admission.
    #[must_use]
    pub const fn reason(&self) -> ProviderDeliveryRejection {
        self.reason
    }

    /// Returns bounded adapter audit observations.
    #[must_use]
    pub const fn observations(&self) -> &ProviderDeliveryObservations {
        &self.observations
    }
}

/// Post-authentication event that was recorded but must not enter admission.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum ProviderDeliveryRejection {
    /// The provider event name is not recognized by this adapter version.
    #[error("provider webhook event is unknown")]
    UnknownEvent,
    /// The event is known but does not represent an admission trigger.
    #[error("provider webhook event is unsupported")]
    UnsupportedEvent,
    /// Required authenticated facts were absent or ambiguous.
    #[error("provider webhook event evidence is incomplete")]
    IncompleteEvent,
    /// Payload repository identity disagreed with endpoint binding.
    #[error("provider webhook payload identity conflicts with its endpoint")]
    PayloadIdentityMismatch,
    /// Authenticated provider bytes were malformed.
    #[error("provider webhook payload is invalid")]
    InvalidPayload,
}

/// Adapter normalization result after successful authentication.
#[derive(Debug)]
pub enum ProviderDeliveryNormalization {
    /// A complete trigger ready for raw evidence storage and durable acceptance.
    Accepted(Box<ProviderDeliveryDraft>),
    /// A sanitized authenticated rejection retained for audit but not admission.
    Rejected(Box<RejectedProviderDeliveryDraft>),
}

impl ProviderDeliveryNormalization {
    /// Returns exact authenticated raw body bytes for immutable object storage.
    #[must_use]
    pub fn raw_body(&self) -> &[u8] {
        match self {
            Self::Accepted(value) => value.authenticated.request().body(),
            Self::Rejected(value) => value.authenticated.request().body(),
        }
    }

    /// Returns the only valid content-addressed descriptor for the raw body.
    ///
    /// # Errors
    ///
    /// Fails only if the static provider raw-evidence blob contract is invalid.
    pub fn raw_descriptor(&self) -> Result<BlobDescriptor, ProviderWebhookError> {
        let request = match self {
            Self::Accepted(value) => value.authenticated.request(),
            Self::Rejected(value) => value.authenticated.request(),
        };
        provider_raw_webhook_descriptor(request.body_digest(), request.body().len() as u64)
    }

    /// Seals either normalized trigger or authenticated rejection after the
    /// caller durably stores exact raw body bytes under `raw_body`.
    ///
    /// # Errors
    ///
    /// Rejects a descriptor inconsistent with the authenticated request.
    pub fn seal(
        self,
        raw_body: BlobDescriptor,
    ) -> Result<crate::ProviderDelivery, ProviderWebhookError> {
        match self {
            Self::Accepted(value) => VerifiedProviderDelivery::seal(*value, raw_body)
                .map(Box::new)
                .map(crate::ProviderDelivery::Trigger),
            Self::Rejected(value) => RejectedProviderDelivery::seal(*value, raw_body)
                .map(Box::new)
                .map(crate::ProviderDelivery::Rejected),
        }
    }
}

/// Provider delivery adapter with an explicit authenticate-before-normalize split.
pub trait DeliveryAdapter: fmt::Debug + Send + Sync {
    /// Returns the unique exact provider type served by this adapter.
    fn provider_type(&self) -> &ProviderTypeId;

    /// Returns the canonical header names ingress may select for this adapter.
    fn selected_header_names(&self) -> &[ProviderWebhookHeaderName];

    /// Authenticates the exact raw body before any JSON or payload decoding.
    ///
    /// # Errors
    ///
    /// Returns a sanitized authentication rejection without retaining raw bytes.
    fn authenticate(
        &self,
        request: ProviderWebhookAuthenticationRequest,
    ) -> Result<AuthenticatedProviderWebhook, ProviderWebhookAuthenticationError>;

    /// Parses and normalizes only an authenticated request typestate.
    fn normalize(
        &self,
        authenticated: AuthenticatedProviderWebhook,
    ) -> ProviderDeliveryNormalization;
}

/// Immutable exact registry of statically linked delivery adapters.
#[derive(Clone)]
pub struct DeliveryAdapterRegistry {
    adapters: BTreeMap<ProviderTypeId, Arc<dyn DeliveryAdapter>>,
}

impl DeliveryAdapterRegistry {
    /// Builds a nonempty bounded duplicate-free adapter registry.
    ///
    /// # Errors
    ///
    /// Rejects empty, oversized, or duplicate provider registrations.
    pub fn new(
        adapters: impl IntoIterator<Item = Arc<dyn DeliveryAdapter>>,
    ) -> Result<Self, DeliveryAdapterRegistryError> {
        let mut registered = BTreeMap::new();
        for adapter in adapters {
            if registered.len() == MAX_DELIVERY_ADAPTERS {
                return Err(DeliveryAdapterRegistryError::TooManyAdapters);
            }
            let headers = adapter.selected_header_names();
            let mut canonical_headers = headers.to_vec();
            canonical_headers.sort();
            if headers.is_empty()
                || headers.len() > MAX_PROVIDER_WEBHOOK_HEADERS
                || canonical_headers.windows(2).any(|pair| pair[0] == pair[1])
            {
                return Err(DeliveryAdapterRegistryError::InvalidHeaderSelection);
            }
            let provider_type = adapter.provider_type().clone();
            if registered.insert(provider_type, adapter).is_some() {
                return Err(DeliveryAdapterRegistryError::DuplicateAdapter);
            }
        }
        if registered.is_empty() {
            return Err(DeliveryAdapterRegistryError::NoAdapters);
        }
        Ok(Self {
            adapters: registered,
        })
    }

    /// Resolves only the exact adapter named by a durable endpoint.
    ///
    /// # Errors
    ///
    /// Fails closed when the exact type is not statically registered.
    pub fn resolve(
        &self,
        endpoint: &ProviderWebhookEndpointManifest,
    ) -> Result<&dyn DeliveryAdapter, DeliveryAdapterRegistryError> {
        self.adapters
            .get(endpoint.provider_type())
            .map(Arc::as_ref)
            .ok_or(DeliveryAdapterRegistryError::UnknownProviderType)
    }

    /// Iterates exact provider types in canonical order.
    pub fn provider_types(&self) -> impl ExactSizeIterator<Item = &ProviderTypeId> {
        self.adapters.keys()
    }
}

impl fmt::Debug for DeliveryAdapterRegistry {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DeliveryAdapterRegistry")
            .field("provider_types", &self.adapters.keys().collect::<Vec<_>>())
            .finish()
    }
}

/// Creates the only valid immutable raw-body descriptor for authenticated bytes.
///
/// # Errors
///
/// Fails only if the statically defined key or media type violates blob contracts.
pub fn provider_raw_webhook_descriptor(
    digest: Sha256Digest,
    size: u64,
) -> Result<BlobDescriptor, ProviderWebhookError> {
    let key = BlobKey::new(format!("{PROVIDER_RAW_WEBHOOK_KEY_PREFIX}/{digest}"))
        .map_err(|_| ProviderWebhookError::RawDescriptor)?;
    let media_type = MediaType::new(PROVIDER_RAW_WEBHOOK_MEDIA_TYPE)
        .map_err(|_| ProviderWebhookError::RawDescriptor)?;
    Ok(BlobDescriptor::new(key, digest, size, media_type))
}

fn validate_raw_descriptor(
    request: &ProviderWebhookRequest,
    descriptor: &BlobDescriptor,
) -> Result<(), ProviderWebhookError> {
    let expected =
        provider_raw_webhook_descriptor(request.body_digest(), request.body.len() as u64)?;
    if descriptor != &expected {
        return Err(ProviderWebhookError::RawDescriptor);
    }
    Ok(())
}

fn validate_durable_evidence(
    instance_id: ProviderInstanceId,
    external_delivery: &ExternalDeliveryIdentity,
    received_at: UnixMillis,
    raw_body: &BlobDescriptor,
    raw_retain_until: UnixMillis,
) -> Result<(), ProviderWebhookError> {
    if external_delivery.instance_id() != instance_id {
        return Err(ProviderWebhookError::PayloadIdentityMismatch);
    }
    if received_at.get() < 0 || raw_retain_until <= received_at {
        return Err(ProviderWebhookError::InvalidReceivedTime);
    }
    let expected = provider_raw_webhook_descriptor(raw_body.digest(), raw_body.size())?;
    if raw_body != &expected {
        return Err(ProviderWebhookError::RawDescriptor);
    }
    Ok(())
}

fn retention_deadline(
    received_at: UnixMillis,
    retention_millis: u64,
) -> Result<UnixMillis, ProviderWebhookError> {
    let retention_millis =
        i64::try_from(retention_millis).map_err(|_| ProviderWebhookError::InvalidRawRetention)?;
    received_at
        .get()
        .checked_add(retention_millis)
        .map(UnixMillis::new)
        .ok_or(ProviderWebhookError::InvalidRawRetention)
}

/// Sanitized unauthenticated webhook rejection.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum ProviderWebhookAuthenticationError {
    /// Required canonical authentication headers were absent or malformed.
    #[error("provider webhook authentication evidence is invalid")]
    InvalidEvidence,
    /// No selected secret generation authenticated the exact raw body.
    #[error("provider webhook signature is invalid")]
    InvalidSignature,
}

/// Invalid endpoint, request, or verified-delivery evidence.
#[derive(Debug, Error)]
pub enum ProviderWebhookError {
    /// Endpoint revisions must be positive signed 64-bit values.
    #[error("provider webhook endpoint revision is invalid")]
    InvalidEndpointRevision,
    /// Endpoint body limit was zero or beyond the hard ingress bound.
    #[error("provider webhook body limit is invalid")]
    InvalidBodyLimit,
    /// Raw evidence retention was zero, excessive, or overflowed its deadline.
    #[error("provider webhook raw-evidence retention is invalid")]
    InvalidRawRetention,
    /// Secret generation selection was empty, excessive, or disagreed with plaintext.
    #[error("provider webhook secret candidates are invalid")]
    InvalidSecretCandidates,
    /// Candidate custody belonged to another endpoint record.
    #[error("provider webhook secret candidates belong to another endpoint")]
    SecretCandidateEndpointMismatch,
    /// One exact named secret generation appeared more than once.
    #[error("provider webhook secret candidate is duplicated")]
    DuplicateSecretCandidate,
    /// Endpoint creation, retirement, and state evidence disagreed.
    #[error("provider webhook endpoint lifecycle is invalid")]
    InvalidEndpointLifecycle,
    /// A successor changed immutable binding or violated revision/lifecycle rules.
    #[error("provider webhook endpoint successor is invalid")]
    InvalidEndpointSuccessor,
    /// The resolved connection disagreed with the endpoint's exact binding.
    #[error("provider webhook endpoint connection binding is invalid")]
    EndpointConnectionMismatch,
    /// The selected endpoint is disabled or retired.
    #[error("provider webhook endpoint is inactive")]
    EndpointInactive,
    /// Selected header name was not canonical lower-case HTTP syntax.
    #[error("provider webhook header name is invalid")]
    InvalidHeaderName,
    /// Selected header value was excessive or contained forbidden controls.
    #[error("provider webhook header value is invalid")]
    InvalidHeaderValue,
    /// Selected header count exceeded the adapter boundary.
    #[error("provider webhook has too many selected headers")]
    TooManyHeaders,
    /// Selected headers exceeded their aggregate byte bound.
    #[error("provider webhook selected headers are too large")]
    HeadersTooLarge,
    /// A selected header name appeared more than once.
    #[error("provider webhook selected header is duplicated")]
    DuplicateHeader,
    /// Body bytes exceeded the resolved endpoint limit.
    #[error("provider webhook body is too large")]
    BodyTooLarge,
    /// Trusted receipt time was before the Unix epoch.
    #[error("provider webhook receipt time is invalid")]
    InvalidReceivedTime,
    /// Adapter signature scheme identifier was not canonical.
    #[error("provider webhook signature scheme is invalid")]
    InvalidSignatureScheme,
    /// An adapter claimed a secret generation not selected by the endpoint.
    #[error("provider webhook verified with an unexpected secret generation")]
    UnexpectedVerifiedSecret,
    /// Adapter observations exceeded their durable bound.
    #[error("provider delivery observations are too large")]
    ObservationsTooLarge,
    /// Normalized trigger evidence was invalid.
    #[error(transparent)]
    Trigger(ProviderTriggerError),
    /// Payload identity disagreed with the resolved endpoint namespace.
    #[error("provider webhook payload identity conflicts with its endpoint")]
    PayloadIdentityMismatch,
    /// Raw immutable object evidence disagreed with authenticated bytes.
    #[error("provider webhook raw-body descriptor is invalid")]
    RawDescriptor,
}

/// Invalid delivery-adapter registry composition or lookup.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum DeliveryAdapterRegistryError {
    /// At least one adapter must be statically composed.
    #[error("at least one provider delivery adapter is required")]
    NoAdapters,
    /// Statically linked adapter count exceeded the hard bound.
    #[error("too many provider delivery adapters are registered")]
    TooManyAdapters,
    /// Two adapters claimed one exact provider type.
    #[error("provider delivery adapter type is duplicated")]
    DuplicateAdapter,
    /// An adapter declared no headers, too many headers, or duplicate names.
    #[error("provider delivery adapter header selection is invalid")]
    InvalidHeaderSelection,
    /// The endpoint's exact provider type was not registered.
    #[error("provider delivery adapter type is not registered")]
    UnknownProviderType,
}
