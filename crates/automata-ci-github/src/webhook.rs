use std::{fmt, num::NonZeroU64};

use automata_ci_scm::ExactRevision;
use bytes::{Bytes, BytesMut};
use reqwest::header::{HeaderMap, HeaderValue};
use ring::{digest, hmac};
use serde::{Deserialize, Deserializer, de};
use thiserror::Error;

use crate::repository_path::{has_ascii_case_insensitive_suffix, is_valid_component};

/// Maximum exact webhook body accepted by workflow admission.
pub const MAX_GITHUB_WEBHOOK_BODY_BYTES: usize = 25 * 1024 * 1024;
/// Maximum configured GitHub webhook secret size.
pub const MAX_GITHUB_WEBHOOK_SECRET_BYTES: usize = 16 * 1024;
/// Maximum commit summaries GitHub documents in one push webhook.
pub const MAX_GITHUB_PUSH_COMMITS: usize = 2_048;
/// Exact durable media type required for a stored authenticated GitHub push.
pub const GITHUB_PUSH_EVENT_MEDIA_TYPE: &str = "application/vnd.automata.github-push+json";
/// Exact durable media type for a version-one authenticated GitHub event.
pub const GITHUB_AUTHENTICATED_EVENT_V1_MEDIA_TYPE: &str =
    "application/vnd.automata.github-authenticated-event.v1+json";

/// GitHub's SHA-256 webhook signature header.
pub const X_HUB_SIGNATURE_256: &str = "x-hub-signature-256";
/// GitHub's provider event-name header.
pub const X_GITHUB_EVENT: &str = "x-github-event";
/// GitHub's provider delivery identifier header.
pub const X_GITHUB_DELIVERY: &str = "x-github-delivery";

const MAX_DELIVERY_ID_BYTES: usize = 128;
const MAX_GIT_REF_BYTES: usize = 1_024;
const MAX_GITHUB_PATH_FILTER_COMMITS: usize = 1_000;
const SHA256_SIGNATURE_PREFIX: &[u8] = b"sha256=";
const ZERO_COMMIT_SHA: &str = "0000000000000000000000000000000000000000";
const WEBHOOK_VERIFIER_FINGERPRINT_DOMAIN: &[u8] =
    b"automata.store.github-webhook-verifier-fingerprint.v1\0";

/// Public, domain-separated identity of one configured webhook verifier key.
///
/// The fingerprint is safe to persist as configuration evidence. It cannot be
/// used to verify a webhook and never exposes the underlying HMAC key.
#[derive(Clone, Copy, Eq, Hash, PartialEq)]
pub struct GithubWebhookVerifierFingerprint([u8; 32]);

impl GithubWebhookVerifierFingerprint {
    /// Returns the exact domain-separated SHA-256 bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Debug for GithubWebhookVerifierFingerprint {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("GithubWebhookVerifierFingerprint")
            .field(&"[public sha256]")
            .finish()
    }
}

/// Exact stored object and durable identity evidence for one authenticated push.
///
/// Construction does not authenticate or decode the body. The value exists so
/// the only stored-body rehydration entry point must receive the complete
/// immutable coordinates recorded after webhook authentication. Call
/// [`rehydrate_stored_authenticated_github_push`] to validate and consume it.
pub struct StoredAuthenticatedGithubPush {
    raw_body: Bytes,
    body_sha256: GithubWebhookBodyDigest,
    encoded_size: u64,
    media_type: Box<str>,
    delivery_id: Box<str>,
    installation_id: u64,
    repository_id: u64,
    repository_owner_id: u64,
    repository_visibility: GithubRepositoryVisibility,
    repository_owner: Box<str>,
    repository_name: Box<str>,
}

/// Version-one durable coordinates for any supported authenticated GitHub event.
///
/// This evidence is distinct from [`StoredAuthenticatedGithubPush`]. The media
/// type and explicit event name prevent legacy push rows from being silently
/// reinterpreted as the generic format. Construction is inert; only
/// [`rehydrate_stored_authenticated_github_webhook_v1`] validates and consumes
/// the coordinates.
pub struct StoredAuthenticatedGithubWebhookV1 {
    raw_body: Bytes,
    body_sha256: GithubWebhookBodyDigest,
    encoded_size: u64,
    media_type: Box<str>,
    event_name: Box<str>,
    delivery_id: Box<str>,
    installation_id: u64,
    repository_id: u64,
    repository_owner_id: u64,
    repository_visibility: GithubRepositoryVisibility,
    repository_owner: Box<str>,
    repository_name: Box<str>,
}

impl StoredAuthenticatedGithubWebhookV1 {
    /// Binds exact stored bytes to the complete version-one durable envelope.
    ///
    /// Validation is deliberately deferred to the consuming rehydration call.
    #[allow(clippy::too_many_arguments)]
    #[must_use]
    pub fn from_durable_coordinates(
        raw_body: Bytes,
        body_sha256: GithubWebhookBodyDigest,
        encoded_size: u64,
        media_type: impl Into<Box<str>>,
        event_name: impl Into<Box<str>>,
        delivery_id: impl Into<Box<str>>,
        installation_id: u64,
        repository_id: u64,
        repository_owner_id: u64,
        repository_visibility: GithubRepositoryVisibility,
        repository_owner: impl Into<Box<str>>,
        repository_name: impl Into<Box<str>>,
    ) -> Self {
        Self {
            raw_body,
            body_sha256,
            encoded_size,
            media_type: media_type.into(),
            event_name: event_name.into(),
            delivery_id: delivery_id.into(),
            installation_id,
            repository_id,
            repository_owner_id,
            repository_visibility,
            repository_owner: repository_owner.into(),
            repository_name: repository_name.into(),
        }
    }
}

impl fmt::Debug for StoredAuthenticatedGithubWebhookV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("StoredAuthenticatedGithubWebhookV1")
            .field("raw_body", &"[redacted]")
            .field("body_sha256", &"[redacted]")
            .field("encoded_size", &self.encoded_size)
            .field("media_type", &"[redacted]")
            .field("event_name", &self.event_name)
            .field("delivery_id", &"[redacted]")
            .field("installation_id", &self.installation_id)
            .field("repository_id", &self.repository_id)
            .field("repository_owner_id", &self.repository_owner_id)
            .field("repository_visibility", &self.repository_visibility)
            .field("repository_owner", &"[redacted]")
            .field("repository_name", &"[redacted]")
            .finish()
    }
}

impl StoredAuthenticatedGithubPush {
    /// Binds exact stored bytes to all durable object and routing coordinates.
    ///
    /// This constructor deliberately performs no partial validation. The
    /// consuming rehydration call checks every coordinate before decoding JSON,
    /// which prevents callers from accidentally treating construction as an
    /// authentication or integrity decision.
    #[allow(clippy::too_many_arguments)]
    #[must_use]
    pub fn from_durable_coordinates(
        raw_body: Bytes,
        body_sha256: GithubWebhookBodyDigest,
        encoded_size: u64,
        media_type: impl Into<Box<str>>,
        delivery_id: impl Into<Box<str>>,
        installation_id: u64,
        repository_id: u64,
        repository_owner_id: u64,
        repository_visibility: GithubRepositoryVisibility,
        repository_owner: impl Into<Box<str>>,
        repository_name: impl Into<Box<str>>,
    ) -> Self {
        Self {
            raw_body,
            body_sha256,
            encoded_size,
            media_type: media_type.into(),
            delivery_id: delivery_id.into(),
            installation_id,
            repository_id,
            repository_owner_id,
            repository_visibility,
            repository_owner: repository_owner.into(),
            repository_name: repository_name.into(),
        }
    }
}

impl fmt::Debug for StoredAuthenticatedGithubPush {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("StoredAuthenticatedGithubPush")
            .field("raw_body", &"[redacted]")
            .field("body_sha256", &"[redacted]")
            .field("encoded_size", &self.encoded_size)
            .field("media_type", &"[redacted]")
            .field("delivery_id", &"[redacted]")
            .field("installation_id", &self.installation_id)
            .field("repository_id", &self.repository_id)
            .field("repository_owner_id", &self.repository_owner_id)
            .field("repository_visibility", &self.repository_visibility)
            .field("repository_owner", &"[redacted]")
            .field("repository_name", &"[redacted]")
            .finish()
    }
}

/// Rehydrates one previously authenticated exact push object.
///
/// Media type, encoded size, SHA-256, and every durable routing identity are
/// checked before the result is returned. Media, size, and digest validation
/// precede JSON decoding. The body is not authenticated again: callers must
/// supply coordinates committed only after the original HMAC boundary accepted
/// these exact bytes.
///
/// # Errors
///
/// Rejects noncanonical object coordinates, digest or identity mismatches,
/// malformed JSON, and any payload that violates the same strict normalization
/// rules as [`GithubWebhookVerifier`].
pub fn rehydrate_stored_authenticated_github_push(
    evidence: StoredAuthenticatedGithubPush,
) -> Result<VerifiedGithubPush, GithubStoredPushError> {
    if evidence.media_type.as_ref() != GITHUB_PUSH_EVENT_MEDIA_TYPE {
        return Err(GithubStoredPushError::UnexpectedMediaType);
    }
    let actual_size = u64::try_from(evidence.raw_body.len()).unwrap_or(u64::MAX);
    if evidence.encoded_size == 0
        || evidence.raw_body.len() > MAX_GITHUB_WEBHOOK_BODY_BYTES
        || actual_size != evidence.encoded_size
    {
        return Err(GithubStoredPushError::SizeMismatch);
    }
    let actual_digest = webhook_body_digest(&evidence.raw_body);
    if actual_digest != evidence.body_sha256 {
        return Err(GithubStoredPushError::DigestMismatch);
    }
    validate_stored_identity(&evidence)?;

    let payload: PushPayload = serde_json::from_slice(&evidence.raw_body)
        .map_err(|_| GithubStoredPushError::MalformedPayload)?;
    validate_stored_payload_identity(&payload, &evidence)?;
    normalize_push(
        PushRequestHeaders {
            event_name: "push".into(),
            delivery_id: evidence.delivery_id,
        },
        evidence.raw_body,
        payload,
    )
    .map_err(|error| match error {
        GithubWebhookError::MalformedPayload => GithubStoredPushError::MalformedPayload,
        GithubWebhookError::InvalidPayload
        | GithubWebhookError::InvalidSecret
        | GithubWebhookError::InvalidHeaders
        | GithubWebhookError::InvalidSignature
        | GithubWebhookError::BodyTooLarge
        | GithubWebhookError::AuthenticationFailed
        | GithubWebhookError::UnsupportedEvent => GithubStoredPushError::InvalidPayload,
    })
}

/// Rehydrates one version-one authenticated GitHub event envelope.
///
/// Media type, size, digest, event name, delivery identity, and repository
/// coordinates are verified before normalized evidence is returned. The body
/// is not authenticated again: callers must supply only coordinates committed
/// by the original HMAC acceptance transaction.
///
/// # Errors
///
/// Rejects legacy or unknown media, invalid durable coordinates, digest drift,
/// duplicate or malformed JSON, unsupported events, and payload identity drift.
pub fn rehydrate_stored_authenticated_github_webhook_v1(
    evidence: StoredAuthenticatedGithubWebhookV1,
) -> Result<crate::VerifiedGithubWebhook, GithubStoredWebhookError> {
    if evidence.media_type.as_ref() != GITHUB_AUTHENTICATED_EVENT_V1_MEDIA_TYPE {
        return Err(GithubStoredWebhookError::UnexpectedMediaType);
    }
    let actual_size = u64::try_from(evidence.raw_body.len()).unwrap_or(u64::MAX);
    if evidence.encoded_size == 0
        || evidence.raw_body.len() > MAX_GITHUB_WEBHOOK_BODY_BYTES
        || actual_size != evidence.encoded_size
    {
        return Err(GithubStoredWebhookError::SizeMismatch);
    }
    if webhook_body_digest(&evidence.raw_body) != evidence.body_sha256 {
        return Err(GithubStoredWebhookError::DigestMismatch);
    }
    if !valid_stored_identity(
        evidence.installation_id,
        evidence.repository_id,
        evidence.repository_owner_id,
        evidence.delivery_id.as_bytes(),
        &evidence.repository_owner,
        &evidence.repository_name,
    ) || !valid_event_name(evidence.event_name.as_bytes())
    {
        return Err(GithubStoredWebhookError::InvalidDurableIdentity);
    }

    let expected_installation_id = evidence.installation_id;
    let expected_repository_id = evidence.repository_id;
    let expected_repository_owner_id = evidence.repository_owner_id;
    let expected_visibility = evidence.repository_visibility;
    let expected_owner = evidence.repository_owner;
    let expected_name = evidence.repository_name;
    let authenticated = AuthenticatedGithubWebhook {
        delivery_id: evidence.delivery_id,
        event_name: evidence.event_name,
        raw_body: evidence.raw_body,
        body_sha256: evidence.body_sha256,
    };
    let normalized = authenticated.normalize().map_err(|error| match error {
        GithubWebhookError::MalformedPayload => GithubStoredWebhookError::MalformedPayload,
        GithubWebhookError::UnsupportedEvent => GithubStoredWebhookError::UnsupportedEvent,
        GithubWebhookError::InvalidPayload
        | GithubWebhookError::InvalidSecret
        | GithubWebhookError::InvalidHeaders
        | GithubWebhookError::InvalidSignature
        | GithubWebhookError::BodyTooLarge
        | GithubWebhookError::AuthenticationFailed => GithubStoredWebhookError::InvalidPayload,
    })?;
    let repository = normalized.repository();
    if normalized.installation_id().get() != expected_installation_id
        || repository.id().get() != expected_repository_id
        || repository.owner_id().get() != expected_repository_owner_id
        || repository.visibility() != expected_visibility
        || repository.owner() != expected_owner.as_ref()
        || repository.name() != expected_name.as_ref()
    {
        return Err(GithubStoredWebhookError::IdentityMismatch);
    }
    Ok(normalized)
}

/// Exact authenticated GitHub webhook envelope before event-specific decoding.
///
/// The event and delivery headers are validated singleton routing evidence but
/// are not covered by GitHub's body HMAC. Consumers must integrity-bind them
/// alongside the exact body when persisting or deduplicating the delivery.
#[derive(Clone, Eq, PartialEq)]
pub struct AuthenticatedGithubWebhook {
    delivery_id: Box<str>,
    event_name: Box<str>,
    raw_body: Bytes,
    body_sha256: GithubWebhookBodyDigest,
}

impl AuthenticatedGithubWebhook {
    /// Returns the validated singleton `X-GitHub-Delivery` value.
    pub fn delivery_id(&self) -> &str {
        &self.delivery_id
    }

    /// Returns the validated singleton `X-GitHub-Event` value.
    pub fn event_name(&self) -> &str {
        &self.event_name
    }

    /// Returns the exact HMAC-authenticated body bytes without reserialization.
    pub const fn raw_body(&self) -> &Bytes {
        &self.raw_body
    }

    /// Returns SHA-256 of the exact authenticated body.
    pub const fn body_sha256(&self) -> GithubWebhookBodyDigest {
        self.body_sha256
    }

    /// Strictly normalizes the authenticated body into supported event evidence.
    ///
    /// The exact body, digest, singleton event and delivery headers, repository,
    /// and installation identity remain attached to the normalized result.
    /// Event-specific decoding rejects malformed JSON, duplicate object keys,
    /// inconsistent identities, unsupported actions, and unbounded selector
    /// fields.
    ///
    /// # Errors
    ///
    /// Returns a sanitized [`GithubWebhookError`] when the authenticated event
    /// is unsupported or cannot be normalized without ambiguity.
    pub fn normalize(self) -> Result<crate::VerifiedGithubWebhook, GithubWebhookError> {
        crate::webhook_event::validate_json(&self.raw_body)?;
        match self.event_name.as_ref() {
            "push" => self
                .into_verified_push()
                .map(crate::VerifiedGithubWebhook::Push),
            "pull_request" => crate::webhook_event::normalize_pull_request(self)
                .map(crate::VerifiedGithubWebhook::PullRequest),
            "merge_group" => crate::webhook_event::normalize_merge_group(self)
                .map(crate::VerifiedGithubWebhook::MergeGroup),
            _ => Err(GithubWebhookError::UnsupportedEvent),
        }
    }

    fn into_verified_push(self) -> Result<VerifiedGithubPush, GithubWebhookError> {
        if self.event_name.as_ref() != "push" {
            return Err(GithubWebhookError::UnsupportedEvent);
        }
        let payload: PushPayload = serde_json::from_slice(&self.raw_body)
            .map_err(|_| GithubWebhookError::MalformedPayload)?;
        normalize_push(
            PushRequestHeaders {
                event_name: self.event_name,
                delivery_id: self.delivery_id,
            },
            self.raw_body,
            payload,
        )
    }
}

impl fmt::Debug for AuthenticatedGithubWebhook {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AuthenticatedGithubWebhook")
            .field("delivery_id", &"[redacted]")
            .field("event_name", &self.event_name)
            .field("raw_body", &"[redacted]")
            .field("body_len", &self.raw_body.len())
            .field("body_sha256", &self.body_sha256)
            .finish()
    }
}

/// Pure authenticator and push normalizer for GitHub webhooks.
///
/// The configured secret is never exposed through `Debug` or an error. Header
/// multiplicity is checked before use, the exact body is bounded before or
/// while it is buffered, and HMAC verification always precedes JSON decoding.
pub struct GithubWebhookVerifier {
    key: hmac::Key,
    fingerprint: GithubWebhookVerifierFingerprint,
}

impl GithubWebhookVerifier {
    /// Creates a verifier from one configured webhook secret.
    ///
    /// # Errors
    ///
    /// Rejects an empty secret or one larger than the bounded configuration
    /// limit.
    pub fn new(secret: &[u8]) -> Result<Self, GithubWebhookError> {
        if secret.is_empty() || secret.len() > MAX_GITHUB_WEBHOOK_SECRET_BYTES {
            return Err(GithubWebhookError::InvalidSecret);
        }
        let mut fingerprint = digest::Context::new(&digest::SHA256);
        fingerprint.update(WEBHOOK_VERIFIER_FINGERPRINT_DOMAIN);
        fingerprint.update(secret);
        let fingerprint = fingerprint.finish();
        let mut fingerprint_bytes = [0_u8; 32];
        fingerprint_bytes.copy_from_slice(fingerprint.as_ref());
        Ok(Self {
            key: hmac::Key::new(hmac::HMAC_SHA256, secret),
            fingerprint: GithubWebhookVerifierFingerprint(fingerprint_bytes),
        })
    }

    /// Returns the public identity derived from the exact configured HMAC key.
    #[must_use]
    pub const fn fingerprint(&self) -> GithubWebhookVerifierFingerprint {
        self.fingerprint
    }

    /// Authenticates one bounded webhook without decoding an event-specific payload.
    ///
    /// This is the common ingress boundary for supported event normalizers. It
    /// accepts every syntactically valid GitHub event name; accepting the
    /// envelope does not imply that Automata supports or will schedule it.
    ///
    /// # Errors
    ///
    /// Rejects oversized bodies, missing or repeated required headers,
    /// malformed signatures, and failed authentication.
    pub fn authenticate(
        &self,
        headers: &HeaderMap,
        raw_body: Bytes,
    ) -> Result<AuthenticatedGithubWebhook, GithubWebhookError> {
        if raw_body.len() > MAX_GITHUB_WEBHOOK_BODY_BYTES {
            return Err(GithubWebhookError::BodyTooLarge);
        }
        let headers = VerifiedHeaders::parse(headers)?;
        self.authenticate_bounded(headers, raw_body)
    }

    /// Buffers bounded chunks and authenticates their exact concatenated bytes.
    ///
    /// # Errors
    ///
    /// Returns the same sanitized errors as [`Self::authenticate`].
    pub fn authenticate_chunks<I, C>(
        &self,
        headers: &HeaderMap,
        chunks: I,
    ) -> Result<AuthenticatedGithubWebhook, GithubWebhookError>
    where
        I: IntoIterator<Item = C>,
        C: AsRef<[u8]>,
    {
        let headers = VerifiedHeaders::parse(headers)?;
        self.authenticate_bounded(headers, bounded_body(chunks)?)
    }

    /// Verifies and normalizes one already-buffered exact webhook body.
    ///
    /// # Errors
    ///
    /// Rejects oversized bodies, missing or repeated required headers,
    /// malformed signatures, failed authentication, unsupported events, and
    /// malformed or internally inconsistent push payloads.
    pub fn verify(
        &self,
        headers: &HeaderMap,
        raw_body: Bytes,
    ) -> Result<VerifiedGithubPush, GithubWebhookError> {
        self.authenticate(headers, raw_body)?.into_verified_push()
    }

    /// Buffers bounded chunks, then verifies and normalizes their exact bytes.
    ///
    /// The running length is checked before every buffer extension, so a body
    /// cannot transiently exceed the workflow-admission event ceiling.
    ///
    /// # Errors
    ///
    /// Returns the same sanitized errors as [`Self::verify`].
    pub fn verify_chunks<I, C>(
        &self,
        headers: &HeaderMap,
        chunks: I,
    ) -> Result<VerifiedGithubPush, GithubWebhookError>
    where
        I: IntoIterator<Item = C>,
        C: AsRef<[u8]>,
    {
        self.authenticate_chunks(headers, chunks)?
            .into_verified_push()
    }

    fn authenticate_bounded(
        &self,
        headers: VerifiedHeaders,
        raw_body: Bytes,
    ) -> Result<AuthenticatedGithubWebhook, GithubWebhookError> {
        hmac::verify(&self.key, &raw_body, &headers.signature)
            .map_err(|_| GithubWebhookError::AuthenticationFailed)?;
        Ok(AuthenticatedGithubWebhook {
            delivery_id: headers.request.delivery_id,
            event_name: headers.request.event_name,
            body_sha256: webhook_body_digest(&raw_body),
            raw_body,
        })
    }
}

fn bounded_body<I, C>(chunks: I) -> Result<Bytes, GithubWebhookError>
where
    I: IntoIterator<Item = C>,
    C: AsRef<[u8]>,
{
    let mut raw_body = BytesMut::new();
    for chunk in chunks {
        let chunk = chunk.as_ref();
        let next_length = raw_body
            .len()
            .checked_add(chunk.len())
            .ok_or(GithubWebhookError::BodyTooLarge)?;
        if next_length > MAX_GITHUB_WEBHOOK_BODY_BYTES {
            return Err(GithubWebhookError::BodyTooLarge);
        }
        raw_body.extend_from_slice(chunk);
    }
    Ok(raw_body.freeze())
}

impl fmt::Debug for GithubWebhookVerifier {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GithubWebhookVerifier")
            .field("secret", &"[redacted]")
            .finish()
    }
}

/// SHA-256 of the exact authenticated raw webhook body.
#[derive(Clone, Copy, Eq, Hash, PartialEq)]
pub struct GithubWebhookBodyDigest([u8; 32]);

impl GithubWebhookBodyDigest {
    /// Constructs a digest from exact canonical SHA-256 bytes.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Returns the canonical digest bytes.
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Display for GithubWebhookBodyDigest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in self.0 {
            write!(formatter, "{byte:02x}")?;
        }
        Ok(())
    }
}

impl fmt::Debug for GithubWebhookBodyDigest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "GithubWebhookBodyDigest({self})")
    }
}

/// Canonical kind of a full GitHub push reference.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GithubPushRefKind {
    /// A `refs/heads/...` branch reference.
    Branch,
    /// A `refs/tags/...` tag reference.
    Tag,
}

/// Validated, unambiguous full GitHub push reference.
#[derive(Clone, Eq, PartialEq)]
pub struct GithubPushRef {
    full: Box<str>,
    kind: GithubPushRefKind,
    short_name_offset: usize,
}

impl GithubPushRef {
    /// Returns the exact canonical full reference.
    pub fn full(&self) -> &str {
        &self.full
    }

    /// Returns the branch or tag name below its canonical namespace.
    pub fn short_name(&self) -> &str {
        &self.full[self.short_name_offset..]
    }

    /// Returns whether this is a branch or tag reference.
    pub const fn kind(&self) -> GithubPushRefKind {
        self.kind
    }
}

impl fmt::Debug for GithubPushRef {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GithubPushRef")
            .field("kind", &self.kind)
            .field("full", &"[redacted]")
            .finish_non_exhaustive()
    }
}

/// Normalized repository identity from the authenticated push body.
#[derive(Clone, Eq, PartialEq)]
pub struct GithubPushRepository {
    id: NonZeroU64,
    owner_id: NonZeroU64,
    visibility: GithubRepositoryVisibility,
    owner: Box<str>,
    name: Box<str>,
    full_name: Box<str>,
}

impl GithubPushRepository {
    pub(crate) fn from_webhook_fields(
        id: u64,
        owner_id: u64,
        private: bool,
        visibility: &str,
        owner: String,
        name: String,
        full_name: String,
    ) -> Result<Self, GithubWebhookError> {
        let id = durable_provider_id(id)?;
        let owner_id = durable_provider_id(owner_id)?;
        let visibility = normalized_repository_visibility(private, visibility)?;
        validate_repository_component(&owner)?;
        validate_repository_component(&name)?;
        if has_ascii_case_insensitive_suffix(&name, ".git")
            || full_name != format!("{owner}/{name}")
        {
            return Err(GithubWebhookError::InvalidPayload);
        }
        Ok(Self {
            id,
            owner_id,
            visibility,
            owner: owner.into_boxed_str(),
            name: name.into_boxed_str(),
            full_name: full_name.into_boxed_str(),
        })
    }

    /// Returns GitHub's nonzero numeric repository identifier.
    pub const fn id(&self) -> NonZeroU64 {
        self.id
    }

    /// Returns GitHub's positive numeric repository-owner identifier, proven
    /// representable by `PostgreSQL` `BIGINT` at authenticated ingress.
    pub const fn owner_id(&self) -> NonZeroU64 {
        self.owner_id
    }

    /// Returns the closed visibility authenticated by mutually consistent
    /// `private` and `visibility` repository fields.
    pub const fn visibility(&self) -> GithubRepositoryVisibility {
        self.visibility
    }

    /// Returns the validated repository owner login.
    pub fn owner(&self) -> &str {
        &self.owner
    }

    /// Returns the validated repository name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Returns the exact owner/name pair agreed by all payload fields.
    pub fn full_name(&self) -> &str {
        &self.full_name
    }
}

impl fmt::Debug for GithubPushRepository {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GithubPushRepository")
            .field("id", &self.id)
            .field("owner_id", &self.owner_id)
            .field("visibility", &self.visibility)
            .field("owner", &"[redacted]")
            .field("name", &"[redacted]")
            .field("full_name", &"[redacted]")
            .finish()
    }
}

/// Closed repository visibility authenticated from a GitHub webhook body.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GithubRepositoryVisibility {
    /// The exact repository is anonymously readable.
    Public,
    /// The exact repository requires installation source authority.
    Private,
}

/// Provider event-selection metadata retained without a compiler dependency.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GithubWebhookEventMetadata {
    /// A push event and its exact provider flags.
    Push {
        /// Whether GitHub declared this reference newly created.
        created: bool,
        /// Whether GitHub declared this reference deleted.
        deleted: bool,
        /// Whether GitHub declared this a non-fast-forward update.
        forced: bool,
    },
}

/// Authenticated and strictly normalized GitHub push evidence.
#[derive(Clone, Eq, PartialEq)]
pub struct VerifiedGithubPush {
    delivery_id: Box<str>,
    event_name: Box<str>,
    raw_body: Bytes,
    body_sha256: GithubWebhookBodyDigest,
    installation_id: NonZeroU64,
    repository: GithubPushRepository,
    git_ref: GithubPushRef,
    before_commit_sha: Box<str>,
    after_commit_sha: Box<str>,
    metadata: GithubWebhookEventMetadata,
    commit_count: usize,
    complete_pushed_commit_revisions: Option<Box<[ExactRevision]>>,
}

impl VerifiedGithubPush {
    /// Returns the exact singleton `X-GitHub-Delivery` value.
    ///
    /// This header is outside the body MAC and must be included separately in
    /// any durable request or idempotency digest.
    pub fn delivery_id(&self) -> &str {
        &self.delivery_id
    }

    /// Returns the exact singleton `X-GitHub-Event` value.
    ///
    /// This header is outside the body MAC and must be included separately in
    /// any durable request digest.
    pub fn event_name(&self) -> &str {
        &self.event_name
    }

    /// Returns the exact authenticated JSON bytes without reserialization.
    pub fn raw_body(&self) -> &Bytes {
        &self.raw_body
    }

    /// Returns SHA-256 of the exact authenticated body.
    pub const fn body_sha256(&self) -> GithubWebhookBodyDigest {
        self.body_sha256
    }

    /// Returns the nonzero GitHub App installation identifier.
    pub const fn installation_id(&self) -> NonZeroU64 {
        self.installation_id
    }

    /// Returns the internally consistent provider repository identity.
    pub const fn repository(&self) -> &GithubPushRepository {
        &self.repository
    }

    /// Returns the canonical full branch or tag reference.
    pub const fn git_ref(&self) -> &GithubPushRef {
        &self.git_ref
    }

    /// Returns the canonical lowercase 40-hex pre-push commit identifier.
    pub fn before_commit_sha(&self) -> &str {
        &self.before_commit_sha
    }

    /// Returns the canonical lowercase 40-hex post-push commit identifier.
    pub fn after_commit_sha(&self) -> &str {
        &self.after_commit_sha
    }

    /// Returns provider metadata required for later trigger selection.
    pub const fn event_metadata(&self) -> GithubWebhookEventMetadata {
        self.metadata
    }

    /// Returns the bounded number of commit summaries observed in the payload.
    ///
    /// GitHub caps the webhook array at [`MAX_GITHUB_PUSH_COMMITS`], so this is
    /// not a claim about the total size of a larger truncated push.
    pub const fn commit_count(&self) -> usize {
        self.commit_count
    }

    /// Returns the complete canonical pushed-commit set when path filtering
    /// requires a provider diff.
    ///
    /// The revisions are lexicographically sorted because provider array order
    /// is not diff-base authority. `Some(empty)` is complete evidence for an
    /// empty array. `None` means the payload contained more than 1,000 commits,
    /// for which GitHub Actions bypasses path-filter diff generation.
    pub fn complete_pushed_commit_revisions(&self) -> Option<&[ExactRevision]> {
        self.complete_pushed_commit_revisions.as_deref()
    }

    /// Returns whether GitHub Actions' commit ceiling requires path filters to
    /// match without generating a diff.
    pub const fn path_filter_commit_limit_exceeded(&self) -> bool {
        self.complete_pushed_commit_revisions.is_none()
    }

    /// Returns the exact provider deletion flag.
    pub const fn deleted(&self) -> bool {
        match self.metadata {
            GithubWebhookEventMetadata::Push { deleted, .. } => deleted,
        }
    }

    /// Returns the exact provider creation flag.
    pub const fn created(&self) -> bool {
        match self.metadata {
            GithubWebhookEventMetadata::Push { created, .. } => created,
        }
    }

    /// Returns the exact provider forced-update flag.
    pub const fn forced(&self) -> bool {
        match self.metadata {
            GithubWebhookEventMetadata::Push { forced, .. } => forced,
        }
    }
}

impl fmt::Debug for VerifiedGithubPush {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("VerifiedGithubPush")
            .field("delivery_id", &"[redacted]")
            .field("event_name", &self.event_name)
            .field("raw_body", &"[redacted]")
            .field("body_len", &self.raw_body.len())
            .field("body_sha256", &self.body_sha256)
            .field("installation_id", &self.installation_id)
            .field("repository", &self.repository)
            .field("git_ref", &self.git_ref)
            .field("before_commit_sha", &"[redacted]")
            .field("after_commit_sha", &"[redacted]")
            .field("metadata", &self.metadata)
            .field("commit_count", &self.commit_count)
            .field(
                "complete_pushed_commit_revisions",
                &self.complete_pushed_commit_revisions.is_some(),
            )
            .finish()
    }
}

/// Sanitized webhook verification and normalization failures.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum GithubWebhookError {
    /// The configured webhook secret is empty or excessive.
    #[error("the GitHub webhook secret is invalid")]
    InvalidSecret,
    /// A required header is absent, repeated, or structurally invalid.
    #[error("the GitHub webhook headers are invalid")]
    InvalidHeaders,
    /// The signature is not canonical lowercase `sha256=` plus 64 hex digits.
    #[error("the GitHub webhook signature encoding is invalid")]
    InvalidSignature,
    /// The raw event exceeds the workflow-admission event ceiling.
    #[error("the GitHub webhook body exceeds the configured limit")]
    BodyTooLarge,
    /// The constant-time HMAC comparison failed.
    #[error("GitHub webhook authentication failed")]
    AuthenticationFailed,
    /// The event is validly signed but is not supported by normalization.
    #[error("the GitHub webhook event is unsupported")]
    UnsupportedEvent,
    /// The authenticated JSON shape could not be decoded unambiguously.
    #[error("the GitHub webhook payload is malformed")]
    MalformedPayload,
    /// Authenticated provider fields violate event invariants.
    #[error("the GitHub webhook payload is inconsistent")]
    InvalidPayload,
}

/// Sanitized stored authenticated-push rehydration failures.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum GithubStoredPushError {
    /// The durable object is not the canonical authenticated-push media type.
    #[error("the stored GitHub push media type is invalid")]
    UnexpectedMediaType,
    /// The durable encoded size is zero, excessive, or differs from the bytes.
    #[error("the stored GitHub push size is invalid")]
    SizeMismatch,
    /// The exact stored bytes do not match the durable SHA-256 coordinate.
    #[error("the stored GitHub push digest does not match")]
    DigestMismatch,
    /// Durable routing coordinates violate the authenticated ingress shape.
    #[error("the stored GitHub push identity is invalid")]
    InvalidDurableIdentity,
    /// The exact stored bytes are not an unambiguous push JSON document.
    #[error("the stored GitHub push payload is malformed")]
    MalformedPayload,
    /// The stored body identity differs from its durable routing coordinates.
    #[error("the stored GitHub push identity does not match its payload")]
    IdentityMismatch,
    /// Stored provider fields violate strict push invariants.
    #[error("the stored GitHub push payload is inconsistent")]
    InvalidPayload,
}

/// Sanitized version-one authenticated-event rehydration failures.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum GithubStoredWebhookError {
    /// The durable object does not use the version-one generic event media type.
    #[error("the stored GitHub event media type is invalid")]
    UnexpectedMediaType,
    /// The stored byte count is zero, excessive, or inconsistent.
    #[error("the stored GitHub event size is invalid")]
    SizeMismatch,
    /// The exact bytes do not match their durable SHA-256 coordinate.
    #[error("the stored GitHub event digest does not match")]
    DigestMismatch,
    /// Durable routing coordinates violate the authenticated ingress shape.
    #[error("the stored GitHub event identity is invalid")]
    InvalidDurableIdentity,
    /// The exact body is not unambiguous JSON.
    #[error("the stored GitHub event payload is malformed")]
    MalformedPayload,
    /// The version-one envelope names an unsupported event.
    #[error("the stored GitHub event is unsupported")]
    UnsupportedEvent,
    /// Stored provider fields violate strict event invariants.
    #[error("the stored GitHub event payload is inconsistent")]
    InvalidPayload,
    /// The normalized body identity differs from durable routing evidence.
    #[error("the stored GitHub event identity does not match its payload")]
    IdentityMismatch,
}

struct PushRequestHeaders {
    event_name: Box<str>,
    delivery_id: Box<str>,
}

struct VerifiedHeaders {
    signature: [u8; 32],
    request: PushRequestHeaders,
}

impl VerifiedHeaders {
    fn parse(headers: &HeaderMap) -> Result<Self, GithubWebhookError> {
        let signature = parse_signature(unique_header(headers, X_HUB_SIGNATURE_256)?)?;
        let event = unique_header(headers, X_GITHUB_EVENT)?;
        if !valid_event_name(event) {
            return Err(GithubWebhookError::InvalidHeaders);
        }
        let delivery = unique_header(headers, X_GITHUB_DELIVERY)?;
        if !valid_delivery_id(delivery) {
            return Err(GithubWebhookError::InvalidHeaders);
        }
        let event_name = std::str::from_utf8(event)
            .map_err(|_| GithubWebhookError::InvalidHeaders)?
            .into();
        let delivery_id = std::str::from_utf8(delivery)
            .map_err(|_| GithubWebhookError::InvalidHeaders)?
            .into();
        Ok(Self {
            signature,
            request: PushRequestHeaders {
                event_name,
                delivery_id,
            },
        })
    }
}

fn valid_event_name(value: &[u8]) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value
            .iter()
            .all(|byte| byte.is_ascii_lowercase() || *byte == b'_')
}

fn valid_delivery_id(value: &[u8]) -> bool {
    !value.is_empty()
        && value.len() <= MAX_DELIVERY_ID_BYTES
        && value
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
}

fn unique_header<'headers>(
    headers: &'headers HeaderMap,
    name: &str,
) -> Result<&'headers [u8], GithubWebhookError> {
    let mut values = headers.get_all(name).iter();
    let value = values.next().ok_or(GithubWebhookError::InvalidHeaders)?;
    if values.next().is_some() {
        return Err(GithubWebhookError::InvalidHeaders);
    }
    Ok(header_bytes(value))
}

fn header_bytes(value: &HeaderValue) -> &[u8] {
    value.as_bytes()
}

fn parse_signature(value: &[u8]) -> Result<[u8; 32], GithubWebhookError> {
    let encoded = value
        .strip_prefix(SHA256_SIGNATURE_PREFIX)
        .filter(|encoded| encoded.len() == 64)
        .ok_or(GithubWebhookError::InvalidSignature)?;
    let mut signature = [0_u8; 32];
    for (target, pair) in signature.iter_mut().zip(encoded.chunks_exact(2)) {
        let high = lower_hex_nibble(pair[0]).ok_or(GithubWebhookError::InvalidSignature)?;
        let low = lower_hex_nibble(pair[1]).ok_or(GithubWebhookError::InvalidSignature)?;
        *target = (high << 4) | low;
    }
    Ok(signature)
}

const fn lower_hex_nibble(value: u8) -> Option<u8> {
    match value {
        b'0'..=b'9' => Some(value - b'0'),
        b'a'..=b'f' => Some(value - b'a' + 10),
        _ => None,
    }
}

#[derive(Deserialize)]
struct PushPayload {
    #[serde(rename = "ref")]
    git_ref: String,
    before: String,
    after: String,
    created: bool,
    deleted: bool,
    forced: bool,
    repository: PushRepositoryPayload,
    installation: PushInstallationPayload,
    commits: BoundedCommits,
}

#[derive(Deserialize)]
struct PushRepositoryPayload {
    id: u64,
    private: bool,
    visibility: String,
    name: String,
    full_name: String,
    owner: PushOwnerPayload,
}

#[derive(Deserialize)]
struct PushOwnerPayload {
    id: u64,
    login: String,
}

#[derive(Deserialize)]
struct PushInstallationPayload {
    id: u64,
}

#[derive(Deserialize)]
struct PushCommitPayload {
    id: String,
}

#[derive(Default)]
struct BoundedCommits(Vec<PushCommitPayload>);

struct NormalizedPushedCommits {
    count: usize,
    complete_revisions: Option<Box<[ExactRevision]>>,
}

impl<'de> Deserialize<'de> for BoundedCommits {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_seq(BoundedCommitVisitor)
    }
}

struct BoundedCommitVisitor;

impl<'de> de::Visitor<'de> for BoundedCommitVisitor {
    type Value = BoundedCommits;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a bounded GitHub push commit collection")
    }

    fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
    where
        A: de::SeqAccess<'de>,
    {
        let mut commits = Vec::new();
        while let Some(commit) = sequence.next_element::<PushCommitPayload>()? {
            if commits.len() == MAX_GITHUB_PUSH_COMMITS {
                return Err(de::Error::custom("push commit count exceeds limit"));
            }
            commits.push(commit);
        }
        Ok(BoundedCommits(commits))
    }
}

fn normalize_push(
    headers: PushRequestHeaders,
    raw_body: Bytes,
    payload: PushPayload,
) -> Result<VerifiedGithubPush, GithubWebhookError> {
    let installation_id = durable_provider_id(payload.installation.id)?;
    let repository = GithubPushRepository::from_webhook_fields(
        payload.repository.id,
        payload.repository.owner.id,
        payload.repository.private,
        &payload.repository.visibility,
        payload.repository.owner.login,
        payload.repository.name,
        payload.repository.full_name,
    )?;

    let git_ref = parse_git_ref(payload.git_ref)?;
    validate_commit_range(
        &payload.before,
        &payload.after,
        payload.created,
        payload.deleted,
    )?;
    let pushed_commits = normalize_pushed_commits(payload.commits)?;
    let body_sha256 = webhook_body_digest(&raw_body);

    Ok(VerifiedGithubPush {
        delivery_id: headers.delivery_id,
        event_name: headers.event_name,
        raw_body,
        body_sha256,
        installation_id,
        repository,
        git_ref,
        before_commit_sha: payload.before.into_boxed_str(),
        after_commit_sha: payload.after.into_boxed_str(),
        metadata: GithubWebhookEventMetadata::Push {
            created: payload.created,
            deleted: payload.deleted,
            forced: payload.forced,
        },
        commit_count: pushed_commits.count,
        complete_pushed_commit_revisions: pushed_commits.complete_revisions,
    })
}

fn normalize_pushed_commits(
    commits: BoundedCommits,
) -> Result<NormalizedPushedCommits, GithubWebhookError> {
    let mut revisions = Vec::with_capacity(commits.0.len());
    for commit in commits.0 {
        if commit.id == ZERO_COMMIT_SHA {
            return Err(GithubWebhookError::InvalidPayload);
        }
        revisions
            .push(ExactRevision::new(commit.id).map_err(|_| GithubWebhookError::InvalidPayload)?);
    }
    revisions.sort_unstable();
    if revisions.windows(2).any(|pair| pair[0] == pair[1]) {
        return Err(GithubWebhookError::InvalidPayload);
    }

    let commit_count = revisions.len();
    let complete =
        (commit_count <= MAX_GITHUB_PATH_FILTER_COMMITS).then(|| revisions.into_boxed_slice());
    Ok(NormalizedPushedCommits {
        count: commit_count,
        complete_revisions: complete,
    })
}

pub(crate) fn durable_provider_id(value: u64) -> Result<NonZeroU64, GithubWebhookError> {
    let value = NonZeroU64::new(value).ok_or(GithubWebhookError::InvalidPayload)?;
    if i64::try_from(value.get()).is_err() {
        return Err(GithubWebhookError::InvalidPayload);
    }
    Ok(value)
}

fn normalized_repository_visibility(
    private: bool,
    visibility: &str,
) -> Result<GithubRepositoryVisibility, GithubWebhookError> {
    match (private, visibility) {
        (false, "public") => Ok(GithubRepositoryVisibility::Public),
        (true, "private") => Ok(GithubRepositoryVisibility::Private),
        _ => Err(GithubWebhookError::InvalidPayload),
    }
}

fn webhook_body_digest(raw_body: &[u8]) -> GithubWebhookBodyDigest {
    let digest = digest::digest(&digest::SHA256, raw_body);
    let mut bytes = [0_u8; 32];
    bytes.copy_from_slice(digest.as_ref());
    GithubWebhookBodyDigest::from_bytes(bytes)
}

fn validate_stored_identity(
    evidence: &StoredAuthenticatedGithubPush,
) -> Result<(), GithubStoredPushError> {
    if !valid_stored_identity(
        evidence.installation_id,
        evidence.repository_id,
        evidence.repository_owner_id,
        evidence.delivery_id.as_bytes(),
        &evidence.repository_owner,
        &evidence.repository_name,
    ) {
        return Err(GithubStoredPushError::InvalidDurableIdentity);
    }
    Ok(())
}

fn valid_stored_identity(
    installation_id: u64,
    repository_id: u64,
    repository_owner_id: u64,
    delivery_id: &[u8],
    repository_owner: &str,
    repository_name: &str,
) -> bool {
    i64::try_from(installation_id).is_ok()
        && installation_id != 0
        && i64::try_from(repository_id).is_ok()
        && repository_id != 0
        && i64::try_from(repository_owner_id).is_ok()
        && repository_owner_id != 0
        && valid_delivery_id(delivery_id)
        && validate_repository_component(repository_owner).is_ok()
        && validate_repository_component(repository_name).is_ok()
        && !has_ascii_case_insensitive_suffix(repository_name, ".git")
}

fn validate_stored_payload_identity(
    payload: &PushPayload,
    evidence: &StoredAuthenticatedGithubPush,
) -> Result<(), GithubStoredPushError> {
    if payload.installation.id != evidence.installation_id
        || payload.repository.id != evidence.repository_id
        || payload.repository.owner.id != evidence.repository_owner_id
        || normalized_repository_visibility(
            payload.repository.private,
            &payload.repository.visibility,
        )
        .map_err(|_| GithubStoredPushError::InvalidPayload)?
            != evidence.repository_visibility
        || payload.repository.owner.login != evidence.repository_owner.as_ref()
        || payload.repository.name != evidence.repository_name.as_ref()
    {
        return Err(GithubStoredPushError::IdentityMismatch);
    }
    Ok(())
}

fn validate_repository_component(value: &str) -> Result<(), GithubWebhookError> {
    if !is_valid_component(value) {
        return Err(GithubWebhookError::InvalidPayload);
    }
    Ok(())
}

pub(crate) fn parse_git_ref(value: String) -> Result<GithubPushRef, GithubWebhookError> {
    if value.len() > MAX_GIT_REF_BYTES {
        return Err(GithubWebhookError::InvalidPayload);
    }
    let (kind, short_name_offset) = if value.starts_with("refs/heads/") {
        (GithubPushRefKind::Branch, "refs/heads/".len())
    } else if value.starts_with("refs/tags/") {
        (GithubPushRefKind::Tag, "refs/tags/".len())
    } else {
        return Err(GithubWebhookError::InvalidPayload);
    };
    let short_name = &value[short_name_offset..];
    if !valid_git_ref_name(short_name) {
        return Err(GithubWebhookError::InvalidPayload);
    }
    Ok(GithubPushRef {
        full: value.into_boxed_str(),
        kind,
        short_name_offset,
    })
}

pub(crate) fn normalize_branch_name(value: String) -> Result<Box<str>, GithubWebhookError> {
    if value
        .len()
        .checked_add("refs/heads/".len())
        .is_none_or(|length| length > MAX_GIT_REF_BYTES)
        || !valid_git_ref_name(&value)
    {
        return Err(GithubWebhookError::InvalidPayload);
    }
    Ok(value.into_boxed_str())
}

fn valid_git_ref_name(short_name: &str) -> bool {
    let invalid = short_name.is_empty()
        || short_name == "@"
        || short_name.starts_with(['/', '.'])
        || short_name.ends_with(['/', '.'])
        || short_name.contains("..")
        || short_name.contains("@{")
        || short_name.contains("//")
        || short_name.split('/').any(|component| {
            component.is_empty()
                || component.starts_with('.')
                || component.ends_with('.')
                || has_ascii_case_insensitive_suffix(component, ".lock")
        })
        || short_name.bytes().any(|byte| {
            byte.is_ascii_control()
                || byte == b' '
                || matches!(byte, b'~' | b'^' | b':' | b'?' | b'*' | b'[' | b'\\')
        });
    !invalid
}

fn validate_commit_range(
    before: &str,
    after: &str,
    created: bool,
    deleted: bool,
) -> Result<(), GithubWebhookError> {
    if !is_commit_sha(before)
        || !is_commit_sha(after)
        || created != (before == ZERO_COMMIT_SHA)
        || deleted != (after == ZERO_COMMIT_SHA)
        || (created && deleted)
    {
        return Err(GithubWebhookError::InvalidPayload);
    }
    Ok(())
}

fn is_commit_sha(value: &str) -> bool {
    if value.len() != 40
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    {
        return false;
    }
    true
}
