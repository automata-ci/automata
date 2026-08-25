use std::{fmt, num::NonZeroU64};

use bytes::{Bytes, BytesMut};
use reqwest::header::{HeaderMap, HeaderValue};
use ring::{digest, hmac};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::repository_path::{has_ascii_case_insensitive_suffix, is_valid_component};

pub use crate::webhook_event::push::{GithubWebhookEventMetadata, VerifiedGithubPush};

/// Maximum exact webhook body accepted by workflow admission.
pub const MAX_GITHUB_WEBHOOK_BODY_BYTES: usize = 26_214_400;
/// Maximum configured GitHub webhook secret size.
pub const MAX_GITHUB_WEBHOOK_SECRET_BYTES: usize = 16_384;
/// Maximum commit summaries GitHub documents in one push webhook.
pub const MAX_GITHUB_PUSH_COMMITS: usize = 2_048;
/// Exact durable media type for a authenticated GitHub event.
pub const GITHUB_AUTHENTICATED_EVENT_MEDIA_TYPE: &str =
    "application/vnd.automata.github-authenticated-event+json";

/// GitHub's SHA-256 webhook signature header.
pub const X_HUB_SIGNATURE_256: &str = "x-hub-signature-256";
/// GitHub's provider event-name header.
pub const X_GITHUB_EVENT: &str = "x-github-event";
/// GitHub's provider delivery identifier header.
pub const X_GITHUB_DELIVERY: &str = "x-github-delivery";

const MAX_DELIVERY_ID_BYTES: usize = 128;
const MAX_GIT_REF_BYTES: usize = 1_024;
const SHA256_SIGNATURE_PREFIX: &[u8] = b"sha256=";
const WEBHOOK_VERIFIER_FINGERPRINT_DOMAIN: &[u8] =
    b"automata.store.github-webhook-verifier-fingerprint.v1\0";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum GithubWebhookLimitRejection {
    Secret,
    DeliveryId,
    GitRef,
}

const fn webhook_secret_byte_rejection(observed: usize) -> Option<GithubWebhookLimitRejection> {
    if observed > MAX_GITHUB_WEBHOOK_SECRET_BYTES {
        return Some(GithubWebhookLimitRejection::Secret);
    }
    None
}

const fn delivery_id_byte_rejection(observed: usize) -> Option<GithubWebhookLimitRejection> {
    if observed > MAX_DELIVERY_ID_BYTES {
        return Some(GithubWebhookLimitRejection::DeliveryId);
    }
    None
}

const fn git_ref_byte_rejection(observed: usize) -> Option<GithubWebhookLimitRejection> {
    if observed > MAX_GIT_REF_BYTES {
        return Some(GithubWebhookLimitRejection::GitRef);
    }
    None
}

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

/// Durable coordinates for any supported authenticated GitHub event.
///
/// The media type and explicit event name prevent rows from being silently
/// reinterpreted as another event kind. Construction is inert; only
/// [`rehydrate_stored_authenticated_github_webhook`] validates and consumes
/// the coordinates.
pub struct StoredAuthenticatedGithubWebhook {
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

impl StoredAuthenticatedGithubWebhook {
    /// Binds exact stored bytes to the complete canonical durable envelope.
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

impl fmt::Debug for StoredAuthenticatedGithubWebhook {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("StoredAuthenticatedGithubWebhook")
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

/// Rehydrates one authenticated GitHub event envelope.
///
/// Media type, size, digest, event name, delivery identity, and repository
/// coordinates are verified before normalized evidence is returned. The body
/// is not authenticated again: callers must supply only coordinates committed
/// by the original HMAC acceptance transaction.
///
/// # Errors
///
/// Rejects unknown media, invalid durable coordinates, digest drift,
/// duplicate or malformed JSON, unsupported events, and payload identity drift.
pub fn rehydrate_stored_authenticated_github_webhook(
    evidence: StoredAuthenticatedGithubWebhook,
) -> Result<crate::VerifiedGithubWebhook, GithubStoredWebhookError> {
    if evidence.media_type.as_ref() != GITHUB_AUTHENTICATED_EVENT_MEDIA_TYPE {
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
    pub(crate) fn from_authenticated_parts(
        delivery_id: &[u8],
        event_name: &[u8],
        raw_body: Bytes,
    ) -> Result<Self, GithubWebhookError> {
        if raw_body.len() > MAX_GITHUB_WEBHOOK_BODY_BYTES
            || !valid_delivery_id(delivery_id)
            || !valid_event_name(event_name)
        {
            return Err(GithubWebhookError::InvalidHeaders);
        }
        let delivery_id = std::str::from_utf8(delivery_id)
            .map_err(|_| GithubWebhookError::InvalidHeaders)?
            .into();
        let event_name = std::str::from_utf8(event_name)
            .map_err(|_| GithubWebhookError::InvalidHeaders)?
            .into();
        let body_sha256 = webhook_body_digest(&raw_body);
        Ok(Self {
            delivery_id,
            event_name,
            raw_body,
            body_sha256,
        })
    }

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
            "repository_dispatch" => crate::webhook_event::normalize_repository_dispatch(self)
                .map(crate::VerifiedGithubWebhook::RepositoryDispatch),
            "check_run" => crate::webhook_event::normalize_check_run(self)
                .map(crate::VerifiedGithubWebhook::CheckRun),
            "check_suite" => crate::webhook_event::normalize_check_suite(self)
                .map(crate::VerifiedGithubWebhook::CheckSuite),
            _ => Err(GithubWebhookError::UnsupportedEvent),
        }
    }

    fn into_verified_push(self) -> Result<VerifiedGithubPush, GithubWebhookError> {
        if self.event_name.as_ref() != "push" {
            return Err(GithubWebhookError::UnsupportedEvent);
        }
        crate::webhook_event::push::decode_push(self)
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
        if secret.is_empty() || webhook_secret_byte_rejection(secret.len()).is_some() {
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
            return Err(GithubWebhookError::BodyTooLarge); // stable webhook-body-limit reason
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
            delivery_id: headers.delivery_id,
            event_name: headers.event_name,
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
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum GithubWebhookRefKind {
    /// A `refs/heads/...` branch reference.
    Branch,
    /// A `refs/tags/...` tag reference.
    Tag,
}

/// Validated, unambiguous full GitHub push reference.
#[derive(Clone, Eq, PartialEq)]
pub struct GithubWebhookRef {
    full: Box<str>,
    kind: GithubWebhookRefKind,
    short_name_offset: usize,
}

impl GithubWebhookRef {
    /// Returns the exact canonical full reference.
    pub fn full(&self) -> &str {
        &self.full
    }

    /// Returns the branch or tag name below its canonical namespace.
    pub fn short_name(&self) -> &str {
        &self.full[self.short_name_offset..]
    }

    /// Returns whether this is a branch or tag reference.
    pub const fn kind(&self) -> GithubWebhookRefKind {
        self.kind
    }
}

impl fmt::Debug for GithubWebhookRef {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GithubWebhookRef")
            .field("kind", &self.kind)
            .field("full", &"[redacted]")
            .finish_non_exhaustive()
    }
}

/// Normalized repository identity from the authenticated push body.
#[derive(Clone, Eq, PartialEq)]
pub struct GithubWebhookRepository {
    id: NonZeroU64,
    owner_id: NonZeroU64,
    visibility: GithubRepositoryVisibility,
    owner: Box<str>,
    name: Box<str>,
    full_name: Box<str>,
}

impl GithubWebhookRepository {
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

impl fmt::Debug for GithubWebhookRepository {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GithubWebhookRepository")
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
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum GithubRepositoryVisibility {
    /// The exact repository is anonymously readable.
    Public,
    /// The exact repository requires installation source authority.
    Private,
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

/// Sanitized authenticated-event rehydration failures.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum GithubStoredWebhookError {
    /// The durable object does not use the canonical generic event media type.
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
    /// The canonical envelope names an unsupported event.
    #[error("the stored GitHub event is unsupported")]
    UnsupportedEvent,
    /// Stored provider fields violate strict event invariants.
    #[error("the stored GitHub event payload is inconsistent")]
    InvalidPayload,
    /// The normalized body identity differs from durable routing evidence.
    #[error("the stored GitHub event identity does not match its payload")]
    IdentityMismatch,
}

struct VerifiedHeaders {
    signature: [u8; 32],
    event_name: Box<str>,
    delivery_id: Box<str>,
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
            event_name,
            delivery_id,
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
        && delivery_id_byte_rejection(value.len()).is_none()
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
    for (target, pair) in signature.iter_mut().zip(encoded.as_chunks::<2>().0) {
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

fn validate_repository_component(value: &str) -> Result<(), GithubWebhookError> {
    if !is_valid_component(value) {
        return Err(GithubWebhookError::InvalidPayload);
    }
    Ok(())
}

pub(crate) fn parse_git_ref(value: String) -> Result<GithubWebhookRef, GithubWebhookError> {
    if git_ref_byte_rejection(value.len()).is_some() {
        return Err(GithubWebhookError::InvalidPayload);
    }
    let (kind, short_name_offset) = if value.starts_with("refs/heads/") {
        (GithubWebhookRefKind::Branch, "refs/heads/".len())
    } else if value.starts_with("refs/tags/") {
        (GithubWebhookRefKind::Tag, "refs/tags/".len())
    } else {
        return Err(GithubWebhookError::InvalidPayload);
    };
    let short_name = &value[short_name_offset..];
    if !valid_git_ref_name(short_name) {
        return Err(GithubWebhookError::InvalidPayload);
    }
    Ok(GithubWebhookRef {
        full: value.into_boxed_str(),
        kind,
        short_name_offset,
    })
}

pub(crate) fn normalize_branch_name(value: String) -> Result<Box<str>, GithubWebhookError> {
    if value
        .len()
        .checked_add("refs/heads/".len())
        .is_none_or(|length| git_ref_byte_rejection(length).is_some())
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

#[cfg(test)]
mod limit_contract_tests {
    use super::*;

    #[test]
    fn webhook_secret_byte_limit_has_exact_boundaries() {
        assert_eq!(
            webhook_secret_byte_rejection(MAX_GITHUB_WEBHOOK_SECRET_BYTES - 1),
            None
        );
        assert_eq!(
            webhook_secret_byte_rejection(MAX_GITHUB_WEBHOOK_SECRET_BYTES),
            None
        );
        assert_eq!(
            webhook_secret_byte_rejection(MAX_GITHUB_WEBHOOK_SECRET_BYTES + 1),
            Some(GithubWebhookLimitRejection::Secret)
        );
    }

    #[test]
    fn delivery_id_byte_limit_has_exact_boundaries() {
        assert_eq!(delivery_id_byte_rejection(MAX_DELIVERY_ID_BYTES - 1), None);
        assert_eq!(delivery_id_byte_rejection(MAX_DELIVERY_ID_BYTES), None);
        assert_eq!(
            delivery_id_byte_rejection(MAX_DELIVERY_ID_BYTES + 1),
            Some(GithubWebhookLimitRejection::DeliveryId)
        );
    }

    #[test]
    fn git_ref_byte_limit_has_exact_boundaries() {
        assert_eq!(git_ref_byte_rejection(MAX_GIT_REF_BYTES - 1), None);
        assert_eq!(git_ref_byte_rejection(MAX_GIT_REF_BYTES), None);
        assert_eq!(
            git_ref_byte_rejection(MAX_GIT_REF_BYTES + 1),
            Some(GithubWebhookLimitRejection::GitRef)
        );
    }
}
