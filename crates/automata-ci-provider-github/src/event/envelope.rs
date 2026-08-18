use std::{fmt, num::NonZeroU64};

use automata_ci_blob::{BlobDescriptor, BlobKey, MediaType};
use automata_ci_core::Sha256Digest;
use serde::{Deserialize, Deserializer, Serialize, Serializer, de::Error as _};
use sha2::{Digest as _, Sha256};
use thiserror::Error;

use crate::{
    GithubRepositoryVisibility, GithubWebhookRef, GithubWebhookRefKind, GithubWebhookRepository,
    VerifiedGithubWebhook,
    webhook::{
        GITHUB_AUTHENTICATED_EVENT_MEDIA_TYPE, MAX_GITHUB_WEBHOOK_BODY_BYTES, durable_provider_id,
        parse_git_ref,
    },
};

use super::{
    actor::GithubEventActor,
    merge_group::GithubMergeGroupEventFacts,
    pull_request::GithubPullRequestEventFacts,
    push::GithubPushEventFacts,
    registry::{GITHUB_EVENT_REGISTRY_SCHEMA_V1, GithubEventRegistryV1, GithubWorkflowEventKind},
    repository_dispatch::GithubRepositoryDispatchEventFacts,
};

/// Schema version of the facts-only sealed GitHub event envelope.
pub const GITHUB_EVENT_ENVELOPE_SCHEMA_V1: u16 = 1;
/// Maximum canonical size of a facts-only event envelope.
pub const MAX_GITHUB_EVENT_ENVELOPE_BYTES: usize = 32_768;
/// Durable media type for canonical schema-v1 envelope bytes.
pub const GITHUB_EVENT_ENVELOPE_V1_MEDIA_TYPE: &str =
    "application/vnd.automata.github-event-envelope.v1+json";
/// Content-addressed key prefix used by authenticated raw GitHub event blobs.
pub const GITHUB_RAW_EVENT_OBJECT_KEY_PREFIX: &str = "provider-deliveries/github/event/sha256";

const MAX_DELIVERY_ID_BYTES: usize = 128;
const ENVELOPE_DIGEST_DOMAIN: &[u8] = b"automata.github-event-envelope.v1\0";

/// Complete immutable blob identity of the raw authenticated webhook payload.
///
/// This type never contains the payload bytes. The key must be the canonical
/// content-addressed key derived from the digest, and media type and size are
/// checked against the authenticated-event contract.
#[derive(Clone, Eq, PartialEq)]
pub struct GithubEventRawBlobIdentity(BlobDescriptor);

impl GithubEventRawBlobIdentity {
    /// Validates and wraps an immutable raw-event blob descriptor.
    ///
    /// # Errors
    ///
    /// Rejects an unexpected media type, an empty or excessive body, or an
    /// object key that is not the canonical path for its digest.
    pub fn new(descriptor: BlobDescriptor) -> Result<Self, GithubEventEnvelopeError> {
        validate_raw_descriptor(&descriptor)?;
        Ok(Self(descriptor))
    }

    /// Returns the validated immutable descriptor.
    #[must_use]
    pub const fn descriptor(&self) -> &BlobDescriptor {
        &self.0
    }
}

impl fmt::Debug for GithubEventRawBlobIdentity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GithubEventRawBlobIdentity")
            .field("key", &"[content-addressed]")
            .field("digest", &self.0.digest())
            .field("size", &self.0.size())
            .field("media_type", &self.0.media_type().as_str())
            .finish()
    }
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct RawBlobWire {
    key: String,
    digest: Sha256Digest,
    size: u64,
    media_type: String,
}

impl Serialize for GithubEventRawBlobIdentity {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        RawBlobWire {
            key: self.0.key().as_str().to_owned(),
            digest: self.0.digest(),
            size: self.0.size(),
            media_type: self.0.media_type().as_str().to_owned(),
        }
        .serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for GithubEventRawBlobIdentity {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let wire = RawBlobWire::deserialize(deserializer)?;
        let key = BlobKey::new(wire.key).map_err(D::Error::custom)?;
        let media_type = MediaType::new(wire.media_type).map_err(D::Error::custom)?;
        Self::new(BlobDescriptor::new(key, wire.digest, wire.size, media_type))
            .map_err(D::Error::custom)
    }
}

/// Stable repository facts authenticated by a GitHub webhook body.
#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct GithubEventRepositoryFacts {
    id: NonZeroU64,
    owner_id: NonZeroU64,
    visibility: GithubRepositoryVisibility,
    owner: Box<str>,
    name: Box<str>,
    full_name: Box<str>,
}

impl GithubEventRepositoryFacts {
    pub(crate) fn from_repository(repository: &GithubWebhookRepository) -> Self {
        Self {
            id: repository.id(),
            owner_id: repository.owner_id(),
            visibility: repository.visibility(),
            owner: repository.owner().into(),
            name: repository.name().into(),
            full_name: repository.full_name().into(),
        }
    }

    pub(crate) fn validate(&self) -> bool {
        let (private, visibility) = match self.visibility {
            GithubRepositoryVisibility::Public => (false, "public"),
            GithubRepositoryVisibility::Private => (true, "private"),
        };
        GithubWebhookRepository::from_webhook_fields(
            self.id.get(),
            self.owner_id.get(),
            private,
            visibility,
            self.owner.to_string(),
            self.name.to_string(),
            self.full_name.to_string(),
        )
        .is_ok()
    }

    /// Returns GitHub's stable repository identifier.
    #[must_use]
    pub const fn id(&self) -> NonZeroU64 {
        self.id
    }

    /// Returns GitHub's stable repository-owner identifier.
    #[must_use]
    pub const fn owner_id(&self) -> NonZeroU64 {
        self.owner_id
    }

    /// Returns the authenticated repository visibility.
    #[must_use]
    pub const fn visibility(&self) -> GithubRepositoryVisibility {
        self.visibility
    }

    /// Returns the validated owner login.
    #[must_use]
    pub fn owner(&self) -> &str {
        &self.owner
    }

    /// Returns the validated repository name.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Returns the consistent owner/name identity.
    #[must_use]
    pub fn full_name(&self) -> &str {
        &self.full_name
    }
}

impl fmt::Debug for GithubEventRepositoryFacts {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GithubEventRepositoryFacts")
            .field("id", &self.id)
            .field("owner_id", &self.owner_id)
            .field("visibility", &self.visibility)
            .field("owner", &"[redacted]")
            .field("name", &"[redacted]")
            .field("full_name", &"[redacted]")
            .finish()
    }
}

/// Validated full branch or tag facts in a sealed event envelope.
#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct GithubEventRefFacts {
    full: Box<str>,
    kind: GithubWebhookRefKind,
}

impl GithubEventRefFacts {
    pub(crate) fn from_ref(git_ref: &GithubWebhookRef) -> Self {
        Self {
            full: git_ref.full().into(),
            kind: git_ref.kind(),
        }
    }

    pub(crate) fn validate(&self) -> bool {
        parse_git_ref(self.full.to_string()).is_ok_and(|git_ref| git_ref.kind() == self.kind)
    }

    /// Returns the exact full reference.
    #[must_use]
    pub fn full(&self) -> &str {
        &self.full
    }

    /// Returns the unqualified reference name when the namespace agrees with
    /// the closed kind.
    #[must_use]
    pub fn short_name(&self) -> Option<&str> {
        match self.kind {
            GithubWebhookRefKind::Branch => self.full.strip_prefix("refs/heads/"),
            GithubWebhookRefKind::Tag => self.full.strip_prefix("refs/tags/"),
        }
    }

    /// Returns whether the reference is a branch or tag.
    #[must_use]
    pub const fn kind(&self) -> GithubWebhookRefKind {
        self.kind
    }
}

impl fmt::Debug for GithubEventRefFacts {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GithubEventRefFacts")
            .field("full", &"[redacted]")
            .field("kind", &self.kind)
            .finish()
    }
}

/// Closed facts payload carried by a schema-v1 event envelope.
#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(
    tag = "kind",
    content = "facts",
    rename_all = "snake_case",
    deny_unknown_fields
)]
pub enum GithubEventFacts {
    /// Authenticated push facts.
    Push(GithubPushEventFacts),
    /// Authenticated pull-request facts.
    PullRequest(GithubPullRequestEventFacts),
    /// Authenticated merge-group facts.
    MergeGroup(GithubMergeGroupEventFacts),
    /// Authenticated repository-dispatch facts.
    RepositoryDispatch(GithubRepositoryDispatchEventFacts),
}

impl GithubEventFacts {
    fn from_verified(event: &VerifiedGithubWebhook) -> Result<Self, GithubEventEnvelopeError> {
        match event {
            VerifiedGithubWebhook::Push(event) => {
                Ok(Self::Push(GithubPushEventFacts::from_verified(event)))
            }
            VerifiedGithubWebhook::PullRequest(event) => Ok(Self::PullRequest(
                GithubPullRequestEventFacts::from_verified(event),
            )),
            VerifiedGithubWebhook::MergeGroup(event) => Ok(Self::MergeGroup(
                GithubMergeGroupEventFacts::from_verified(event),
            )),
            VerifiedGithubWebhook::RepositoryDispatch(event) => Ok(Self::RepositoryDispatch(
                GithubRepositoryDispatchEventFacts::from_verified(event),
            )),
            VerifiedGithubWebhook::CheckRun(_) | VerifiedGithubWebhook::CheckSuite(_) => {
                Err(GithubEventEnvelopeError::ControlEvent)
            }
        }
    }

    fn validate(&self) -> bool {
        match self {
            Self::Push(facts) => facts.validate(),
            Self::PullRequest(facts) => facts.validate(),
            Self::MergeGroup(facts) => facts.validate(),
            Self::RepositoryDispatch(facts) => facts.validate(),
        }
    }

    /// Returns the closed workflow-event kind.
    #[must_use]
    pub const fn kind(&self) -> GithubWorkflowEventKind {
        match self {
            Self::Push(_) => GithubWorkflowEventKind::Push,
            Self::PullRequest(_) => GithubWorkflowEventKind::PullRequest,
            Self::MergeGroup(_) => GithubWorkflowEventKind::MergeGroup,
            Self::RepositoryDispatch(_) => GithubWorkflowEventKind::RepositoryDispatch,
        }
    }

    /// Returns the provider activity discriminator when this event has one.
    #[must_use]
    pub fn activity(&self) -> Option<&str> {
        match self {
            Self::Push(_) => None,
            Self::PullRequest(facts) => Some(facts.action().as_str()),
            Self::MergeGroup(facts) => Some(facts.action().as_str()),
            Self::RepositoryDispatch(facts) => Some(facts.event_type()),
        }
    }

    /// Returns the authenticated webhook sender when present.
    #[must_use]
    pub const fn triggering_actor(&self) -> Option<&GithubEventActor> {
        match self {
            Self::Push(facts) => facts.actor(),
            Self::PullRequest(facts) => facts.actor(),
            Self::MergeGroup(facts) => facts.actor(),
            Self::RepositoryDispatch(facts) => facts.actor(),
        }
    }

    /// Returns the distinct source author for events that authenticate one.
    #[must_use]
    pub const fn source_actor(&self) -> Option<&GithubEventActor> {
        match self {
            Self::PullRequest(facts) => facts.source_actor(),
            Self::Push(_) | Self::MergeGroup(_) | Self::RepositoryDispatch(_) => None,
        }
    }

    /// Returns the repository in whose security context the workflow executes.
    #[must_use]
    pub const fn target_repository(&self) -> &GithubEventRepositoryFacts {
        match self {
            Self::Push(facts) => facts.target_repository(),
            Self::PullRequest(facts) => facts.target_repository(),
            Self::MergeGroup(facts) => facts.target_repository(),
            Self::RepositoryDispatch(facts) => facts.target_repository(),
        }
    }

    /// Returns the authoritative source repository, or `None` when merge-group
    /// constituent sources require later provider evidence.
    #[must_use]
    pub const fn source_repository(&self) -> Option<&GithubEventRepositoryFacts> {
        match self {
            Self::Push(facts) => Some(facts.target_repository()),
            Self::PullRequest(facts) => Some(facts.source_repository()),
            Self::MergeGroup(_) => None,
            Self::RepositoryDispatch(facts) => Some(facts.target_repository()),
        }
    }

    /// Returns the authenticated source/target fork relationship when known.
    #[must_use]
    pub fn is_fork(&self) -> Option<bool> {
        match self {
            Self::Push(_) | Self::RepositoryDispatch(_) => Some(false),
            Self::PullRequest(facts) => Some(facts.is_fork()),
            Self::MergeGroup(_) => None,
        }
    }
}

impl fmt::Debug for GithubEventFacts {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GithubEventFacts")
            .field("kind", &self.kind())
            .field("facts", &"[redacted]")
            .finish()
    }
}

#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct EncodedEnvelopeV1 {
    schema: u16,
    registry_schema: u16,
    delivery_id: Box<str>,
    installation_id: NonZeroU64,
    raw_event: GithubEventRawBlobIdentity,
    event: GithubEventFacts,
}

/// Canonical, facts-only, content-addressed GitHub workflow-event envelope.
///
/// Construction is restricted to a verified webhook or strict canonical
/// rehydration. Raw webhook bytes are never retained; only their immutable blob
/// identity is present. The canonical bytes and their domain-separated digest
/// are cached so persistence can atomically bind the exact schema projection.
#[derive(Clone, Eq, PartialEq)]
pub struct GithubSealedEventEnvelopeV1 {
    encoded: EncodedEnvelopeV1,
    canonical_bytes: Box<[u8]>,
    digest: Sha256Digest,
}

impl GithubSealedEventEnvelopeV1 {
    /// Seals a verified workflow event against its immutable raw-blob identity.
    ///
    /// # Errors
    ///
    /// Rejects control events, registry mismatches, invalid blob identity,
    /// digest or size mismatches, invalid facts, and excessive encoding size.
    pub fn seal(
        event: &VerifiedGithubWebhook,
        raw_event: BlobDescriptor,
    ) -> Result<Self, GithubEventEnvelopeError> {
        GithubEventRegistryV1::validate()
            .map_err(|_| GithubEventEnvelopeError::RegistryInvariant)?;
        let facts = GithubEventFacts::from_verified(event)?;
        let registration = GithubEventRegistryV1::lookup(event.event_name())
            .map_err(|_| GithubEventEnvelopeError::UnregisteredEvent)?;
        if registration.kind() != facts.kind() {
            return Err(GithubEventEnvelopeError::EventIdentityMismatch);
        }
        if raw_event.digest() != Sha256Digest::from_bytes(*event.body_sha256().as_bytes()) {
            return Err(GithubEventEnvelopeError::RawDigestMismatch);
        }
        let observed_size = u64::try_from(event.raw_body().len())
            .map_err(|_| GithubEventEnvelopeError::RawSizeMismatch)?;
        if raw_event.size() != observed_size {
            return Err(GithubEventEnvelopeError::RawSizeMismatch);
        }
        let raw_event = GithubEventRawBlobIdentity::new(raw_event)?;
        let encoded = EncodedEnvelopeV1 {
            schema: GITHUB_EVENT_ENVELOPE_SCHEMA_V1,
            registry_schema: GITHUB_EVENT_REGISTRY_SCHEMA_V1,
            delivery_id: event.delivery_id().into(),
            installation_id: event.installation_id(),
            raw_event,
            event: facts,
        };
        Self::from_validated_encoded(encoded)
    }

    /// Rehydrates exact canonical bytes and validates their external digest.
    ///
    /// # Errors
    ///
    /// Fails closed for excessive, malformed, duplicate, unknown, noncanonical,
    /// prior/future-schema, invalid-fact, or wrong-digest encodings.
    pub fn from_canonical_bytes(
        bytes: &[u8],
        expected_digest: Sha256Digest,
    ) -> Result<Self, GithubEventEnvelopeError> {
        if bytes.is_empty() || bytes.len() > MAX_GITHUB_EVENT_ENVELOPE_BYTES {
            return Err(GithubEventEnvelopeError::EnvelopeSize);
        }
        let encoded: EncodedEnvelopeV1 = serde_json::from_slice(bytes)
            .map_err(|_| GithubEventEnvelopeError::MalformedEncoding)?;
        validate_encoded(&encoded)?;
        let canonical =
            serde_json::to_vec(&encoded).map_err(|_| GithubEventEnvelopeError::EncodingFailure)?;
        if canonical.as_slice() != bytes {
            return Err(GithubEventEnvelopeError::NoncanonicalEncoding);
        }
        let digest = envelope_digest(bytes);
        if digest != expected_digest {
            return Err(GithubEventEnvelopeError::EnvelopeDigestMismatch);
        }
        Ok(Self {
            encoded,
            canonical_bytes: canonical.into_boxed_slice(),
            digest,
        })
    }

    fn from_validated_encoded(
        encoded: EncodedEnvelopeV1,
    ) -> Result<Self, GithubEventEnvelopeError> {
        validate_encoded(&encoded)?;
        let canonical_bytes =
            serde_json::to_vec(&encoded).map_err(|_| GithubEventEnvelopeError::EncodingFailure)?;
        if canonical_bytes.len() > MAX_GITHUB_EVENT_ENVELOPE_BYTES {
            return Err(GithubEventEnvelopeError::EnvelopeSize);
        }
        let digest = envelope_digest(&canonical_bytes);
        Ok(Self {
            encoded,
            canonical_bytes: canonical_bytes.into_boxed_slice(),
            digest,
        })
    }

    /// Returns the envelope schema version.
    #[must_use]
    pub const fn schema(&self) -> u16 {
        self.encoded.schema
    }

    /// Returns the exact registry schema used to interpret the facts.
    #[must_use]
    pub const fn registry_schema(&self) -> u16 {
        self.encoded.registry_schema
    }

    /// Returns the provider delivery identifier outside the body MAC.
    #[must_use]
    pub fn delivery_id(&self) -> &str {
        &self.encoded.delivery_id
    }

    /// Returns the authenticated GitHub App installation identifier.
    #[must_use]
    pub const fn installation_id(&self) -> NonZeroU64 {
        self.encoded.installation_id
    }

    /// Returns the immutable raw-event blob identity.
    #[must_use]
    pub const fn raw_event(&self) -> &GithubEventRawBlobIdentity {
        &self.encoded.raw_event
    }

    /// Returns the closed normalized event facts.
    #[must_use]
    pub const fn event(&self) -> &GithubEventFacts {
        &self.encoded.event
    }

    /// Returns exact canonical envelope bytes for immutable persistence.
    #[must_use]
    pub fn canonical_bytes(&self) -> &[u8] {
        &self.canonical_bytes
    }

    /// Returns the domain-separated SHA-256 of the canonical envelope bytes.
    #[must_use]
    pub const fn digest(&self) -> Sha256Digest {
        self.digest
    }
}

impl fmt::Debug for GithubSealedEventEnvelopeV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GithubSealedEventEnvelopeV1")
            .field("schema", &self.encoded.schema)
            .field("registry_schema", &self.encoded.registry_schema)
            .field("delivery_id", &"[redacted]")
            .field("installation_id", &self.encoded.installation_id)
            .field("raw_event", &self.encoded.raw_event)
            .field("event", &self.encoded.event)
            .field("canonical_bytes", &"[redacted]")
            .field("digest", &self.digest)
            .finish()
    }
}

/// Sanitized schema-v1 event-envelope failure.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum GithubEventEnvelopeError {
    /// A Check Run or Check Suite control was passed to the workflow-event boundary.
    #[error("GitHub control events cannot be sealed as workflow events")]
    ControlEvent,
    /// The provider event name is not in the closed schema-v1 registry.
    #[error("the GitHub workflow event is not registered")]
    UnregisteredEvent,
    /// The compiled registry violates its completeness contract.
    #[error("the GitHub workflow event registry is invalid")]
    RegistryInvariant,
    /// Header, normalized variant, and closed event kind disagree.
    #[error("the GitHub workflow event identity is inconsistent")]
    EventIdentityMismatch,
    /// The raw blob has an unexpected durable media type.
    #[error("the raw GitHub event blob media type is invalid")]
    RawMediaType,
    /// The raw blob size is empty, excessive, or differs from authenticated bytes.
    #[error("the raw GitHub event blob size is invalid")]
    RawSizeMismatch,
    /// The raw blob digest differs from the authenticated body digest.
    #[error("the raw GitHub event blob digest is invalid")]
    RawDigestMismatch,
    /// The raw blob key is not the canonical path for its digest.
    #[error("the raw GitHub event blob key is invalid")]
    RawObjectKey,
    /// Normalized facts violate their closed event-kind invariants.
    #[error("the GitHub event facts are invalid")]
    InvalidFacts,
    /// The encoded envelope uses a prior or future envelope schema.
    #[error("the GitHub event envelope schema is unsupported")]
    UnsupportedSchema,
    /// The encoded envelope uses a prior or future registry schema.
    #[error("the GitHub event registry schema is unsupported")]
    UnsupportedRegistrySchema,
    /// The encoded envelope is empty or exceeds its ceiling.
    #[error("the GitHub event envelope size is invalid")]
    EnvelopeSize,
    /// JSON is malformed, ambiguous, duplicated, or names an unknown kind.
    #[error("the GitHub event envelope encoding is malformed")]
    MalformedEncoding,
    /// JSON is valid but not the exact canonical serialization.
    #[error("the GitHub event envelope encoding is not canonical")]
    NoncanonicalEncoding,
    /// Canonical bytes differ from the externally persisted envelope digest.
    #[error("the GitHub event envelope digest does not match")]
    EnvelopeDigestMismatch,
    /// Canonical serialization unexpectedly failed.
    #[error("the GitHub event envelope could not be encoded")]
    EncodingFailure,
}

fn validate_encoded(encoded: &EncodedEnvelopeV1) -> Result<(), GithubEventEnvelopeError> {
    if encoded.schema != GITHUB_EVENT_ENVELOPE_SCHEMA_V1 {
        return Err(GithubEventEnvelopeError::UnsupportedSchema);
    }
    if encoded.registry_schema != GITHUB_EVENT_REGISTRY_SCHEMA_V1 {
        return Err(GithubEventEnvelopeError::UnsupportedRegistrySchema);
    }
    if !valid_delivery_id(&encoded.delivery_id)
        || durable_provider_id(encoded.installation_id.get()).is_err()
    {
        return Err(GithubEventEnvelopeError::InvalidFacts);
    }
    validate_raw_descriptor(encoded.raw_event.descriptor())?;
    GithubEventRegistryV1::validate().map_err(|_| GithubEventEnvelopeError::RegistryInvariant)?;
    let registration = GithubEventRegistryV1::lookup(encoded.event.kind().as_str())
        .map_err(|_| GithubEventEnvelopeError::UnregisteredEvent)?;
    if registration.kind() != encoded.event.kind() || !encoded.event.validate() {
        return Err(GithubEventEnvelopeError::InvalidFacts);
    }
    Ok(())
}

fn validate_raw_descriptor(descriptor: &BlobDescriptor) -> Result<(), GithubEventEnvelopeError> {
    if descriptor.media_type().as_str() != GITHUB_AUTHENTICATED_EVENT_MEDIA_TYPE {
        return Err(GithubEventEnvelopeError::RawMediaType);
    }
    if descriptor.size() == 0
        || descriptor.size() > u64::try_from(MAX_GITHUB_WEBHOOK_BODY_BYTES).unwrap_or(u64::MAX)
    {
        return Err(GithubEventEnvelopeError::RawSizeMismatch);
    }
    let expected_key = format!(
        "{GITHUB_RAW_EVENT_OBJECT_KEY_PREFIX}/{}.json",
        descriptor.digest()
    );
    if descriptor.key().as_str() != expected_key {
        return Err(GithubEventEnvelopeError::RawObjectKey);
    }
    Ok(())
}

fn valid_delivery_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_DELIVERY_ID_BYTES
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
}

fn envelope_digest(bytes: &[u8]) -> Sha256Digest {
    let mut digest = Sha256::new();
    digest.update(ENVELOPE_DIGEST_DOMAIN);
    digest.update(bytes);
    Sha256Digest::from_bytes(digest.finalize().into())
}
