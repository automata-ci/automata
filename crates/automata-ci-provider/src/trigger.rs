//! Provider-neutral, authenticated webhook trigger facts.

use std::fmt;

use automata_ci_core::{GitObjectId, Sha256Digest};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use thiserror::Error;

use crate::{
    ExternalChangeId, ExternalMergeQueueId, ExternalRepositoryIdentity, ExternalSubjectIdentity,
    ProviderDefaultBranch, ProviderRepositoryPath, RepositoryVisibility,
};

/// Maximum UTF-8 bytes in a provider-native event or activity name.
pub const MAX_PROVIDER_EVENT_NAME_BYTES: usize = 128;
/// Maximum canonical bytes retained from repository-dispatch input.
pub const MAX_PROVIDER_DISPATCH_INPUT_BYTES: usize = 32 * 1_024;
/// Maximum canonical bytes in one normalized trigger document.
pub const MAX_NORMALIZED_TRIGGER_BYTES: usize = 64 * 1_024;

const TRIGGER_DIGEST_DOMAIN: &[u8] = b"automata.provider.normalized-trigger.v1\0";
const DISPATCH_INPUT_DIGEST_DOMAIN: &[u8] = b"automata.provider.dispatch-input.v1\0";

/// Bounded provider-native event name retained as authenticated evidence.
#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(try_from = "String", into = "String")]
pub struct ProviderEventName(String);

impl ProviderEventName {
    /// Validates a nonempty, trimmed event name without control characters.
    ///
    /// # Errors
    ///
    /// Rejects empty, untrimmed, control-bearing, or oversized names.
    pub fn new(value: impl Into<String>) -> Result<Self, ProviderTriggerError> {
        let value = value.into();
        validate_text(&value, MAX_PROVIDER_EVENT_NAME_BYTES)?;
        Ok(Self(value))
    }

    /// Returns the exact provider-native event name.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for ProviderEventName {
    type Error = ProviderTriggerError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl From<ProviderEventName> for String {
    fn from(value: ProviderEventName) -> Self {
        value.0
    }
}

/// Complete authenticated repository facts used by admission.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderRepository {
    identity: ExternalRepositoryIdentity,
    path: ProviderRepositoryPath,
    visibility: RepositoryVisibility,
}

impl ProviderRepository {
    /// Binds stable repository identity to its authenticated path and visibility.
    #[must_use]
    pub const fn new(
        identity: ExternalRepositoryIdentity,
        path: ProviderRepositoryPath,
        visibility: RepositoryVisibility,
    ) -> Self {
        Self {
            identity,
            path,
            visibility,
        }
    }

    /// Returns the instance-scoped stable repository identity.
    #[must_use]
    pub const fn identity(&self) -> &ExternalRepositoryIdentity {
        &self.identity
    }

    /// Returns the authenticated provider path retained for display and audit.
    #[must_use]
    pub const fn path(&self) -> &ProviderRepositoryPath {
        &self.path
    }

    /// Returns authenticated repository visibility.
    #[must_use]
    pub const fn visibility(&self) -> RepositoryVisibility {
        self.visibility
    }
}

/// Provider-independent Git reference class.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderGitRefKind {
    /// A reference below `refs/heads/`.
    Branch,
    /// A reference below `refs/tags/`.
    Tag,
}

/// Exact full branch or tag reference authenticated by a provider.
#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(try_from = "UncheckedProviderGitRef")]
pub struct ProviderGitRef {
    full: String,
    kind: ProviderGitRefKind,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct UncheckedProviderGitRef {
    full: String,
    kind: ProviderGitRefKind,
}

impl ProviderGitRef {
    /// Validates a full branch or tag reference and its declared namespace.
    ///
    /// # Errors
    ///
    /// Rejects an invalid Git ref, unsupported namespace, or mismatched kind.
    pub fn new(
        full: impl Into<String>,
        kind: ProviderGitRefKind,
    ) -> Result<Self, ProviderTriggerError> {
        let full = full.into();
        let prefix = match kind {
            ProviderGitRefKind::Branch => "refs/heads/",
            ProviderGitRefKind::Tag => "refs/tags/",
        };
        let Some(short) = full.strip_prefix(prefix) else {
            return Err(ProviderTriggerError::InvalidGitRef);
        };
        if !valid_ref_name(short) {
            return Err(ProviderTriggerError::InvalidGitRef);
        }
        if kind == ProviderGitRefKind::Branch
            && ProviderDefaultBranch::new(short.to_owned()).is_err()
        {
            return Err(ProviderTriggerError::InvalidGitRef);
        }
        Ok(Self { full, kind })
    }

    /// Returns the full `refs/heads/...` or `refs/tags/...` name.
    #[must_use]
    pub fn full(&self) -> &str {
        &self.full
    }

    /// Returns the unqualified ref name.
    #[must_use]
    pub fn short_name(&self) -> &str {
        match self.kind {
            ProviderGitRefKind::Branch => &self.full["refs/heads/".len()..],
            ProviderGitRefKind::Tag => &self.full["refs/tags/".len()..],
        }
    }

    /// Returns whether this is a branch or tag.
    #[must_use]
    pub const fn kind(&self) -> ProviderGitRefKind {
        self.kind
    }
}

impl TryFrom<UncheckedProviderGitRef> for ProviderGitRef {
    type Error = ProviderTriggerError;

    fn try_from(value: UncheckedProviderGitRef) -> Result<Self, Self::Error> {
        Self::new(value.full, value.kind)
    }
}

/// Authenticated push trigger.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(try_from = "UncheckedPushTrigger")]
pub struct PushTrigger {
    repository: ProviderRepository,
    git_ref: ProviderGitRef,
    before: Option<GitObjectId>,
    after: Option<GitObjectId>,
    forced: bool,
    actor: Option<ExternalSubjectIdentity>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct UncheckedPushTrigger {
    repository: ProviderRepository,
    git_ref: ProviderGitRef,
    before: Option<GitObjectId>,
    after: Option<GitObjectId>,
    forced: bool,
    actor: Option<ExternalSubjectIdentity>,
}

impl PushTrigger {
    /// Constructs a push, creation, or deletion with exact object identities.
    ///
    /// # Errors
    ///
    /// Rejects absent before and after identities, algorithm drift, or identities
    /// belonging to another provider instance.
    pub fn new(
        repository: ProviderRepository,
        git_ref: ProviderGitRef,
        before: Option<GitObjectId>,
        after: Option<GitObjectId>,
        forced: bool,
        actor: Option<ExternalSubjectIdentity>,
    ) -> Result<Self, ProviderTriggerError> {
        if before.is_none() && after.is_none() {
            return Err(ProviderTriggerError::MissingObjectIdentity);
        }
        if before
            .zip(after)
            .is_some_and(|(before, after)| before.algorithm() != after.algorithm())
        {
            return Err(ProviderTriggerError::ObjectAlgorithmMismatch);
        }
        validate_subject_instance(repository.identity(), actor.as_ref())?;
        Ok(Self {
            repository,
            git_ref,
            before,
            after,
            forced,
            actor,
        })
    }

    /// Returns the repository receiving the reference update.
    #[must_use]
    pub const fn repository(&self) -> &ProviderRepository {
        &self.repository
    }

    /// Returns the updated reference.
    #[must_use]
    pub const fn git_ref(&self) -> &ProviderGitRef {
        &self.git_ref
    }

    /// Returns the pre-update object, or absence for creation.
    #[must_use]
    pub const fn before(&self) -> Option<GitObjectId> {
        self.before
    }

    /// Returns the post-update object, or absence for deletion.
    #[must_use]
    pub const fn after(&self) -> Option<GitObjectId> {
        self.after
    }

    /// Returns whether the provider authenticated a forced update.
    #[must_use]
    pub const fn forced(&self) -> bool {
        self.forced
    }

    /// Returns the triggering actor when supplied by the provider.
    #[must_use]
    pub const fn actor(&self) -> Option<&ExternalSubjectIdentity> {
        self.actor.as_ref()
    }
}

impl TryFrom<UncheckedPushTrigger> for PushTrigger {
    type Error = ProviderTriggerError;

    fn try_from(value: UncheckedPushTrigger) -> Result<Self, Self::Error> {
        Self::new(
            value.repository,
            value.git_ref,
            value.before,
            value.after,
            value.forced,
            value.actor,
        )
    }
}

/// Provider-independent pull-request lifecycle activity.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PullRequestActivity {
    /// A change was opened.
    Opened,
    /// A previously closed change was reopened.
    Reopened,
    /// The source ref changed.
    Synchronized,
    /// The change was closed without merging.
    Closed,
    /// The change was merged.
    Merged,
    /// A draft became ready for review.
    ReadyForReview,
    /// A reviewable change became a draft.
    ConvertedToDraft,
    /// Metadata affecting workflow selection changed.
    MetadataChanged,
}

/// Authenticated pull-request or merge-request trigger.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(try_from = "UncheckedPullRequestTrigger")]
pub struct PullRequestTrigger {
    change_id: ExternalChangeId,
    activity: PullRequestActivity,
    target_repository: ProviderRepository,
    source_repository: ProviderRepository,
    base_ref: ProviderGitRef,
    head_ref: ProviderGitRef,
    base_object: GitObjectId,
    head_object: GitObjectId,
    merge_object: Option<GitObjectId>,
    draft: bool,
    actor: Option<ExternalSubjectIdentity>,
    author: Option<ExternalSubjectIdentity>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct UncheckedPullRequestTrigger {
    change_id: ExternalChangeId,
    activity: PullRequestActivity,
    target_repository: ProviderRepository,
    source_repository: ProviderRepository,
    base_ref: ProviderGitRef,
    head_ref: ProviderGitRef,
    base_object: GitObjectId,
    head_object: GitObjectId,
    merge_object: Option<GitObjectId>,
    draft: bool,
    actor: Option<ExternalSubjectIdentity>,
    author: Option<ExternalSubjectIdentity>,
}

impl PullRequestTrigger {
    /// Constructs exact source and target facts for one change event.
    ///
    /// # Errors
    ///
    /// Rejects cross-instance evidence, non-branch refs, or object-algorithm drift.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        change_id: ExternalChangeId,
        activity: PullRequestActivity,
        target_repository: ProviderRepository,
        source_repository: ProviderRepository,
        base_ref: ProviderGitRef,
        head_ref: ProviderGitRef,
        base_object: GitObjectId,
        head_object: GitObjectId,
        merge_object: Option<GitObjectId>,
        draft: bool,
        actor: Option<ExternalSubjectIdentity>,
        author: Option<ExternalSubjectIdentity>,
    ) -> Result<Self, ProviderTriggerError> {
        if base_ref.kind() != ProviderGitRefKind::Branch
            || head_ref.kind() != ProviderGitRefKind::Branch
        {
            return Err(ProviderTriggerError::InvalidGitRef);
        }
        let instance_id = target_repository.identity().instance_id();
        if source_repository.identity().instance_id() != instance_id
            || actor
                .as_ref()
                .is_some_and(|value| value.instance_id() != instance_id)
            || author
                .as_ref()
                .is_some_and(|value| value.instance_id() != instance_id)
        {
            return Err(ProviderTriggerError::InstanceMismatch);
        }
        if base_object.algorithm() != head_object.algorithm()
            || merge_object.is_some_and(|value| value.algorithm() != head_object.algorithm())
        {
            return Err(ProviderTriggerError::ObjectAlgorithmMismatch);
        }
        Ok(Self {
            change_id,
            activity,
            target_repository,
            source_repository,
            base_ref,
            head_ref,
            base_object,
            head_object,
            merge_object,
            draft,
            actor,
            author,
        })
    }

    /// Returns the provider-native change identity.
    #[must_use]
    pub const fn change_id(&self) -> &ExternalChangeId {
        &self.change_id
    }

    /// Returns the normalized lifecycle activity.
    #[must_use]
    pub const fn activity(&self) -> PullRequestActivity {
        self.activity
    }

    /// Returns the repository in whose security context workflows execute.
    #[must_use]
    pub const fn target_repository(&self) -> &ProviderRepository {
        &self.target_repository
    }

    /// Returns the authoritative source repository.
    #[must_use]
    pub const fn source_repository(&self) -> &ProviderRepository {
        &self.source_repository
    }

    /// Returns the exact target object.
    #[must_use]
    pub const fn base_object(&self) -> GitObjectId {
        self.base_object
    }

    /// Returns the exact source object.
    #[must_use]
    pub const fn head_object(&self) -> GitObjectId {
        self.head_object
    }

    /// Returns an authenticated merge candidate when the provider supplied one.
    #[must_use]
    pub const fn merge_object(&self) -> Option<GitObjectId> {
        self.merge_object
    }

    /// Returns whether the change was a draft at delivery time.
    #[must_use]
    pub const fn draft(&self) -> bool {
        self.draft
    }
}

impl TryFrom<UncheckedPullRequestTrigger> for PullRequestTrigger {
    type Error = ProviderTriggerError;

    fn try_from(value: UncheckedPullRequestTrigger) -> Result<Self, Self::Error> {
        Self::new(
            value.change_id,
            value.activity,
            value.target_repository,
            value.source_repository,
            value.base_ref,
            value.head_ref,
            value.base_object,
            value.head_object,
            value.merge_object,
            value.draft,
            value.actor,
            value.author,
        )
    }
}

/// Provider-independent merge-queue lifecycle activity.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MergeQueueActivity {
    /// A merge candidate entered or changed in the queue.
    Queued,
    /// A candidate was removed or invalidated.
    Removed,
}

/// Authenticated merge-queue candidate trigger.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(try_from = "UncheckedMergeQueueTrigger")]
pub struct MergeQueueTrigger {
    queue_id: ExternalMergeQueueId,
    activity: MergeQueueActivity,
    repository: ProviderRepository,
    target_ref: ProviderGitRef,
    target_object: GitObjectId,
    candidate_object: GitObjectId,
    actor: Option<ExternalSubjectIdentity>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct UncheckedMergeQueueTrigger {
    queue_id: ExternalMergeQueueId,
    activity: MergeQueueActivity,
    repository: ProviderRepository,
    target_ref: ProviderGitRef,
    target_object: GitObjectId,
    candidate_object: GitObjectId,
    actor: Option<ExternalSubjectIdentity>,
}

impl MergeQueueTrigger {
    /// Constructs one exact merge-queue candidate.
    ///
    /// # Errors
    ///
    /// Rejects non-branch targets, object-algorithm drift, or cross-instance actors.
    pub fn new(
        queue_id: ExternalMergeQueueId,
        activity: MergeQueueActivity,
        repository: ProviderRepository,
        target_ref: ProviderGitRef,
        target_object: GitObjectId,
        candidate_object: GitObjectId,
        actor: Option<ExternalSubjectIdentity>,
    ) -> Result<Self, ProviderTriggerError> {
        if target_ref.kind() != ProviderGitRefKind::Branch {
            return Err(ProviderTriggerError::InvalidGitRef);
        }
        if target_object.algorithm() != candidate_object.algorithm() {
            return Err(ProviderTriggerError::ObjectAlgorithmMismatch);
        }
        validate_subject_instance(repository.identity(), actor.as_ref())?;
        Ok(Self {
            queue_id,
            activity,
            repository,
            target_ref,
            target_object,
            candidate_object,
            actor,
        })
    }

    /// Returns the merge-queue candidate identity.
    #[must_use]
    pub const fn queue_id(&self) -> &ExternalMergeQueueId {
        &self.queue_id
    }

    /// Returns the normalized queue activity.
    #[must_use]
    pub const fn activity(&self) -> MergeQueueActivity {
        self.activity
    }

    /// Returns the target repository.
    #[must_use]
    pub const fn repository(&self) -> &ProviderRepository {
        &self.repository
    }

    /// Returns the exact synthetic candidate object.
    #[must_use]
    pub const fn candidate_object(&self) -> GitObjectId {
        self.candidate_object
    }
}

impl TryFrom<UncheckedMergeQueueTrigger> for MergeQueueTrigger {
    type Error = ProviderTriggerError;

    fn try_from(value: UncheckedMergeQueueTrigger) -> Result<Self, Self::Error> {
        Self::new(
            value.queue_id,
            value.activity,
            value.repository,
            value.target_ref,
            value.target_object,
            value.candidate_object,
            value.actor,
        )
    }
}

/// Bounded canonical repository-dispatch input retained for admission.
#[derive(Clone, Eq, PartialEq)]
pub struct ProviderDispatchInput {
    canonical_bytes: Vec<u8>,
    digest: Sha256Digest,
}

impl ProviderDispatchInput {
    /// Accepts an exact canonical adapter encoding.
    ///
    /// # Errors
    ///
    /// Rejects oversized input. Empty input is a valid empty dispatch document.
    pub fn new(canonical_bytes: Vec<u8>) -> Result<Self, ProviderTriggerError> {
        if canonical_bytes.len() > MAX_PROVIDER_DISPATCH_INPUT_BYTES {
            return Err(ProviderTriggerError::DispatchInputTooLarge);
        }
        let mut hash = Sha256::new();
        hash.update(DISPATCH_INPUT_DIGEST_DOMAIN);
        hash.update((canonical_bytes.len() as u64).to_be_bytes());
        hash.update(&canonical_bytes);
        Ok(Self {
            canonical_bytes,
            digest: Sha256Digest::from_bytes(hash.finalize().into()),
        })
    }

    /// Returns exact canonical adapter bytes.
    #[must_use]
    pub fn canonical_bytes(&self) -> &[u8] {
        &self.canonical_bytes
    }

    /// Returns the domain-separated input digest.
    #[must_use]
    pub const fn digest(&self) -> Sha256Digest {
        self.digest
    }
}

impl fmt::Debug for ProviderDispatchInput {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProviderDispatchInput")
            .field("canonical_bytes", &"[CANONICAL]")
            .field("byte_length", &self.canonical_bytes.len())
            .field("digest", &self.digest)
            .finish()
    }
}

impl Serialize for ProviderDispatchInput {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&URL_SAFE_NO_PAD.encode(&self.canonical_bytes))
    }
}

impl<'de> Deserialize<'de> for ProviderDispatchInput {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let encoded = String::deserialize(deserializer)?;
        let bytes = URL_SAFE_NO_PAD
            .decode(encoded)
            .map_err(serde::de::Error::custom)?;
        Self::new(bytes).map_err(serde::de::Error::custom)
    }
}

/// Authenticated custom repository-dispatch trigger.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(try_from = "UncheckedRepositoryDispatchTrigger")]
pub struct RepositoryDispatchTrigger {
    repository: ProviderRepository,
    event_type: ProviderEventName,
    input: ProviderDispatchInput,
    actor: Option<ExternalSubjectIdentity>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct UncheckedRepositoryDispatchTrigger {
    repository: ProviderRepository,
    event_type: ProviderEventName,
    input: ProviderDispatchInput,
    actor: Option<ExternalSubjectIdentity>,
}

impl RepositoryDispatchTrigger {
    /// Constructs a bounded custom event.
    ///
    /// # Errors
    ///
    /// Rejects an actor from another provider instance.
    pub fn new(
        repository: ProviderRepository,
        event_type: ProviderEventName,
        input: ProviderDispatchInput,
        actor: Option<ExternalSubjectIdentity>,
    ) -> Result<Self, ProviderTriggerError> {
        validate_subject_instance(repository.identity(), actor.as_ref())?;
        Ok(Self {
            repository,
            event_type,
            input,
            actor,
        })
    }

    /// Returns the target repository.
    #[must_use]
    pub const fn repository(&self) -> &ProviderRepository {
        &self.repository
    }

    /// Returns the provider-normalized custom event type.
    #[must_use]
    pub const fn event_type(&self) -> &ProviderEventName {
        &self.event_type
    }

    /// Returns bounded canonical dispatch input.
    #[must_use]
    pub const fn input(&self) -> &ProviderDispatchInput {
        &self.input
    }
}

impl TryFrom<UncheckedRepositoryDispatchTrigger> for RepositoryDispatchTrigger {
    type Error = ProviderTriggerError;

    fn try_from(value: UncheckedRepositoryDispatchTrigger) -> Result<Self, Self::Error> {
        Self::new(value.repository, value.event_type, value.input, value.actor)
    }
}

/// Closed set of webhook sources that may enter workflow admission.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", content = "facts", rename_all = "snake_case")]
pub enum NormalizedTrigger {
    /// A branch or tag update.
    Push(PushTrigger),
    /// A pull request or merge request.
    PullRequest(PullRequestTrigger),
    /// A provider merge-queue candidate.
    MergeQueue(MergeQueueTrigger),
    /// A provider-authenticated custom repository event.
    RepositoryDispatch(RepositoryDispatchTrigger),
}

impl NormalizedTrigger {
    /// Returns the repository in whose security context admission occurs.
    #[must_use]
    pub const fn target_repository(&self) -> &ProviderRepository {
        match self {
            Self::Push(value) => value.repository(),
            Self::PullRequest(value) => value.target_repository(),
            Self::MergeQueue(value) => value.repository(),
            Self::RepositoryDispatch(value) => value.repository(),
        }
    }

    /// Encodes a bounded canonical trigger document and its domain-separated digest.
    ///
    /// # Errors
    ///
    /// Fails if serialization fails or exceeds the durable normalized-event bound.
    pub fn seal(&self) -> Result<SealedNormalizedTrigger, ProviderTriggerError> {
        let bytes = serde_json::to_vec(self).map_err(|_| ProviderTriggerError::Encoding)?;
        if bytes.len() > MAX_NORMALIZED_TRIGGER_BYTES {
            return Err(ProviderTriggerError::NormalizedTriggerTooLarge);
        }
        SealedNormalizedTrigger::from_canonical_bytes(bytes)
    }
}

/// Exact canonical normalized-trigger bytes and identity.
#[derive(Clone, Eq, PartialEq)]
pub struct SealedNormalizedTrigger {
    trigger: NormalizedTrigger,
    canonical_bytes: Vec<u8>,
    digest: Sha256Digest,
}

impl SealedNormalizedTrigger {
    /// Strictly decodes and byte-for-byte verifies canonical trigger bytes.
    ///
    /// # Errors
    ///
    /// Rejects malformed, noncanonical, or oversized bytes.
    pub fn from_canonical_bytes(canonical_bytes: Vec<u8>) -> Result<Self, ProviderTriggerError> {
        if canonical_bytes.is_empty() || canonical_bytes.len() > MAX_NORMALIZED_TRIGGER_BYTES {
            return Err(ProviderTriggerError::NormalizedTriggerTooLarge);
        }
        let trigger: NormalizedTrigger =
            serde_json::from_slice(&canonical_bytes).map_err(|_| ProviderTriggerError::Encoding)?;
        let encoded = serde_json::to_vec(&trigger).map_err(|_| ProviderTriggerError::Encoding)?;
        if encoded != canonical_bytes {
            return Err(ProviderTriggerError::NonCanonicalEncoding);
        }
        let mut hash = Sha256::new();
        hash.update(TRIGGER_DIGEST_DOMAIN);
        hash.update((canonical_bytes.len() as u64).to_be_bytes());
        hash.update(&canonical_bytes);
        Ok(Self {
            trigger,
            canonical_bytes,
            digest: Sha256Digest::from_bytes(hash.finalize().into()),
        })
    }

    /// Returns strongly typed normalized facts.
    #[must_use]
    pub const fn trigger(&self) -> &NormalizedTrigger {
        &self.trigger
    }

    /// Returns exact canonical bytes.
    #[must_use]
    pub fn canonical_bytes(&self) -> &[u8] {
        &self.canonical_bytes
    }

    /// Returns the domain-separated trigger digest.
    #[must_use]
    pub const fn digest(&self) -> Sha256Digest {
        self.digest
    }
}

impl fmt::Debug for SealedNormalizedTrigger {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SealedNormalizedTrigger")
            .field("trigger", &self.trigger)
            .field("canonical_bytes", &"[CANONICAL]")
            .field("byte_length", &self.canonical_bytes.len())
            .field("digest", &self.digest)
            .finish()
    }
}

fn validate_subject_instance(
    repository: &ExternalRepositoryIdentity,
    actor: Option<&ExternalSubjectIdentity>,
) -> Result<(), ProviderTriggerError> {
    if actor.is_some_and(|actor| actor.instance_id() != repository.instance_id()) {
        return Err(ProviderTriggerError::InstanceMismatch);
    }
    Ok(())
}

fn validate_text(value: &str, maximum: usize) -> Result<(), ProviderTriggerError> {
    if value.is_empty() || value.trim() != value {
        return Err(ProviderTriggerError::InvalidEventName);
    }
    if value.len() > maximum || value.chars().any(char::is_control) {
        return Err(ProviderTriggerError::InvalidEventName);
    }
    Ok(())
}

#[allow(clippy::case_sensitive_file_extension_comparisons)]
fn valid_ref_name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 1_024
        && value != "@"
        && !value.starts_with(['-', '/', '.'])
        && !value.ends_with(['/', '.'])
        && !value.ends_with(".lock")
        && !value.contains("//")
        && !value.contains("..")
        && !value.contains("@{")
        && !value.chars().any(|character| {
            character.is_control()
                || character.is_whitespace()
                || matches!(character, '~' | '^' | ':' | '?' | '*' | '[' | '\\')
        })
}

/// Invalid normalized trigger evidence.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum ProviderTriggerError {
    /// An event name violated the bounded untrusted-text contract.
    #[error("provider event name is invalid")]
    InvalidEventName,
    /// A branch or tag reference was malformed or inconsistent.
    #[error("provider Git reference is invalid")]
    InvalidGitRef,
    /// A push contained neither a before nor after object.
    #[error("provider trigger is missing an exact Git object identity")]
    MissingObjectIdentity,
    /// Exact objects from one repository event used different hash algorithms.
    #[error("provider trigger Git object algorithms disagree")]
    ObjectAlgorithmMismatch,
    /// Provider-native identities crossed configured instance namespaces.
    #[error("provider trigger identities belong to different instances")]
    InstanceMismatch,
    /// Canonical repository-dispatch input exceeded its bound.
    #[error("provider repository-dispatch input exceeds its maximum size")]
    DispatchInputTooLarge,
    /// A normalized trigger exceeded its durable bound.
    #[error("normalized provider trigger exceeds its maximum size")]
    NormalizedTriggerTooLarge,
    /// Strongly typed trigger encoding or decoding failed.
    #[error("normalized provider trigger encoding is invalid")]
    Encoding,
    /// Supplied bytes decoded but were not the exact canonical representation.
    #[error("normalized provider trigger is not canonically encoded")]
    NonCanonicalEncoding,
}

#[cfg(test)]
mod tests {
    use automata_ci_core::GitObjectAlgorithm;

    use super::*;
    use crate::{ExternalRepositoryId, ProviderInstanceId};

    fn object(hex: char) -> GitObjectId {
        GitObjectId::from_hex(GitObjectAlgorithm::Sha1, &hex.to_string().repeat(40))
            .expect("valid object")
    }

    fn repository(instance_id: ProviderInstanceId) -> ProviderRepository {
        ProviderRepository::new(
            ExternalRepositoryIdentity::new(
                instance_id,
                ExternalRepositoryId::new("42").expect("repository ID"),
            ),
            ProviderRepositoryPath::new("owner/repository").expect("repository path"),
            RepositoryVisibility::Private,
        )
    }

    #[test]
    fn push_round_trip_is_canonical_and_algorithm_bearing() {
        let trigger = NormalizedTrigger::Push(
            PushTrigger::new(
                repository(ProviderInstanceId::new()),
                ProviderGitRef::new("refs/heads/main", ProviderGitRefKind::Branch).expect("branch"),
                Some(object('a')),
                Some(object('b')),
                false,
                None,
            )
            .expect("push"),
        );

        let sealed = trigger.seal().expect("sealed trigger");
        let decoded =
            SealedNormalizedTrigger::from_canonical_bytes(sealed.canonical_bytes().to_vec())
                .expect("canonical round trip");
        assert_eq!(decoded, sealed);
    }

    #[test]
    fn cross_instance_pull_request_is_rejected() {
        let result = PullRequestTrigger::new(
            ExternalChangeId::new("7").expect("change ID"),
            PullRequestActivity::Opened,
            repository(ProviderInstanceId::new()),
            repository(ProviderInstanceId::new()),
            ProviderGitRef::new("refs/heads/main", ProviderGitRefKind::Branch).expect("base"),
            ProviderGitRef::new("refs/heads/topic", ProviderGitRefKind::Branch).expect("head"),
            object('a'),
            object('b'),
            None,
            false,
            None,
            None,
        );

        assert_eq!(result, Err(ProviderTriggerError::InstanceMismatch));
    }

    #[test]
    fn all_zero_deletion_sentinel_is_represented_as_absence() {
        let result = PushTrigger::new(
            repository(ProviderInstanceId::new()),
            ProviderGitRef::new("refs/tags/v1", ProviderGitRefKind::Tag).expect("tag"),
            None,
            None,
            false,
            None,
        );

        assert_eq!(result, Err(ProviderTriggerError::MissingObjectIdentity));
    }
}
