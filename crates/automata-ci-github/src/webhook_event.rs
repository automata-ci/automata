use std::{collections::BTreeSet, fmt, num::NonZeroU64};

use automata_ci_scm::ExactRevision;
use bytes::Bytes;
use serde::{
    Deserialize,
    de::{self, DeserializeSeed, IgnoredAny, MapAccess, SeqAccess, Visitor},
};

use crate::webhook::{
    AuthenticatedGithubWebhook, GithubPushRef, GithubPushRefKind, GithubPushRepository,
    GithubWebhookBodyDigest, GithubWebhookError, VerifiedGithubPush, durable_provider_id,
    normalize_branch_name, parse_git_ref,
};

const ZERO_COMMIT_SHA: &str = "0000000000000000000000000000000000000000";

/// Repository identity retained by normalized non-push webhook evidence.
///
/// This is an event-neutral alias of the repository type already exposed by
/// the stable push API.
pub type GithubWebhookRepository = GithubPushRepository;

/// Validated full reference retained by normalized webhook evidence.
///
/// This is an event-neutral alias of the full-reference type already exposed
/// by the stable push API.
pub type GithubWebhookRef = GithubPushRef;

/// A currently documented GitHub `pull_request` webhook activity.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum GithubPullRequestAction {
    /// The pull request was assigned.
    Assigned,
    /// Automatic merging was disabled.
    AutoMergeDisabled,
    /// Automatic merging was enabled.
    AutoMergeEnabled,
    /// The pull request was closed.
    Closed,
    /// The pull request was converted to draft state.
    ConvertedToDraft,
    /// A milestone was removed.
    Demilestoned,
    /// The pull request was removed from a merge queue.
    Dequeued,
    /// The pull request metadata was edited.
    Edited,
    /// The pull request was added to a merge queue.
    Enqueued,
    /// A label was added.
    Labeled,
    /// Conversation locking was enabled.
    Locked,
    /// A milestone was added.
    Milestoned,
    /// The pull request was opened.
    Opened,
    /// The pull request became ready for review.
    ReadyForReview,
    /// The pull request was reopened.
    Reopened,
    /// A review request was removed.
    ReviewRequestRemoved,
    /// A review was requested.
    ReviewRequested,
    /// The pull request was stacked.
    Stacked,
    /// The pull-request head changed.
    Synchronize,
    /// An assignee was removed.
    Unassigned,
    /// A label was removed.
    Unlabeled,
    /// Conversation locking was disabled.
    Unlocked,
}

impl GithubPullRequestAction {
    /// Returns GitHub's canonical activity spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Assigned => "assigned",
            Self::AutoMergeDisabled => "auto_merge_disabled",
            Self::AutoMergeEnabled => "auto_merge_enabled",
            Self::Closed => "closed",
            Self::ConvertedToDraft => "converted_to_draft",
            Self::Demilestoned => "demilestoned",
            Self::Dequeued => "dequeued",
            Self::Edited => "edited",
            Self::Enqueued => "enqueued",
            Self::Labeled => "labeled",
            Self::Locked => "locked",
            Self::Milestoned => "milestoned",
            Self::Opened => "opened",
            Self::ReadyForReview => "ready_for_review",
            Self::Reopened => "reopened",
            Self::ReviewRequestRemoved => "review_request_removed",
            Self::ReviewRequested => "review_requested",
            Self::Stacked => "stacked",
            Self::Synchronize => "synchronize",
            Self::Unassigned => "unassigned",
            Self::Unlabeled => "unlabeled",
            Self::Unlocked => "unlocked",
        }
    }
}

/// A currently documented GitHub `merge_group` webhook activity.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum GithubMergeGroupAction {
    /// GitHub requested checks for a newly created merge group.
    ChecksRequested,
    /// GitHub destroyed a merge group.
    Destroyed,
}

impl GithubMergeGroupAction {
    /// Returns GitHub's canonical activity spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ChecksRequested => "checks_requested",
            Self::Destroyed => "destroyed",
        }
    }
}

/// Strictly normalized evidence for every webhook event supported by this boundary.
#[derive(Clone, Eq, PartialEq)]
#[non_exhaustive]
pub enum VerifiedGithubWebhook {
    /// A normalized push using the existing stable push evidence API.
    Push(VerifiedGithubPush),
    /// A normalized pull-request event.
    PullRequest(VerifiedGithubPullRequest),
    /// A normalized merge-queue group event.
    MergeGroup(VerifiedGithubMergeGroup),
}

impl VerifiedGithubWebhook {
    /// Returns the exact singleton delivery header outside the body MAC.
    #[must_use]
    pub fn delivery_id(&self) -> &str {
        match self {
            Self::Push(event) => event.delivery_id(),
            Self::PullRequest(event) => event.delivery_id(),
            Self::MergeGroup(event) => event.delivery_id(),
        }
    }

    /// Returns the exact singleton event-name header outside the body MAC.
    #[must_use]
    pub fn event_name(&self) -> &str {
        match self {
            Self::Push(event) => event.event_name(),
            Self::PullRequest(event) => event.event_name(),
            Self::MergeGroup(event) => event.event_name(),
        }
    }

    /// Returns the exact HMAC-authenticated body without reserialization.
    #[must_use]
    pub fn raw_body(&self) -> &Bytes {
        match self {
            Self::Push(event) => event.raw_body(),
            Self::PullRequest(event) => event.raw_body(),
            Self::MergeGroup(event) => event.raw_body(),
        }
    }

    /// Returns SHA-256 of the exact authenticated body.
    #[must_use]
    pub const fn body_sha256(&self) -> GithubWebhookBodyDigest {
        match self {
            Self::Push(event) => event.body_sha256(),
            Self::PullRequest(event) => event.body_sha256(),
            Self::MergeGroup(event) => event.body_sha256(),
        }
    }

    /// Returns the nonzero GitHub App installation identifier.
    #[must_use]
    pub const fn installation_id(&self) -> NonZeroU64 {
        match self {
            Self::Push(event) => event.installation_id(),
            Self::PullRequest(event) => event.installation_id(),
            Self::MergeGroup(event) => event.installation_id(),
        }
    }

    /// Returns the internally consistent event repository identity.
    #[must_use]
    pub const fn repository(&self) -> &GithubWebhookRepository {
        match self {
            Self::Push(event) => event.repository(),
            Self::PullRequest(event) => event.repository(),
            Self::MergeGroup(event) => event.repository(),
        }
    }
}

impl fmt::Debug for VerifiedGithubWebhook {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Push(event) => formatter.debug_tuple("Push").field(event).finish(),
            Self::PullRequest(event) => formatter.debug_tuple("PullRequest").field(event).finish(),
            Self::MergeGroup(event) => formatter.debug_tuple("MergeGroup").field(event).finish(),
        }
    }
}

/// Authenticated and strictly normalized pull-request webhook evidence.
#[derive(Clone, Eq, PartialEq)]
pub struct VerifiedGithubPullRequest {
    authenticated: AuthenticatedGithubWebhook,
    installation_id: NonZeroU64,
    repository: GithubWebhookRepository,
    head_repository: GithubWebhookRepository,
    number: NonZeroU64,
    action: GithubPullRequestAction,
    head_revision: ExactRevision,
    base_revision: ExactRevision,
    head_ref: Box<str>,
    base_ref: Box<str>,
}

impl VerifiedGithubPullRequest {
    /// Returns the exact singleton delivery header outside the body MAC.
    #[must_use]
    pub fn delivery_id(&self) -> &str {
        self.authenticated.delivery_id()
    }

    /// Returns the exact `pull_request` event-name header.
    #[must_use]
    pub fn event_name(&self) -> &str {
        self.authenticated.event_name()
    }

    /// Returns the exact HMAC-authenticated body without reserialization.
    #[must_use]
    pub const fn raw_body(&self) -> &Bytes {
        self.authenticated.raw_body()
    }

    /// Returns SHA-256 of the exact authenticated body.
    #[must_use]
    pub const fn body_sha256(&self) -> GithubWebhookBodyDigest {
        self.authenticated.body_sha256()
    }

    /// Returns the nonzero GitHub App installation identifier.
    #[must_use]
    pub const fn installation_id(&self) -> NonZeroU64 {
        self.installation_id
    }

    /// Returns the base repository where the pull request occurred.
    #[must_use]
    pub const fn repository(&self) -> &GithubWebhookRepository {
        &self.repository
    }

    /// Returns the exact source repository for the pull-request head.
    #[must_use]
    pub const fn head_repository(&self) -> &GithubWebhookRepository {
        &self.head_repository
    }

    /// Returns the positive pull-request number within the base repository.
    #[must_use]
    pub const fn number(&self) -> NonZeroU64 {
        self.number
    }

    /// Returns the validated provider activity.
    #[must_use]
    pub const fn action(&self) -> GithubPullRequestAction {
        self.action
    }

    /// Returns the canonical pull-request head commit.
    #[must_use]
    pub const fn head_revision(&self) -> &ExactRevision {
        &self.head_revision
    }

    /// Returns the canonical base-branch commit observed by the payload.
    #[must_use]
    pub const fn base_revision(&self) -> &ExactRevision {
        &self.base_revision
    }

    /// Returns the validated unqualified pull-request head branch.
    #[must_use]
    pub fn head_ref(&self) -> &str {
        &self.head_ref
    }

    /// Returns the validated unqualified target branch used by trigger filters.
    #[must_use]
    pub fn base_ref(&self) -> &str {
        &self.base_ref
    }
}

impl fmt::Debug for VerifiedGithubPullRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("VerifiedGithubPullRequest")
            .field("delivery_id", &"[redacted]")
            .field("event_name", &self.authenticated.event_name())
            .field("raw_body", &"[redacted]")
            .field("body_len", &self.authenticated.raw_body().len())
            .field("body_sha256", &self.authenticated.body_sha256())
            .field("installation_id", &self.installation_id)
            .field("repository", &self.repository)
            .field("head_repository", &self.head_repository)
            .field("number", &self.number)
            .field("action", &self.action)
            .field("head_revision", &"[redacted]")
            .field("base_revision", &"[redacted]")
            .field("head_ref", &"[redacted]")
            .field("base_ref", &"[redacted]")
            .finish()
    }
}

/// Authenticated and strictly normalized merge-queue group webhook evidence.
#[derive(Clone, Eq, PartialEq)]
pub struct VerifiedGithubMergeGroup {
    authenticated: AuthenticatedGithubWebhook,
    installation_id: NonZeroU64,
    repository: GithubWebhookRepository,
    action: GithubMergeGroupAction,
    head_revision: ExactRevision,
    base_revision: ExactRevision,
    head_ref: GithubWebhookRef,
    base_ref: GithubWebhookRef,
}

impl VerifiedGithubMergeGroup {
    /// Returns the exact singleton delivery header outside the body MAC.
    #[must_use]
    pub fn delivery_id(&self) -> &str {
        self.authenticated.delivery_id()
    }

    /// Returns the exact `merge_group` event-name header.
    #[must_use]
    pub fn event_name(&self) -> &str {
        self.authenticated.event_name()
    }

    /// Returns the exact HMAC-authenticated body without reserialization.
    #[must_use]
    pub const fn raw_body(&self) -> &Bytes {
        self.authenticated.raw_body()
    }

    /// Returns SHA-256 of the exact authenticated body.
    #[must_use]
    pub const fn body_sha256(&self) -> GithubWebhookBodyDigest {
        self.authenticated.body_sha256()
    }

    /// Returns the nonzero GitHub App installation identifier.
    #[must_use]
    pub const fn installation_id(&self) -> NonZeroU64 {
        self.installation_id
    }

    /// Returns the repository whose merge queue created the group.
    #[must_use]
    pub const fn repository(&self) -> &GithubWebhookRepository {
        &self.repository
    }

    /// Returns the validated provider activity.
    #[must_use]
    pub const fn action(&self) -> GithubMergeGroupAction {
        self.action
    }

    /// Returns the canonical merge-group head commit to check.
    #[must_use]
    pub const fn head_revision(&self) -> &ExactRevision {
        &self.head_revision
    }

    /// Returns the canonical parent commit of the merge group.
    #[must_use]
    pub const fn base_revision(&self) -> &ExactRevision {
        &self.base_revision
    }

    /// Returns the canonical full merge-group branch reference.
    #[must_use]
    pub const fn head_ref(&self) -> &GithubWebhookRef {
        &self.head_ref
    }

    /// Returns the canonical full target-branch reference.
    #[must_use]
    pub const fn base_ref(&self) -> &GithubWebhookRef {
        &self.base_ref
    }
}

impl fmt::Debug for VerifiedGithubMergeGroup {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("VerifiedGithubMergeGroup")
            .field("delivery_id", &"[redacted]")
            .field("event_name", &self.authenticated.event_name())
            .field("raw_body", &"[redacted]")
            .field("body_len", &self.authenticated.raw_body().len())
            .field("body_sha256", &self.authenticated.body_sha256())
            .field("installation_id", &self.installation_id)
            .field("repository", &self.repository)
            .field("action", &self.action)
            .field("head_revision", &"[redacted]")
            .field("base_revision", &"[redacted]")
            .field("head_ref", &"[redacted]")
            .field("base_ref", &"[redacted]")
            .finish()
    }
}

#[derive(Deserialize)]
struct PullRequestPayload {
    action: String,
    number: u64,
    pull_request: PullRequestObjectPayload,
    repository: RepositoryPayload,
    installation: InstallationPayload,
    #[serde(rename = "sender")]
    _sender: IgnoredAny,
}

#[derive(Deserialize)]
struct PullRequestObjectPayload {
    number: u64,
    head: PullRequestBranchPayload,
    base: PullRequestBranchPayload,
}

#[derive(Deserialize)]
struct PullRequestBranchPayload {
    #[serde(rename = "ref")]
    git_ref: String,
    sha: String,
    repo: RepositoryPayload,
}

#[derive(Deserialize)]
struct MergeGroupPayload {
    action: String,
    merge_group: MergeGroupObjectPayload,
    repository: RepositoryPayload,
    installation: InstallationPayload,
}

#[derive(Deserialize)]
struct MergeGroupObjectPayload {
    head_sha: String,
    head_ref: String,
    base_sha: String,
    base_ref: String,
    #[serde(rename = "head_commit")]
    _head_commit: IgnoredAny,
}

#[derive(Deserialize)]
struct RepositoryPayload {
    id: u64,
    private: bool,
    visibility: String,
    name: String,
    full_name: String,
    owner: RepositoryOwnerPayload,
}

impl RepositoryPayload {
    fn normalize(self) -> Result<GithubWebhookRepository, GithubWebhookError> {
        GithubPushRepository::from_webhook_fields(
            self.id,
            self.owner.id,
            self.private,
            &self.visibility,
            self.owner.login,
            self.name,
            self.full_name,
        )
    }
}

#[derive(Deserialize)]
struct RepositoryOwnerPayload {
    id: u64,
    login: String,
}

#[derive(Deserialize)]
struct InstallationPayload {
    id: u64,
}

pub(crate) fn normalize_pull_request(
    authenticated: AuthenticatedGithubWebhook,
) -> Result<VerifiedGithubPullRequest, GithubWebhookError> {
    let payload: PullRequestPayload = serde_json::from_slice(authenticated.raw_body())
        .map_err(|_| GithubWebhookError::MalformedPayload)?;
    let action = normalize_pull_request_action(&payload.action)?;
    let number = durable_provider_id(payload.number)?;
    if payload.pull_request.number != number.get() {
        return Err(GithubWebhookError::InvalidPayload);
    }
    let installation_id = durable_provider_id(payload.installation.id)?;
    let repository = payload.repository.normalize()?;
    let base_repository = payload.pull_request.base.repo.normalize()?;
    if base_repository != repository {
        return Err(GithubWebhookError::InvalidPayload);
    }
    let head_repository = payload.pull_request.head.repo.normalize()?;
    let head_revision = exact_revision(payload.pull_request.head.sha)?;
    let base_revision = exact_revision(payload.pull_request.base.sha)?;
    let head_ref = normalize_branch_name(payload.pull_request.head.git_ref)?;
    let base_ref = normalize_branch_name(payload.pull_request.base.git_ref)?;

    Ok(VerifiedGithubPullRequest {
        authenticated,
        installation_id,
        repository,
        head_repository,
        number,
        action,
        head_revision,
        base_revision,
        head_ref,
        base_ref,
    })
}

pub(crate) fn normalize_merge_group(
    authenticated: AuthenticatedGithubWebhook,
) -> Result<VerifiedGithubMergeGroup, GithubWebhookError> {
    let payload: MergeGroupPayload = serde_json::from_slice(authenticated.raw_body())
        .map_err(|_| GithubWebhookError::MalformedPayload)?;
    let action = normalize_merge_group_action(&payload.action)?;
    let installation_id = durable_provider_id(payload.installation.id)?;
    let repository = payload.repository.normalize()?;
    let head_revision = exact_revision(payload.merge_group.head_sha)?;
    let base_revision = exact_revision(payload.merge_group.base_sha)?;
    let head_ref = full_branch_ref(payload.merge_group.head_ref)?;
    let base_ref = full_branch_ref(payload.merge_group.base_ref)?;

    Ok(VerifiedGithubMergeGroup {
        authenticated,
        installation_id,
        repository,
        action,
        head_revision,
        base_revision,
        head_ref,
        base_ref,
    })
}

fn normalize_pull_request_action(
    action: &str,
) -> Result<GithubPullRequestAction, GithubWebhookError> {
    match action {
        "assigned" => Ok(GithubPullRequestAction::Assigned),
        "auto_merge_disabled" => Ok(GithubPullRequestAction::AutoMergeDisabled),
        "auto_merge_enabled" => Ok(GithubPullRequestAction::AutoMergeEnabled),
        "closed" => Ok(GithubPullRequestAction::Closed),
        "converted_to_draft" => Ok(GithubPullRequestAction::ConvertedToDraft),
        "demilestoned" => Ok(GithubPullRequestAction::Demilestoned),
        "dequeued" => Ok(GithubPullRequestAction::Dequeued),
        "edited" => Ok(GithubPullRequestAction::Edited),
        "enqueued" => Ok(GithubPullRequestAction::Enqueued),
        "labeled" => Ok(GithubPullRequestAction::Labeled),
        "locked" => Ok(GithubPullRequestAction::Locked),
        "milestoned" => Ok(GithubPullRequestAction::Milestoned),
        "opened" => Ok(GithubPullRequestAction::Opened),
        "ready_for_review" => Ok(GithubPullRequestAction::ReadyForReview),
        "reopened" => Ok(GithubPullRequestAction::Reopened),
        "review_request_removed" => Ok(GithubPullRequestAction::ReviewRequestRemoved),
        "review_requested" => Ok(GithubPullRequestAction::ReviewRequested),
        "stacked" => Ok(GithubPullRequestAction::Stacked),
        "synchronize" => Ok(GithubPullRequestAction::Synchronize),
        "unassigned" => Ok(GithubPullRequestAction::Unassigned),
        "unlabeled" => Ok(GithubPullRequestAction::Unlabeled),
        "unlocked" => Ok(GithubPullRequestAction::Unlocked),
        _ => Err(GithubWebhookError::InvalidPayload),
    }
}

fn normalize_merge_group_action(
    action: &str,
) -> Result<GithubMergeGroupAction, GithubWebhookError> {
    match action {
        "checks_requested" => Ok(GithubMergeGroupAction::ChecksRequested),
        "destroyed" => Ok(GithubMergeGroupAction::Destroyed),
        _ => Err(GithubWebhookError::InvalidPayload),
    }
}

fn exact_revision(value: String) -> Result<ExactRevision, GithubWebhookError> {
    if value == ZERO_COMMIT_SHA {
        return Err(GithubWebhookError::InvalidPayload);
    }
    ExactRevision::new(value).map_err(|_| GithubWebhookError::InvalidPayload)
}

fn full_branch_ref(value: String) -> Result<GithubWebhookRef, GithubWebhookError> {
    let git_ref = parse_git_ref(value)?;
    if git_ref.kind() != GithubPushRefKind::Branch {
        return Err(GithubWebhookError::InvalidPayload);
    }
    Ok(git_ref)
}

pub(crate) fn validate_json(raw_body: &[u8]) -> Result<(), GithubWebhookError> {
    let mut deserializer = serde_json::Deserializer::from_slice(raw_body);
    UniqueJsonSeed
        .deserialize(&mut deserializer)
        .and_then(|()| deserializer.end())
        .map_err(|_| GithubWebhookError::MalformedPayload)
}

struct UniqueJsonSeed;

impl<'de> DeserializeSeed<'de> for UniqueJsonSeed {
    type Value = ();

    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_any(UniqueJsonVisitor)
    }
}

struct UniqueJsonVisitor;

impl<'de> Visitor<'de> for UniqueJsonVisitor {
    type Value = ();

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("JSON without duplicate object keys")
    }

    fn visit_bool<E>(self, _: bool) -> Result<Self::Value, E> {
        Ok(())
    }

    fn visit_i64<E>(self, _: i64) -> Result<Self::Value, E> {
        Ok(())
    }

    fn visit_u64<E>(self, _: u64) -> Result<Self::Value, E> {
        Ok(())
    }

    fn visit_f64<E>(self, _: f64) -> Result<Self::Value, E> {
        Ok(())
    }

    fn visit_str<E>(self, _: &str) -> Result<Self::Value, E> {
        Ok(())
    }

    fn visit_string<E>(self, _: String) -> Result<Self::Value, E> {
        Ok(())
    }

    fn visit_none<E>(self) -> Result<Self::Value, E> {
        Ok(())
    }

    fn visit_unit<E>(self) -> Result<Self::Value, E> {
        Ok(())
    }

    fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        while sequence.next_element_seed(UniqueJsonSeed)?.is_some() {}
        Ok(())
    }

    fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut keys = BTreeSet::new();
        while let Some(key) = map.next_key::<String>()? {
            if !keys.insert(key) {
                return Err(de::Error::custom("duplicate JSON object key"));
            }
            map.next_value_seed(UniqueJsonSeed)?;
        }
        Ok(())
    }
}
