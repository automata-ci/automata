use std::{collections::BTreeSet, fmt, num::NonZeroU64};

use automata_ci_core::GitObjectId;
use bytes::Bytes;
use serde::{
    Deserialize, Serialize,
    de::{self, DeserializeSeed, IgnoredAny, MapAccess, SeqAccess, Visitor},
};
use serde_json::{Map as JsonMap, Value as JsonValue};

use crate::event::GithubEventActor;
use crate::webhook::{
    AuthenticatedGithubWebhook, GithubWebhookBodyDigest, GithubWebhookError, GithubWebhookRef,
    GithubWebhookRefKind, GithubWebhookRepository, durable_provider_id, normalize_branch_name,
    parse_git_ref,
};

macro_rules! verified_github_webhook_authenticated_accessors {
    (push) => {
        /// Returns the exact singleton `X-GitHub-Delivery` value.
        ///
        /// This header is outside the body MAC and must be included separately in
        /// any durable request or idempotency digest.
        pub fn delivery_id(&self) -> &str {
            self.identity.authenticated.delivery_id()
        }

        /// Returns the exact singleton `X-GitHub-Event` value.
        ///
        /// This header is outside the body MAC and must be included separately in
        /// any durable request digest.
        pub fn event_name(&self) -> &str {
            self.identity.authenticated.event_name()
        }

        /// Returns the exact authenticated JSON bytes without reserialization.
        pub fn raw_body(&self) -> &Bytes {
            self.identity.authenticated.raw_body()
        }

        /// Returns SHA-256 of the exact authenticated body.
        pub const fn body_sha256(&self) -> GithubWebhookBodyDigest {
            self.identity.authenticated.body_sha256()
        }

        /// Returns the nonzero GitHub App installation identifier.
        pub const fn installation_id(&self) -> NonZeroU64 {
            self.identity.installation_id
        }
    };
    ($event_name:literal, $installation:literal) => {
        /// Returns the exact singleton delivery header outside the body MAC.
        #[must_use]
        pub fn delivery_id(&self) -> &str {
            self.identity.authenticated.delivery_id()
        }

        #[doc = $event_name]
        #[must_use]
        pub fn event_name(&self) -> &str {
            self.identity.authenticated.event_name()
        }

        /// Returns the exact HMAC-authenticated body without reserialization.
        #[must_use]
        pub const fn raw_body(&self) -> &Bytes {
            self.identity.authenticated.raw_body()
        }

        /// Returns SHA-256 of the exact authenticated body.
        #[must_use]
        pub const fn body_sha256(&self) -> GithubWebhookBodyDigest {
            self.identity.authenticated.body_sha256()
        }

        #[doc = $installation]
        #[must_use]
        pub const fn installation_id(&self) -> NonZeroU64 {
            self.identity.installation_id
        }
    };
}

macro_rules! verified_github_webhook_repository_accessor {
    (push) => {
        /// Returns the internally consistent provider repository identity.
        pub const fn repository(&self) -> &GithubWebhookRepository {
            &self.identity.repository
        }
    };
    ($repository:literal) => {
        #[doc = $repository]
        #[must_use]
        pub const fn repository(&self) -> &GithubWebhookRepository {
            &self.identity.repository
        }
    };
}

macro_rules! verified_github_webhook_accessors {
    (|$event:ident| $(
        $(#[$attribute:meta])*
        [$($constness:tt)*] fn $name:ident -> $return_type:ty = $body:expr;
    )*) => {
        $(
            $(#[$attribute])*
            pub $($constness)* fn $name(&self) -> $return_type {
                let $event = self;
                $body
            }
        )*
    };
}

macro_rules! debug_verified_github_webhook_identity {
    ($debug:ident, $identity:expr, workflow) => {
        $debug
            .field("delivery_id", &"[redacted]")
            .field("event_name", &$identity.authenticated.event_name())
            .field("raw_body", &"[redacted]")
            .field("body_len", &$identity.authenticated.raw_body().len())
            .field("body_sha256", &$identity.authenticated.body_sha256())
            .field("installation_id", &$identity.installation_id);
    };
    ($debug:ident, $identity:expr, control) => {
        $debug
            .field("delivery_id", &"[redacted]")
            .field("event_name", &$identity.authenticated.event_name())
            .field("body_sha256", &$identity.authenticated.body_sha256())
            .field("installation_id", &$identity.installation_id)
            .field("repository", &$identity.repository);
    };
}

pub(super) mod push;

use push::VerifiedGithubPush;

const ZERO_COMMIT_SHA: &str = "0000000000000000000000000000000000000000";
const MAX_REPOSITORY_DISPATCH_EVENT_TYPE_CHARS: usize = 100;
const MAX_REPOSITORY_DISPATCH_CLIENT_PAYLOAD_PROPERTIES: usize = 10;
const MAX_REPOSITORY_DISPATCH_CLIENT_PAYLOAD_CHARS: usize = 65_535;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum GithubRepositoryDispatchLimitRejection {
    EventTypeCharacters,
    ClientPayloadProperties,
    ClientPayloadCharacters,
}

const fn repository_dispatch_event_type_rejection(
    observed: usize,
) -> Option<GithubRepositoryDispatchLimitRejection> {
    if observed > MAX_REPOSITORY_DISPATCH_EVENT_TYPE_CHARS {
        return Some(GithubRepositoryDispatchLimitRejection::EventTypeCharacters);
    }
    None
}

const fn repository_dispatch_payload_property_rejection(
    observed: usize,
) -> Option<GithubRepositoryDispatchLimitRejection> {
    if observed > MAX_REPOSITORY_DISPATCH_CLIENT_PAYLOAD_PROPERTIES {
        return Some(GithubRepositoryDispatchLimitRejection::ClientPayloadProperties);
    }
    None
}

const fn repository_dispatch_payload_character_rejection(
    observed: usize,
) -> Option<GithubRepositoryDispatchLimitRejection> {
    if observed > MAX_REPOSITORY_DISPATCH_CLIENT_PAYLOAD_CHARS {
        return Some(GithubRepositoryDispatchLimitRejection::ClientPayloadCharacters);
    }
    None
}

#[derive(Clone, Eq, PartialEq)]
struct VerifiedGithubWebhookIdentity {
    authenticated: AuthenticatedGithubWebhook,
    installation_id: NonZeroU64,
    repository: GithubWebhookRepository,
}

impl VerifiedGithubWebhookIdentity {
    const fn new(
        authenticated: AuthenticatedGithubWebhook,
        installation_id: NonZeroU64,
        repository: GithubWebhookRepository,
    ) -> Self {
        Self {
            authenticated,
            installation_id,
            repository,
        }
    }
}

/// A currently documented GitHub `pull_request` webhook activity.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
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
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum GithubMergeGroupAction {
    /// GitHub requested checks for a newly created merge group.
    ChecksRequested,
    /// GitHub destroyed a merge group.
    Destroyed,
}

/// A native GitHub Check Run control accepted by Automata.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GithubCheckRunAction {
    /// GitHub's standard re-request control.
    Rerequested,
    /// Re-run the complete source workflow.
    RerunAll,
    /// Re-run failed jobs and their dependents.
    RerunFailed,
    /// Re-run the selected logical job and its dependents.
    RerunJob,
}

impl GithubCheckRunAction {
    /// Returns the canonical GitHub/Automata action spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Rerequested => "rerequested",
            Self::RerunAll => "rerun_all",
            Self::RerunFailed => "rerun_failed",
            Self::RerunJob => "rerun_job",
        }
    }
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
    /// A normalized custom repository-dispatch event.
    RepositoryDispatch(VerifiedGithubRepositoryDispatch),
    /// A normalized native Check Run rerun request.
    CheckRun(VerifiedGithubCheckRun),
    /// A normalized native Check Suite rerun request.
    CheckSuite(VerifiedGithubCheckSuite),
}

impl VerifiedGithubWebhook {
    const fn identity(&self) -> &VerifiedGithubWebhookIdentity {
        match self {
            Self::Push(event) => &event.identity,
            Self::PullRequest(event) => &event.identity,
            Self::MergeGroup(event) => &event.identity,
            Self::RepositoryDispatch(event) => &event.identity,
            Self::CheckRun(event) => &event.identity,
            Self::CheckSuite(event) => &event.identity,
        }
    }

    /// Returns the exact singleton delivery header outside the body MAC.
    #[must_use]
    pub fn delivery_id(&self) -> &str {
        self.identity().authenticated.delivery_id()
    }

    /// Returns the exact singleton event-name header outside the body MAC.
    #[must_use]
    pub fn event_name(&self) -> &str {
        self.identity().authenticated.event_name()
    }

    /// Returns the exact HMAC-authenticated body without reserialization.
    #[must_use]
    pub fn raw_body(&self) -> &Bytes {
        self.identity().authenticated.raw_body()
    }

    /// Returns SHA-256 of the exact authenticated body.
    #[must_use]
    pub const fn body_sha256(&self) -> GithubWebhookBodyDigest {
        self.identity().authenticated.body_sha256()
    }

    /// Returns the nonzero GitHub App installation identifier.
    #[must_use]
    pub const fn installation_id(&self) -> NonZeroU64 {
        self.identity().installation_id
    }

    /// Returns the internally consistent event repository identity.
    #[must_use]
    pub const fn repository(&self) -> &GithubWebhookRepository {
        &self.identity().repository
    }
}

impl fmt::Debug for VerifiedGithubWebhook {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Push(event) => formatter.debug_tuple("Push").field(event).finish(),
            Self::PullRequest(event) => formatter.debug_tuple("PullRequest").field(event).finish(),
            Self::MergeGroup(event) => formatter.debug_tuple("MergeGroup").field(event).finish(),
            Self::RepositoryDispatch(event) => formatter
                .debug_tuple("RepositoryDispatch")
                .field(event)
                .finish(),
            Self::CheckRun(event) => formatter.debug_tuple("CheckRun").field(event).finish(),
            Self::CheckSuite(event) => formatter.debug_tuple("CheckSuite").field(event).finish(),
        }
    }
}

/// Authenticated identity for one native Check Run rerun control.
#[derive(Clone, Eq, PartialEq)]
pub struct VerifiedGithubCheckRun {
    identity: VerifiedGithubWebhookIdentity,
    actor: GithubEventActor,
    app_id: NonZeroU64,
    run_id: NonZeroU64,
    suite_id: NonZeroU64,
    head_revision: GitObjectId,
    external_id: Box<str>,
    action: GithubCheckRunAction,
}

impl VerifiedGithubCheckRun {
    verified_github_webhook_authenticated_accessors!(
        "Returns the exact `check_run` event-name header.",
        "Returns the nonzero App installation identifier."
    );
    verified_github_webhook_repository_accessor!(
        "Returns the exact repository from the signed payload."
    );
    verified_github_webhook_accessors! { |event|
        /// Returns the authenticated GitHub sender facts to reauthorize.
        #[must_use]
        [const] fn actor -> &GithubEventActor = &event.actor;
        /// Returns the GitHub App that owns the Check Run.
        #[must_use]
        [const] fn app_id -> NonZeroU64 = event.app_id;
        /// Returns the exact Check Run identifier.
        #[must_use]
        [const] fn run_id -> NonZeroU64 = event.run_id;
        /// Returns the exact Check Suite identifier.
        #[must_use]
        [const] fn suite_id -> NonZeroU64 = event.suite_id;
        /// Returns the exact checked commit.
        #[must_use]
        [const] fn head_revision -> &GitObjectId = &event.head_revision;
        /// Returns Automata's bounded external Check identity.
        #[must_use]
        [] fn external_id -> &str = &event.external_id;
        /// Returns the requested rerun operation.
        #[must_use]
        [const] fn action -> GithubCheckRunAction = event.action;
    }
}

impl fmt::Debug for VerifiedGithubCheckRun {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut debug = formatter.debug_struct("VerifiedGithubCheckRun");
        debug_verified_github_webhook_identity!(debug, self.identity, control);
        debug
            .field("actor", &self.actor)
            .field("app_id", &self.app_id)
            .field("run_id", &self.run_id)
            .field("suite_id", &self.suite_id)
            .field("head_revision", &"[redacted]")
            .field("external_id", &"[redacted]")
            .field("action", &self.action)
            .finish()
    }
}

/// Authenticated identity for one native Check Suite re-request.
#[derive(Clone, Eq, PartialEq)]
pub struct VerifiedGithubCheckSuite {
    identity: VerifiedGithubWebhookIdentity,
    actor: GithubEventActor,
    app_id: NonZeroU64,
    suite_id: NonZeroU64,
    head_revision: GitObjectId,
}

impl VerifiedGithubCheckSuite {
    verified_github_webhook_authenticated_accessors!(
        "Returns the exact `check_suite` event-name header.",
        "Returns the nonzero App installation identifier."
    );
    verified_github_webhook_repository_accessor!(
        "Returns the exact repository from the signed payload."
    );
    verified_github_webhook_accessors! { |event|
        /// Returns the authenticated GitHub sender facts to reauthorize.
        #[must_use]
        [const] fn actor -> &GithubEventActor = &event.actor;
        /// Returns the GitHub App that owns the Check Suite.
        #[must_use]
        [const] fn app_id -> NonZeroU64 = event.app_id;
        /// Returns the exact Check Suite identifier.
        #[must_use]
        [const] fn suite_id -> NonZeroU64 = event.suite_id;
        /// Returns the exact checked commit.
        #[must_use]
        [const] fn head_revision -> &GitObjectId = &event.head_revision;
    }
}

impl fmt::Debug for VerifiedGithubCheckSuite {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut debug = formatter.debug_struct("VerifiedGithubCheckSuite");
        debug_verified_github_webhook_identity!(debug, self.identity, control);
        debug
            .field("actor", &self.actor)
            .field("app_id", &self.app_id)
            .field("suite_id", &self.suite_id)
            .field("head_revision", &"[redacted]")
            .finish()
    }
}

/// Authenticated and strictly normalized custom repository-dispatch evidence.
///
/// The exact client payload remains available through the authenticated raw
/// body and this typed view, but is always redacted from `Debug` output.
#[derive(Clone, Eq, PartialEq)]
pub struct VerifiedGithubRepositoryDispatch {
    identity: VerifiedGithubWebhookIdentity,
    actor: Option<GithubEventActor>,
    event_type: Box<str>,
    branch: Box<str>,
    git_ref: Box<str>,
    client_payload: Option<JsonMap<String, JsonValue>>,
}

impl VerifiedGithubRepositoryDispatch {
    verified_github_webhook_authenticated_accessors!(
        "Returns the exact `repository_dispatch` event-name header.",
        "Returns the nonzero GitHub App installation identifier."
    );

    verified_github_webhook_accessors! { |event|
        /// Returns the authenticated sender facts when supplied by the webhook.
        #[must_use]
        [const] fn actor -> Option<&GithubEventActor> = event.actor.as_ref();
    }

    verified_github_webhook_repository_accessor!(
        "Returns the repository that received the custom dispatch."
    );

    verified_github_webhook_accessors! { |event|
        /// Returns the bounded custom event type used by `on.repository_dispatch.types`.
        #[must_use]
        [] fn event_type -> &str = &event.event_type;
        /// Returns the validated unqualified default-branch name.
        #[must_use]
        [] fn branch -> &str = &event.branch;
        /// Returns the full default-branch reference used by the workflow run.
        #[must_use]
        [] fn git_ref -> &str = &event.git_ref;
        /// Returns the bounded custom client payload, or `None` for JSON `null`.
        #[must_use]
        [const] fn client_payload -> Option<&JsonMap<String, JsonValue>> = event.client_payload.as_ref();
    }
}

impl fmt::Debug for VerifiedGithubRepositoryDispatch {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut debug = formatter.debug_struct("VerifiedGithubRepositoryDispatch");
        debug_verified_github_webhook_identity!(debug, self.identity, workflow);
        debug
            .field("actor", &self.actor)
            .field("repository", &self.identity.repository)
            .field("event_type", &"[redacted]")
            .field("branch", &"[redacted]")
            .field("git_ref", &"[redacted]")
            .field("client_payload", &"[redacted]")
            .finish()
    }
}

/// Authenticated and strictly normalized pull-request webhook evidence.
#[derive(Clone, Eq, PartialEq)]
pub struct VerifiedGithubPullRequest {
    identity: VerifiedGithubWebhookIdentity,
    actor: Option<GithubEventActor>,
    source_actor: Option<GithubEventActor>,
    head_repository: GithubWebhookRepository,
    number: NonZeroU64,
    action: GithubPullRequestAction,
    merged: bool,
    draft: bool,
    head_revision: GitObjectId,
    base_revision: GitObjectId,
    merge_revision: Option<GitObjectId>,
    head_ref: Box<str>,
    base_ref: Box<str>,
    git_ref: Box<str>,
}

impl VerifiedGithubPullRequest {
    verified_github_webhook_authenticated_accessors!(
        "Returns the exact `pull_request` event-name header.",
        "Returns the nonzero GitHub App installation identifier."
    );

    verified_github_webhook_accessors! { |event|
        /// Returns the authenticated event sender facts when supplied by GitHub.
        #[must_use]
        [const] fn actor -> Option<&GithubEventActor> = event.actor.as_ref();
        /// Returns the pull-request author's authenticated identity facts when
        /// supplied by GitHub.
        #[must_use]
        [const] fn source_actor -> Option<&GithubEventActor> = event.source_actor.as_ref();
    }

    verified_github_webhook_repository_accessor!(
        "Returns the base repository where the pull request occurred."
    );

    verified_github_webhook_accessors! { |event|
        /// Returns the exact source repository for the pull-request head.
        #[must_use]
        [const] fn head_repository -> &GithubWebhookRepository = &event.head_repository;
        /// Returns the positive pull-request number within the base repository.
        #[must_use]
        [const] fn number -> NonZeroU64 = event.number;
        /// Returns the validated provider activity.
        #[must_use]
        [const] fn action -> GithubPullRequestAction = event.action;
        /// Returns whether this event describes a pull request that was merged.
        #[must_use]
        [const] fn merged -> bool = event.merged;
        /// Returns whether the pull request is currently a draft.
        #[must_use]
        [const] fn draft -> bool = event.draft;
        /// Returns the canonical pull-request head commit.
        #[must_use]
        [const] fn head_revision -> &GitObjectId = &event.head_revision;
        /// Returns the canonical base-branch commit observed by the payload.
        #[must_use]
        [const] fn base_revision -> &GitObjectId = &event.base_revision;
        /// Returns the merge-branch commit used as `GITHUB_SHA` for this event.
        ///
        /// GitHub may send `null` before it has materialized the pull-request merge
        /// commit; absence remains explicit rather than inventing an object identity.
        #[must_use]
        [const] fn merge_revision -> Option<GitObjectId> = event.merge_revision;
        /// Returns the validated unqualified pull-request head branch.
        #[must_use]
        [] fn head_ref -> &str = &event.head_ref;
        /// Returns the validated unqualified target branch used by trigger filters.
        #[must_use]
        [] fn base_ref -> &str = &event.base_ref;
        /// Returns the full ref GitHub assigns to the workflow run.
        #[must_use]
        [] fn git_ref -> &str = &event.git_ref;
    }
}

impl fmt::Debug for VerifiedGithubPullRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut debug = formatter.debug_struct("VerifiedGithubPullRequest");
        debug_verified_github_webhook_identity!(debug, self.identity, workflow);
        debug
            .field("actor", &self.actor)
            .field("source_actor", &self.source_actor)
            .field("repository", &self.identity.repository)
            .field("head_repository", &self.head_repository)
            .field("number", &self.number)
            .field("action", &self.action)
            .field("merged", &self.merged)
            .field("draft", &self.draft)
            .field("head_revision", &"[redacted]")
            .field("base_revision", &"[redacted]")
            .field("merge_revision", &"[redacted]")
            .field("head_ref", &"[redacted]")
            .field("base_ref", &"[redacted]")
            .field("git_ref", &"[redacted]")
            .finish()
    }
}

/// Authenticated and strictly normalized merge-queue group webhook evidence.
#[derive(Clone, Eq, PartialEq)]
pub struct VerifiedGithubMergeGroup {
    identity: VerifiedGithubWebhookIdentity,
    actor: Option<GithubEventActor>,
    action: GithubMergeGroupAction,
    head_revision: GitObjectId,
    base_revision: GitObjectId,
    head_ref: GithubWebhookRef,
    base_ref: GithubWebhookRef,
}

impl VerifiedGithubMergeGroup {
    verified_github_webhook_authenticated_accessors!(
        "Returns the exact `merge_group` event-name header.",
        "Returns the nonzero GitHub App installation identifier."
    );

    verified_github_webhook_accessors! { |event|
        /// Returns the authenticated sender facts when supplied by the webhook.
        #[must_use]
        [const] fn actor -> Option<&GithubEventActor> = event.actor.as_ref();
    }

    verified_github_webhook_repository_accessor!(
        "Returns the repository whose merge queue created the group."
    );

    verified_github_webhook_accessors! { |event|
        /// Returns the validated provider activity.
        #[must_use]
        [const] fn action -> GithubMergeGroupAction = event.action;
        /// Returns the canonical merge-group head commit to check.
        #[must_use]
        [const] fn head_revision -> &GitObjectId = &event.head_revision;
        /// Returns the canonical parent commit of the merge group.
        #[must_use]
        [const] fn base_revision -> &GitObjectId = &event.base_revision;
        /// Returns the canonical full merge-group branch reference.
        #[must_use]
        [const] fn head_ref -> &GithubWebhookRef = &event.head_ref;
        /// Returns the canonical full target-branch reference.
        #[must_use]
        [const] fn base_ref -> &GithubWebhookRef = &event.base_ref;
    }
}

impl fmt::Debug for VerifiedGithubMergeGroup {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut debug = formatter.debug_struct("VerifiedGithubMergeGroup");
        debug_verified_github_webhook_identity!(debug, self.identity, workflow);
        debug
            .field("actor", &self.actor)
            .field("repository", &self.identity.repository)
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
    #[serde(default)]
    sender: Option<SenderPayload>,
}

#[derive(Deserialize)]
struct PullRequestObjectPayload {
    number: u64,
    merged: bool,
    draft: bool,
    #[serde(default)]
    merge_commit_sha: PullRequestMergeCommitShaPayload,
    #[serde(default)]
    user: Option<SenderPayload>,
    head: PullRequestBranchPayload,
    base: PullRequestBranchPayload,
}

#[derive(Default, Deserialize)]
#[serde(untagged)]
enum PullRequestMergeCommitShaPayload {
    Revision(String),
    Null(()),
    #[serde(skip)]
    #[default]
    Missing,
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
    #[serde(default)]
    sender: Option<SenderPayload>,
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
struct RepositoryDispatchPayload {
    action: String,
    branch: String,
    client_payload: JsonValue,
    repository: RepositoryPayload,
    installation: InstallationPayload,
    #[serde(default)]
    sender: Option<SenderPayload>,
}

#[derive(Deserialize)]
struct RepositoryPayload {
    id: u64,
    private: bool,
    visibility: String,
    name: String,
    full_name: String,
    owner: RepositoryOwnerPayload,
    #[serde(default)]
    default_branch: Option<String>,
}

impl RepositoryPayload {
    fn normalize(self) -> Result<GithubWebhookRepository, GithubWebhookError> {
        GithubWebhookRepository::from_webhook_fields(
            self.id,
            self.owner.id,
            self.private,
            &self.visibility,
            self.owner.login,
            self.name,
            self.full_name,
        )
    }

    fn normalize_with_default_branch(
        self,
    ) -> Result<(GithubWebhookRepository, Box<str>), GithubWebhookError> {
        let default_branch = self
            .default_branch
            .clone()
            .ok_or(GithubWebhookError::InvalidPayload)
            .and_then(normalize_branch_name)?;
        self.normalize()
            .map(|repository| (repository, default_branch))
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

#[derive(Deserialize)]
struct CheckRunPayload {
    action: String,
    check_run: CheckRunObjectPayload,
    repository: RepositoryPayload,
    installation: InstallationPayload,
    sender: SenderPayload,
    #[serde(default)]
    requested_action: Option<RequestedActionPayload>,
}

#[derive(Deserialize)]
struct CheckRunObjectPayload {
    id: u64,
    head_sha: String,
    external_id: String,
    status: String,
    conclusion: Option<String>,
    app: AppPayload,
    check_suite: CheckSuiteReferencePayload,
}

#[derive(Deserialize)]
struct CheckSuitePayload {
    action: String,
    check_suite: CheckSuiteObjectPayload,
    repository: RepositoryPayload,
    installation: InstallationPayload,
    sender: SenderPayload,
}

#[derive(Deserialize)]
struct CheckSuiteObjectPayload {
    id: u64,
    head_sha: String,
    status: String,
    conclusion: Option<String>,
    app: AppPayload,
}

#[derive(Deserialize)]
struct CheckSuiteReferencePayload {
    id: u64,
    head_sha: String,
}

#[derive(Deserialize)]
struct AppPayload {
    id: u64,
}

#[derive(Deserialize)]
struct SenderPayload {
    id: u64,
    #[serde(default)]
    login: Option<String>,
    #[serde(rename = "type", default)]
    kind: Option<String>,
}

impl SenderPayload {
    fn normalize(self) -> Result<GithubEventActor, GithubWebhookError> {
        GithubEventActor::from_webhook_fields(self.id, self.login, self.kind.as_deref())
    }
}

#[derive(Deserialize)]
struct RequestedActionPayload {
    identifier: String,
}

pub(crate) fn normalize_check_run(
    authenticated: AuthenticatedGithubWebhook,
) -> Result<VerifiedGithubCheckRun, GithubWebhookError> {
    let payload: CheckRunPayload = serde_json::from_slice(authenticated.raw_body())
        .map_err(|_| GithubWebhookError::MalformedPayload)?;
    let action = match (payload.action.as_str(), payload.requested_action) {
        ("rerequested", None) => GithubCheckRunAction::Rerequested,
        ("requested_action", Some(requested)) => match requested.identifier.as_str() {
            "rerun_all" => GithubCheckRunAction::RerunAll,
            "rerun_failed" => GithubCheckRunAction::RerunFailed,
            "rerun_job" => GithubCheckRunAction::RerunJob,
            _ => return Err(GithubWebhookError::InvalidPayload),
        },
        _ => return Err(GithubWebhookError::InvalidPayload),
    };
    if payload.check_run.status != "completed"
        || payload.check_run.conclusion.is_none()
        || payload.check_run.external_id.is_empty()
        || payload.check_run.external_id.len() > 1_024
        || payload
            .check_run
            .external_id
            .chars()
            .any(|character| character.is_control() || character.is_whitespace())
    {
        return Err(GithubWebhookError::InvalidPayload);
    }
    let head_revision = exact_revision(payload.check_run.head_sha)?;
    let suite_revision = exact_revision(payload.check_run.check_suite.head_sha)?;
    if head_revision != suite_revision {
        return Err(GithubWebhookError::InvalidPayload);
    }
    let actor = payload.sender.normalize()?;
    let installation_id = durable_provider_id(payload.installation.id)?;
    let repository = payload.repository.normalize()?;
    let app_id = durable_provider_id(payload.check_run.app.id)?;
    let run_id = durable_provider_id(payload.check_run.id)?;
    let suite_id = durable_provider_id(payload.check_run.check_suite.id)?;
    Ok(VerifiedGithubCheckRun {
        identity: VerifiedGithubWebhookIdentity::new(authenticated, installation_id, repository),
        actor,
        app_id,
        run_id,
        suite_id,
        head_revision,
        external_id: payload.check_run.external_id.into_boxed_str(),
        action,
    })
}

pub(crate) fn normalize_check_suite(
    authenticated: AuthenticatedGithubWebhook,
) -> Result<VerifiedGithubCheckSuite, GithubWebhookError> {
    let payload: CheckSuitePayload = serde_json::from_slice(authenticated.raw_body())
        .map_err(|_| GithubWebhookError::MalformedPayload)?;
    if payload.action != "rerequested"
        || payload.check_suite.status != "completed"
        || payload.check_suite.conclusion.is_none()
    {
        return Err(GithubWebhookError::InvalidPayload);
    }
    let actor = payload.sender.normalize()?;
    let installation_id = durable_provider_id(payload.installation.id)?;
    let repository = payload.repository.normalize()?;
    let app_id = durable_provider_id(payload.check_suite.app.id)?;
    let suite_id = durable_provider_id(payload.check_suite.id)?;
    let head_revision = exact_revision(payload.check_suite.head_sha)?;
    Ok(VerifiedGithubCheckSuite {
        identity: VerifiedGithubWebhookIdentity::new(authenticated, installation_id, repository),
        actor,
        app_id,
        suite_id,
        head_revision,
    })
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
    let merge_revision = match payload.pull_request.merge_commit_sha {
        PullRequestMergeCommitShaPayload::Revision(revision) => Some(exact_revision(revision)?),
        PullRequestMergeCommitShaPayload::Null(()) if !payload.pull_request.merged => None,
        PullRequestMergeCommitShaPayload::Null(()) | PullRequestMergeCommitShaPayload::Missing => {
            return Err(GithubWebhookError::InvalidPayload);
        }
    };
    let head_ref = normalize_branch_name(payload.pull_request.head.git_ref)?;
    let base_ref = normalize_branch_name(payload.pull_request.base.git_ref)?;
    if payload.pull_request.merged && action != GithubPullRequestAction::Closed {
        return Err(GithubWebhookError::InvalidPayload);
    }
    let git_ref = if payload.pull_request.merged {
        format!("refs/heads/{base_ref}")
    } else {
        format!("refs/pull/{number}/merge")
    }
    .into_boxed_str();
    let actor = payload.sender.map(SenderPayload::normalize).transpose()?;
    let source_actor = payload
        .pull_request
        .user
        .map(SenderPayload::normalize)
        .transpose()?;

    Ok(VerifiedGithubPullRequest {
        identity: VerifiedGithubWebhookIdentity::new(authenticated, installation_id, repository),
        actor,
        source_actor,
        head_repository,
        number,
        action,
        merged: payload.pull_request.merged,
        draft: payload.pull_request.draft,
        head_revision,
        base_revision,
        merge_revision,
        head_ref,
        base_ref,
        git_ref,
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
    let actor = payload.sender.map(SenderPayload::normalize).transpose()?;

    Ok(VerifiedGithubMergeGroup {
        identity: VerifiedGithubWebhookIdentity::new(authenticated, installation_id, repository),
        actor,
        action,
        head_revision,
        base_revision,
        head_ref,
        base_ref,
    })
}

pub(crate) fn normalize_repository_dispatch(
    authenticated: AuthenticatedGithubWebhook,
) -> Result<VerifiedGithubRepositoryDispatch, GithubWebhookError> {
    let payload: RepositoryDispatchPayload = serde_json::from_slice(authenticated.raw_body())
        .map_err(|_| GithubWebhookError::MalformedPayload)?;
    let event_type = normalize_repository_dispatch_event_type(payload.action)?;
    let branch = normalize_branch_name(payload.branch)?;
    let installation_id = durable_provider_id(payload.installation.id)?;
    let (repository, default_branch) = payload.repository.normalize_with_default_branch()?;
    if branch != default_branch {
        return Err(GithubWebhookError::InvalidPayload);
    }
    let client_payload = normalize_repository_dispatch_client_payload(payload.client_payload)?;
    let git_ref = format!("refs/heads/{branch}").into_boxed_str();
    let actor = payload.sender.map(SenderPayload::normalize).transpose()?;

    Ok(VerifiedGithubRepositoryDispatch {
        identity: VerifiedGithubWebhookIdentity::new(authenticated, installation_id, repository),
        actor,
        event_type,
        branch,
        git_ref,
        client_payload,
    })
}

fn normalize_repository_dispatch_event_type(
    event_type: String,
) -> Result<Box<str>, GithubWebhookError> {
    let character_count = event_type.chars().count();
    if character_count == 0
        || repository_dispatch_event_type_rejection(character_count).is_some()
        || event_type.chars().any(char::is_control)
    {
        return Err(GithubWebhookError::InvalidPayload);
    }
    Ok(event_type.into_boxed_str())
}

fn normalize_repository_dispatch_client_payload(
    value: JsonValue,
) -> Result<Option<JsonMap<String, JsonValue>>, GithubWebhookError> {
    if value.is_null() {
        return Ok(None);
    }
    let JsonValue::Object(object) = value else {
        return Err(GithubWebhookError::InvalidPayload);
    };
    if repository_dispatch_payload_property_rejection(object.len()).is_some() {
        return Err(GithubWebhookError::InvalidPayload);
    }
    let encoded = serde_json::to_string(&object).map_err(|_| GithubWebhookError::InvalidPayload)?;
    if repository_dispatch_payload_character_rejection(encoded.chars().count()).is_some() {
        return Err(GithubWebhookError::InvalidPayload);
    }
    Ok(Some(object))
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

fn exact_revision(value: String) -> Result<GitObjectId, GithubWebhookError> {
    if value == ZERO_COMMIT_SHA {
        return Err(GithubWebhookError::InvalidPayload);
    }
    GitObjectId::from_provider_hex(value).map_err(|_| GithubWebhookError::InvalidPayload)
}

fn full_branch_ref(value: String) -> Result<GithubWebhookRef, GithubWebhookError> {
    let git_ref = parse_git_ref(value)?;
    if git_ref.kind() != GithubWebhookRefKind::Branch {
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

#[cfg(test)]
mod limit_contract_tests {
    use super::*;

    #[test]
    fn repository_dispatch_event_type_limit_has_exact_boundaries() {
        assert_eq!(
            repository_dispatch_event_type_rejection(MAX_REPOSITORY_DISPATCH_EVENT_TYPE_CHARS - 1),
            None
        );
        assert_eq!(
            repository_dispatch_event_type_rejection(MAX_REPOSITORY_DISPATCH_EVENT_TYPE_CHARS),
            None
        );
        assert_eq!(
            repository_dispatch_event_type_rejection(MAX_REPOSITORY_DISPATCH_EVENT_TYPE_CHARS + 1),
            Some(GithubRepositoryDispatchLimitRejection::EventTypeCharacters)
        );
    }

    #[test]
    fn repository_dispatch_payload_property_limit_has_exact_boundaries() {
        let minus_one = MAX_REPOSITORY_DISPATCH_CLIENT_PAYLOAD_PROPERTIES - 1;
        let at = MAX_REPOSITORY_DISPATCH_CLIENT_PAYLOAD_PROPERTIES;
        let plus_one = MAX_REPOSITORY_DISPATCH_CLIENT_PAYLOAD_PROPERTIES + 1;
        assert_eq!(
            repository_dispatch_payload_property_rejection(minus_one),
            None
        );
        assert_eq!(repository_dispatch_payload_property_rejection(at), None);
        assert_eq!(
            repository_dispatch_payload_property_rejection(plus_one),
            Some(GithubRepositoryDispatchLimitRejection::ClientPayloadProperties)
        );
    }

    #[test]
    fn repository_dispatch_payload_character_limit_has_exact_boundaries() {
        let minus_one = MAX_REPOSITORY_DISPATCH_CLIENT_PAYLOAD_CHARS - 1;
        let at = MAX_REPOSITORY_DISPATCH_CLIENT_PAYLOAD_CHARS;
        let plus_one = MAX_REPOSITORY_DISPATCH_CLIENT_PAYLOAD_CHARS + 1;
        assert_eq!(
            repository_dispatch_payload_character_rejection(minus_one),
            None
        );
        assert_eq!(repository_dispatch_payload_character_rejection(at), None);
        assert_eq!(
            repository_dispatch_payload_character_rejection(plus_one),
            Some(GithubRepositoryDispatchLimitRejection::ClientPayloadCharacters)
        );
    }
}
