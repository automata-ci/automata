use std::{fmt, num::NonZeroU64};

use automata_ci_core::GitObjectId;
use bytes::Bytes;
use serde::{Deserialize, Deserializer, de};

use super::{
    InstallationPayload, RepositoryOwnerPayload, SenderPayload, VerifiedGithubWebhookIdentity,
};
use crate::{
    event::GithubEventActor,
    webhook::{
        AuthenticatedGithubWebhook, GithubWebhookBodyDigest, GithubWebhookError, GithubWebhookRef,
        GithubWebhookRepository, MAX_GITHUB_PUSH_COMMITS, durable_provider_id, parse_git_ref,
    },
};

const MAX_GITHUB_PATH_FILTER_COMMITS: usize = 1_000;
const ZERO_COMMIT_SHA: &str = "0000000000000000000000000000000000000000";

const fn push_commit_count_rejected(observed: usize) -> bool {
    observed > MAX_GITHUB_PUSH_COMMITS
}

const fn path_filter_commit_count_rejected(observed: usize) -> bool {
    observed > MAX_GITHUB_PATH_FILTER_COMMITS
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
    pub(super) identity: VerifiedGithubWebhookIdentity,
    actor: Option<GithubEventActor>,
    git_ref: GithubWebhookRef,
    before_commit_sha: Box<str>,
    after_commit_sha: Box<str>,
    metadata: GithubWebhookEventMetadata,
    commit_count: usize,
    complete_pushed_commit_revisions: Option<Box<[GitObjectId]>>,
}

impl VerifiedGithubPush {
    verified_github_webhook_authenticated_accessors!(push);

    verified_github_webhook_accessors! { |event|
        /// Returns the authenticated sender facts when supplied by the webhook.
        #[must_use]
        [const] fn actor -> Option<&GithubEventActor> = event.actor.as_ref();
    }

    verified_github_webhook_repository_accessor!(push);

    verified_github_webhook_accessors! { |event|
        /// Returns the canonical full branch or tag reference.
        [const] fn git_ref -> &GithubWebhookRef = &event.git_ref;
        /// Returns the canonical lowercase 40-hex pre-push commit identifier.
        [] fn before_commit_sha -> &str = &event.before_commit_sha;
        /// Returns the canonical lowercase 40-hex post-push commit identifier.
        [] fn after_commit_sha -> &str = &event.after_commit_sha;
        /// Returns provider metadata required for later trigger selection.
        [const] fn event_metadata -> GithubWebhookEventMetadata = event.metadata;
        /// Returns the bounded number of commit summaries observed in the payload.
        ///
        /// GitHub caps the webhook array at [`MAX_GITHUB_PUSH_COMMITS`], so this is
        /// not a claim about the total size of a larger truncated push.
        [const] fn commit_count -> usize = event.commit_count;
        /// Returns the complete canonical pushed-commit set when path filtering
        /// requires a provider diff.
        ///
        /// The revisions are lexicographically sorted because provider array order
        /// is not diff-base authority. `Some(empty)` is complete evidence for an
        /// empty array. `None` means the payload contained more than 1,000 commits,
        /// for which GitHub Actions bypasses path-filter diff generation.
        [] fn complete_pushed_commit_revisions -> Option<&[GitObjectId]> = event.complete_pushed_commit_revisions.as_deref();
        /// Returns whether GitHub Actions' commit ceiling requires path filters to
        /// match without generating a diff.
        [const] fn path_filter_commit_limit_exceeded -> bool = event.complete_pushed_commit_revisions.is_none();
        /// Returns the exact provider deletion flag.
        [const] fn deleted -> bool = match event.metadata {
            GithubWebhookEventMetadata::Push { deleted, .. } => deleted,
        };
        /// Returns the exact provider creation flag.
        [const] fn created -> bool = match event.metadata {
            GithubWebhookEventMetadata::Push { created, .. } => created,
        };
        /// Returns the exact provider forced-update flag.
        [const] fn forced -> bool = match event.metadata {
            GithubWebhookEventMetadata::Push { forced, .. } => forced,
        };
    }
}

impl fmt::Debug for VerifiedGithubPush {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut debug = formatter.debug_struct("VerifiedGithubPush");
        debug_verified_github_webhook_identity!(debug, self.identity, workflow);
        debug
            .field("actor", &self.actor)
            .field("repository", &self.identity.repository)
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
    installation: InstallationPayload,
    #[serde(default)]
    sender: Option<SenderPayload>,
    commits: BoundedCommits,
}

#[derive(Deserialize)]
struct PushRepositoryPayload {
    id: u64,
    private: bool,
    visibility: String,
    name: String,
    full_name: String,
    owner: RepositoryOwnerPayload,
}

#[derive(Deserialize)]
struct PushCommitPayload {
    id: String,
}

#[derive(Default)]
struct BoundedCommits(Vec<PushCommitPayload>);

struct NormalizedPushedCommits {
    count: usize,
    complete_revisions: Option<Box<[GitObjectId]>>,
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
            let projected = commits
                .len()
                .checked_add(1)
                .ok_or_else(|| de::Error::custom("push commit count exceeds limit"))?;
            if push_commit_count_rejected(projected) {
                return Err(de::Error::custom("push commit count exceeds limit"));
            }
            commits.push(commit);
        }
        Ok(BoundedCommits(commits))
    }
}

pub(crate) fn decode_push(
    authenticated: AuthenticatedGithubWebhook,
) -> Result<VerifiedGithubPush, GithubWebhookError> {
    let payload: PushPayload = serde_json::from_slice(authenticated.raw_body())
        .map_err(|_| GithubWebhookError::MalformedPayload)?;
    normalize_push(authenticated, payload)
}

fn normalize_push(
    authenticated: AuthenticatedGithubWebhook,
    payload: PushPayload,
) -> Result<VerifiedGithubPush, GithubWebhookError> {
    let installation_id = durable_provider_id(payload.installation.id)?;
    let actor = payload.sender.map(SenderPayload::normalize).transpose()?;
    let repository = GithubWebhookRepository::from_webhook_fields(
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

    Ok(VerifiedGithubPush {
        identity: VerifiedGithubWebhookIdentity::new(authenticated, installation_id, repository),
        actor,
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
        revisions.push(
            GitObjectId::from_provider_hex(commit.id)
                .map_err(|_| GithubWebhookError::InvalidPayload)?,
        );
    }
    revisions.sort_unstable();
    if revisions.windows(2).any(|pair| pair[0] == pair[1]) {
        return Err(GithubWebhookError::InvalidPayload);
    }

    let commit_count = revisions.len();
    let complete =
        (!path_filter_commit_count_rejected(commit_count)).then(|| revisions.into_boxed_slice());
    Ok(NormalizedPushedCommits {
        count: commit_count,
        complete_revisions: complete,
    })
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

#[cfg(test)]
mod limit_contract_tests {
    use super::*;

    #[test]
    fn push_commit_count_limit_has_exact_boundaries() {
        assert!(!push_commit_count_rejected(MAX_GITHUB_PUSH_COMMITS - 1));
        assert!(!push_commit_count_rejected(MAX_GITHUB_PUSH_COMMITS));
        assert!(push_commit_count_rejected(MAX_GITHUB_PUSH_COMMITS + 1));
    }

    #[test]
    fn path_filter_commit_count_limit_has_exact_boundaries() {
        assert!(!path_filter_commit_count_rejected(
            MAX_GITHUB_PATH_FILTER_COMMITS - 1
        ));
        assert!(!path_filter_commit_count_rejected(
            MAX_GITHUB_PATH_FILTER_COMMITS
        ));
        assert!(path_filter_commit_count_rejected(
            MAX_GITHUB_PATH_FILTER_COMMITS + 1
        ));
    }
}
