use std::fmt;

use serde::{Deserialize, Serialize};

use crate::{
    GithubPushRefKind, MAX_GITHUB_PUSH_COMMITS, VerifiedGithubPush,
    webhook::GithubWebhookEventMetadata,
};

use super::{
    GithubEventActor, GithubEventRefFacts, GithubEventRepositoryFacts,
    registry::{
        GithubEventActivityPolicy, GithubEventChangedFilesStrategy, GithubEventRecursionPolicy,
        GithubEventRefRule, GithubEventRegistryEntry, GithubEventSourceRule,
        GithubEventTriggerModel, GithubEventTrustFact, GithubWorkflowEventKind,
    },
};

const ZERO_COMMIT_SHA: &str = "0000000000000000000000000000000000000000";

const TRUST_FACTS: &[GithubEventTrustFact] = &[
    GithubEventTrustFact::TriggeringActor,
    GithubEventTrustFact::SourceRepository,
    GithubEventTrustFact::TargetRepository,
    GithubEventTrustFact::ForkRelationship,
    GithubEventTrustFact::References,
    GithubEventTrustFact::Revisions,
    GithubEventTrustFact::Recursion,
];

pub(crate) const REGISTRATION: GithubEventRegistryEntry = GithubEventRegistryEntry {
    kind: GithubWorkflowEventKind::Push,
    event_name: "push",
    activities: GithubEventActivityPolicy::None,
    trigger: GithubEventTriggerModel::Push,
    reference: GithubEventRefRule::PushedReference,
    source: GithubEventSourceRule::EventRepository,
    changed_files: GithubEventChangedFilesStrategy::PushCompare,
    trust_facts: TRUST_FACTS,
    recursion: GithubEventRecursionPolicy::GithubTokenSuppressed,
};

/// Facts-only schema-v1 projection of an authenticated GitHub push.
#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct GithubPushEventFacts {
    actor: Option<GithubEventActor>,
    target_repository: GithubEventRepositoryFacts,
    git_ref: GithubEventRefFacts,
    before_revision: Box<str>,
    after_revision: Box<str>,
    update: GithubPushUpdateFacts,
    commit_count: usize,
    complete_changed_file_range: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct GithubPushUpdateFacts {
    created: bool,
    deleted: bool,
    forced: bool,
}

impl GithubPushEventFacts {
    pub(crate) fn from_verified(event: &VerifiedGithubPush) -> Self {
        let GithubWebhookEventMetadata::Push {
            created,
            deleted,
            forced,
        } = event.event_metadata();
        Self {
            actor: event.actor().cloned(),
            target_repository: GithubEventRepositoryFacts::from_repository(event.repository()),
            git_ref: GithubEventRefFacts::from_ref(event.git_ref()),
            before_revision: event.before_commit_sha().into(),
            after_revision: event.after_commit_sha().into(),
            update: GithubPushUpdateFacts {
                created,
                deleted,
                forced,
            },
            commit_count: event.commit_count(),
            complete_changed_file_range: !event.path_filter_commit_limit_exceeded(),
        }
    }

    pub(crate) fn validate(&self) -> bool {
        self.actor
            .as_ref()
            .is_none_or(|actor| actor.validate().is_ok())
            && self.target_repository.validate()
            && self.git_ref.validate()
            && valid_push_revision(&self.before_revision)
            && valid_push_revision(&self.after_revision)
            && self.update.created == (self.before_revision.as_ref() == ZERO_COMMIT_SHA)
            && self.update.deleted == (self.after_revision.as_ref() == ZERO_COMMIT_SHA)
            && !(self.update.created && self.update.deleted)
            && self.commit_count <= MAX_GITHUB_PUSH_COMMITS
            && self.complete_changed_file_range == (self.commit_count <= 1_000)
    }

    /// Returns the authenticated sender facts when supplied by GitHub.
    #[must_use]
    pub const fn actor(&self) -> Option<&GithubEventActor> {
        self.actor.as_ref()
    }

    /// Returns the repository that is both source and target for this push.
    #[must_use]
    pub const fn target_repository(&self) -> &GithubEventRepositoryFacts {
        &self.target_repository
    }

    /// Returns the exact pushed branch or tag reference.
    #[must_use]
    pub const fn git_ref(&self) -> &GithubEventRefFacts {
        &self.git_ref
    }

    /// Returns the authenticated pre-push revision, including the zero sentinel.
    #[must_use]
    pub fn before_revision(&self) -> &str {
        &self.before_revision
    }

    /// Returns the authenticated post-push revision, including the zero sentinel.
    #[must_use]
    pub fn after_revision(&self) -> &str {
        &self.after_revision
    }

    /// Returns whether GitHub declared reference creation.
    #[must_use]
    pub const fn created(&self) -> bool {
        self.update.created
    }

    /// Returns whether GitHub declared reference deletion.
    #[must_use]
    pub const fn deleted(&self) -> bool {
        self.update.deleted
    }

    /// Returns whether GitHub declared a forced update.
    #[must_use]
    pub const fn forced(&self) -> bool {
        self.update.forced
    }

    /// Returns the bounded commit-summary count.
    #[must_use]
    pub const fn commit_count(&self) -> usize {
        self.commit_count
    }

    /// Returns whether the payload commit range can be used for path selection.
    #[must_use]
    pub const fn complete_changed_file_range(&self) -> bool {
        self.complete_changed_file_range
    }

    /// Returns the closed reference kind.
    #[must_use]
    pub const fn ref_kind(&self) -> GithubPushRefKind {
        self.git_ref.kind()
    }
}

impl fmt::Debug for GithubPushEventFacts {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GithubPushEventFacts")
            .field("actor", &self.actor)
            .field("target_repository", &self.target_repository)
            .field("git_ref", &self.git_ref)
            .field("before_revision", &"[redacted]")
            .field("after_revision", &"[redacted]")
            .field("update", &self.update)
            .field("commit_count", &self.commit_count)
            .field(
                "complete_changed_file_range",
                &self.complete_changed_file_range,
            )
            .finish()
    }
}

fn valid_push_revision(value: &str) -> bool {
    value.len() == 40
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}
