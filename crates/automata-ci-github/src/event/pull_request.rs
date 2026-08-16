use std::{fmt, num::NonZeroU64};

use automata_ci_scm::ExactRevision;
use serde::{Deserialize, Serialize};

use crate::{GithubPullRequestAction, VerifiedGithubPullRequest, webhook::normalize_branch_name};

use super::{
    GithubEventActor, GithubEventRepositoryFacts,
    registry::{
        GithubEventActivityPolicy, GithubEventChangedFilesStrategy, GithubEventRecursionPolicy,
        GithubEventRefRule, GithubEventRegistryEntry, GithubEventSourceRule,
        GithubEventTriggerModel, GithubEventTrustFact, GithubWorkflowEventKind,
    },
};

const ACTIVITIES: &[&str] = &[
    "assigned",
    "auto_merge_disabled",
    "auto_merge_enabled",
    "closed",
    "converted_to_draft",
    "demilestoned",
    "dequeued",
    "edited",
    "enqueued",
    "labeled",
    "locked",
    "milestoned",
    "opened",
    "ready_for_review",
    "reopened",
    "review_request_removed",
    "review_requested",
    "stacked",
    "synchronize",
    "unassigned",
    "unlabeled",
    "unlocked",
];

const TRUST_FACTS: &[GithubEventTrustFact] = &[
    GithubEventTrustFact::TriggeringActor,
    GithubEventTrustFact::SourceActor,
    GithubEventTrustFact::SourceRepository,
    GithubEventTrustFact::TargetRepository,
    GithubEventTrustFact::ForkRelationship,
    GithubEventTrustFact::Activity,
    GithubEventTrustFact::References,
    GithubEventTrustFact::Revisions,
    GithubEventTrustFact::Recursion,
];

pub(crate) const REGISTRATION: GithubEventRegistryEntry = GithubEventRegistryEntry {
    kind: GithubWorkflowEventKind::PullRequest,
    event_name: "pull_request",
    activities: GithubEventActivityPolicy::Closed(ACTIVITIES),
    trigger: GithubEventTriggerModel::PullRequest,
    reference: GithubEventRefRule::PullRequestExecutionReference,
    source: GithubEventSourceRule::PullRequestHeadRepository,
    changed_files: GithubEventChangedFilesStrategy::PullRequestFiles,
    trust_facts: TRUST_FACTS,
    recursion: GithubEventRecursionPolicy::GithubTokenSuppressed,
};

/// Facts-only schema-v1 projection of an authenticated pull-request event.
#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct GithubPullRequestEventFacts {
    actor: Option<GithubEventActor>,
    source_actor: Option<GithubEventActor>,
    target_repository: GithubEventRepositoryFacts,
    source_repository: GithubEventRepositoryFacts,
    number: NonZeroU64,
    action: GithubPullRequestAction,
    merged: bool,
    source_revision: ExactRevision,
    target_revision: ExactRevision,
    execution_revision: ExactRevision,
    source_ref: Box<str>,
    target_ref: Box<str>,
    execution_ref: Box<str>,
}

impl GithubPullRequestEventFacts {
    pub(crate) fn from_verified(event: &VerifiedGithubPullRequest) -> Self {
        Self {
            actor: event.actor().cloned(),
            source_actor: event.source_actor().cloned(),
            target_repository: GithubEventRepositoryFacts::from_repository(event.repository()),
            source_repository: GithubEventRepositoryFacts::from_repository(event.head_repository()),
            number: event.number(),
            action: event.action(),
            merged: event.merged(),
            source_revision: event.head_revision().clone(),
            target_revision: event.base_revision().clone(),
            // Delivery source ingestion and GitHub Checks are bound to the
            // signed head revision. A synchronize webhook may still carry the
            // previous synthetic merge revision while GitHub rematerializes
            // refs/pull/<n>/merge, so that value is not execution authority.
            execution_revision: event.head_revision().clone(),
            source_ref: event.head_ref().into(),
            target_ref: event.base_ref().into(),
            execution_ref: event.git_ref().into(),
        }
    }

    pub(crate) fn validate(&self) -> bool {
        self.actor
            .as_ref()
            .is_none_or(|actor| actor.validate().is_ok())
            && self
                .source_actor
                .as_ref()
                .is_none_or(|actor| actor.validate().is_ok())
            && self.target_repository.validate()
            && self.source_repository.validate()
            && normalize_branch_name(self.source_ref.to_string()).is_ok()
            && normalize_branch_name(self.target_ref.to_string()).is_ok()
            && (!self.merged || self.action == GithubPullRequestAction::Closed)
            && self.execution_ref.as_ref()
                == if self.merged {
                    format!("refs/heads/{}", self.target_ref)
                } else {
                    format!("refs/pull/{}/merge", self.number)
                }
    }

    /// Returns the event sender facts when supplied by GitHub.
    #[must_use]
    pub const fn actor(&self) -> Option<&GithubEventActor> {
        self.actor.as_ref()
    }

    /// Returns the pull-request author facts when supplied by GitHub.
    #[must_use]
    pub const fn source_actor(&self) -> Option<&GithubEventActor> {
        self.source_actor.as_ref()
    }

    /// Returns the base repository receiving the pull request.
    #[must_use]
    pub const fn target_repository(&self) -> &GithubEventRepositoryFacts {
        &self.target_repository
    }

    /// Returns the repository containing the pull-request head.
    #[must_use]
    pub const fn source_repository(&self) -> &GithubEventRepositoryFacts {
        &self.source_repository
    }

    /// Returns whether source and target repository identities differ.
    #[must_use]
    pub fn is_fork(&self) -> bool {
        self.source_repository.id() != self.target_repository.id()
    }

    /// Returns the pull-request number within the target repository.
    #[must_use]
    pub const fn number(&self) -> NonZeroU64 {
        self.number
    }

    /// Returns the closed provider activity.
    #[must_use]
    pub const fn action(&self) -> GithubPullRequestAction {
        self.action
    }

    /// Returns whether the pull request was merged.
    #[must_use]
    pub const fn merged(&self) -> bool {
        self.merged
    }

    /// Returns the exact source revision.
    #[must_use]
    pub const fn source_revision(&self) -> &ExactRevision {
        &self.source_revision
    }

    /// Returns the exact target revision observed by the event.
    #[must_use]
    pub const fn target_revision(&self) -> &ExactRevision {
        &self.target_revision
    }

    /// Returns the exact revision GitHub assigned to workflow execution.
    #[must_use]
    pub const fn execution_revision(&self) -> &ExactRevision {
        &self.execution_revision
    }

    /// Returns the unqualified source branch.
    #[must_use]
    pub fn source_ref(&self) -> &str {
        &self.source_ref
    }

    /// Returns the unqualified target branch.
    #[must_use]
    pub fn target_ref(&self) -> &str {
        &self.target_ref
    }

    /// Returns the exact synthetic or post-merge workflow reference.
    #[must_use]
    pub fn execution_ref(&self) -> &str {
        &self.execution_ref
    }
}

impl fmt::Debug for GithubPullRequestEventFacts {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GithubPullRequestEventFacts")
            .field("actor", &self.actor)
            .field("source_actor", &self.source_actor)
            .field("target_repository", &self.target_repository)
            .field("source_repository", &self.source_repository)
            .field("number", &self.number)
            .field("action", &self.action)
            .field("merged", &self.merged)
            .field("source_revision", &"[redacted]")
            .field("target_revision", &"[redacted]")
            .field("execution_revision", &"[redacted]")
            .field("source_ref", &"[redacted]")
            .field("target_ref", &"[redacted]")
            .field("execution_ref", &"[redacted]")
            .finish()
    }
}
