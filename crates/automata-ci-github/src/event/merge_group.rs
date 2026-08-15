use std::fmt;

use automata_ci_scm::ExactRevision;
use serde::{Deserialize, Serialize};

use crate::{GithubMergeGroupAction, VerifiedGithubMergeGroup};

use super::{
    GithubEventActor, GithubEventRefFacts, GithubEventRepositoryFacts,
    registry::{
        GithubEventActivityPolicy, GithubEventChangedFilesStrategy, GithubEventRecursionPolicy,
        GithubEventRefRule, GithubEventRegistryEntry, GithubEventSourceRule,
        GithubEventTriggerModel, GithubEventTrustFact, GithubWorkflowEventKind,
    },
};

const ACTIVITIES: &[&str] = &["checks_requested", "destroyed"];
const TRUST_FACTS: &[GithubEventTrustFact] = &[
    GithubEventTrustFact::TriggeringActor,
    GithubEventTrustFact::TargetRepository,
    GithubEventTrustFact::Activity,
    GithubEventTrustFact::References,
    GithubEventTrustFact::Revisions,
    GithubEventTrustFact::Recursion,
];

pub(crate) const REGISTRATION: GithubEventRegistryEntry = GithubEventRegistryEntry {
    kind: GithubWorkflowEventKind::MergeGroup,
    event_name: "merge_group",
    activities: GithubEventActivityPolicy::Closed(ACTIVITIES),
    trigger: GithubEventTriggerModel::MergeGroup,
    reference: GithubEventRefRule::MergeGroupHeadReference,
    source: GithubEventSourceRule::MergeGroupTargetWithUnresolvedConstituents,
    changed_files: GithubEventChangedFilesStrategy::None,
    trust_facts: TRUST_FACTS,
    recursion: GithubEventRecursionPolicy::GithubTokenSuppressed,
};

/// Facts-only schema-v1 projection of an authenticated merge-group event.
#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct GithubMergeGroupEventFacts {
    actor: Option<GithubEventActor>,
    target_repository: GithubEventRepositoryFacts,
    action: GithubMergeGroupAction,
    execution_revision: ExactRevision,
    target_revision: ExactRevision,
    execution_ref: GithubEventRefFacts,
    target_ref: GithubEventRefFacts,
}

impl GithubMergeGroupEventFacts {
    pub(crate) fn from_verified(event: &VerifiedGithubMergeGroup) -> Self {
        Self {
            actor: event.actor().cloned(),
            target_repository: GithubEventRepositoryFacts::from_repository(event.repository()),
            action: event.action(),
            execution_revision: event.head_revision().clone(),
            target_revision: event.base_revision().clone(),
            execution_ref: GithubEventRefFacts::from_ref(event.head_ref()),
            target_ref: GithubEventRefFacts::from_ref(event.base_ref()),
        }
    }

    pub(crate) fn validate(&self) -> bool {
        self.actor
            .as_ref()
            .is_none_or(|actor| actor.validate().is_ok())
            && self.target_repository.validate()
            && self.execution_ref.validate()
            && self.target_ref.validate()
    }

    /// Returns the event sender facts when supplied by GitHub.
    #[must_use]
    pub const fn actor(&self) -> Option<&GithubEventActor> {
        self.actor.as_ref()
    }

    /// Returns the repository whose merge queue owns this group.
    #[must_use]
    pub const fn target_repository(&self) -> &GithubEventRepositoryFacts {
        &self.target_repository
    }

    /// Returns the closed provider activity.
    #[must_use]
    pub const fn action(&self) -> GithubMergeGroupAction {
        self.action
    }

    /// Returns the exact merge-group revision used for execution.
    #[must_use]
    pub const fn execution_revision(&self) -> &ExactRevision {
        &self.execution_revision
    }

    /// Returns the exact target revision observed by the group.
    #[must_use]
    pub const fn target_revision(&self) -> &ExactRevision {
        &self.target_revision
    }

    /// Returns the exact merge-group head reference.
    #[must_use]
    pub const fn execution_ref(&self) -> &GithubEventRefFacts {
        &self.execution_ref
    }

    /// Returns the exact target reference.
    #[must_use]
    pub const fn target_ref(&self) -> &GithubEventRefFacts {
        &self.target_ref
    }
}

impl fmt::Debug for GithubMergeGroupEventFacts {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GithubMergeGroupEventFacts")
            .field("actor", &self.actor)
            .field("target_repository", &self.target_repository)
            .field("action", &self.action)
            .field("execution_revision", &"[redacted]")
            .field("target_revision", &"[redacted]")
            .field("execution_ref", &"[redacted]")
            .field("target_ref", &"[redacted]")
            .finish()
    }
}
