use std::fmt;

use serde::{Deserialize, Serialize};

use crate::{VerifiedGithubRepositoryDispatch, webhook::normalize_branch_name};

use super::{
    GithubEventActor, GithubEventRepositoryFacts,
    registry::{
        GithubEventActivityPolicy, GithubEventChangedFilesStrategy, GithubEventRecursionPolicy,
        GithubEventRefRule, GithubEventRegistryEntry, GithubEventSourceRule,
        GithubEventTriggerModel, GithubEventTrustFact, GithubWorkflowEventKind,
    },
};

const TRUST_FACTS: &[GithubEventTrustFact] = &[
    GithubEventTrustFact::TriggeringActor,
    GithubEventTrustFact::SourceRepository,
    GithubEventTrustFact::TargetRepository,
    GithubEventTrustFact::ForkRelationship,
    GithubEventTrustFact::Activity,
    GithubEventTrustFact::References,
    GithubEventTrustFact::Recursion,
];

pub(crate) const REGISTRATION: GithubEventRegistryEntry = GithubEventRegistryEntry {
    kind: GithubWorkflowEventKind::RepositoryDispatch,
    event_name: "repository_dispatch",
    activities: GithubEventActivityPolicy::BoundedRepositoryDispatchType,
    trigger: GithubEventTriggerModel::RepositoryDispatch,
    reference: GithubEventRefRule::RepositoryDefaultBranch,
    source: GithubEventSourceRule::EventRepository,
    changed_files: GithubEventChangedFilesStrategy::None,
    trust_facts: TRUST_FACTS,
    recursion: GithubEventRecursionPolicy::ExplicitDispatchRequiresPolicy,
};

/// Facts-only schema-v1 projection of an authenticated repository dispatch.
///
/// The arbitrary `client_payload` is deliberately absent. Its exact bytes are
/// bound by the raw-object digest and must not become ambient policy input.
#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct GithubRepositoryDispatchEventFacts {
    actor: Option<GithubEventActor>,
    target_repository: GithubEventRepositoryFacts,
    event_type: Box<str>,
    branch: Box<str>,
    git_ref: Box<str>,
}

impl GithubRepositoryDispatchEventFacts {
    pub(crate) fn from_verified(event: &VerifiedGithubRepositoryDispatch) -> Self {
        Self {
            actor: event.actor().cloned(),
            target_repository: GithubEventRepositoryFacts::from_repository(event.repository()),
            event_type: event.event_type().into(),
            branch: event.branch().into(),
            git_ref: event.git_ref().into(),
        }
    }

    pub(crate) fn validate(&self) -> bool {
        let event_type_chars = self.event_type.chars().count();
        self.actor
            .as_ref()
            .is_none_or(|actor| actor.validate().is_ok())
            && self.target_repository.validate()
            && (1..=100).contains(&event_type_chars)
            && !self.event_type.chars().any(char::is_control)
            && normalize_branch_name(self.branch.to_string()).is_ok()
            && self.git_ref.as_ref() == format!("refs/heads/{}", self.branch)
    }

    /// Returns the event sender facts when supplied by GitHub.
    #[must_use]
    pub const fn actor(&self) -> Option<&GithubEventActor> {
        self.actor.as_ref()
    }

    /// Returns the repository that is both source and target for this dispatch.
    #[must_use]
    pub const fn target_repository(&self) -> &GithubEventRepositoryFacts {
        &self.target_repository
    }

    /// Returns the bounded custom event type.
    #[must_use]
    pub fn event_type(&self) -> &str {
        &self.event_type
    }

    /// Returns the authenticated default branch.
    #[must_use]
    pub fn branch(&self) -> &str {
        &self.branch
    }

    /// Returns the exact default-branch workflow reference.
    #[must_use]
    pub fn git_ref(&self) -> &str {
        &self.git_ref
    }
}

impl fmt::Debug for GithubRepositoryDispatchEventFacts {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GithubRepositoryDispatchEventFacts")
            .field("actor", &self.actor)
            .field("target_repository", &self.target_repository)
            .field("event_type", &"[redacted]")
            .field("branch", &"[redacted]")
            .field("git_ref", &"[redacted]")
            .finish()
    }
}
