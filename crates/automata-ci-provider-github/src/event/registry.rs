use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};
use thiserror::Error;

use super::{merge_group, pull_request, push, repository_dispatch};

/// Schema version of the closed GitHub workflow-event registry.
pub const GITHUB_EVENT_REGISTRY_SCHEMA_V1: u16 = 1;

/// Workflow-producing GitHub event kinds supported by registry schema v1.
///
/// Native Check Run and Check Suite webhook messages are deliberately absent:
/// they are control-plane rerun inputs, not workflow-trigger events.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum GithubWorkflowEventKind {
    /// A Git reference update.
    Push,
    /// A pull-request lifecycle activity.
    PullRequest,
    /// A merge-queue group lifecycle activity.
    MergeGroup,
    /// An explicitly requested custom repository event.
    RepositoryDispatch,
}

impl GithubWorkflowEventKind {
    /// Every event kind in schema v1, in canonical registry order.
    pub const ALL: [Self; 4] = [
        Self::Push,
        Self::PullRequest,
        Self::MergeGroup,
        Self::RepositoryDispatch,
    ];

    /// Returns GitHub's canonical webhook header spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Push => "push",
            Self::PullRequest => "pull_request",
            Self::MergeGroup => "merge_group",
            Self::RepositoryDispatch => "repository_dispatch",
        }
    }
}

/// How a registry entry constrains provider activity names.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GithubEventActivityPolicy {
    /// The event has no provider activity discriminator.
    None,
    /// Only the listed provider activities are accepted.
    Closed(&'static [&'static str]),
    /// A nonempty, provider-bounded repository-dispatch type is accepted.
    BoundedRepositoryDispatchType,
}

/// Typed trigger projection used by workflow selection.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GithubEventTriggerModel {
    /// GitHub `push` trigger semantics.
    Push,
    /// GitHub `pull_request` trigger semantics.
    PullRequest,
    /// GitHub `merge_group` trigger semantics.
    MergeGroup,
    /// GitHub `repository_dispatch` trigger semantics.
    RepositoryDispatch,
}

/// Authoritative reference rule for an event kind.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GithubEventRefRule {
    /// Use the exact pushed branch or tag reference.
    PushedReference,
    /// Use the synthetic pull-request merge ref, or the base ref after merge.
    PullRequestExecutionReference,
    /// Use the exact merge-group head reference.
    MergeGroupHeadReference,
    /// Use the repository default branch authenticated by the dispatch body.
    RepositoryDefaultBranch,
}

/// Authoritative source-repository rule for an event kind.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GithubEventSourceRule {
    /// Source and target are the event repository.
    EventRepository,
    /// Source is the pull-request head repository and target is the base repository.
    PullRequestHeadRepository,
    /// The merge group is target-owned and remains read-only without constituent evidence.
    MergeGroupTargetWithUnresolvedConstituents,
}

/// Provider evidence used to calculate changed files.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GithubEventChangedFilesStrategy {
    /// Compare the authenticated before and after push revisions.
    PushCompare,
    /// Enumerate the pull request's files through the pinned provider API.
    PullRequestFiles,
    /// This event kind has no changed-file trigger input.
    None,
}

/// Provider recursion behavior relevant to workflow admission.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GithubEventRecursionPolicy {
    /// Events produced by the repository `GITHUB_TOKEN` are suppressed upstream.
    GithubTokenSuppressed,
    /// Repository dispatch is an explicit recursion-capable ingress and needs policy.
    ExplicitDispatchRequiresPolicy,
}

/// Authenticated facts a later authorization policy may consume.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum GithubEventTrustFact {
    /// Stable identity and classification of the webhook sender.
    TriggeringActor,
    /// Stable identity and classification of the source author, when distinct.
    SourceActor,
    /// Immutable source repository identity.
    SourceRepository,
    /// Immutable target repository identity.
    TargetRepository,
    /// Whether source and target repositories are identical.
    ForkRelationship,
    /// Provider activity discriminator.
    Activity,
    /// Source and target references.
    References,
    /// Source, target, and execution revisions.
    Revisions,
    /// Provider recursion semantics.
    Recursion,
}

/// One immutable row in the schema-v1 event registry.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GithubEventRegistryEntry {
    pub(crate) kind: GithubWorkflowEventKind,
    pub(crate) event_name: &'static str,
    pub(crate) activities: GithubEventActivityPolicy,
    pub(crate) trigger: GithubEventTriggerModel,
    pub(crate) reference: GithubEventRefRule,
    pub(crate) source: GithubEventSourceRule,
    pub(crate) changed_files: GithubEventChangedFilesStrategy,
    pub(crate) trust_facts: &'static [GithubEventTrustFact],
    pub(crate) recursion: GithubEventRecursionPolicy,
}

impl GithubEventRegistryEntry {
    /// Returns the closed event kind.
    #[must_use]
    pub const fn kind(self) -> GithubWorkflowEventKind {
        self.kind
    }

    /// Returns the exact `X-GitHub-Event` value.
    #[must_use]
    pub const fn event_name(self) -> &'static str {
        self.event_name
    }

    /// Returns the activity discriminator policy.
    #[must_use]
    pub const fn activities(self) -> GithubEventActivityPolicy {
        self.activities
    }

    /// Returns the typed workflow-trigger projection.
    #[must_use]
    pub const fn trigger(self) -> GithubEventTriggerModel {
        self.trigger
    }

    /// Returns the authoritative reference rule.
    #[must_use]
    pub const fn reference_rule(self) -> GithubEventRefRule {
        self.reference
    }

    /// Returns the authoritative source-repository rule.
    #[must_use]
    pub const fn source_rule(self) -> GithubEventSourceRule {
        self.source
    }

    /// Returns the changed-file evidence strategy.
    #[must_use]
    pub const fn changed_files_strategy(self) -> GithubEventChangedFilesStrategy {
        self.changed_files
    }

    /// Returns the complete authorization-input inventory.
    #[must_use]
    pub const fn trust_facts(self) -> &'static [GithubEventTrustFact] {
        self.trust_facts
    }

    /// Returns the provider recursion policy.
    #[must_use]
    pub const fn recursion_policy(self) -> GithubEventRecursionPolicy {
        self.recursion
    }
}

const ENTRIES: [GithubEventRegistryEntry; 4] = [
    push::REGISTRATION,
    pull_request::REGISTRATION,
    merge_group::REGISTRATION,
    repository_dispatch::REGISTRATION,
];

/// Closed schema-v1 registry for workflow-producing GitHub events.
#[derive(Debug)]
pub struct GithubEventRegistryV1;

impl GithubEventRegistryV1 {
    /// Returns the registry schema version.
    #[must_use]
    pub const fn schema() -> u16 {
        GITHUB_EVENT_REGISTRY_SCHEMA_V1
    }

    /// Returns every registration in canonical order.
    #[must_use]
    pub const fn entries() -> &'static [GithubEventRegistryEntry] {
        &ENTRIES
    }

    /// Looks up an exact provider event name and fails closed for controls or
    /// unknown future event kinds.
    ///
    /// # Errors
    ///
    /// Returns [`GithubEventRegistryError::UnsupportedEvent`] when the name is
    /// not one of the four schema-v1 workflow event kinds.
    pub fn lookup(event_name: &str) -> Result<GithubEventRegistryEntry, GithubEventRegistryError> {
        ENTRIES
            .iter()
            .copied()
            .find(|entry| entry.event_name == event_name)
            .ok_or(GithubEventRegistryError::UnsupportedEvent)
    }

    /// Returns the registration for a closed event kind.
    #[must_use]
    pub const fn entry(kind: GithubWorkflowEventKind) -> GithubEventRegistryEntry {
        match kind {
            GithubWorkflowEventKind::Push => push::REGISTRATION,
            GithubWorkflowEventKind::PullRequest => pull_request::REGISTRATION,
            GithubWorkflowEventKind::MergeGroup => merge_group::REGISTRATION,
            GithubWorkflowEventKind::RepositoryDispatch => repository_dispatch::REGISTRATION,
        }
    }

    /// Proves registry completeness, uniqueness, canonical names, activities,
    /// and trust-input uniqueness.
    ///
    /// # Errors
    ///
    /// Returns a sanitized invariant error for an incomplete or ambiguous
    /// compiled registry.
    pub fn validate() -> Result<(), GithubEventRegistryError> {
        validate_entries(&ENTRIES)
    }
}

/// Closed-registry validation or lookup failure.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum GithubEventRegistryError {
    /// The name is not a workflow-producing event in schema v1.
    #[error("the GitHub workflow event is not registered")]
    UnsupportedEvent,
    /// A compiled event kind is absent or repeated.
    #[error("the GitHub workflow event registry is incomplete or duplicated")]
    IncompleteOrDuplicate,
    /// A registration's provider name does not match its closed kind.
    #[error("a GitHub workflow event registration has a noncanonical name")]
    NoncanonicalName,
    /// A closed activity or trust-fact list contains a duplicate.
    #[error("a GitHub workflow event registration contains duplicate facts")]
    DuplicateFact,
}

fn validate_entries(entries: &[GithubEventRegistryEntry]) -> Result<(), GithubEventRegistryError> {
    if entries.len() != GithubWorkflowEventKind::ALL.len() {
        return Err(GithubEventRegistryError::IncompleteOrDuplicate);
    }
    let mut kinds = BTreeSet::new();
    let mut names = BTreeSet::new();
    for entry in entries {
        if entry.event_name != entry.kind.as_str()
            || !kinds.insert(entry.kind)
            || !names.insert(entry.event_name)
        {
            return Err(if entry.event_name == entry.kind.as_str() {
                GithubEventRegistryError::IncompleteOrDuplicate
            } else {
                GithubEventRegistryError::NoncanonicalName
            });
        }
        if let GithubEventActivityPolicy::Closed(activities) = entry.activities {
            let unique = activities.iter().copied().collect::<BTreeSet<_>>();
            if unique.len() != activities.len() {
                return Err(GithubEventRegistryError::DuplicateFact);
            }
        }
        let trust_facts = entry.trust_facts.iter().copied().collect::<BTreeSet<_>>();
        if trust_facts.len() != entry.trust_facts.len() {
            return Err(GithubEventRegistryError::DuplicateFact);
        }
    }
    if GithubWorkflowEventKind::ALL
        .iter()
        .any(|kind| !kinds.contains(kind))
    {
        return Err(GithubEventRegistryError::IncompleteOrDuplicate);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compiled_registry_is_complete_and_unique() {
        assert_eq!(GithubEventRegistryV1::validate(), Ok(()));
    }

    #[test]
    fn duplicate_registration_fails_closed() {
        let duplicate = [push::REGISTRATION, push::REGISTRATION];
        assert_eq!(
            validate_entries(&duplicate),
            Err(GithubEventRegistryError::IncompleteOrDuplicate)
        );
    }

    #[test]
    fn controls_and_unknown_events_are_not_workflow_events() {
        for event in ["check_run", "check_suite", "issues", "workflow_dispatch"] {
            assert_eq!(
                GithubEventRegistryV1::lookup(event),
                Err(GithubEventRegistryError::UnsupportedEvent)
            );
        }
    }
}
