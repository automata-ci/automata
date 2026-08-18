use std::fmt;

use automata_ci_core::Sha256Digest;
use automata_ci_provider::NormalizedTrigger;

use crate::provider_event_document::{merge_queue_activity_name, pull_request_activity_name};

use super::GithubWorkflowDispatchInputs;

/// Provider-verified changed-file selection used by path-filter evaluation.
#[derive(Clone, Eq, PartialEq)]
#[non_exhaustive]
pub enum ProviderChangedFiles {
    /// The exact bounded file list considered by the provider's diff selection.
    Complete {
        /// Canonical repository-relative path candidates. A rename contributes
        /// both its previous and current path.
        files: Vec<String>,
        /// Provider file records represented by the path candidates.
        selected_file_count: usize,
        /// Provider evidence digest when selection used production evidence.
        evidence_digest: Option<Sha256Digest>,
    },
    /// The provider required path filtering to be bypassed.
    BypassPathFilters {
        /// Provider evidence digest when run-all used production evidence.
        evidence_digest: Option<Sha256Digest>,
    },
}

impl ProviderChangedFiles {
    /// Creates a complete changed-file selection.
    #[must_use]
    pub fn complete(files: impl IntoIterator<Item = impl Into<String>>) -> Self {
        let files = files.into_iter().map(Into::into).collect::<Vec<_>>();
        Self::Complete {
            selected_file_count: files.len(),
            files,
            evidence_digest: None,
        }
    }

    /// Creates a complete changed-file selection bound to provider evidence.
    #[must_use]
    pub fn complete_with_evidence(
        files: impl IntoIterator<Item = impl Into<String>>,
        evidence_digest: Sha256Digest,
    ) -> Self {
        let files = files.into_iter().map(Into::into).collect::<Vec<_>>();
        Self::Complete {
            selected_file_count: files.len(),
            files,
            evidence_digest: Some(evidence_digest),
        }
    }

    /// Creates a complete provider selection where rename records may produce
    /// two repository-relative path candidates.
    #[must_use]
    pub fn complete_selection_with_evidence(
        files: impl IntoIterator<Item = impl Into<String>>,
        selected_file_count: usize,
        evidence_digest: Sha256Digest,
    ) -> Self {
        Self::Complete {
            files: files.into_iter().map(Into::into).collect(),
            selected_file_count,
            evidence_digest: Some(evidence_digest),
        }
    }

    /// Records provider evidence that path filters must be treated as matched.
    #[must_use]
    pub const fn bypass_path_filters() -> Self {
        Self::BypassPathFilters {
            evidence_digest: None,
        }
    }

    /// Records provider-proven run-all selection bound to its evidence.
    #[must_use]
    pub const fn bypass_path_filters_with_evidence(evidence_digest: Sha256Digest) -> Self {
        Self::BypassPathFilters {
            evidence_digest: Some(evidence_digest),
        }
    }

    /// Returns the external evidence digest carried into immutable plan provenance.
    #[must_use]
    pub const fn evidence_digest(&self) -> Option<Sha256Digest> {
        match self {
            Self::Complete {
                evidence_digest, ..
            }
            | Self::BypassPathFilters { evidence_digest } => *evidence_digest,
        }
    }

    /// Returns the bounded path set, or `None` for provider-proven run-all.
    #[must_use]
    pub fn complete_files(&self) -> Option<&[String]> {
        match self {
            Self::Complete { files, .. } => Some(files),
            Self::BypassPathFilters { .. } => None,
        }
    }

    /// Returns provider file records represented by complete path candidates.
    #[must_use]
    pub const fn selected_file_count(&self) -> Option<usize> {
        match self {
            Self::Complete {
                selected_file_count,
                ..
            } => Some(*selected_file_count),
            Self::BypassPathFilters { .. } => None,
        }
    }
}

impl fmt::Debug for ProviderChangedFiles {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Complete {
                files,
                selected_file_count,
                ..
            } => formatter
                .debug_struct("Complete")
                .field("selected_file_count", selected_file_count)
                .field("path_candidate_count", &files.len())
                .field("evidence_bound", &self.evidence_digest().is_some())
                .finish_non_exhaustive(),
            Self::BypassPathFilters { .. } => formatter
                .debug_struct("BypassPathFilters")
                .field("evidence_bound", &self.evidence_digest().is_some())
                .finish(),
        }
    }
}

/// Selection metadata from a verified provider event or trusted invocation.
///
/// Provider-specific selector fields remain attached only to the compile
/// request. When changed-file evidence participates in selection, its
/// canonical digest is copied into provider-neutral event provenance so the
/// immutable plan and its admission digest bind the external decision without
/// granting provider authority.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum ProviderEventMetadata {
    /// A normalized `push` event.
    Push {
        /// The payload's top-level `deleted` value.
        deleted: bool,
        /// Provider-verified diff selection, required only for path filters.
        changed_files: Option<ProviderChangedFiles>,
    },
    /// A normalized pull-request or merge-request event.
    PullRequest {
        /// The payload's top-level activity `action`.
        action: String,
        /// `pull_request.base.ref`, without a `refs/heads/` prefix.
        base_ref: String,
        /// Provider-verified diff selection, required only for path filters.
        changed_files: Option<ProviderChangedFiles>,
    },
    /// A normalized merge-queue event.
    MergeGroup {
        /// The payload's top-level activity `action`.
        action: String,
        /// The merge group's fully qualified target branch reference.
        base_ref: String,
    },
    /// A provider-verified custom `repository_dispatch` invocation.
    RepositoryDispatch {
        /// The exact bounded custom event type from the authenticated payload.
        event_type: String,
    },
    /// A trusted scheduler invocation for one configured `on.schedule` entry.
    Schedule {
        /// The exact configured cron expression that fired the workflow.
        cron: String,
    },
    /// A provider-verified `workflow_dispatch` invocation.
    WorkflowDispatch {
        /// Bounded raw input properties to validate against the selected source contract.
        inputs: GithubWorkflowDispatchInputs,
    },
}

impl ProviderEventMetadata {
    /// Converts authenticated provider-neutral trigger facts into the event
    /// vocabulary understood by the Actions workflow dialect.
    #[must_use]
    pub fn from_normalized_trigger(trigger: &NormalizedTrigger) -> Self {
        match trigger {
            NormalizedTrigger::Push(push) => Self::push(push.after().is_none()),
            NormalizedTrigger::PullRequest(pull_request) => Self::pull_request(
                pull_request_activity_name(pull_request.activity()),
                pull_request.base_ref().short_name(),
            ),
            NormalizedTrigger::MergeQueue(merge_queue) => Self::merge_group(
                merge_queue_activity_name(merge_queue.activity()),
                merge_queue.target_ref().full(),
            ),
            NormalizedTrigger::RepositoryDispatch(dispatch) => {
                Self::repository_dispatch(dispatch.event_type().as_str())
            }
        }
    }

    /// Reports whether selector metadata retains the normalized trigger's
    /// immutable event shape and activity fields.
    ///
    /// Changed-file evidence may refine only push and pull-request metadata;
    /// it cannot alter event identity, activity, deletion state, or target ref.
    #[must_use]
    pub fn matches_normalized_trigger(&self, trigger: &NormalizedTrigger) -> bool {
        match (self, trigger) {
            (Self::Push { deleted, .. }, NormalizedTrigger::Push(push)) => {
                *deleted == push.after().is_none()
            }
            (
                Self::PullRequest {
                    action, base_ref, ..
                },
                NormalizedTrigger::PullRequest(pull_request),
            ) => {
                action == pull_request_activity_name(pull_request.activity())
                    && base_ref == pull_request.base_ref().short_name()
            }
            (
                Self::MergeGroup { action, base_ref },
                NormalizedTrigger::MergeQueue(merge_queue),
            ) => {
                action == merge_queue_activity_name(merge_queue.activity())
                    && base_ref == merge_queue.target_ref().full()
            }
            (
                Self::RepositoryDispatch { event_type },
                NormalizedTrigger::RepositoryDispatch(dispatch),
            ) => event_type == dispatch.event_type().as_str(),
            _ => false,
        }
    }

    /// Returns external changed-file evidence used by this event, when present.
    #[must_use]
    pub const fn changed_files_evidence_digest(&self) -> Option<Sha256Digest> {
        match self {
            Self::Push { changed_files, .. } | Self::PullRequest { changed_files, .. } => {
                match changed_files {
                    Some(changed_files) => changed_files.evidence_digest(),
                    None => None,
                }
            }
            Self::MergeGroup { .. }
            | Self::RepositoryDispatch { .. }
            | Self::Schedule { .. }
            | Self::WorkflowDispatch { .. } => None,
        }
    }

    /// Creates metadata for a `push` payload.
    #[must_use]
    pub const fn push(deleted: bool) -> Self {
        Self::Push {
            deleted,
            changed_files: None,
        }
    }

    /// Creates metadata for a `push` payload with verified diff selection.
    #[must_use]
    pub const fn push_with_changed_files(
        deleted: bool,
        changed_files: ProviderChangedFiles,
    ) -> Self {
        Self::Push {
            deleted,
            changed_files: Some(changed_files),
        }
    }

    /// Creates metadata for a `pull_request` payload.
    #[must_use]
    pub fn pull_request(action: impl Into<String>, base_ref: impl Into<String>) -> Self {
        Self::PullRequest {
            action: action.into(),
            base_ref: base_ref.into(),
            changed_files: None,
        }
    }

    /// Creates pull-request metadata with verified diff selection.
    #[must_use]
    pub fn pull_request_with_changed_files(
        action: impl Into<String>,
        base_ref: impl Into<String>,
        changed_files: ProviderChangedFiles,
    ) -> Self {
        Self::PullRequest {
            action: action.into(),
            base_ref: base_ref.into(),
            changed_files: Some(changed_files),
        }
    }

    /// Creates metadata for a merge-queue group event.
    #[must_use]
    pub fn merge_group(action: impl Into<String>, base_ref: impl Into<String>) -> Self {
        Self::MergeGroup {
            action: action.into(),
            base_ref: base_ref.into(),
        }
    }

    /// Creates metadata for a custom repository-dispatch event.
    #[must_use]
    pub fn repository_dispatch(event_type: impl Into<String>) -> Self {
        Self::RepositoryDispatch {
            event_type: event_type.into(),
        }
    }

    /// Creates metadata for a scheduled invocation.
    #[must_use]
    pub fn schedule(cron: impl Into<String>) -> Self {
        Self::Schedule { cron: cron.into() }
    }

    /// Creates metadata for a manually dispatched invocation.
    ///
    /// The input wrapper must have been constructed from integrity-verified
    /// provider evidence; the compiler validates it against the exact workflow
    /// source contract before producing an `inputs` context.
    #[must_use]
    pub const fn workflow_dispatch(inputs: GithubWorkflowDispatchInputs) -> Self {
        Self::WorkflowDispatch { inputs }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use automata_ci_provider::{MergeQueueActivity, PullRequestActivity};

    #[test]
    fn normalized_provider_activities_map_to_actions_dialect_names() {
        assert_eq!(
            pull_request_activity_name(PullRequestActivity::Synchronized),
            "synchronize"
        );
        assert_eq!(
            pull_request_activity_name(PullRequestActivity::Merged),
            "closed"
        );
        assert_eq!(
            merge_queue_activity_name(MergeQueueActivity::Queued),
            "checks_requested"
        );
        assert_eq!(
            merge_queue_activity_name(MergeQueueActivity::Removed),
            "destroyed"
        );
    }
}
