use std::fmt;

use super::GithubWorkflowDispatchInputs;

/// Provider-verified changed-file selection used by path-filter evaluation.
#[derive(Clone, Eq, PartialEq)]
#[non_exhaustive]
pub enum GithubChangedFiles {
    /// The exact bounded file list considered by GitHub's diff selection.
    Complete(Vec<String>),
    /// GitHub bypassed path filtering because the diff could not be produced.
    BypassPathFilters,
}

impl GithubChangedFiles {
    /// Creates a complete changed-file selection.
    #[must_use]
    pub fn complete(files: impl IntoIterator<Item = impl Into<String>>) -> Self {
        Self::Complete(files.into_iter().map(Into::into).collect())
    }

    /// Records provider evidence that path filters must be treated as matched.
    #[must_use]
    pub const fn bypass_path_filters() -> Self {
        Self::BypassPathFilters
    }
}

impl fmt::Debug for GithubChangedFiles {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Complete(files) => formatter
                .debug_struct("Complete")
                .field("file_count", &files.len())
                .finish_non_exhaustive(),
            Self::BypassPathFilters => formatter.write_str("BypassPathFilters"),
        }
    }
}

/// Selection metadata from a verified GitHub event or provider invocation.
///
/// The neutral workflow event provenance intentionally does not carry
/// provider-specific selector fields.
/// Keep the metadata attached to the compile request; it is not copied into
/// the provider-neutral workflow plan. Until a future plan schema carries a
/// canonical selection digest, admission must integrity-bind the verified raw
/// webhook payload to the immutable plan so replay cannot substitute these
/// fields.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum GithubEventMetadata {
    /// A GitHub `push` payload.
    Push {
        /// The payload's top-level `deleted` value.
        deleted: bool,
        /// Provider-verified diff selection, required only for path filters.
        changed_files: Option<GithubChangedFiles>,
    },
    /// A GitHub `pull_request` payload.
    PullRequest {
        /// The payload's top-level activity `action`.
        action: String,
        /// `pull_request.base.ref`, without a `refs/heads/` prefix.
        base_ref: String,
        /// Provider-verified diff selection, required only for path filters.
        changed_files: Option<GithubChangedFiles>,
    },
    /// A GitHub `merge_group` payload.
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

impl GithubEventMetadata {
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
    pub const fn push_with_changed_files(deleted: bool, changed_files: GithubChangedFiles) -> Self {
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
        changed_files: GithubChangedFiles,
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
