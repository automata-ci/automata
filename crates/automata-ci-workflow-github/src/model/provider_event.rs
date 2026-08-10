use std::fmt;

/// Provider-verified changed-file selection used by path-filter evaluation.
#[derive(Clone, Eq, PartialEq)]
#[non_exhaustive]
pub enum GithubChangedFilesV1 {
    /// The exact bounded file list considered by GitHub's diff selection.
    Complete(Vec<String>),
    /// GitHub bypassed path filtering because the diff could not be produced.
    BypassPathFilters,
}

impl GithubChangedFilesV1 {
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

impl fmt::Debug for GithubChangedFilesV1 {
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
/// This type is explicitly versioned because the neutral workflow event
/// provenance intentionally does not carry provider-specific selector fields.
/// Keep the metadata attached to the compile request; it is not copied into
/// the provider-neutral workflow plan. Until a future plan schema carries a
/// canonical selection digest, admission must integrity-bind the verified raw
/// webhook payload to the immutable plan so replay cannot substitute these
/// fields.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum GithubEventMetadataV1 {
    /// A GitHub `push` payload.
    Push {
        /// The payload's top-level `deleted` value.
        deleted: bool,
        /// Provider-verified diff selection, required only for path filters.
        changed_files: Option<GithubChangedFilesV1>,
    },
    /// A GitHub `pull_request` payload.
    PullRequest {
        /// The payload's top-level activity `action`.
        action: String,
        /// `pull_request.base.ref`, without a `refs/heads/` prefix.
        base_ref: String,
        /// Provider-verified diff selection, required only for path filters.
        changed_files: Option<GithubChangedFilesV1>,
    },
    /// A trusted scheduler invocation for one configured `on.schedule` entry.
    Schedule {
        /// The exact configured cron expression that fired the workflow.
        cron: String,
    },
}

impl GithubEventMetadataV1 {
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
        changed_files: GithubChangedFilesV1,
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
        changed_files: GithubChangedFilesV1,
    ) -> Self {
        Self::PullRequest {
            action: action.into(),
            base_ref: base_ref.into(),
            changed_files: Some(changed_files),
        }
    }

    /// Creates metadata for a scheduled invocation.
    #[must_use]
    pub fn schedule(cron: impl Into<String>) -> Self {
        Self::Schedule { cron: cron.into() }
    }
}
