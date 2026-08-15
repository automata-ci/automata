use std::fmt;

use automata_ci_core::Sha256Digest;

use super::GithubWorkflowDispatchInputs;

/// Provider-verified changed-file selection used by path-filter evaluation.
#[derive(Clone, Eq, PartialEq)]
#[non_exhaustive]
pub enum GithubChangedFiles {
    /// The exact bounded file list considered by GitHub's diff selection.
    Complete {
        /// Canonical repository-relative paths.
        files: Vec<String>,
        /// Provider evidence digest when selection used production evidence.
        evidence_digest: Option<Sha256Digest>,
    },
    /// GitHub bypassed path filtering because the diff could not be produced.
    BypassPathFilters {
        /// Provider evidence digest when run-all used production evidence.
        evidence_digest: Option<Sha256Digest>,
    },
}

impl GithubChangedFiles {
    /// Creates a complete changed-file selection.
    #[must_use]
    pub fn complete(files: impl IntoIterator<Item = impl Into<String>>) -> Self {
        Self::Complete {
            files: files.into_iter().map(Into::into).collect(),
            evidence_digest: None,
        }
    }

    /// Creates a complete changed-file selection bound to provider evidence.
    #[must_use]
    pub fn complete_with_evidence(
        files: impl IntoIterator<Item = impl Into<String>>,
        evidence_digest: Sha256Digest,
    ) -> Self {
        Self::Complete {
            files: files.into_iter().map(Into::into).collect(),
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
}

impl fmt::Debug for GithubChangedFiles {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Complete { files, .. } => formatter
                .debug_struct("Complete")
                .field("file_count", &files.len())
                .field("evidence_bound", &self.evidence_digest().is_some())
                .finish_non_exhaustive(),
            Self::BypassPathFilters { .. } => formatter
                .debug_struct("BypassPathFilters")
                .field("evidence_bound", &self.evidence_digest().is_some())
                .finish(),
        }
    }
}

/// Selection metadata from a verified GitHub event or provider invocation.
///
/// Provider-specific selector fields remain attached only to the compile
/// request. When changed-file evidence participates in selection, its
/// canonical digest is copied into provider-neutral event provenance so the
/// immutable plan and its admission digest bind the external decision without
/// granting provider authority.
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
