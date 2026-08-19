use std::{
    collections::{BTreeSet, HashSet},
    fmt,
    num::NonZeroU64,
    time::Instant,
};

use async_trait::async_trait;
use automata_ci_auth::{github::GithubEndpointError, secret::SecretStringRef};
use automata_ci_core::GitObjectId;
use automata_ci_provider::{NormalizedTrigger, ProviderRepositoryPath, PushCommitEvidence};
use automata_ci_scm::{
    ChangedFile, ChangedFileIncompleteReason, ChangedFileNotApplicableReason,
    ChangedFilePageAccumulator, ChangedFilePageEvidence, ChangedFileRead, ChangedFileReader,
    ChangedFileRequest, RepositoryId, ScmError, ScmErrorKind,
};
use bytes::Bytes;
use reqwest::{RequestBuilder, StatusCode, header::ACCEPT};
use ring::digest::{Context as DigestContext, SHA256};
use serde::Deserialize;
use url::Url;

use crate::{
    endpoint::{GithubHttpEndpoint, authorization_header_value},
    factory::decode_connection,
    repository_path,
    response::{JsonResponse, decode_json, read_json_response},
};

const ACCEPT_API_JSON: &str = "application/vnd.github+json";
const COMPARE_COMMITS_PER_PAGE: usize = 100;
const PULL_REQUEST_FILES_PER_PAGE: usize = 100;
const MAX_ACTIONS_PUSH_COMMITS: usize = 1_000;
const MAX_CHANGED_PATH_BYTES: usize = 4_096;

/// Maximum changed-file records exposed by GitHub's Compare REST response.
pub const MAX_GITHUB_COMPARE_PATH_FILTER_FILES: usize = 300;
/// Exact documented pull-request path-filter selection window.
///
/// Pull-request Files REST exposes at most the first 3,000 records, matching
/// the documented GitHub Actions path-filter evaluation window.
pub const MAX_GITHUB_PULL_REQUEST_PATH_FILTER_FILES: usize = 3_000;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum GithubChangedFilesLimitRejection {
    ActionsPushCommitCount,
    CompareFileCount,
    ChangedPathBytes,
}

const fn actions_push_commit_count_rejection(
    observed: usize,
) -> Option<GithubChangedFilesLimitRejection> {
    if observed > MAX_ACTIONS_PUSH_COMMITS {
        return Some(GithubChangedFilesLimitRejection::ActionsPushCommitCount);
    }
    None
}

const fn compare_file_count_rejection(observed: usize) -> Option<GithubChangedFilesLimitRejection> {
    if observed > MAX_GITHUB_COMPARE_PATH_FILTER_FILES {
        return Some(GithubChangedFilesLimitRejection::CompareFileCount);
    }
    None
}

const fn changed_path_byte_rejection(observed: usize) -> Option<GithubChangedFilesLimitRejection> {
    if observed > MAX_CHANGED_PATH_BYTES {
        return Some(GithubChangedFilesLimitRejection::ChangedPathBytes);
    }
    None
}

/// Installation authentication for one GitHub push comparison.
pub struct GithubPushDiffAuthority<'credential>(SecretStringRef<'credential>);

impl<'credential> GithubPushDiffAuthority<'credential> {
    /// Binds the comparison to an installation token with `contents: read`.
    #[must_use]
    pub const fn new(credential: SecretStringRef<'credential>) -> Self {
        Self(credential)
    }
}

/// Installation authentication for one GitHub pull-request comparison.
pub struct GithubPullRequestDiffAuthority<'credential>(SecretStringRef<'credential>);

impl<'credential> GithubPullRequestDiffAuthority<'credential> {
    /// Binds the comparison to an installation token with `pull requests: read`.
    #[must_use]
    pub const fn new(credential: SecretStringRef<'credential>) -> Self {
        Self(credential)
    }
}

/// One bounded, exact GitHub pull-request three-dot comparison.
pub struct GithubPullRequestDiffRequest<'request> {
    repository: &'request RepositoryId,
    head_repository: &'request RepositoryId,
    number: NonZeroU64,
    base: &'request GitObjectId,
    head: &'request GitObjectId,
    authority: GithubPullRequestDiffAuthority<'request>,
    deadline: Instant,
}

impl<'request> GithubPullRequestDiffRequest<'request> {
    /// Creates a request bound to the webhook's exact base and head revisions.
    #[must_use]
    pub const fn new(
        repository: &'request RepositoryId,
        head_repository: &'request RepositoryId,
        number: NonZeroU64,
        base: &'request GitObjectId,
        head: &'request GitObjectId,
        authority: GithubPullRequestDiffAuthority<'request>,
        deadline: Instant,
    ) -> Self {
        Self {
            repository,
            head_repository,
            number,
            base,
            head,
            authority,
            deadline,
        }
    }
}

impl fmt::Debug for GithubPullRequestDiffRequest<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GithubPullRequestDiffRequest")
            .field("repository", &"[redacted]")
            .field("head_repository", &"[redacted]")
            .field("number", &self.number)
            .field("base", &"[redacted]")
            .field("head", &"[redacted]")
            .field("authority", &self.authority)
            .field("deadline", &"[monotonic deadline]")
            .finish()
    }
}

impl fmt::Debug for GithubPushDiffAuthority<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("GithubPushDiffAuthority([redacted])")
    }
}

impl fmt::Debug for GithubPullRequestDiffAuthority<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("GithubPullRequestDiffAuthority([redacted])")
    }
}

/// Exact signed push shape to compare or reject before provider I/O.
pub enum GithubPushDiffRange {
    /// An existing non-forced branch update with its complete pushed-commit set.
    Existing {
        /// Exact pre-push commit.
        before: GitObjectId,
        /// Exact post-push commit.
        after: GitObjectId,
        /// Complete signed pushed-commit identities, in any order.
        pushed_commits: Vec<GitObjectId>,
    },
    /// A newly created branch whose Actions diff base is not exposed by Compare REST.
    Created,
    /// A deleted branch, which has no post-push source revision to compare.
    Deleted,
    /// A forced update for which a merge-base comparison cannot prove two-dot parity.
    Forced,
}

impl fmt::Debug for GithubPushDiffRange {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Existing { pushed_commits, .. } => formatter
                .debug_struct("Existing")
                .field("pushed_commit_count", &pushed_commits.len())
                .finish_non_exhaustive(),
            Self::Created => formatter.write_str("Created"),
            Self::Deleted => formatter.write_str("Deleted"),
            Self::Forced => formatter.write_str("Forced"),
        }
    }
}

/// One bounded, exact GitHub push-diff request.
pub struct GithubPushDiffRequest<'request> {
    repository: &'request RepositoryId,
    range: GithubPushDiffRange,
    authority: GithubPushDiffAuthority<'request>,
    deadline: Instant,
}

impl<'request> GithubPushDiffRequest<'request> {
    /// Creates a request whose monotonic deadline covers every comparison page.
    #[must_use]
    pub const fn new(
        repository: &'request RepositoryId,
        range: GithubPushDiffRange,
        authority: GithubPushDiffAuthority<'request>,
        deadline: Instant,
    ) -> Self {
        Self {
            repository,
            range,
            authority,
            deadline,
        }
    }
}

impl fmt::Debug for GithubPushDiffRequest<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GithubPushDiffRequest")
            .field("repository", &"[redacted]")
            .field("range", &self.range)
            .field("authority", &self.authority)
            .field("deadline", &"[monotonic deadline]")
            .finish()
    }
}

/// Why GitHub's public REST evidence cannot be treated as a complete Actions diff.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum GithubPushDiffIncompleteReason {
    /// Actions uses a special new-branch base that Compare REST does not expose.
    CreatedPush,
    /// A deleted push has no exact post-push tree.
    DeletedPush,
    /// A forced or divergent update cannot use merge-base results as a two-dot diff.
    DivergedPush,
    /// Compare REST returned more than its documented 300-record transport window.
    FileListCapped,
    /// Provider evidence was malformed or did not bind to the exact signed push.
    InvalidEvidence,
    /// GitHub rejected the request or supplied authority.
    ProviderRejected,
}

/// Canonical SHA-256 of exact provider path-selection evidence.
#[derive(Clone, Copy, Eq, Hash, PartialEq)]
pub struct GithubChangedFilesEvidenceDigest([u8; 32]);

impl GithubChangedFilesEvidenceDigest {
    /// Returns the canonical digest bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Debug for GithubChangedFilesEvidenceDigest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("GithubChangedFilesEvidenceDigest([redacted])")
    }
}

/// One provider file record in github.com Actions' selected diff window.
#[derive(Clone, Eq, PartialEq)]
pub struct GithubChangedFile {
    current_path: String,
    previous_path: Option<String>,
}

impl GithubChangedFile {
    /// Returns the file's current repository-relative path.
    #[must_use]
    pub fn current_path(&self) -> &str {
        &self.current_path
    }

    /// Returns the previous path for a rename record.
    #[must_use]
    pub fn previous_path(&self) -> Option<&str> {
        self.previous_path.as_deref()
    }
}

impl fmt::Debug for GithubChangedFile {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GithubChangedFile")
            .field("renamed", &self.previous_path.is_some())
            .finish_non_exhaustive()
    }
}

/// Complete, exact provider evidence for one supported existing-branch push.
#[derive(Clone, Eq, PartialEq)]
pub struct GithubCompletePushDiff {
    before: GitObjectId,
    after: GitObjectId,
    selected_file_count: usize,
    changed_files: Vec<GithubChangedFile>,
    changed_paths: Vec<String>,
    response_pages: Vec<Vec<u8>>,
    evidence_digest: GithubChangedFilesEvidenceDigest,
}

/// Complete, exact provider evidence for one pull-request three-dot diff.
#[derive(Clone, Eq, PartialEq)]
pub struct GithubCompletePullRequestDiff {
    number: NonZeroU64,
    base: GitObjectId,
    head: GitObjectId,
    selected_file_count: usize,
    changed_files: Vec<GithubChangedFile>,
    changed_paths: Vec<String>,
    total_changed_files: u64,
    page_digests: Vec<GithubChangedFilesEvidenceDigest>,
    response_pages: Vec<Vec<u8>>,
    evidence_digest: GithubChangedFilesEvidenceDigest,
}

impl GithubCompletePullRequestDiff {
    /// Returns the exact pull-request number proven by both snapshots.
    #[must_use]
    pub const fn number(&self) -> NonZeroU64 {
        self.number
    }

    /// Returns the exact webhook base revision proven by the response.
    #[must_use]
    pub const fn base(&self) -> &GitObjectId {
        &self.base
    }

    /// Returns the exact webhook head revision proven by the response.
    #[must_use]
    pub const fn head(&self) -> &GitObjectId {
        &self.head
    }

    /// Returns the number of provider file records in Actions' exact window.
    #[must_use]
    pub const fn selected_file_count(&self) -> usize {
        self.selected_file_count
    }

    /// Returns the exact provider file records in Actions' selected window.
    #[must_use]
    pub fn changed_files(&self) -> &[GithubChangedFile] {
        &self.changed_files
    }

    /// Consumes the evidence and returns its exact provider file records.
    #[must_use]
    pub fn into_changed_files(self) -> Vec<GithubChangedFile> {
        self.changed_files
    }

    /// Returns the canonical lexicographically sorted changed paths.
    #[must_use]
    pub fn changed_paths(&self) -> &[String] {
        &self.changed_paths
    }

    /// Consumes the evidence and returns its canonical changed paths.
    #[must_use]
    pub fn into_changed_paths(self) -> Vec<String> {
        self.changed_paths
    }

    /// Returns the provider-reported total changed-file count.
    #[must_use]
    pub const fn total_changed_files(&self) -> u64 {
        self.total_changed_files
    }

    /// Returns page-chain digests in exact provider order.
    #[must_use]
    pub fn page_digests(&self) -> &[GithubChangedFilesEvidenceDigest] {
        &self.page_digests
    }

    /// Returns the canonical exact-request evidence digest.
    #[must_use]
    pub const fn evidence_digest(&self) -> GithubChangedFilesEvidenceDigest {
        self.evidence_digest
    }
}

impl fmt::Debug for GithubCompletePullRequestDiff {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GithubCompletePullRequestDiff")
            .field("base", &"[redacted]")
            .field("head", &"[redacted]")
            .field("changed_path_count", &self.changed_paths.len())
            .field("page_count", &self.page_digests.len())
            .finish_non_exhaustive()
    }
}

/// Provider disposition for an exact pull-request three-dot diff.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum GithubPullRequestDiffOutcome {
    /// Complete evidence safe for path-filter evaluation.
    Complete(Box<GithubCompletePullRequestDiff>),
    /// Provider, transport, rate-limit budget, or deadline is temporarily unavailable.
    RetryableUnavailable,
    /// Evidence was malformed, mismatched, or unsupported and must fail closed.
    Invalid(GithubPushDiffIncompleteReason),
}

impl GithubCompletePushDiff {
    /// Returns the exact pre-push commit proven by the response.
    #[must_use]
    pub const fn before(&self) -> &GitObjectId {
        &self.before
    }

    /// Returns the exact post-push commit proven by the response and final page.
    #[must_use]
    pub const fn after(&self) -> &GitObjectId {
        &self.after
    }

    /// Returns the number of provider file records in Actions' exact window.
    #[must_use]
    pub const fn selected_file_count(&self) -> usize {
        self.selected_file_count
    }

    /// Returns the exact provider file records in Actions' selected window.
    #[must_use]
    pub fn changed_files(&self) -> &[GithubChangedFile] {
        &self.changed_files
    }

    /// Consumes the evidence and returns its exact provider file records.
    #[must_use]
    pub fn into_changed_files(self) -> Vec<GithubChangedFile> {
        self.changed_files
    }

    /// Returns the canonical lexicographically sorted changed paths.
    #[must_use]
    pub fn changed_paths(&self) -> &[String] {
        &self.changed_paths
    }

    /// Consumes the evidence and returns its canonical changed paths.
    #[must_use]
    pub fn into_changed_paths(self) -> Vec<String> {
        self.changed_paths
    }

    /// Returns the canonical exact-request evidence digest.
    #[must_use]
    pub const fn evidence_digest(&self) -> GithubChangedFilesEvidenceDigest {
        self.evidence_digest
    }
}

impl fmt::Debug for GithubCompletePushDiff {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GithubCompletePushDiff")
            .field("before", &"[redacted]")
            .field("after", &"[redacted]")
            .field("changed_path_count", &self.changed_paths.len())
            .finish_non_exhaustive()
    }
}

/// Provider disposition for an exact push-diff request.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum GithubPushDiffOutcome {
    /// Complete evidence safe for path-filter evaluation.
    Complete(GithubCompletePushDiff),
    /// Provider, transport, rate-limit budget, or deadline is temporarily unavailable.
    RetryableUnavailable,
    /// Evidence was malformed, mismatched, or unsupported and must fail closed.
    Invalid(GithubPushDiffIncompleteReason),
}

#[derive(Debug)]
enum CompareFailure {
    Incomplete(GithubPushDiffIncompleteReason),
    Unavailable,
}

#[derive(Deserialize)]
struct ComparePage {
    status: String,
    ahead_by: u64,
    behind_by: u64,
    total_commits: u64,
    base_commit: CompareCommit,
    merge_base_commit: CompareCommit,
    commits: Vec<CompareCommit>,
    #[serde(default)]
    files: Option<Vec<CompareFile>>,
}

#[derive(Deserialize)]
struct CompareCommit {
    sha: String,
}

#[derive(Deserialize)]
struct CompareFile {
    filename: String,
    status: String,
    #[serde(default)]
    previous_filename: Option<String>,
}

#[derive(Clone, Deserialize, Eq, PartialEq)]
struct PullRequestSnapshot {
    number: u64,
    state: String,
    changed_files: u64,
    base: PullRequestBranchSnapshot,
    head: PullRequestBranchSnapshot,
}

#[derive(Clone, Deserialize, Eq, PartialEq)]
struct PullRequestBranchSnapshot {
    sha: String,
    repo: PullRequestRepositorySnapshot,
}

#[derive(Clone, Deserialize, Eq, PartialEq)]
struct PullRequestRepositorySnapshot {
    full_name: String,
}

#[derive(Deserialize)]
struct PullRequestFile {
    sha: String,
    filename: String,
    status: String,
    #[serde(default)]
    previous_filename: Option<String>,
}

struct ExistingDiff<'request> {
    repository: &'request RepositoryId,
    before: &'request GitObjectId,
    after: &'request GitObjectId,
    pushed_commits: &'request [GitObjectId],
    authority: &'request GithubPushDiffAuthority<'request>,
    deadline: Instant,
}

struct PullRequestDiff<'request> {
    repository: &'request RepositoryId,
    head_repository: &'request RepositoryId,
    number: NonZeroU64,
    base: &'request GitObjectId,
    head: &'request GitObjectId,
    authority: &'request GithubPullRequestDiffAuthority<'request>,
    deadline: Instant,
}

#[derive(Clone, Copy)]
struct ChangedFilesEvidenceCoordinates<'request> {
    event_kind: &'static [u8],
    repository: &'request RepositoryId,
    head_repository: Option<&'request RepositoryId>,
    pull_request_number: Option<NonZeroU64>,
    base: &'request GitObjectId,
    head: &'request GitObjectId,
    pull_request_state: Option<&'request str>,
    provider_total_changed_files: Option<u64>,
}

impl GithubHttpEndpoint {
    /// Resolves demonstrably complete changed-file evidence for one signed push.
    ///
    /// Existing non-forced updates are accepted only when Compare REST proves
    /// that the exact `before` commit is also the merge base, every paginated
    /// commit equals the signed webhook set, the final commit is exact `after`,
    /// and Compare REST returns no more than its 300 changed-file records.
    /// Renames contribute both their previous and current repository-relative
    /// paths. Other push shapes return an explicit incomplete disposition
    /// without inventing an empty path list.
    ///
    /// # Errors
    ///
    /// Returns [`GithubPushDiffOutcome::RetryableUnavailable`] for an expired
    /// deadline, transport/server failure, or rate limiting.
    pub async fn push_changed_files(
        &self,
        request: GithubPushDiffRequest<'_>,
    ) -> GithubPushDiffOutcome {
        let existing = match &request.range {
            GithubPushDiffRange::Created => {
                return GithubPushDiffOutcome::Invalid(GithubPushDiffIncompleteReason::CreatedPush);
            }
            GithubPushDiffRange::Deleted => {
                return GithubPushDiffOutcome::Invalid(GithubPushDiffIncompleteReason::DeletedPush);
            }
            GithubPushDiffRange::Forced => {
                return GithubPushDiffOutcome::Invalid(
                    GithubPushDiffIncompleteReason::DivergedPush,
                );
            }
            GithubPushDiffRange::Existing {
                before,
                after,
                pushed_commits,
            } => ExistingDiff {
                repository: request.repository,
                before,
                after,
                pushed_commits,
                authority: &request.authority,
                deadline: request.deadline,
            },
        };
        match self.compare_existing_push(existing).await {
            Ok(evidence) => GithubPushDiffOutcome::Complete(evidence),
            Err(CompareFailure::Incomplete(reason)) => GithubPushDiffOutcome::Invalid(reason),
            Err(CompareFailure::Unavailable) => GithubPushDiffOutcome::RetryableUnavailable,
        }
    }

    /// Resolves complete changed-file evidence for one pull request.
    ///
    /// GitHub Actions evaluates pull-request path filters with a three-dot
    /// comparison. This operation snapshots the exact pull-request number,
    /// base repository, head repository, base revision, and head revision on
    /// both sides of GitHub's paginated pull-request-files endpoint. It accepts
    /// GitHub Actions' exact first-3,000-file selection window only when all
    /// required 100-file pages are present and globally duplicate-free. A
    /// provider-reported 3,001st file is deliberately not fetched or matched.
    ///
    /// # Errors
    ///
    /// Returns [`GithubPullRequestDiffOutcome::RetryableUnavailable`] for an
    /// expired deadline, transport/server failure, or rate limiting.
    pub async fn pull_request_changed_files(
        &self,
        request: GithubPullRequestDiffRequest<'_>,
    ) -> GithubPullRequestDiffOutcome {
        let request = PullRequestDiff {
            repository: request.repository,
            head_repository: request.head_repository,
            number: request.number,
            base: request.base,
            head: request.head,
            authority: &request.authority,
            deadline: request.deadline,
        };
        match self.compare_pull_request(request).await {
            Ok(evidence) => GithubPullRequestDiffOutcome::Complete(Box::new(evidence)),
            Err(CompareFailure::Incomplete(reason)) => {
                GithubPullRequestDiffOutcome::Invalid(reason)
            }
            Err(CompareFailure::Unavailable) => GithubPullRequestDiffOutcome::RetryableUnavailable,
        }
    }

    async fn compare_existing_push(
        &self,
        request: ExistingDiff<'_>,
    ) -> Result<GithubCompletePushDiff, CompareFailure> {
        validate_requested_commits(request.before, request.after, request.pushed_commits)?;
        let deadline = self.effective_compare_deadline(request.deadline)?;
        let expected_commits = canonical_revisions(request.pushed_commits);
        let page_count =
            comparison_page_count(expected_commits.len(), self.trusted.limits().max_pages)?;
        let mut observed_commits = Vec::with_capacity(expected_commits.len());
        let mut changed_files = None;
        let mut response_pages = Vec::with_capacity(page_count);
        for page_number in 1..=page_count {
            let endpoint = self.compare_url(
                request.repository,
                request.before,
                request.after,
                page_number,
            )?;
            let (response, response_body) = self
                .fetch_compare_page(endpoint, request.authority, deadline)
                .await?;
            response_pages.push(response_body);
            validate_page_identity(&response, request.before, expected_commits.len())?;
            validate_page_length(&response, page_number, page_count, expected_commits.len())?;
            if page_number == 1 {
                changed_files = Some(complete_changed_files(response.files)?);
            } else if response.files.is_some() {
                return Err(invalid_evidence());
            }
            observed_commits.extend(response.commits.into_iter().map(|commit| commit.sha));
        }
        validate_observed_commits(&observed_commits, &expected_commits, request.after)?;
        let changed_files = changed_files.ok_or_else(invalid_evidence)?;
        let selected_file_count = changed_files.len();
        let changed_paths = canonical_changed_paths(&changed_files);
        let evidence_digest = changed_files_evidence_digest(
            ChangedFilesEvidenceCoordinates {
                event_kind: b"push",
                repository: request.repository,
                head_repository: None,
                pull_request_number: None,
                base: request.before,
                head: request.after,
                pull_request_state: None,
                provider_total_changed_files: None,
            },
            &[],
            selected_file_count,
            &changed_paths,
        );
        Ok(GithubCompletePushDiff {
            before: *request.before,
            after: *request.after,
            selected_file_count,
            changed_files,
            changed_paths,
            response_pages,
            evidence_digest,
        })
    }

    async fn compare_pull_request(
        &self,
        request: PullRequestDiff<'_>,
    ) -> Result<GithubCompletePullRequestDiff, CompareFailure> {
        if request.base == request.head {
            return Err(invalid_evidence());
        }
        let deadline = self.effective_compare_deadline(request.deadline)?;
        let snapshot_endpoint = self.pull_request_url(request.repository, request.number, None)?;
        let (initial, initial_body) = self
            .fetch_pull_request_snapshot(snapshot_endpoint, request.authority, deadline)
            .await?;
        let mut response_pages = vec![initial_body];
        validate_pull_request_snapshot(&initial, &request)?;
        let maximum_pull_request_files = u64::try_from(MAX_GITHUB_PULL_REQUEST_PATH_FILTER_FILES)
            .map_err(|_| invalid_evidence())?;
        let selected_count = usize::try_from(initial.changed_files.min(maximum_pull_request_files))
            .map_err(|_| invalid_evidence())?;
        let page_count = selected_count.div_ceil(PULL_REQUEST_FILES_PER_PAGE);
        if page_count > self.trusted.limits().max_pages {
            return Err(invalid_evidence());
        }
        let mut changed_files = Vec::with_capacity(selected_count);
        let mut observed_filenames = HashSet::with_capacity(selected_count);
        let mut page_digests = Vec::with_capacity(page_count);
        for page_number in 1..=page_count {
            let endpoint =
                self.pull_request_url(request.repository, request.number, Some(page_number))?;
            let (files, page_body) = self
                .fetch_pull_request_file_page(endpoint, request.authority, deadline)
                .await?;
            response_pages.push(page_body);
            let expected = if page_number < page_count {
                PULL_REQUEST_FILES_PER_PAGE
            } else {
                selected_count - PULL_REQUEST_FILES_PER_PAGE * (page_count - 1)
            };
            if files.len() != expected {
                return Err(invalid_evidence());
            }
            let (page_files, page_digest) = complete_pull_request_file_page(page_number, files)?;
            if page_files
                .iter()
                .any(|file| !observed_filenames.insert(file.current_path().to_owned()))
            {
                return Err(invalid_evidence());
            }
            changed_files.extend(page_files);
            page_digests.push(page_digest);
        }
        let final_endpoint = self.pull_request_url(request.repository, request.number, None)?;
        let (final_snapshot, final_body) = self
            .fetch_pull_request_snapshot(final_endpoint, request.authority, deadline)
            .await?;
        response_pages.push(final_body);
        validate_pull_request_snapshot(&final_snapshot, &request)?;
        if final_snapshot != initial {
            return Err(invalid_evidence());
        }
        if observed_filenames.len() != selected_count {
            return Err(invalid_evidence());
        }
        let changed_paths = canonical_changed_paths(&changed_files);
        let evidence_digest = changed_files_evidence_digest(
            ChangedFilesEvidenceCoordinates {
                event_kind: b"pull_request",
                repository: request.repository,
                head_repository: Some(request.head_repository),
                pull_request_number: Some(request.number),
                base: request.base,
                head: request.head,
                pull_request_state: Some(&initial.state),
                provider_total_changed_files: Some(initial.changed_files),
            },
            &page_digests,
            selected_count,
            &changed_paths,
        );
        Ok(GithubCompletePullRequestDiff {
            number: request.number,
            base: *request.base,
            head: *request.head,
            selected_file_count: selected_count,
            changed_files,
            changed_paths,
            total_changed_files: initial.changed_files,
            page_digests,
            response_pages,
            evidence_digest,
        })
    }

    fn pull_request_url(
        &self,
        repository: &RepositoryId,
        number: NonZeroU64,
        files_page: Option<usize>,
    ) -> Result<Url, CompareFailure> {
        let (owner, name) = repository_components(repository)?;
        let mut endpoint = self.trusted.api_base().clone();
        let mut segments = endpoint
            .path_segments_mut()
            .map_err(|()| invalid_evidence())?;
        segments.pop_if_empty();
        segments.push("repos");
        segments.push(owner);
        segments.push(name);
        segments.push("pulls");
        segments.push(&number.get().to_string());
        if files_page.is_some() {
            segments.push("files");
        }
        drop(segments);
        if let Some(page_number) = files_page {
            endpoint
                .query_pairs_mut()
                .append_pair("per_page", &PULL_REQUEST_FILES_PER_PAGE.to_string())
                .append_pair("page", &page_number.to_string());
        }
        if !self.trusted.trusts_api_url(&endpoint) {
            return Err(invalid_evidence());
        }
        Ok(endpoint)
    }

    async fn fetch_pull_request_snapshot(
        &self,
        endpoint: Url,
        authority: &GithubPullRequestDiffAuthority<'_>,
        deadline: Instant,
    ) -> Result<(PullRequestSnapshot, Vec<u8>), CompareFailure> {
        let response = self
            .fetch_pull_request_json(endpoint, authority, deadline)
            .await?;
        if response.status != StatusCode::OK {
            return Err(invalid_evidence());
        }
        let decoded = decode_json(&response.body).map_err(classify_endpoint_error)?;
        Ok((decoded, response.body.to_vec()))
    }

    async fn fetch_pull_request_file_page(
        &self,
        endpoint: Url,
        authority: &GithubPullRequestDiffAuthority<'_>,
        deadline: Instant,
    ) -> Result<(Vec<PullRequestFile>, Vec<u8>), CompareFailure> {
        let response = self
            .fetch_pull_request_json(endpoint, authority, deadline)
            .await?;
        if response.status != StatusCode::OK {
            return Err(invalid_evidence());
        }
        let decoded = decode_json(&response.body).map_err(classify_endpoint_error)?;
        Ok((decoded, response.body.to_vec()))
    }

    async fn fetch_pull_request_json(
        &self,
        endpoint: Url,
        authority: &GithubPullRequestDiffAuthority<'_>,
        deadline: Instant,
    ) -> Result<JsonResponse, CompareFailure> {
        let remaining = deadline
            .checked_duration_since(Instant::now())
            .filter(|duration| !duration.is_zero())
            .ok_or(CompareFailure::Unavailable)?;
        let request =
            pull_request_request(self.client.get(endpoint), authority)?.timeout(remaining);
        let response = request
            .send()
            .await
            .map_err(|_| CompareFailure::Unavailable)?;
        read_json_response(response, self.trusted.limits().max_response_bytes, false)
            .await
            .map_err(classify_endpoint_error)
    }

    fn effective_compare_deadline(&self, requested: Instant) -> Result<Instant, CompareFailure> {
        let now = Instant::now();
        if requested <= now {
            return Err(CompareFailure::Unavailable);
        }
        let configured = now
            .checked_add(self.trusted.limits().request_timeout())
            .ok_or(CompareFailure::Unavailable)?;
        Ok(requested.min(configured))
    }

    fn compare_url(
        &self,
        repository: &RepositoryId,
        before: &GitObjectId,
        after: &GitObjectId,
        page_number: usize,
    ) -> Result<Url, CompareFailure> {
        let (owner, name) = repository_components(repository)?;
        let base_head = format!("{before}...{after}");
        let mut endpoint = self.trusted.api_base().clone();
        let mut segments = endpoint
            .path_segments_mut()
            .map_err(|()| invalid_evidence())?;
        segments.pop_if_empty();
        segments.push("repos");
        segments.push(owner);
        segments.push(name);
        segments.push("compare");
        segments.push(&base_head);
        drop(segments);
        endpoint
            .query_pairs_mut()
            .append_pair("per_page", &COMPARE_COMMITS_PER_PAGE.to_string())
            .append_pair("page", &page_number.to_string());
        if !self.trusted.trusts_api_url(&endpoint) {
            return Err(invalid_evidence());
        }
        Ok(endpoint)
    }

    async fn fetch_compare_page(
        &self,
        endpoint: Url,
        authority: &GithubPushDiffAuthority<'_>,
        deadline: Instant,
    ) -> Result<(ComparePage, Vec<u8>), CompareFailure> {
        let remaining = deadline
            .checked_duration_since(Instant::now())
            .filter(|duration| !duration.is_zero())
            .ok_or(CompareFailure::Unavailable)?;
        let request = compare_request(self.client.get(endpoint), authority)?.timeout(remaining);
        let response = request
            .send()
            .await
            .map_err(|_| CompareFailure::Unavailable)?;
        let response =
            read_json_response(response, self.trusted.limits().max_response_bytes, false)
                .await
                .map_err(classify_endpoint_error)?;
        let decoded = decode_compare_page(&response)?;
        Ok((decoded, response.body.to_vec()))
    }
}

#[async_trait]
impl ChangedFileReader for GithubHttpEndpoint {
    async fn read_changed_files(
        &self,
        request: ChangedFileRequest<'_>,
    ) -> Result<ChangedFileRead, ScmError> {
        let policy = decode_connection(request.connection().configuration().adapter_policy())
            .map_err(|_| ScmError::new(ScmErrorKind::InvalidResponse))?;
        if request
            .trigger()
            .trigger()
            .target_repository()
            .path()
            .as_str()
            != policy.repository().as_str()
        {
            return Err(ScmError::new(ScmErrorKind::InvalidResponse));
        }
        let deadline = Instant::now()
            .checked_add(self.trusted.limits().request_timeout())
            .ok_or_else(|| ScmError::new(ScmErrorKind::Unavailable))?;
        match request.trigger().trigger() {
            NormalizedTrigger::Push(push) => {
                let range = match (push.before(), push.after(), push.forced()) {
                    (_, _, true) => GithubPushDiffRange::Forced,
                    (None, Some(_), false) => GithubPushDiffRange::Created,
                    (Some(_), None, false) => GithubPushDiffRange::Deleted,
                    (Some(before), Some(after), false) => {
                        let pushed_commits = match push.commit_evidence() {
                            PushCommitEvidence::Complete(commits) => commits.clone(),
                            PushCommitEvidence::ProviderLimitExceeded => {
                                return incomplete_without_pages(
                                    &request,
                                    ChangedFileIncompleteReason::ProviderRecordLimit,
                                );
                            }
                        };
                        GithubPushDiffRange::Existing {
                            before,
                            after,
                            pushed_commits,
                        }
                    }
                    (None, None, false) => {
                        return Err(ScmError::new(ScmErrorKind::InvalidResponse));
                    }
                };
                let repository = RepositoryId::new(policy.repository().as_str())
                    .map_err(|_| ScmError::new(ScmErrorKind::InvalidResponse))?;
                let authority = push_authority(&request);
                let outcome = self
                    .push_changed_files(GithubPushDiffRequest::new(
                        &repository,
                        range,
                        authority,
                        deadline,
                    ))
                    .await;
                translate_common_push(&request, outcome)
            }
            NormalizedTrigger::PullRequest(pull_request) => {
                let repository = RepositoryId::new(policy.repository().as_str())
                    .map_err(|_| ScmError::new(ScmErrorKind::InvalidResponse))?;
                let head_repository =
                    RepositoryId::new(pull_request.source_repository().path().as_str())
                        .map_err(|_| ScmError::new(ScmErrorKind::InvalidResponse))?;
                let number = pull_request
                    .change_id()
                    .as_str()
                    .parse::<u64>()
                    .ok()
                    .and_then(NonZeroU64::new)
                    .ok_or_else(|| ScmError::new(ScmErrorKind::InvalidResponse))?;
                let base = pull_request.base_object();
                let head = pull_request.head_object();
                let authority = pull_request_authority(&request);
                let outcome = self
                    .pull_request_changed_files(GithubPullRequestDiffRequest::new(
                        &repository,
                        &head_repository,
                        number,
                        &base,
                        &head,
                        authority,
                        deadline,
                    ))
                    .await;
                translate_common_pull_request(&request, outcome)
            }
            NormalizedTrigger::MergeQueue(_) | NormalizedTrigger::RepositoryDispatch(_) => Ok(
                ChangedFileRead::not_applicable(ChangedFileNotApplicableReason::EventClass),
            ),
        }
    }
}

fn push_authority<'request>(
    request: &'request ChangedFileRequest<'request>,
) -> GithubPushDiffAuthority<'request> {
    GithubPushDiffAuthority::new(request.credential())
}

fn pull_request_authority<'request>(
    request: &'request ChangedFileRequest<'request>,
) -> GithubPullRequestDiffAuthority<'request> {
    GithubPullRequestDiffAuthority::new(request.credential())
}

fn translate_common_push(
    request: &ChangedFileRequest<'_>,
    outcome: GithubPushDiffOutcome,
) -> Result<ChangedFileRead, ScmError> {
    match outcome {
        GithubPushDiffOutcome::Complete(complete) => {
            let pages = common_page_evidence(request, &complete.response_pages)?;
            let files = common_changed_files(complete.changed_files)?;
            if files.len() > request.limits().maximum_files() {
                return ChangedFileRead::incomplete(
                    request,
                    ChangedFileIncompleteReason::ProviderRecordLimit,
                    complete.selected_file_count as u64,
                    pages,
                )
                .map_err(common_evidence_error);
            }
            ChangedFileRead::complete(request, files, complete.selected_file_count as u64, pages)
                .map_err(common_evidence_error)
        }
        GithubPushDiffOutcome::Invalid(reason) => translate_invalid(request, reason),
        GithubPushDiffOutcome::RetryableUnavailable => {
            Err(ScmError::new(ScmErrorKind::Unavailable))
        }
    }
}

fn translate_common_pull_request(
    request: &ChangedFileRequest<'_>,
    outcome: GithubPullRequestDiffOutcome,
) -> Result<ChangedFileRead, ScmError> {
    match outcome {
        GithubPullRequestDiffOutcome::Complete(complete) => {
            let complete = *complete;
            let pages = common_page_evidence(request, &complete.response_pages)?;
            if complete.total_changed_files
                > u64::try_from(complete.selected_file_count).unwrap_or(u64::MAX)
                || complete.selected_file_count > request.limits().maximum_files()
            {
                return ChangedFileRead::incomplete(
                    request,
                    ChangedFileIncompleteReason::ProviderRecordLimit,
                    complete.total_changed_files,
                    pages,
                )
                .map_err(common_evidence_error);
            }
            let files = common_changed_files(complete.changed_files)?;
            ChangedFileRead::complete(request, files, complete.total_changed_files, pages)
                .map_err(common_evidence_error)
        }
        GithubPullRequestDiffOutcome::Invalid(reason) => translate_invalid(request, reason),
        GithubPullRequestDiffOutcome::RetryableUnavailable => {
            Err(ScmError::new(ScmErrorKind::Unavailable))
        }
    }
}

fn common_changed_files(files: Vec<GithubChangedFile>) -> Result<Vec<ChangedFile>, ScmError> {
    files
        .into_iter()
        .map(|file| {
            let current = ProviderRepositoryPath::new(file.current_path)
                .map_err(|_| ScmError::new(ScmErrorKind::InvalidResponse))?;
            match file.previous_path {
                Some(previous) => ChangedFile::renamed(
                    ProviderRepositoryPath::new(previous)
                        .map_err(|_| ScmError::new(ScmErrorKind::InvalidResponse))?,
                    current,
                )
                .map_err(common_evidence_error),
                None => Ok(ChangedFile::changed(current)),
            }
        })
        .collect()
}

fn common_page_evidence(
    request: &ChangedFileRequest<'_>,
    pages: &[Vec<u8>],
) -> Result<ChangedFilePageEvidence, ScmError> {
    let mut evidence = ChangedFilePageAccumulator::new(request);
    for page in pages {
        evidence.begin_page().map_err(common_evidence_error)?;
        evidence
            .push_chunk(&Bytes::copy_from_slice(page))
            .map_err(common_evidence_error)?;
        evidence.finish_page().map_err(common_evidence_error)?;
    }
    evidence.finish().map_err(common_evidence_error)
}

fn incomplete_without_pages(
    request: &ChangedFileRequest<'_>,
    reason: ChangedFileIncompleteReason,
) -> Result<ChangedFileRead, ScmError> {
    let pages = ChangedFilePageAccumulator::new(request)
        .finish()
        .map_err(common_evidence_error)?;
    ChangedFileRead::incomplete(request, reason, 0, pages).map_err(common_evidence_error)
}

fn translate_invalid(
    request: &ChangedFileRequest<'_>,
    reason: GithubPushDiffIncompleteReason,
) -> Result<ChangedFileRead, ScmError> {
    match reason {
        GithubPushDiffIncompleteReason::CreatedPush => {
            incomplete_without_pages(request, ChangedFileIncompleteReason::CreatedRef)
        }
        GithubPushDiffIncompleteReason::DeletedPush => {
            incomplete_without_pages(request, ChangedFileIncompleteReason::DeletedRef)
        }
        GithubPushDiffIncompleteReason::DivergedPush => {
            incomplete_without_pages(request, ChangedFileIncompleteReason::ForcedUpdate)
        }
        GithubPushDiffIncompleteReason::FileListCapped => {
            incomplete_without_pages(request, ChangedFileIncompleteReason::ProviderRecordLimit)
        }
        GithubPushDiffIncompleteReason::InvalidEvidence => {
            Err(ScmError::new(ScmErrorKind::InvalidResponse))
        }
        GithubPushDiffIncompleteReason::ProviderRejected => {
            Err(ScmError::new(ScmErrorKind::Forbidden))
        }
    }
}

fn common_evidence_error(_error: automata_ci_scm::ChangedFileReadError) -> ScmError {
    ScmError::new(ScmErrorKind::InvalidResponse)
}

fn invalid_evidence() -> CompareFailure {
    CompareFailure::Incomplete(GithubPushDiffIncompleteReason::InvalidEvidence)
}

fn repository_components(repository: &RepositoryId) -> Result<(&str, &str), CompareFailure> {
    repository_path::split(repository.as_str()).ok_or_else(invalid_evidence)
}

fn validate_requested_commits(
    before: &GitObjectId,
    after: &GitObjectId,
    commits: &[GitObjectId],
) -> Result<(), CompareFailure> {
    if before == after
        || commits.is_empty()
        || actions_push_commit_count_rejection(commits.len()).is_some()
        || !commits.iter().any(|commit| commit == after)
        || commits.iter().any(|commit| commit == before)
    {
        return Err(invalid_evidence());
    }
    let unique = commits.iter().collect::<HashSet<_>>();
    if unique.len() != commits.len() {
        return Err(invalid_evidence());
    }
    Ok(())
}

fn canonical_revisions(commits: &[GitObjectId]) -> Vec<GitObjectId> {
    let mut commits = commits.to_vec();
    commits.sort_unstable();
    commits
}

fn comparison_page_count(
    commit_count: usize,
    maximum_pages: usize,
) -> Result<usize, CompareFailure> {
    let pages = commit_count.div_ceil(COMPARE_COMMITS_PER_PAGE);
    if pages == 0 || pages > maximum_pages {
        return Err(invalid_evidence());
    }
    Ok(pages)
}

fn compare_request(
    request: RequestBuilder,
    authority: &GithubPushDiffAuthority<'_>,
) -> Result<RequestBuilder, CompareFailure> {
    let request = request.header(ACCEPT, ACCEPT_API_JSON);
    let authorization =
        authorization_header_value(authority.0.expose_secret()).map_err(classify_endpoint_error)?;
    Ok(request.header(reqwest::header::AUTHORIZATION, authorization))
}

fn pull_request_request(
    request: RequestBuilder,
    authority: &GithubPullRequestDiffAuthority<'_>,
) -> Result<RequestBuilder, CompareFailure> {
    let request = request.header(ACCEPT, ACCEPT_API_JSON);
    let authorization =
        authorization_header_value(authority.0.expose_secret()).map_err(classify_endpoint_error)?;
    Ok(request.header(reqwest::header::AUTHORIZATION, authorization))
}

fn validate_pull_request_snapshot(
    snapshot: &PullRequestSnapshot,
    request: &PullRequestDiff<'_>,
) -> Result<(), CompareFailure> {
    if snapshot.number != request.number.get()
        || !matches!(snapshot.state.as_str(), "open" | "closed")
        || GitObjectId::from_provider_hex(&snapshot.base.sha).ok() != Some(*request.base)
        || GitObjectId::from_provider_hex(&snapshot.head.sha).ok() != Some(*request.head)
        || snapshot.base.repo.full_name != request.repository.as_str()
        || snapshot.head.repo.full_name != request.head_repository.as_str()
    {
        return Err(invalid_evidence());
    }
    Ok(())
}

fn complete_pull_request_file_page(
    page_number: usize,
    files: Vec<PullRequestFile>,
) -> Result<(Vec<GithubChangedFile>, GithubChangedFilesEvidenceDigest), CompareFailure> {
    let mut digest = DigestContext::new(&SHA256);
    digest.update(b"automata.github.pull-request-file-page.v2\0");
    digest_u64(
        &mut digest,
        u64::try_from(page_number).map_err(|_| invalid_evidence())?,
    );
    digest_u64(
        &mut digest,
        u64::try_from(files.len()).map_err(|_| invalid_evidence())?,
    );
    let mut changed_files = Vec::with_capacity(files.len());
    let mut filenames = HashSet::with_capacity(files.len());
    for file in files {
        if GitObjectId::from_provider_hex(&file.sha).is_err() {
            return Err(invalid_evidence());
        }
        let changed_file = complete_changed_file(
            &file.status,
            &file.filename,
            file.previous_filename.as_deref(),
        )?;
        if !filenames.insert(file.filename.clone()) {
            return Err(invalid_evidence());
        }
        digest_part(&mut digest, file.sha.as_bytes())?;
        digest_part(&mut digest, file.status.as_bytes())?;
        digest_part(&mut digest, file.filename.as_bytes())?;
        digest_optional_part(
            &mut digest,
            file.previous_filename.as_deref().map(str::as_bytes),
        );
        changed_files.push(changed_file);
    }
    Ok((changed_files, finish_digest(digest)))
}

fn changed_files_evidence_digest(
    coordinates: ChangedFilesEvidenceCoordinates<'_>,
    page_digests: &[GithubChangedFilesEvidenceDigest],
    selected_file_count: usize,
    changed_paths: &[String],
) -> GithubChangedFilesEvidenceDigest {
    let mut digest = DigestContext::new(&SHA256);
    digest.update(b"automata.github.changed-files-evidence.v2\0");
    // These values were already validated by their typed constructors, so
    // their bounded lengths cannot fail this infallible aggregate step.
    digest_part(&mut digest, coordinates.event_kind).expect("fixed event kind is bounded");
    digest_part(&mut digest, coordinates.repository.as_str().as_bytes())
        .expect("repository identity is bounded");
    digest_optional_part(
        &mut digest,
        coordinates
            .head_repository
            .map(RepositoryId::as_str)
            .map(str::as_bytes),
    );
    digest_u64(
        &mut digest,
        coordinates.pull_request_number.map_or(0, NonZeroU64::get),
    );
    digest_part(&mut digest, coordinates.base.as_bytes()).expect("exact revision is bounded");
    digest_part(&mut digest, coordinates.head.as_bytes()).expect("exact revision is bounded");
    digest_optional_part(
        &mut digest,
        coordinates.pull_request_state.map(str::as_bytes),
    );
    match coordinates.provider_total_changed_files {
        Some(total) => {
            digest_u64(&mut digest, 1);
            digest_u64(&mut digest, total);
        }
        None => digest_u64(&mut digest, 0),
    }
    digest_u64(
        &mut digest,
        u64::try_from(page_digests.len()).expect("bounded page-digest count"),
    );
    for page_digest in page_digests {
        digest.update(page_digest.as_bytes());
    }
    digest_u64(
        &mut digest,
        u64::try_from(selected_file_count).expect("bounded selected-file count"),
    );
    digest_u64(
        &mut digest,
        u64::try_from(changed_paths.len()).expect("bounded changed-path count"),
    );
    for path in changed_paths {
        digest_part(&mut digest, path.as_bytes()).expect("validated path is bounded");
    }
    finish_digest(digest)
}

fn digest_optional_part(digest: &mut DigestContext, value: Option<&[u8]>) {
    match value {
        Some(value) => {
            digest_u64(digest, 1);
            digest_part(digest, value).expect("typed optional evidence is bounded");
        }
        None => digest_u64(digest, 0),
    }
}

fn digest_part(digest: &mut DigestContext, value: &[u8]) -> Result<(), CompareFailure> {
    digest_u64(
        digest,
        u64::try_from(value.len()).map_err(|_| invalid_evidence())?,
    );
    digest.update(value);
    Ok(())
}

fn digest_u64(digest: &mut DigestContext, value: u64) {
    digest.update(&value.to_be_bytes());
}

fn finish_digest(digest: DigestContext) -> GithubChangedFilesEvidenceDigest {
    let finished = digest.finish();
    let mut bytes = [0_u8; 32];
    bytes.copy_from_slice(finished.as_ref());
    GithubChangedFilesEvidenceDigest(bytes)
}

fn classify_endpoint_error(error: GithubEndpointError) -> CompareFailure {
    match error {
        GithubEndpointError::Forbidden
        | GithubEndpointError::RateLimited { .. }
        | GithubEndpointError::Unavailable => CompareFailure::Unavailable,
        GithubEndpointError::Unauthorized => {
            CompareFailure::Incomplete(GithubPushDiffIncompleteReason::ProviderRejected)
        }
        GithubEndpointError::InvalidResponse => invalid_evidence(),
    }
}

fn decode_compare_page(response: &JsonResponse) -> Result<ComparePage, CompareFailure> {
    if response.status != StatusCode::OK {
        return Err(invalid_evidence());
    }
    decode_json(&response.body).map_err(classify_endpoint_error)
}

fn validate_page_identity(
    page: &ComparePage,
    before: &GitObjectId,
    expected_commits: usize,
) -> Result<(), CompareFailure> {
    let expected_commits = u64::try_from(expected_commits).map_err(|_| invalid_evidence())?;
    if page.status != "ahead"
        || page.behind_by != 0
        || page.ahead_by != expected_commits
        || page.total_commits != expected_commits
        || GitObjectId::from_provider_hex(&page.base_commit.sha).ok() != Some(*before)
        || GitObjectId::from_provider_hex(&page.merge_base_commit.sha).ok() != Some(*before)
    {
        return Err(CompareFailure::Incomplete(
            GithubPushDiffIncompleteReason::DivergedPush,
        ));
    }
    Ok(())
}

fn validate_page_length(
    page: &ComparePage,
    page_number: usize,
    page_count: usize,
    total_commits: usize,
) -> Result<(), CompareFailure> {
    let expected = if page_number < page_count {
        COMPARE_COMMITS_PER_PAGE
    } else {
        total_commits - COMPARE_COMMITS_PER_PAGE * (page_count - 1)
    };
    if page.commits.len() != expected {
        return Err(invalid_evidence());
    }
    Ok(())
}

fn validate_observed_commits(
    observed: &[String],
    expected: &[GitObjectId],
    after: &GitObjectId,
) -> Result<(), CompareFailure> {
    let mut canonical = observed
        .iter()
        .map(GitObjectId::from_provider_hex)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| invalid_evidence())?;
    if canonical.last() != Some(after) {
        return Err(invalid_evidence());
    }
    canonical.sort_unstable();
    if canonical != expected || canonical.windows(2).any(|pair| pair[0] == pair[1]) {
        return Err(invalid_evidence());
    }
    Ok(())
}

fn complete_changed_files(
    files: Option<Vec<CompareFile>>,
) -> Result<Vec<GithubChangedFile>, CompareFailure> {
    let files = files.ok_or_else(invalid_evidence)?;
    let selected_file_count = files.len();
    if compare_file_count_rejection(selected_file_count).is_some() {
        return Err(CompareFailure::Incomplete(
            GithubPushDiffIncompleteReason::FileListCapped,
        ));
    }
    let mut filenames = HashSet::with_capacity(selected_file_count);
    let mut changed_files = Vec::with_capacity(selected_file_count);
    for file in files {
        let changed_file = complete_changed_file(
            &file.status,
            &file.filename,
            file.previous_filename.as_deref(),
        )?;
        if !filenames.insert(file.filename) {
            return Err(invalid_evidence());
        }
        changed_files.push(changed_file);
    }
    Ok(changed_files)
}

fn complete_changed_file(
    status: &str,
    filename: &str,
    previous_filename: Option<&str>,
) -> Result<GithubChangedFile, CompareFailure> {
    if !valid_changed_path(filename) {
        return Err(invalid_evidence());
    }
    match (status, previous_filename) {
        ("added" | "modified" | "removed", None) => Ok(GithubChangedFile {
            current_path: filename.to_owned(),
            previous_path: None,
        }),
        ("renamed", Some(previous_filename))
            if previous_filename != filename && valid_changed_path(previous_filename) =>
        {
            Ok(GithubChangedFile {
                current_path: filename.to_owned(),
                previous_path: Some(previous_filename.to_owned()),
            })
        }
        _ => Err(invalid_evidence()),
    }
}

fn canonical_changed_paths(files: &[GithubChangedFile]) -> Vec<String> {
    let mut paths = BTreeSet::new();
    for file in files {
        if let Some(previous_path) = &file.previous_path {
            paths.insert(previous_path.clone());
        }
        paths.insert(file.current_path.clone());
    }
    paths.into_iter().collect()
}

fn valid_changed_path(path: &str) -> bool {
    !path.is_empty()
        && changed_path_byte_rejection(path.len()).is_none()
        && !path.starts_with('/')
        && !path.chars().any(char::is_control)
        && path
            .split('/')
            .all(|component| !component.is_empty() && !matches!(component, "." | ".."))
}

#[cfg(test)]
mod limit_contract_tests {
    use super::*;

    #[test]
    fn actions_push_commit_count_limit_has_exact_boundaries() {
        assert_eq!(
            actions_push_commit_count_rejection(MAX_ACTIONS_PUSH_COMMITS - 1),
            None
        );
        assert_eq!(
            actions_push_commit_count_rejection(MAX_ACTIONS_PUSH_COMMITS),
            None
        );
        assert_eq!(
            actions_push_commit_count_rejection(MAX_ACTIONS_PUSH_COMMITS + 1),
            Some(GithubChangedFilesLimitRejection::ActionsPushCommitCount)
        );
    }

    #[test]
    fn compare_file_count_limit_has_exact_boundaries() {
        assert_eq!(
            compare_file_count_rejection(MAX_GITHUB_COMPARE_PATH_FILTER_FILES - 1),
            None
        );
        assert_eq!(
            compare_file_count_rejection(MAX_GITHUB_COMPARE_PATH_FILTER_FILES),
            None
        );
        assert_eq!(
            compare_file_count_rejection(MAX_GITHUB_COMPARE_PATH_FILTER_FILES + 1),
            Some(GithubChangedFilesLimitRejection::CompareFileCount)
        );
    }

    #[test]
    fn changed_path_byte_limit_has_exact_boundaries() {
        assert_eq!(
            changed_path_byte_rejection(MAX_CHANGED_PATH_BYTES - 1),
            None
        );
        assert_eq!(changed_path_byte_rejection(MAX_CHANGED_PATH_BYTES), None);
        assert_eq!(
            changed_path_byte_rejection(MAX_CHANGED_PATH_BYTES + 1),
            Some(GithubChangedFilesLimitRejection::ChangedPathBytes)
        );
    }
}
