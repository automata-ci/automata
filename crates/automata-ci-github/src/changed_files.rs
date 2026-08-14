use std::{collections::HashSet, fmt, time::Instant};

use automata_ci_auth::{github::GithubEndpointError, secret::SecretString};
use automata_ci_scm::{ExactRevision, RepositoryId};
use reqwest::{RequestBuilder, StatusCode, header::ACCEPT};
use serde::Deserialize;
use thiserror::Error;
use url::Url;

use crate::{
    endpoint::{GithubHttpEndpoint, authorization_header},
    repository_path,
    response::{JsonResponse, decode_json, read_json_response},
};

const ACCEPT_API_JSON: &str = "application/vnd.github+json";
const COMPARE_COMMITS_PER_PAGE: usize = 100;
const GITHUB_COMPARE_FILE_CAP: usize = 300;
const MAX_ACTIONS_PUSH_COMMITS: usize = 1_000;
const MAX_CHANGED_PATH_BYTES: usize = 4_096;

/// Largest GitHub Compare JSON file collection that is demonstrably complete.
///
/// GitHub documents a 300-file response cap without a total-file count. An
/// exactly 300-entry response is therefore ambiguous and is never accepted as
/// complete.
pub const MAX_COMPLETE_GITHUB_COMPARE_FILES: usize = GITHUB_COMPARE_FILE_CAP - 1;

/// Least-authority authentication for one GitHub push comparison.
pub enum GithubPushDiffAuthority<'credential> {
    /// Read a public repository without an Authorization header.
    PublicAnonymous,
    /// Read a private repository with an exact installation `contents: read` token.
    PrivateInstallationContentsRead(&'credential SecretString),
}

/// Least-authority authentication for one GitHub pull-request comparison.
pub type GithubPullRequestDiffAuthority<'credential> = GithubPushDiffAuthority<'credential>;

/// One bounded, exact GitHub pull-request three-dot comparison.
pub struct GithubPullRequestDiffRequest<'request> {
    repository: &'request RepositoryId,
    base: &'request ExactRevision,
    head: &'request ExactRevision,
    authority: GithubPullRequestDiffAuthority<'request>,
    deadline: Instant,
}

impl<'request> GithubPullRequestDiffRequest<'request> {
    /// Creates a request bound to the webhook's exact base and head revisions.
    #[must_use]
    pub const fn new(
        repository: &'request RepositoryId,
        base: &'request ExactRevision,
        head: &'request ExactRevision,
        authority: GithubPullRequestDiffAuthority<'request>,
        deadline: Instant,
    ) -> Self {
        Self {
            repository,
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
            .field("base", &"[redacted]")
            .field("head", &"[redacted]")
            .field("authority", &self.authority)
            .field("deadline", &"[monotonic deadline]")
            .finish()
    }
}

impl fmt::Debug for GithubPushDiffAuthority<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PublicAnonymous => formatter.write_str("PublicAnonymous"),
            Self::PrivateInstallationContentsRead(_) => {
                formatter.write_str("PrivateInstallationContentsRead([redacted])")
            }
        }
    }
}

/// Exact signed push shape to compare or reject before provider I/O.
pub enum GithubPushDiffRange {
    /// An existing non-forced branch update with its complete pushed-commit set.
    Existing {
        /// Exact pre-push commit.
        before: ExactRevision,
        /// Exact post-push commit.
        after: ExactRevision,
        /// Complete signed pushed-commit identities, in any order.
        pushed_commits: Vec<ExactRevision>,
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
    /// The Compare JSON file list reached its undocumented-completeness boundary.
    FileListCapped,
    /// Rename status cannot be losslessly represented by the current path-only model.
    RenamedPath,
    /// Provider evidence was malformed or did not bind to the exact signed push.
    InvalidEvidence,
    /// GitHub rejected the request or supplied authority.
    ProviderRejected,
}

/// Complete, exact provider evidence for one supported existing-branch push.
#[derive(Clone, Eq, PartialEq)]
pub struct GithubCompletePushDiff {
    before: ExactRevision,
    after: ExactRevision,
    changed_paths: Vec<String>,
}

/// Complete, exact provider evidence for one pull-request three-dot diff.
#[derive(Clone, Eq, PartialEq)]
pub struct GithubCompletePullRequestDiff {
    base: ExactRevision,
    head: ExactRevision,
    changed_paths: Vec<String>,
}

impl GithubCompletePullRequestDiff {
    /// Returns the exact webhook base revision proven by the response.
    #[must_use]
    pub const fn base(&self) -> &ExactRevision {
        &self.base
    }

    /// Returns the exact webhook head revision proven by the response.
    #[must_use]
    pub const fn head(&self) -> &ExactRevision {
        &self.head
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
}

impl fmt::Debug for GithubCompletePullRequestDiff {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GithubCompletePullRequestDiff")
            .field("base", &"[redacted]")
            .field("head", &"[redacted]")
            .field("changed_path_count", &self.changed_paths.len())
            .finish()
    }
}

/// Provider disposition for an exact pull-request three-dot diff.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum GithubPullRequestDiffOutcome {
    /// Complete evidence safe for path-filter evaluation.
    Complete(GithubCompletePullRequestDiff),
    /// The public API did not prove a complete Actions-equivalent path set.
    Incomplete(GithubPushDiffIncompleteReason),
}

/// Sanitized temporary failure while obtaining pull-request diff evidence.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum GithubPullRequestDiffError {
    /// The provider, rate-limit budget, transport, or overall deadline is unavailable.
    #[error("GitHub pull-request diff evidence is temporarily unavailable")]
    Unavailable,
}

impl GithubCompletePushDiff {
    /// Returns the exact pre-push commit proven by the response.
    #[must_use]
    pub const fn before(&self) -> &ExactRevision {
        &self.before
    }

    /// Returns the exact post-push commit proven by the response and final page.
    #[must_use]
    pub const fn after(&self) -> &ExactRevision {
        &self.after
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
}

impl fmt::Debug for GithubCompletePushDiff {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GithubCompletePushDiff")
            .field("before", &"[redacted]")
            .field("after", &"[redacted]")
            .field("changed_path_count", &self.changed_paths.len())
            .finish()
    }
}

/// Provider disposition for an exact push-diff request.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum GithubPushDiffOutcome {
    /// Complete evidence safe for path-filter evaluation.
    Complete(GithubCompletePushDiff),
    /// The public API did not prove a complete Actions-equivalent path set.
    Incomplete(GithubPushDiffIncompleteReason),
}

/// Sanitized temporary failure while obtaining push-diff evidence.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum GithubPushDiffError {
    /// The provider, rate-limit budget, transport, or overall deadline is unavailable.
    #[error("GitHub push-diff evidence is temporarily unavailable")]
    Unavailable,
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

struct ExistingDiff<'request> {
    repository: &'request RepositoryId,
    before: &'request ExactRevision,
    after: &'request ExactRevision,
    pushed_commits: &'request [ExactRevision],
    authority: &'request GithubPushDiffAuthority<'request>,
    deadline: Instant,
}

struct PullRequestDiff<'request> {
    repository: &'request RepositoryId,
    base: &'request ExactRevision,
    head: &'request ExactRevision,
    authority: &'request GithubPullRequestDiffAuthority<'request>,
    deadline: Instant,
}

impl GithubHttpEndpoint {
    /// Resolves demonstrably complete changed-file evidence for one signed push.
    ///
    /// Existing non-forced updates are accepted only when Compare REST proves
    /// that the exact `before` commit is also the merge base, every paginated
    /// commit equals the signed webhook set, the final commit is exact `after`,
    /// and fewer than 300 unique non-renamed paths are returned. Other push
    /// shapes return an explicit incomplete disposition without inventing an
    /// empty or truncated path list.
    ///
    /// # Errors
    ///
    /// Returns [`GithubPushDiffError::Unavailable`] for an expired deadline,
    /// transport/server failure, or rate limiting.
    pub async fn push_changed_files(
        &self,
        request: GithubPushDiffRequest<'_>,
    ) -> Result<GithubPushDiffOutcome, GithubPushDiffError> {
        let existing = match &request.range {
            GithubPushDiffRange::Created => {
                return Ok(incomplete(GithubPushDiffIncompleteReason::CreatedPush));
            }
            GithubPushDiffRange::Deleted => {
                return Ok(incomplete(GithubPushDiffIncompleteReason::DeletedPush));
            }
            GithubPushDiffRange::Forced => {
                return Ok(incomplete(GithubPushDiffIncompleteReason::DivergedPush));
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
            Ok(evidence) => Ok(GithubPushDiffOutcome::Complete(evidence)),
            Err(CompareFailure::Incomplete(reason)) => Ok(incomplete(reason)),
            Err(CompareFailure::Unavailable) => Err(GithubPushDiffError::Unavailable),
        }
    }

    /// Resolves complete changed-file evidence for one pull request.
    ///
    /// GitHub Actions evaluates pull-request path filters with a three-dot
    /// comparison. This operation uses the webhook's immutable base and head
    /// revisions, verifies every comparison page remains bound to them, and
    /// accepts fewer than 300 unique non-renamed paths. An ambiguous capped or
    /// renamed result is returned as incomplete instead of a truncated list.
    ///
    /// # Errors
    ///
    /// Returns [`GithubPullRequestDiffError::Unavailable`] for an expired
    /// deadline, transport/server failure, or rate limiting.
    pub async fn pull_request_changed_files(
        &self,
        request: GithubPullRequestDiffRequest<'_>,
    ) -> Result<GithubPullRequestDiffOutcome, GithubPullRequestDiffError> {
        let request = PullRequestDiff {
            repository: request.repository,
            base: request.base,
            head: request.head,
            authority: &request.authority,
            deadline: request.deadline,
        };
        match self.compare_pull_request(request).await {
            Ok(evidence) => Ok(GithubPullRequestDiffOutcome::Complete(evidence)),
            Err(CompareFailure::Incomplete(reason)) => {
                Ok(GithubPullRequestDiffOutcome::Incomplete(reason))
            }
            Err(CompareFailure::Unavailable) => Err(GithubPullRequestDiffError::Unavailable),
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
        let mut changed_paths = None;
        for page_number in 1..=page_count {
            let endpoint = self.compare_url(
                request.repository,
                request.before,
                request.after,
                page_number,
            )?;
            let response = self
                .fetch_compare_page(endpoint, request.authority, deadline)
                .await?;
            validate_page_identity(&response, request.before, expected_commits.len())?;
            validate_page_length(&response, page_number, page_count, expected_commits.len())?;
            if page_number == 1 {
                changed_paths = Some(complete_changed_paths(response.files)?);
            } else if response.files.is_some() {
                return Err(invalid_evidence());
            }
            observed_commits.extend(response.commits.into_iter().map(|commit| commit.sha));
        }
        validate_observed_commits(&observed_commits, &expected_commits, request.after)?;
        Ok(GithubCompletePushDiff {
            before: request.before.clone(),
            after: request.after.clone(),
            changed_paths: changed_paths.ok_or_else(invalid_evidence)?,
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
        let first_endpoint = self.compare_url(request.repository, request.base, request.head, 1)?;
        let first = self
            .fetch_compare_page(first_endpoint, request.authority, deadline)
            .await?;
        let total_commits = usize::try_from(first.total_commits).map_err(|_| invalid_evidence())?;
        let page_count = comparison_page_count(total_commits, self.trusted.limits().max_pages)?;
        let identity = validate_pull_request_page_identity(&first, request.base, total_commits)?;
        validate_page_length(&first, 1, page_count, total_commits)?;
        let changed_paths = complete_changed_paths(first.files)?;
        let mut observed_commits = first
            .commits
            .into_iter()
            .map(|commit| commit.sha)
            .collect::<Vec<_>>();
        for page_number in 2..=page_count {
            let endpoint =
                self.compare_url(request.repository, request.base, request.head, page_number)?;
            let page = self
                .fetch_compare_page(endpoint, request.authority, deadline)
                .await?;
            if validate_pull_request_page_identity(&page, request.base, total_commits)? != identity
                || page.files.is_some()
            {
                return Err(invalid_evidence());
            }
            validate_page_length(&page, page_number, page_count, total_commits)?;
            observed_commits.extend(page.commits.into_iter().map(|commit| commit.sha));
        }
        validate_pull_request_commits(&observed_commits, request.head)?;
        Ok(GithubCompletePullRequestDiff {
            base: request.base.clone(),
            head: request.head.clone(),
            changed_paths,
        })
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
        before: &ExactRevision,
        after: &ExactRevision,
        page_number: usize,
    ) -> Result<Url, CompareFailure> {
        let (owner, name) = repository_components(repository)?;
        let base_head = format!("{}...{}", before.as_str(), after.as_str());
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
    ) -> Result<ComparePage, CompareFailure> {
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
        decode_compare_page(&response)
    }
}

fn incomplete(reason: GithubPushDiffIncompleteReason) -> GithubPushDiffOutcome {
    GithubPushDiffOutcome::Incomplete(reason)
}

fn invalid_evidence() -> CompareFailure {
    CompareFailure::Incomplete(GithubPushDiffIncompleteReason::InvalidEvidence)
}

fn repository_components(repository: &RepositoryId) -> Result<(&str, &str), CompareFailure> {
    repository_path::split(repository.as_str()).ok_or_else(invalid_evidence)
}

fn validate_requested_commits(
    before: &ExactRevision,
    after: &ExactRevision,
    commits: &[ExactRevision],
) -> Result<(), CompareFailure> {
    if before == after
        || commits.is_empty()
        || commits.len() > MAX_ACTIONS_PUSH_COMMITS
        || !commits.iter().any(|commit| commit == after)
        || commits.iter().any(|commit| commit == before)
    {
        return Err(invalid_evidence());
    }
    let unique = commits
        .iter()
        .map(ExactRevision::as_str)
        .collect::<HashSet<_>>();
    if unique.len() != commits.len() {
        return Err(invalid_evidence());
    }
    Ok(())
}

fn canonical_revisions(commits: &[ExactRevision]) -> Vec<&str> {
    let mut commits = commits
        .iter()
        .map(ExactRevision::as_str)
        .collect::<Vec<_>>();
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
    match authority {
        GithubPushDiffAuthority::PublicAnonymous => Ok(request),
        GithubPushDiffAuthority::PrivateInstallationContentsRead(token) => {
            let authorization = authorization_header(token).map_err(classify_endpoint_error)?;
            Ok(request.header(reqwest::header::AUTHORIZATION, authorization))
        }
    }
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
    before: &ExactRevision,
    expected_commits: usize,
) -> Result<(), CompareFailure> {
    let expected_commits = u64::try_from(expected_commits).map_err(|_| invalid_evidence())?;
    if page.status != "ahead"
        || page.behind_by != 0
        || page.ahead_by != expected_commits
        || page.total_commits != expected_commits
        || page.base_commit.sha != before.as_str()
        || page.merge_base_commit.sha != before.as_str()
    {
        return Err(CompareFailure::Incomplete(
            GithubPushDiffIncompleteReason::DivergedPush,
        ));
    }
    Ok(())
}

#[derive(Eq, PartialEq)]
struct PullRequestPageIdentity {
    status: String,
    ahead_by: u64,
    behind_by: u64,
    merge_base: String,
}

fn validate_pull_request_page_identity(
    page: &ComparePage,
    base: &ExactRevision,
    expected_commits: usize,
) -> Result<PullRequestPageIdentity, CompareFailure> {
    let expected_commits = u64::try_from(expected_commits).map_err(|_| invalid_evidence())?;
    if !matches!(page.status.as_str(), "ahead" | "diverged")
        || page.ahead_by != expected_commits
        || page.total_commits != expected_commits
        || page.base_commit.sha != base.as_str()
        || ExactRevision::new(&page.merge_base_commit.sha).is_err()
    {
        return Err(invalid_evidence());
    }
    Ok(PullRequestPageIdentity {
        status: page.status.clone(),
        ahead_by: page.ahead_by,
        behind_by: page.behind_by,
        merge_base: page.merge_base_commit.sha.clone(),
    })
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
    expected: &[&str],
    after: &ExactRevision,
) -> Result<(), CompareFailure> {
    if observed.last().map(String::as_str) != Some(after.as_str()) {
        return Err(invalid_evidence());
    }
    let mut canonical = observed.iter().map(String::as_str).collect::<Vec<_>>();
    canonical.sort_unstable();
    if canonical != expected || canonical.windows(2).any(|pair| pair[0] == pair[1]) {
        return Err(invalid_evidence());
    }
    Ok(())
}

fn validate_pull_request_commits(
    observed: &[String],
    head: &ExactRevision,
) -> Result<(), CompareFailure> {
    if observed.last().map(String::as_str) != Some(head.as_str())
        || observed
            .iter()
            .any(|commit| ExactRevision::new(commit).is_err())
    {
        return Err(invalid_evidence());
    }
    let unique = observed.iter().map(String::as_str).collect::<HashSet<_>>();
    if unique.len() != observed.len() {
        return Err(invalid_evidence());
    }
    Ok(())
}

fn complete_changed_paths(files: Option<Vec<CompareFile>>) -> Result<Vec<String>, CompareFailure> {
    let files = files.ok_or_else(invalid_evidence)?;
    if files.len() >= GITHUB_COMPARE_FILE_CAP {
        return Err(CompareFailure::Incomplete(
            GithubPushDiffIncompleteReason::FileListCapped,
        ));
    }
    let mut paths = Vec::with_capacity(files.len());
    for file in files {
        if file.status == "renamed" {
            return Err(CompareFailure::Incomplete(
                GithubPushDiffIncompleteReason::RenamedPath,
            ));
        }
        if !matches!(file.status.as_str(), "added" | "modified" | "removed")
            || file.previous_filename.is_some()
            || !valid_changed_path(&file.filename)
        {
            return Err(invalid_evidence());
        }
        paths.push(file.filename);
    }
    paths.sort_unstable();
    if paths.windows(2).any(|pair| pair[0] == pair[1]) {
        return Err(invalid_evidence());
    }
    Ok(paths)
}

fn valid_changed_path(path: &str) -> bool {
    !path.is_empty()
        && path.len() <= MAX_CHANGED_PATH_BYTES
        && !path.starts_with('/')
        && !path.chars().any(char::is_control)
        && path
            .split('/')
            .all(|component| !component.is_empty() && !matches!(component, "." | ".."))
}
