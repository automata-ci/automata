use std::{collections::HashSet, fmt};

use automata_ci_auth::{github::GithubEndpointError, secret::SecretString};
use automata_ci_scm::{ExactRevision, RepositoryId};
use reqwest::{
    Response, StatusCode,
    header::{ACCEPT, AUTHORIZATION, HeaderMap, RETRY_AFTER},
};
use serde::{Deserialize, Deserializer, Serialize};
use thiserror::Error;
use time::{OffsetDateTime, format_description::well_known::Rfc3339};
use url::Url;

use crate::{
    config::same_origin,
    endpoint::{GithubHttpEndpoint, authorization_header},
    pagination, repository_path,
    response::{decode_json, read_json_response},
};

const ACCEPT_API_JSON: &str = "application/vnd.github+json";
const MAX_CHECK_NAME_BYTES: usize = 255;
const MAX_EXTERNAL_ID_BYTES: usize = 1_024;
const MAX_DETAILS_URL_BYTES: usize = 2_048;
const MAX_CHECK_OUTPUT_TITLE_BYTES: usize = 255;
const MAX_CHECK_OUTPUT_SUMMARY_BYTES: usize = 65_535;
const MAX_CHECK_OUTPUT_TEXT_BYTES: usize = 65_535;
const MAX_CHECK_ANNOTATION_PATH_BYTES: usize = 4_096;
const MAX_CHECK_ANNOTATION_MESSAGE_BYTES: usize = 65_535;
const MAX_CHECK_ANNOTATION_TITLE_BYTES: usize = 255;
const MAX_CHECK_ANNOTATIONS_PER_REQUEST: usize = 50;
const CHECK_ANNOTATIONS_PER_PAGE: usize = 100;
const CHECK_SUITES_PER_PAGE: usize = 100;
const CHECK_RUNS_PER_PAGE: usize = 100;
const MAX_GITHUB_ID: u64 = i64::MAX as u64;
const MAX_RETRY_AFTER_SECONDS: u64 = 86_400;
const MAX_RATE_LIMIT_RESET_SECONDS: u64 = 253_402_300_799;
const X_RATE_LIMIT_REMAINING: &str = "x-ratelimit-remaining";
const X_RATE_LIMIT_RESET: &str = "x-ratelimit-reset";

/// A positive GitHub App identifier used to confine Check Run responses.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct GithubCheckAppId(u64);

impl GithubCheckAppId {
    /// Creates a positive identifier representable by GitHub's signed integer schema.
    ///
    /// # Errors
    ///
    /// Rejects zero and values outside GitHub's signed 64-bit identifier range.
    pub const fn new(value: u64) -> Result<Self, GithubCheckModelError> {
        if value == 0 || value > MAX_GITHUB_ID {
            return Err(GithubCheckModelError::InvalidIdentifier);
        }
        Ok(Self(value))
    }

    /// Returns the numeric GitHub App identifier.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }
}

/// A positive GitHub Check Suite identifier.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct GithubCheckSuiteId(u64);

impl GithubCheckSuiteId {
    /// Creates a positive identifier representable by GitHub's signed integer schema.
    ///
    /// # Errors
    ///
    /// Rejects zero and values outside GitHub's signed 64-bit identifier range.
    pub const fn new(value: u64) -> Result<Self, GithubCheckModelError> {
        if value == 0 || value > MAX_GITHUB_ID {
            return Err(GithubCheckModelError::InvalidIdentifier);
        }
        Ok(Self(value))
    }

    /// Returns the numeric Check Suite identifier.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }
}

/// A positive GitHub Check Run identifier.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct GithubCheckRunId(u64);

impl GithubCheckRunId {
    /// Creates a positive identifier representable by GitHub's signed integer schema.
    ///
    /// # Errors
    ///
    /// Rejects zero and values outside GitHub's signed 64-bit identifier range.
    pub const fn new(value: u64) -> Result<Self, GithubCheckModelError> {
        if value == 0 || value > MAX_GITHUB_ID {
            return Err(GithubCheckModelError::InvalidIdentifier);
        }
        Ok(Self(value))
    }

    /// Returns the numeric Check Run identifier.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }
}

/// A bounded, printable Check Run name.
///
/// Debug formatting deliberately omits the value because names can originate in
/// repository configuration.
#[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct GithubCheckName(String);

impl GithubCheckName {
    /// Creates a printable UTF-8 name with no leading or trailing whitespace.
    ///
    /// # Errors
    ///
    /// Rejects empty, oversized, control-containing, or edge-whitespace names.
    pub fn new(value: impl Into<String>) -> Result<Self, GithubCheckModelError> {
        let value = value.into();
        if value.is_empty()
            || value.len() > MAX_CHECK_NAME_BYTES
            || value.trim() != value
            || value.chars().any(char::is_control)
        {
            return Err(GithubCheckModelError::InvalidCheckName);
        }
        Ok(Self(value))
    }

    /// Returns the validated name for the GitHub request boundary.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for GithubCheckName {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("GithubCheckName([REDACTED])")
    }
}

/// A bounded, printable external idempotency identity for one Check Run.
///
/// Debug formatting deliberately omits the value.
#[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct GithubCheckExternalId(String);

impl GithubCheckExternalId {
    /// Creates a nonempty graphic-ASCII external identifier.
    ///
    /// # Errors
    ///
    /// Rejects empty, oversized, whitespace-containing, or non-ASCII values.
    pub fn new(value: impl Into<String>) -> Result<Self, GithubCheckModelError> {
        let value = value.into();
        if value.is_empty()
            || value.len() > MAX_EXTERNAL_ID_BYTES
            || !value.bytes().all(|byte| matches!(byte, b'!'..=b'~'))
        {
            return Err(GithubCheckModelError::InvalidExternalId);
        }
        Ok(Self(value))
    }

    /// Returns the validated external identifier for the GitHub request boundary.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for GithubCheckExternalId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("GithubCheckExternalId([REDACTED])")
    }
}

/// Exact Automata dashboard URL attached to one Check Run.
#[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct GithubCheckDetailsUrl(Url);

impl GithubCheckDetailsUrl {
    /// Creates a bounded absolute HTTP(S) dashboard URL without credentials or fragments.
    ///
    /// # Errors
    ///
    /// Rejects non-HTTP(S), non-hierarchical, credential-bearing, fragmented,
    /// or oversized URLs.
    pub fn new(value: Url) -> Result<Self, GithubCheckModelError> {
        if value.as_str().len() > MAX_DETAILS_URL_BYTES
            || value.cannot_be_a_base()
            || value.host_str().is_none()
            || !value.username().is_empty()
            || value.password().is_some()
            || value.fragment().is_some()
            || !matches!(value.scheme(), "http" | "https")
        {
            return Err(GithubCheckModelError::InvalidDetailsUrl);
        }
        Ok(Self(value))
    }

    /// Returns the exact URL encoded at the provider boundary.
    #[must_use]
    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }
}

impl fmt::Debug for GithubCheckDetailsUrl {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("GithubCheckDetailsUrl([configured])")
    }
}

/// Canonical UTC timestamp accepted by GitHub's Checks API.
#[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct GithubCheckTimestamp(String);

impl GithubCheckTimestamp {
    /// Formats a non-negative Unix millisecond instant as RFC 3339 UTC.
    ///
    /// # Errors
    ///
    /// Rejects negative or out-of-range instants.
    pub fn from_unix_millis(value: i64) -> Result<Self, GithubCheckModelError> {
        if value < 0 {
            return Err(GithubCheckModelError::InvalidTimestamp);
        }
        let nanos = i128::from(value)
            .checked_mul(1_000_000)
            .ok_or(GithubCheckModelError::InvalidTimestamp)?;
        let instant = OffsetDateTime::from_unix_timestamp_nanos(nanos)
            .map_err(|_| GithubCheckModelError::InvalidTimestamp)?;
        let value = instant
            .format(&Rfc3339)
            .map_err(|_| GithubCheckModelError::InvalidTimestamp)?;
        Ok(Self(value))
    }

    /// Returns the canonical provider value.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for GithubCheckTimestamp {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("GithubCheckTimestamp([validated])")
    }
}

/// Bounded native Markdown presentation for one GitHub Check Run update.
#[derive(Clone, Eq, PartialEq)]
pub struct GithubCheckOutput {
    title: String,
    summary: String,
    text: Option<String>,
}

impl GithubCheckOutput {
    /// Creates a bounded title, required Markdown summary, and optional Markdown detail.
    ///
    /// # Errors
    ///
    /// Rejects empty, oversized, non-canonical, or unsafe control-containing text.
    pub fn new(
        title: impl Into<String>,
        summary: impl Into<String>,
        text: Option<String>,
    ) -> Result<Self, GithubCheckModelError> {
        let title = title.into();
        let summary = summary.into();
        if title.is_empty()
            || title.len() > MAX_CHECK_OUTPUT_TITLE_BYTES
            || title.trim() != title
            || title.chars().any(char::is_control)
            || summary.trim().is_empty()
            || summary.len() > MAX_CHECK_OUTPUT_SUMMARY_BYTES
            || !canonical_markdown(&summary)
            || text.as_ref().is_some_and(|text| {
                text.trim().is_empty()
                    || text.len() > MAX_CHECK_OUTPUT_TEXT_BYTES
                    || !canonical_markdown(text)
            })
        {
            return Err(GithubCheckModelError::InvalidOutput);
        }
        Ok(Self {
            title,
            summary,
            text,
        })
    }

    /// Returns the native Check output title.
    #[must_use]
    pub fn title(&self) -> &str {
        &self.title
    }

    /// Returns the required Markdown summary.
    #[must_use]
    pub fn summary(&self) -> &str {
        &self.summary
    }

    /// Returns optional detailed Markdown.
    #[must_use]
    pub fn text(&self) -> Option<&str> {
        self.text.as_deref()
    }
}

impl fmt::Debug for GithubCheckOutput {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GithubCheckOutput")
            .field("title", &"[REDACTED]")
            .field("summary", &"[REDACTED]")
            .field("text", &self.text.as_ref().map(|_| "[REDACTED]"))
            .finish()
    }
}

/// Severity displayed for one source annotation in GitHub's Checks UI.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum GithubCheckAnnotationLevel {
    /// A failing diagnostic.
    Failure,
    /// A warning diagnostic.
    Warning,
    /// An informational diagnostic.
    Notice,
}

/// One bounded repository-relative source annotation for a GitHub Check Run.
#[derive(Clone, Eq, PartialEq, Serialize)]
pub struct GithubCheckAnnotation {
    path: String,
    start_line: u32,
    end_line: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    start_column: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    end_column: Option<u32>,
    annotation_level: GithubCheckAnnotationLevel,
    message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    title: Option<String>,
}

impl GithubCheckAnnotation {
    /// Creates one canonical source annotation.
    ///
    /// # Errors
    ///
    /// Rejects unsafe paths, invalid locations, oversized text, or unsupported
    /// control characters.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        path: impl Into<String>,
        start_line: u32,
        end_line: u32,
        start_column: Option<u32>,
        end_column: Option<u32>,
        annotation_level: GithubCheckAnnotationLevel,
        message: impl Into<String>,
        title: Option<String>,
    ) -> Result<Self, GithubCheckModelError> {
        let path = path.into();
        let message = message.into();
        let path_is_safe = !path.is_empty()
            && path.len() <= MAX_CHECK_ANNOTATION_PATH_BYTES
            && !path.starts_with('/')
            && !path.contains('\\')
            && !path.chars().any(char::is_control)
            && path
                .split('/')
                .all(|component| !component.is_empty() && !matches!(component, "." | ".."));
        let columns_are_valid = match (start_column, end_column) {
            (None, None) => true,
            (Some(start), Some(end)) => start_line == end_line && start > 0 && end >= start,
            (None, Some(_)) | (Some(_), None) => false,
        };
        if !path_is_safe
            || start_line == 0
            || end_line < start_line
            || !columns_are_valid
            || message.trim().is_empty()
            || message.len() > MAX_CHECK_ANNOTATION_MESSAGE_BYTES
            || !canonical_markdown(&message)
            || title.as_ref().is_some_and(|title| {
                title.trim().is_empty()
                    || title.len() > MAX_CHECK_ANNOTATION_TITLE_BYTES
                    || !canonical_markdown(title)
            })
        {
            return Err(GithubCheckModelError::InvalidAnnotation);
        }
        Ok(Self {
            path,
            start_line,
            end_line,
            start_column,
            end_column,
            annotation_level,
            message,
            title,
        })
    }

    /// Returns the canonical repository-relative path.
    #[must_use]
    pub fn path(&self) -> &str {
        &self.path
    }

    /// Returns the inclusive starting line.
    #[must_use]
    pub const fn start_line(&self) -> u32 {
        self.start_line
    }

    /// Returns the inclusive ending line.
    #[must_use]
    pub const fn end_line(&self) -> u32 {
        self.end_line
    }

    /// Returns the optional starting column.
    #[must_use]
    pub const fn start_column(&self) -> Option<u32> {
        self.start_column
    }

    /// Returns the optional ending column.
    #[must_use]
    pub const fn end_column(&self) -> Option<u32> {
        self.end_column
    }

    /// Returns the provider annotation severity.
    #[must_use]
    pub const fn level(&self) -> GithubCheckAnnotationLevel {
        self.annotation_level
    }

    /// Returns the masked diagnostic message.
    #[must_use]
    pub fn message(&self) -> &str {
        &self.message
    }

    /// Returns the optional masked annotation title.
    #[must_use]
    pub fn title(&self) -> Option<&str> {
        self.title.as_deref()
    }
}

impl fmt::Debug for GithubCheckAnnotation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GithubCheckAnnotation")
            .field("path", &"[REDACTED]")
            .field("start_line", &self.start_line)
            .field("end_line", &self.end_line)
            .field("start_column", &self.start_column)
            .field("end_column", &self.end_column)
            .field("annotation_level", &self.annotation_level)
            .field("message", &"[REDACTED]")
            .field("title", &self.title.as_ref().map(|_| "[REDACTED]"))
            .finish()
    }
}

fn canonical_markdown(value: &str) -> bool {
    !value
        .chars()
        .any(|character| character.is_control() && !matches!(character, '\n' | '\t'))
}

/// Immutable identity expected on every response for one Automata Check Run.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GithubCheckRunIdentity {
    app_id: GithubCheckAppId,
    suite_id: GithubCheckSuiteId,
    head_sha: ExactRevision,
    name: GithubCheckName,
    external_id: GithubCheckExternalId,
    details_url: GithubCheckDetailsUrl,
}

impl GithubCheckRunIdentity {
    /// Creates an exact response-validation and reconciliation identity.
    #[must_use]
    pub const fn new(
        app_id: GithubCheckAppId,
        suite_id: GithubCheckSuiteId,
        head_sha: ExactRevision,
        name: GithubCheckName,
        external_id: GithubCheckExternalId,
        details_url: GithubCheckDetailsUrl,
    ) -> Self {
        Self {
            app_id,
            suite_id,
            head_sha,
            name,
            external_id,
            details_url,
        }
    }

    /// Returns the expected GitHub App identifier.
    #[must_use]
    pub const fn app_id(&self) -> GithubCheckAppId {
        self.app_id
    }

    /// Returns the expected Check Suite identifier.
    #[must_use]
    pub const fn suite_id(&self) -> GithubCheckSuiteId {
        self.suite_id
    }

    /// Returns the expected exact commit revision.
    #[must_use]
    pub const fn head_sha(&self) -> &ExactRevision {
        &self.head_sha
    }

    /// Returns the expected Check Run name.
    #[must_use]
    pub const fn name(&self) -> &GithubCheckName {
        &self.name
    }

    /// Returns the expected external identity.
    #[must_use]
    pub const fn external_id(&self) -> &GithubCheckExternalId {
        &self.external_id
    }

    /// Returns the exact Automata dashboard URL.
    #[must_use]
    pub const fn details_url(&self) -> &GithubCheckDetailsUrl {
        &self.details_url
    }
}

/// A terminal conclusion Automata is permitted to publish.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GithubCheckConclusion {
    /// Human action is required.
    ActionRequired,
    /// Execution was cancelled.
    Cancelled,
    /// Execution failed.
    Failure,
    /// Execution was neutral.
    Neutral,
    /// Execution succeeded.
    Success,
    /// Execution was skipped.
    Skipped,
    /// Execution timed out.
    TimedOut,
}

impl GithubCheckConclusion {
    const fn as_str(self) -> &'static str {
        match self {
            Self::ActionRequired => "action_required",
            Self::Cancelled => "cancelled",
            Self::Failure => "failure",
            Self::Neutral => "neutral",
            Self::Success => "success",
            Self::Skipped => "skipped",
            Self::TimedOut => "timed_out",
        }
    }

    const fn title(self) -> &'static str {
        match self {
            Self::ActionRequired => "Action required",
            Self::Cancelled => "Cancelled",
            Self::Failure => "Failed",
            Self::Neutral => "Completed",
            Self::Success => "Passed",
            Self::Skipped => "Skipped",
            Self::TimedOut => "Timed out",
        }
    }

    const fn summary(self) -> &'static str {
        match self {
            Self::ActionRequired => "Automata needs attention.",
            Self::Cancelled => "The job was cancelled.",
            Self::Failure => "The job failed. Diagnostics and logs are available in Automata.",
            Self::Neutral => "The job completed with a neutral result.",
            Self::Success => "The job completed successfully.",
            Self::Skipped => "The job was skipped.",
            Self::TimedOut => {
                "The job timed out. Its last recorded progress is available in Automata."
            }
        }
    }
}

/// A conclusion observed in a validated GitHub response.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GithubObservedCheckConclusion {
    /// Human action is required.
    ActionRequired,
    /// Execution was cancelled.
    Cancelled,
    /// Execution failed.
    Failure,
    /// Execution was neutral.
    Neutral,
    /// Execution succeeded.
    Success,
    /// Execution was skipped.
    Skipped,
    /// GitHub marked the run stale.
    Stale,
    /// Execution timed out.
    TimedOut,
}

impl From<GithubCheckConclusion> for GithubObservedCheckConclusion {
    fn from(value: GithubCheckConclusion) -> Self {
        match value {
            GithubCheckConclusion::ActionRequired => Self::ActionRequired,
            GithubCheckConclusion::Cancelled => Self::Cancelled,
            GithubCheckConclusion::Failure => Self::Failure,
            GithubCheckConclusion::Neutral => Self::Neutral,
            GithubCheckConclusion::Success => Self::Success,
            GithubCheckConclusion::Skipped => Self::Skipped,
            GithubCheckConclusion::TimedOut => Self::TimedOut,
        }
    }
}

/// Validated lifecycle state for a Check Run owned by this App.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GithubCheckRunState {
    /// The run is queued.
    Queued,
    /// The run is in progress.
    InProgress,
    /// The run is terminal with the accompanying conclusion.
    Completed(GithubObservedCheckConclusion),
}

/// Sanitized Check Suite identity returned after a create request.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GithubCheckSuite {
    id: GithubCheckSuiteId,
    app_id: GithubCheckAppId,
    head_sha: ExactRevision,
}

impl GithubCheckSuite {
    /// Returns the suite identifier.
    #[must_use]
    pub const fn id(&self) -> GithubCheckSuiteId {
        self.id
    }

    /// Returns the App that owns the suite.
    #[must_use]
    pub const fn app_id(&self) -> GithubCheckAppId {
        self.app_id
    }

    /// Returns the exact suite revision.
    #[must_use]
    pub const fn head_sha(&self) -> &ExactRevision {
        &self.head_sha
    }
}

/// Sanitized Check Run evidence returned by the HTTP boundary.
#[derive(Debug, Eq, PartialEq)]
pub struct GithubCheckRun {
    id: GithubCheckRunId,
    identity: GithubCheckRunIdentity,
    state: GithubCheckRunState,
}

impl GithubCheckRun {
    /// Returns the Check Run identifier.
    #[must_use]
    pub const fn id(&self) -> GithubCheckRunId {
        self.id
    }

    /// Returns the exact validated identity.
    #[must_use]
    pub const fn identity(&self) -> &GithubCheckRunIdentity {
        &self.identity
    }

    /// Returns the validated provider state.
    #[must_use]
    pub const fn state(&self) -> GithubCheckRunState {
        self.state
    }
}

/// Determinate response to Check Suite creation, or explicit mutation uncertainty.
#[derive(Debug, Eq, PartialEq)]
pub enum GithubCheckSuiteCreateOutcome {
    /// GitHub returned `200`, proving the suite already existed.
    Existing(GithubCheckSuite),
    /// GitHub returned `201`, proving a new suite was created.
    Created(GithubCheckSuite),
    /// The POST may have reached GitHub but no valid outcome was observed.
    Indeterminate(GithubCheckCreateIndeterminate),
}

/// Determinate response to Check Run creation, or explicit mutation uncertainty.
#[derive(Debug, Eq, PartialEq)]
pub enum GithubCheckRunCreateOutcome {
    /// GitHub returned an exact `201` response for the requested identity.
    Created(GithubCheckRun),
    /// The POST may have reached GitHub but no valid outcome was observed.
    Indeterminate(GithubCheckCreateIndeterminate),
}

/// Exact reconciliation result after an indeterminate Check Run POST.
#[derive(Debug, Eq, PartialEq)]
pub enum GithubCheckRunReconciliation {
    /// No exact App/name/SHA/external-id/suite match was observed.
    Missing,
    /// Exactly one fully matching Check Run was observed.
    Exact(GithubCheckRun),
    /// More than one fully matching Check Run was observed.
    Ambiguous,
}

/// Why a create mutation has no determinate result.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GithubCheckCreateIndeterminateKind {
    /// Transport completion was not observed.
    Transport,
    /// GitHub returned a timeout or server-error status.
    ProviderUnavailable,
    /// A success status or body did not satisfy the exact response contract.
    InvalidSuccessResponse,
}

/// Value-free evidence accompanying an indeterminate create mutation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GithubCheckCreateIndeterminate {
    kind: GithubCheckCreateIndeterminateKind,
    retry: GithubCheckRetryEvidence,
}

impl GithubCheckCreateIndeterminate {
    /// Returns the closed uncertainty classification.
    #[must_use]
    pub const fn kind(self) -> GithubCheckCreateIndeterminateKind {
        self.kind
    }

    /// Returns bounded retry and rate-limit response-header evidence.
    #[must_use]
    pub const fn retry_evidence(self) -> GithubCheckRetryEvidence {
        self.retry
    }
}

/// Bounded, body-free retry evidence from GitHub response headers.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct GithubCheckRetryEvidence {
    retry_after_seconds: Option<u64>,
    rate_limit_reset_at: Option<u64>,
    rate_limit_remaining_zero: bool,
}

impl GithubCheckRetryEvidence {
    /// Returns a bounded delta-seconds `Retry-After` value when present and valid.
    #[must_use]
    pub const fn retry_after_seconds(self) -> Option<u64> {
        self.retry_after_seconds
    }

    /// Returns a bounded UTC epoch-seconds rate-limit reset when present and valid.
    #[must_use]
    pub const fn rate_limit_reset_at(self) -> Option<u64> {
        self.rate_limit_reset_at
    }

    /// Reports whether one exact `X-RateLimit-Remaining: 0` header was observed.
    #[must_use]
    pub const fn rate_limit_remaining_zero(self) -> bool {
        self.rate_limit_remaining_zero
    }
}

/// Invalid bounded Checks request-model construction.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum GithubCheckModelError {
    /// A numeric identifier is zero or exceeds GitHub's signed 64-bit range.
    #[error("the GitHub Checks identifier is invalid")]
    InvalidIdentifier,
    /// A Check Run name violates the bounded printable-name policy.
    #[error("the GitHub Check Run name is invalid")]
    InvalidCheckName,
    /// An external Check Run identity violates the bounded graphic-value policy.
    #[error("the GitHub Check Run external identity is invalid")]
    InvalidExternalId,
    /// A Check Run details URL violates the bounded absolute-URL policy.
    #[error("the GitHub Check Run details URL is invalid")]
    InvalidDetailsUrl,
    /// A lifecycle timestamp was negative or outside RFC 3339's range.
    #[error("invalid GitHub Check timestamp")]
    InvalidTimestamp,
    /// Native Check output violated the bounded canonical Markdown policy.
    #[error("invalid GitHub Check output")]
    InvalidOutput,
    /// A source annotation violated path, location, or bounded text policy.
    #[error("invalid GitHub Check annotation")]
    InvalidAnnotation,
}

/// Sanitized failure at the GitHub Checks HTTP boundary.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum GithubChecksError {
    /// The local repository identity is not a valid GitHub owner/name pair.
    #[error("the GitHub Checks request is invalid")]
    InvalidRequest,
    /// GitHub rejected the server-service credential.
    #[error("GitHub rejected the Checks credential")]
    Unauthorized,
    /// GitHub denied the Checks operation.
    #[error("GitHub denied the Checks operation")]
    Forbidden,
    /// The requested GitHub Checks resource does not exist.
    #[error("the GitHub Checks resource was not found")]
    NotFound,
    /// GitHub reported a conflict for the Checks operation.
    #[error("GitHub rejected the conflicting Checks operation")]
    Conflict,
    /// GitHub rejected the semantic request.
    #[error("GitHub rejected the Checks request")]
    Rejected,
    /// GitHub rate limited the operation with bounded header-only evidence.
    #[error("GitHub rate limited the Checks operation")]
    RateLimited(GithubCheckRetryEvidence),
    /// GitHub or the transport is unavailable with bounded header-only evidence.
    #[error("the GitHub Checks endpoint is unavailable")]
    Unavailable(GithubCheckRetryEvidence),
    /// GitHub returned an invalid, unexpected, or oversized response.
    #[error("GitHub returned an invalid Checks response")]
    InvalidResponse,
}

#[derive(Serialize)]
struct CreateSuiteBody<'a> {
    head_sha: &'a str,
}

#[derive(Deserialize)]
struct SuiteResponse {
    id: u64,
    head_sha: String,
    app: AppResponse,
}

#[derive(Deserialize)]
struct CheckSuitesPage {
    total_count: u64,
    check_suites: Vec<SuiteResponse>,
}

#[derive(Serialize)]
struct CreateRunBody<'a> {
    name: &'a str,
    head_sha: &'a str,
    status: &'static str,
    external_id: &'a str,
    details_url: &'a str,
    output: CheckOutputBody<'a>,
}

#[derive(Serialize)]
struct StartRunBody<'a> {
    status: &'static str,
    started_at: &'a str,
    output: CheckOutputBody<'a>,
}

#[derive(Serialize)]
struct CompleteRunBody<'a> {
    status: &'static str,
    conclusion: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    started_at: Option<&'a str>,
    completed_at: &'a str,
    output: CheckOutputBody<'a>,
}

#[derive(Serialize)]
struct AnnotateRunBody<'a> {
    output: CheckOutputAnnotationsBody<'a>,
}

#[derive(Serialize)]
struct CheckOutputAnnotationsBody<'a> {
    title: &'a str,
    summary: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    text: Option<&'a str>,
    annotations: &'a [GithubCheckAnnotation],
}

#[derive(Clone, Copy, Serialize)]
struct CheckOutputBody<'a> {
    title: &'a str,
    summary: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    text: Option<&'a str>,
}

#[derive(Deserialize)]
struct CheckRunsPage {
    total_count: u64,
    check_runs: Vec<RunResponse>,
}

#[derive(Deserialize)]
struct AnnotationResponse {
    path: String,
    start_line: u32,
    end_line: u32,
    start_column: Option<u32>,
    end_column: Option<u32>,
    annotation_level: String,
    message: String,
    title: Option<String>,
}

#[derive(Deserialize)]
struct RunResponse {
    id: u64,
    head_sha: String,
    #[serde(default, deserialize_with = "deserialize_present_nullable")]
    external_id: Present<Option<String>>,
    #[serde(default, deserialize_with = "deserialize_present_nullable")]
    details_url: Present<Option<String>>,
    status: String,
    #[serde(default, deserialize_with = "deserialize_present_nullable")]
    conclusion: Present<Option<String>>,
    name: String,
    check_suite: SuiteReference,
    app: AppResponse,
}

#[derive(Deserialize)]
struct SuiteReference {
    id: u64,
}

#[derive(Deserialize)]
struct AppResponse {
    id: u64,
}

#[derive(Default)]
enum Present<T> {
    #[default]
    Missing,
    Value(T),
}

impl<T> Present<T> {
    fn into_value(self) -> Option<T> {
        match self {
            Self::Missing => None,
            Self::Value(value) => Some(value),
        }
    }
}

fn deserialize_present_nullable<'de, D, T>(deserializer: D) -> Result<Present<T>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
    T::deserialize(deserializer).map(Present::Value)
}

struct ValidatedRun {
    id: GithubCheckRunId,
    app_id: GithubCheckAppId,
    suite_id: GithubCheckSuiteId,
    head_sha: ExactRevision,
    name: GithubCheckName,
    external_id: Option<GithubCheckExternalId>,
    details_url: Option<GithubCheckDetailsUrl>,
    state: GithubCheckRunState,
}

impl GithubHttpEndpoint {
    /// Creates or resolves the App's Check Suite for an exact commit.
    ///
    /// The POST is issued once. A transport failure, timeout, server error, or
    /// malformed success response is returned as [`GithubCheckSuiteCreateOutcome::Indeterminate`]
    /// so a caller cannot accidentally treat the mutation as safely retryable.
    ///
    /// # Errors
    ///
    /// Returns a sanitized determinate error for credential, authorization,
    /// rate-limit, request, redirect, or provider-contract rejection.
    pub async fn create_check_suite(
        &self,
        repository: &RepositoryId,
        head_sha: &ExactRevision,
        app_id: GithubCheckAppId,
        server_service_token: &SecretString,
    ) -> Result<GithubCheckSuiteCreateOutcome, GithubChecksError> {
        let endpoint = self.checks_repository_url(repository, &["check-suites"])?;
        let body = CreateSuiteBody {
            head_sha: head_sha.as_str(),
        };
        let Ok(response) =
            authenticated_checks_request(self.client.post(endpoint), server_service_token)?
                .json(&body)
                .send()
                .await
        else {
            return Ok(GithubCheckSuiteCreateOutcome::Indeterminate(indeterminate(
                GithubCheckCreateIndeterminateKind::Transport,
                None,
            )));
        };
        let status = response.status();
        if matches!(status, StatusCode::OK | StatusCode::CREATED) {
            let Ok(suite) = self
                .decode_suite_create_response(response, head_sha, app_id)
                .await
            else {
                return Ok(GithubCheckSuiteCreateOutcome::Indeterminate(indeterminate(
                    GithubCheckCreateIndeterminateKind::InvalidSuccessResponse,
                    None,
                )));
            };
            return Ok(if status == StatusCode::OK {
                GithubCheckSuiteCreateOutcome::Existing(suite)
            } else {
                GithubCheckSuiteCreateOutcome::Created(suite)
            });
        }
        if status == StatusCode::UNPROCESSABLE_ENTITY
            && let Some(suite) = self
                .resolve_existing_check_suite(repository, head_sha, app_id, server_service_token)
                .await?
        {
            return Ok(GithubCheckSuiteCreateOutcome::Existing(suite));
        }
        classify_create_failure(&response).map(GithubCheckSuiteCreateOutcome::Indeterminate)
    }

    async fn resolve_existing_check_suite(
        &self,
        repository: &RepositoryId,
        head_sha: &ExactRevision,
        app_id: GithubCheckAppId,
        server_service_token: &SecretString,
    ) -> Result<Option<GithubCheckSuite>, GithubChecksError> {
        let app_id_query = app_id.get().to_string();
        let mut endpoint = self
            .checks_repository_url(repository, &["commits", head_sha.as_str(), "check-suites"])?;
        endpoint
            .query_pairs_mut()
            .append_pair("app_id", &app_id_query)
            .append_pair("per_page", &CHECK_SUITES_PER_PAGE.to_string())
            .append_pair("page", "1");
        let response =
            authenticated_checks_request(self.client.get(endpoint), server_service_token)?
                .send()
                .await
                .map_err(|_| GithubChecksError::Unavailable(GithubCheckRetryEvidence::default()))?;
        if response.status() != StatusCode::OK {
            return Err(map_error_response(&response));
        }
        let response =
            read_json_response(response, self.trusted.limits().max_response_bytes, false)
                .await
                .map_err(map_endpoint_error)?;
        let page: CheckSuitesPage = decode_json(&response.body).map_err(map_endpoint_error)?;
        if page.check_suites.len() > 1
            || page.check_suites.len() > CHECK_SUITES_PER_PAGE
            || u64::try_from(page.check_suites.len()).ok() != Some(page.total_count)
        {
            return Err(GithubChecksError::InvalidResponse);
        }
        page.check_suites
            .into_iter()
            .next()
            .map(|suite| validate_suite(suite, head_sha, app_id))
            .transpose()
    }

    /// Creates one queued Check Run with a native summary and exact Details link.
    ///
    /// The POST is issued once. Any possibly-applied transport or provider outcome
    /// is explicit and must be reconciled with [`Self::reconcile_check_run_creation`].
    ///
    /// # Errors
    ///
    /// Returns a sanitized determinate error for credential, authorization,
    /// rate-limit, request, redirect, or provider-contract rejection.
    pub async fn create_check_run(
        &self,
        repository: &RepositoryId,
        identity: &GithubCheckRunIdentity,
        server_service_token: &SecretString,
    ) -> Result<GithubCheckRunCreateOutcome, GithubChecksError> {
        let endpoint = self.checks_repository_url(repository, &["check-runs"])?;
        let summary = check_summary("Waiting for a runner.", identity.details_url.as_str());
        let body = CreateRunBody {
            name: identity.name.as_str(),
            head_sha: identity.head_sha.as_str(),
            status: "queued",
            external_id: identity.external_id.as_str(),
            details_url: identity.details_url.as_str(),
            output: CheckOutputBody {
                title: "Queued",
                summary: &summary,
                text: None,
            },
        };
        let Ok(response) =
            authenticated_checks_request(self.client.post(endpoint), server_service_token)?
                .json(&body)
                .send()
                .await
        else {
            return Ok(GithubCheckRunCreateOutcome::Indeterminate(indeterminate(
                GithubCheckCreateIndeterminateKind::Transport,
                None,
            )));
        };
        if response.status() != StatusCode::CREATED {
            return classify_create_failure(&response)
                .map(GithubCheckRunCreateOutcome::Indeterminate);
        }
        let run = match self.decode_run_response(response).await {
            Ok(run)
                if run_matches_identity(&run, identity)
                    && run.state == GithubCheckRunState::Queued =>
            {
                into_public_run(&run, identity)
            }
            Ok(_) | Err(_) => {
                return Ok(GithubCheckRunCreateOutcome::Indeterminate(indeterminate(
                    GithubCheckCreateIndeterminateKind::InvalidSuccessResponse,
                    None,
                )));
            }
        };
        Ok(GithubCheckRunCreateOutcome::Created(run))
    }

    /// Fully paginates the exact suite/name query and reconciles one create identity.
    ///
    /// GitHub's required `filter=all`, exact `check_name`, and `per_page=100`
    /// parameters are retained and revalidated on every pagination URL. The
    /// suite-specific endpoint avoids the ref-list endpoint's documented
    /// 1,000-suite truncation. Results outside the requested external ID are
    /// ignored; duplicate exact matches are reported as ambiguous.
    ///
    /// # Errors
    ///
    /// Returns a sanitized error for transport/provider failure, malformed or
    /// cross-origin pagination, page cycles, excess pages/items, duplicate returned
    /// run IDs, or response items that violate the App/name/ref query.
    pub async fn reconcile_check_run_creation(
        &self,
        repository: &RepositoryId,
        identity: &GithubCheckRunIdentity,
        server_service_token: &SecretString,
    ) -> Result<GithubCheckRunReconciliation, GithubChecksError> {
        let suite_id = identity.suite_id.get().to_string();
        let mut endpoint =
            self.checks_repository_url(repository, &["check-suites", &suite_id, "check-runs"])?;
        endpoint
            .query_pairs_mut()
            .append_pair("check_name", identity.name.as_str())
            .append_pair("filter", "all")
            .append_pair("per_page", &CHECK_RUNS_PER_PAGE.to_string())
            .append_pair("page", "1");
        let expected_path = endpoint.path().to_owned();
        let maximum_pages = self.trusted.limits().max_pages;
        let maximum_items = maximum_pages
            .checked_mul(CHECK_RUNS_PER_PAGE)
            .ok_or(GithubChecksError::InvalidResponse)?;
        let maximum_items_u64 =
            u64::try_from(maximum_items).map_err(|_| GithubChecksError::InvalidResponse)?;
        let mut visited_pages = HashSet::new();
        let mut returned_ids = HashSet::new();
        let mut observed_total_count = None;
        let mut observed_items = 0_usize;
        let mut exact_match = None;
        let mut ambiguous = false;
        let mut current_page = 1_u64;

        for _ in 0..maximum_pages {
            if !visited_pages.insert(current_page) {
                return Err(GithubChecksError::InvalidResponse);
            }
            let response = authenticated_checks_request(
                self.client.get(endpoint.clone()),
                server_service_token,
            )?
            .send()
            .await
            .map_err(|_| GithubChecksError::Unavailable(GithubCheckRetryEvidence::default()))?;
            if response.status() != StatusCode::OK {
                return Err(map_error_response(&response));
            }
            let response =
                read_json_response(response, self.trusted.limits().max_response_bytes, false)
                    .await
                    .map_err(map_endpoint_error)?;
            let page: CheckRunsPage = decode_json(&response.body).map_err(map_endpoint_error)?;
            if page.check_runs.len() > CHECK_RUNS_PER_PAGE || page.total_count > maximum_items_u64 {
                return Err(GithubChecksError::InvalidResponse);
            }
            match observed_total_count {
                None => observed_total_count = Some(page.total_count),
                Some(total) if total == page.total_count => {}
                Some(_) => return Err(GithubChecksError::InvalidResponse),
            }
            observed_items = observed_items
                .checked_add(page.check_runs.len())
                .filter(|count| *count <= maximum_items)
                .ok_or(GithubChecksError::InvalidResponse)?;

            for wire in page.check_runs {
                let run = validate_run(wire)?;
                if !returned_ids.insert(run.id) || !run_matches_query(&run, identity) {
                    return Err(GithubChecksError::InvalidResponse);
                }
                if run_matches_identity(&run, identity) {
                    if exact_match.is_some() {
                        ambiguous = true;
                    } else {
                        exact_match = Some(into_public_run(&run, identity));
                    }
                }
            }

            let Some(next) = next_check_run_page(
                &response.headers,
                &self.trusted,
                &expected_path,
                identity,
                current_page,
            )?
            else {
                if u64::try_from(observed_items).ok() != observed_total_count {
                    return Err(GithubChecksError::InvalidResponse);
                }
                return Ok(finish_reconciliation(ambiguous, exact_match));
            };
            current_page = current_page
                .checked_add(1)
                .ok_or(GithubChecksError::InvalidResponse)?;
            endpoint = next;
        }
        Err(GithubChecksError::InvalidResponse)
    }

    /// Gets one exact Check Run ID and validates its complete immutable identity.
    ///
    /// # Errors
    ///
    /// Returns a sanitized error unless GitHub returns exact `200` JSON matching
    /// the run ID, App, suite, head SHA, name, external ID, and closed state.
    pub async fn get_check_run(
        &self,
        repository: &RepositoryId,
        run_id: GithubCheckRunId,
        identity: &GithubCheckRunIdentity,
        server_service_token: &SecretString,
    ) -> Result<GithubCheckRun, GithubChecksError> {
        let run_id_segment = run_id.get().to_string();
        let endpoint = self.checks_repository_url(repository, &["check-runs", &run_id_segment])?;
        let response =
            authenticated_checks_request(self.client.get(endpoint), server_service_token)?
                .send()
                .await
                .map_err(|_| GithubChecksError::Unavailable(GithubCheckRetryEvidence::default()))?;
        if response.status() != StatusCode::OK {
            return Err(map_error_response(&response));
        }
        let run = self.decode_run_response(response).await?;
        if run.id != run_id || !run_matches_identity(&run, identity) {
            return Err(GithubChecksError::InvalidResponse);
        }
        Ok(into_public_run(&run, identity))
    }

    /// Advances one exact queued Check Run to `in_progress`.
    ///
    /// Includes the durable execution start time and a compact native summary.
    /// Repeating the same exact state assignment is safe after a transport ambiguity.
    ///
    /// # Errors
    ///
    /// Returns a sanitized error unless GitHub returns exact `200` JSON matching
    /// the run ID, immutable identity, and `in_progress` state with no conclusion.
    pub async fn start_check_run(
        &self,
        repository: &RepositoryId,
        run_id: GithubCheckRunId,
        identity: &GithubCheckRunIdentity,
        started_at: &GithubCheckTimestamp,
        server_service_token: &SecretString,
    ) -> Result<GithubCheckRun, GithubChecksError> {
        let run_id_segment = run_id.get().to_string();
        let endpoint = self.checks_repository_url(repository, &["check-runs", &run_id_segment])?;
        let summary = check_summary(
            "This job is running. Live progress and logs are available in Automata.",
            identity.details_url.as_str(),
        );
        let body = StartRunBody {
            status: "in_progress",
            started_at: started_at.as_str(),
            output: CheckOutputBody {
                title: "Running",
                summary: &summary,
                text: None,
            },
        };
        let response =
            authenticated_checks_request(self.client.patch(endpoint), server_service_token)?
                .json(&body)
                .send()
                .await
                .map_err(|_| GithubChecksError::Unavailable(GithubCheckRetryEvidence::default()))?;
        if response.status() != StatusCode::OK {
            return Err(map_error_response(&response));
        }
        let run = self.decode_run_response(response).await?;
        if run.id != run_id
            || !run_matches_identity(&run, identity)
            || run.state != GithubCheckRunState::InProgress
        {
            return Err(GithubChecksError::InvalidResponse);
        }
        Ok(into_public_run(&run, identity))
    }

    /// Publishes an immutable terminal state, completion time, and native summary.
    ///
    /// # Errors
    ///
    /// Returns a sanitized error unless GitHub returns exact `200` JSON matching
    /// the run ID, immutable identity, completed state, and requested conclusion.
    #[allow(clippy::too_many_arguments)]
    pub async fn complete_check_run(
        &self,
        repository: &RepositoryId,
        run_id: GithubCheckRunId,
        identity: &GithubCheckRunIdentity,
        conclusion: GithubCheckConclusion,
        started_at: Option<&GithubCheckTimestamp>,
        completed_at: &GithubCheckTimestamp,
        server_service_token: &SecretString,
    ) -> Result<GithubCheckRun, GithubChecksError> {
        let summary = check_summary(conclusion.summary(), identity.details_url.as_str());
        let output = GithubCheckOutput::new(conclusion.title(), summary, None)
            .map_err(|_| GithubChecksError::InvalidRequest)?;
        self.complete_check_run_with_output(
            repository,
            run_id,
            identity,
            conclusion,
            started_at,
            completed_at,
            &output,
            server_service_token,
        )
        .await
    }

    /// Publishes an immutable terminal state with a caller-supplied bounded presentation.
    ///
    /// # Errors
    ///
    /// Returns a sanitized error unless GitHub returns exact `200` JSON matching
    /// the run ID, immutable identity, completed state, and requested conclusion.
    #[allow(clippy::too_many_arguments)]
    pub async fn complete_check_run_with_output(
        &self,
        repository: &RepositoryId,
        run_id: GithubCheckRunId,
        identity: &GithubCheckRunIdentity,
        conclusion: GithubCheckConclusion,
        started_at: Option<&GithubCheckTimestamp>,
        completed_at: &GithubCheckTimestamp,
        output: &GithubCheckOutput,
        server_service_token: &SecretString,
    ) -> Result<GithubCheckRun, GithubChecksError> {
        let run_id_segment = run_id.get().to_string();
        let endpoint = self.checks_repository_url(repository, &["check-runs", &run_id_segment])?;
        let body = CompleteRunBody {
            status: "completed",
            conclusion: conclusion.as_str(),
            started_at: started_at.map(GithubCheckTimestamp::as_str),
            completed_at: completed_at.as_str(),
            output: CheckOutputBody {
                title: output.title(),
                summary: output.summary(),
                text: output.text(),
            },
        };
        let response =
            authenticated_checks_request(self.client.patch(endpoint), server_service_token)?
                .json(&body)
                .send()
                .await
                .map_err(|_| GithubChecksError::Unavailable(GithubCheckRetryEvidence::default()))?;
        if response.status() != StatusCode::OK {
            return Err(map_error_response(&response));
        }
        let run = self.decode_run_response(response).await?;
        let expected_state =
            GithubCheckRunState::Completed(GithubObservedCheckConclusion::from(conclusion));
        if run.id != run_id || !run_matches_identity(&run, identity) || run.state != expected_state
        {
            return Err(GithubChecksError::InvalidResponse);
        }
        Ok(into_public_run(&run, identity))
    }

    /// Appends one bounded source-annotation batch to a completed Check Run.
    ///
    /// GitHub appends annotations rather than replacing them. Callers must use
    /// a durable cursor and reconcile transport ambiguity before retrying.
    ///
    /// # Errors
    ///
    /// Rejects empty or oversized batches locally and otherwise returns a
    /// sanitized error unless GitHub returns the exact completed Check Run.
    #[allow(clippy::too_many_arguments)]
    pub async fn append_check_run_annotations(
        &self,
        repository: &RepositoryId,
        run_id: GithubCheckRunId,
        identity: &GithubCheckRunIdentity,
        conclusion: GithubCheckConclusion,
        output: &GithubCheckOutput,
        annotations: &[GithubCheckAnnotation],
        server_service_token: &SecretString,
    ) -> Result<GithubCheckRun, GithubChecksError> {
        if annotations.is_empty() || annotations.len() > MAX_CHECK_ANNOTATIONS_PER_REQUEST {
            return Err(GithubChecksError::InvalidRequest);
        }
        let run_id_segment = run_id.get().to_string();
        let endpoint = self.checks_repository_url(repository, &["check-runs", &run_id_segment])?;
        let body = AnnotateRunBody {
            output: CheckOutputAnnotationsBody {
                title: output.title(),
                summary: output.summary(),
                text: output.text(),
                annotations,
            },
        };
        let response =
            authenticated_checks_request(self.client.patch(endpoint), server_service_token)?
                .json(&body)
                .send()
                .await
                .map_err(|_| GithubChecksError::Unavailable(GithubCheckRetryEvidence::default()))?;
        if response.status() != StatusCode::OK {
            return Err(map_error_response(&response));
        }
        let run = self.decode_run_response(response).await?;
        let expected_state =
            GithubCheckRunState::Completed(GithubObservedCheckConclusion::from(conclusion));
        if run.id != run_id || !run_matches_identity(&run, identity) || run.state != expected_state
        {
            return Err(GithubChecksError::InvalidResponse);
        }
        Ok(into_public_run(&run, identity))
    }

    /// Fully paginates and validates every annotation currently on one Check Run.
    ///
    /// # Errors
    ///
    /// Returns a sanitized error for transport/provider failure, malformed or
    /// cross-origin pagination, excess pages/items, or invalid annotation data.
    pub async fn list_check_run_annotations(
        &self,
        repository: &RepositoryId,
        run_id: GithubCheckRunId,
        server_service_token: &SecretString,
    ) -> Result<Vec<GithubCheckAnnotation>, GithubChecksError> {
        let run_id_segment = run_id.get().to_string();
        let mut endpoint = self
            .checks_repository_url(repository, &["check-runs", &run_id_segment, "annotations"])?;
        endpoint
            .query_pairs_mut()
            .append_pair("per_page", &CHECK_ANNOTATIONS_PER_PAGE.to_string())
            .append_pair("page", "1");
        let expected_path = endpoint.path().to_owned();
        let mut annotations = Vec::new();
        let mut current_page = 1_u64;
        let mut visited_pages = HashSet::new();
        for _ in 0..self.trusted.limits().max_pages {
            if !visited_pages.insert(current_page) {
                return Err(GithubChecksError::InvalidResponse);
            }
            let response = authenticated_checks_request(
                self.client.get(endpoint.clone()),
                server_service_token,
            )?
            .send()
            .await
            .map_err(|_| GithubChecksError::Unavailable(GithubCheckRetryEvidence::default()))?;
            if response.status() != StatusCode::OK {
                return Err(map_error_response(&response));
            }
            let response =
                read_json_response(response, self.trusted.limits().max_response_bytes, false)
                    .await
                    .map_err(map_endpoint_error)?;
            let page: Vec<AnnotationResponse> =
                decode_json(&response.body).map_err(map_endpoint_error)?;
            if page.len() > CHECK_ANNOTATIONS_PER_PAGE {
                return Err(GithubChecksError::InvalidResponse);
            }
            annotations.reserve(page.len());
            for annotation in page {
                annotations.push(validate_annotation(annotation)?);
                if annotations.len() > 4_096 {
                    return Err(GithubChecksError::InvalidResponse);
                }
            }
            let Some(next) = next_annotation_page(
                &response.headers,
                &self.trusted,
                &expected_path,
                current_page,
            )?
            else {
                return Ok(annotations);
            };
            current_page = current_page
                .checked_add(1)
                .ok_or(GithubChecksError::InvalidResponse)?;
            endpoint = next;
        }
        Err(GithubChecksError::InvalidResponse)
    }

    fn checks_repository_url(
        &self,
        repository: &RepositoryId,
        tail: &[&str],
    ) -> Result<Url, GithubChecksError> {
        let (owner, name) =
            repository_path::split(repository.as_str()).ok_or(GithubChecksError::InvalidRequest)?;
        let mut endpoint = self.trusted.api_base().clone();
        let mut segments = endpoint
            .path_segments_mut()
            .map_err(|()| GithubChecksError::InvalidRequest)?;
        segments.pop_if_empty();
        segments.push("repos");
        segments.push(owner);
        segments.push(name);
        for component in tail {
            segments.push(component);
        }
        drop(segments);
        if !self.trusted.trusts_api_url(&endpoint) || endpoint.query().is_some() {
            return Err(GithubChecksError::InvalidRequest);
        }
        Ok(endpoint)
    }

    async fn decode_suite_create_response(
        &self,
        response: Response,
        expected_sha: &ExactRevision,
        expected_app: GithubCheckAppId,
    ) -> Result<GithubCheckSuite, GithubChecksError> {
        let response =
            read_json_response(response, self.trusted.limits().max_response_bytes, false)
                .await
                .map_err(map_endpoint_error)?;
        let wire: SuiteResponse = decode_json(&response.body).map_err(map_endpoint_error)?;
        validate_suite(wire, expected_sha, expected_app)
    }

    async fn decode_run_response(
        &self,
        response: Response,
    ) -> Result<ValidatedRun, GithubChecksError> {
        let response =
            read_json_response(response, self.trusted.limits().max_response_bytes, false)
                .await
                .map_err(map_endpoint_error)?;
        let wire: RunResponse = decode_json(&response.body).map_err(map_endpoint_error)?;
        validate_run(wire)
    }
}

fn check_summary(message: &str, details_url: &str) -> String {
    format!("{message}\n\n[Open this job in Automata]({details_url})")
}

fn validate_suite(
    wire: SuiteResponse,
    expected_sha: &ExactRevision,
    expected_app: GithubCheckAppId,
) -> Result<GithubCheckSuite, GithubChecksError> {
    let id = GithubCheckSuiteId::new(wire.id).map_err(|_| GithubChecksError::InvalidResponse)?;
    let app_id =
        GithubCheckAppId::new(wire.app.id).map_err(|_| GithubChecksError::InvalidResponse)?;
    let head_sha =
        ExactRevision::new(wire.head_sha).map_err(|_| GithubChecksError::InvalidResponse)?;
    if app_id != expected_app || &head_sha != expected_sha {
        return Err(GithubChecksError::InvalidResponse);
    }
    Ok(GithubCheckSuite {
        id,
        app_id,
        head_sha,
    })
}

fn validate_run(wire: RunResponse) -> Result<ValidatedRun, GithubChecksError> {
    let id = GithubCheckRunId::new(wire.id).map_err(|_| GithubChecksError::InvalidResponse)?;
    let app_id =
        GithubCheckAppId::new(wire.app.id).map_err(|_| GithubChecksError::InvalidResponse)?;
    let suite_id = GithubCheckSuiteId::new(wire.check_suite.id)
        .map_err(|_| GithubChecksError::InvalidResponse)?;
    let head_sha =
        ExactRevision::new(wire.head_sha).map_err(|_| GithubChecksError::InvalidResponse)?;
    let name = GithubCheckName::new(wire.name).map_err(|_| GithubChecksError::InvalidResponse)?;
    let external_id = wire
        .external_id
        .into_value()
        .ok_or(GithubChecksError::InvalidResponse)?
        .map(GithubCheckExternalId::new)
        .transpose()
        .map_err(|_| GithubChecksError::InvalidResponse)?;
    let details_url = wire
        .details_url
        .into_value()
        .ok_or(GithubChecksError::InvalidResponse)?
        .map(|value| {
            Url::parse(&value)
                .map_err(|_| GithubChecksError::InvalidResponse)
                .and_then(|url| {
                    GithubCheckDetailsUrl::new(url).map_err(|_| GithubChecksError::InvalidResponse)
                })
        })
        .transpose()?;
    let conclusion = wire
        .conclusion
        .into_value()
        .ok_or(GithubChecksError::InvalidResponse)?;
    let state = parse_run_state(&wire.status, conclusion.as_deref())?;
    Ok(ValidatedRun {
        id,
        app_id,
        suite_id,
        head_sha,
        name,
        external_id,
        details_url,
        state,
    })
}

fn parse_run_state(
    status: &str,
    conclusion: Option<&str>,
) -> Result<GithubCheckRunState, GithubChecksError> {
    match (status, conclusion) {
        ("queued", None) => Ok(GithubCheckRunState::Queued),
        ("in_progress", None) => Ok(GithubCheckRunState::InProgress),
        ("completed", Some(conclusion)) => Ok(GithubCheckRunState::Completed(
            parse_observed_conclusion(conclusion)?,
        )),
        _ => Err(GithubChecksError::InvalidResponse),
    }
}

fn parse_observed_conclusion(
    conclusion: &str,
) -> Result<GithubObservedCheckConclusion, GithubChecksError> {
    match conclusion {
        "action_required" => Ok(GithubObservedCheckConclusion::ActionRequired),
        "cancelled" => Ok(GithubObservedCheckConclusion::Cancelled),
        "failure" => Ok(GithubObservedCheckConclusion::Failure),
        "neutral" => Ok(GithubObservedCheckConclusion::Neutral),
        "success" => Ok(GithubObservedCheckConclusion::Success),
        "skipped" => Ok(GithubObservedCheckConclusion::Skipped),
        "stale" => Ok(GithubObservedCheckConclusion::Stale),
        "timed_out" => Ok(GithubObservedCheckConclusion::TimedOut),
        _ => Err(GithubChecksError::InvalidResponse),
    }
}

fn run_matches_query(run: &ValidatedRun, identity: &GithubCheckRunIdentity) -> bool {
    run.app_id == identity.app_id
        && run.suite_id == identity.suite_id
        && run.head_sha == identity.head_sha
        && run.name == identity.name
}

fn run_matches_identity(run: &ValidatedRun, identity: &GithubCheckRunIdentity) -> bool {
    run_matches_query(run, identity)
        && run.external_id.as_ref() == Some(&identity.external_id)
        && run.details_url.as_ref() == Some(&identity.details_url)
}

fn into_public_run(run: &ValidatedRun, identity: &GithubCheckRunIdentity) -> GithubCheckRun {
    GithubCheckRun {
        id: run.id,
        identity: identity.clone(),
        state: run.state,
    }
}

fn finish_reconciliation(
    ambiguous: bool,
    exact_match: Option<GithubCheckRun>,
) -> GithubCheckRunReconciliation {
    if ambiguous {
        GithubCheckRunReconciliation::Ambiguous
    } else {
        exact_match.map_or(
            GithubCheckRunReconciliation::Missing,
            GithubCheckRunReconciliation::Exact,
        )
    }
}

fn authenticated_checks_request(
    request: reqwest::RequestBuilder,
    token: &SecretString,
) -> Result<reqwest::RequestBuilder, GithubChecksError> {
    let authorization = authorization_header(token).map_err(map_endpoint_error)?;
    Ok(request
        .header(ACCEPT, ACCEPT_API_JSON)
        .header(AUTHORIZATION, authorization))
}

fn classify_create_failure(
    response: &Response,
) -> Result<GithubCheckCreateIndeterminate, GithubChecksError> {
    let status = response.status();
    if status == StatusCode::REQUEST_TIMEOUT || status.is_server_error() || status.is_success() {
        let kind = if status == StatusCode::REQUEST_TIMEOUT || status.is_server_error() {
            GithubCheckCreateIndeterminateKind::ProviderUnavailable
        } else {
            GithubCheckCreateIndeterminateKind::InvalidSuccessResponse
        };
        return Ok(indeterminate(kind, Some(response.headers())));
    }
    Err(map_error_response(response))
}

fn indeterminate(
    kind: GithubCheckCreateIndeterminateKind,
    headers: Option<&HeaderMap>,
) -> GithubCheckCreateIndeterminate {
    GithubCheckCreateIndeterminate {
        kind,
        retry: headers.map_or_else(GithubCheckRetryEvidence::default, retry_evidence),
    }
}

fn map_error_response(response: &Response) -> GithubChecksError {
    let evidence = retry_evidence(response.headers());
    match response.status() {
        StatusCode::UNAUTHORIZED => GithubChecksError::Unauthorized,
        StatusCode::FORBIDDEN if is_rate_limited(response.headers()) => {
            GithubChecksError::RateLimited(evidence)
        }
        StatusCode::FORBIDDEN => GithubChecksError::Forbidden,
        StatusCode::NOT_FOUND => GithubChecksError::NotFound,
        StatusCode::CONFLICT => GithubChecksError::Conflict,
        StatusCode::UNPROCESSABLE_ENTITY => GithubChecksError::Rejected,
        StatusCode::TOO_MANY_REQUESTS => GithubChecksError::RateLimited(evidence),
        StatusCode::REQUEST_TIMEOUT => GithubChecksError::Unavailable(evidence),
        status if status.is_server_error() => GithubChecksError::Unavailable(evidence),
        _ => GithubChecksError::InvalidResponse,
    }
}

fn map_endpoint_error(error: GithubEndpointError) -> GithubChecksError {
    match error {
        GithubEndpointError::Unauthorized => GithubChecksError::Unauthorized,
        GithubEndpointError::Forbidden => GithubChecksError::Forbidden,
        GithubEndpointError::RateLimited {
            retry_after_seconds,
        } => GithubChecksError::RateLimited(GithubCheckRetryEvidence {
            retry_after_seconds: retry_after_seconds
                .filter(|value| *value <= MAX_RETRY_AFTER_SECONDS),
            ..GithubCheckRetryEvidence::default()
        }),
        GithubEndpointError::Unavailable => {
            GithubChecksError::Unavailable(GithubCheckRetryEvidence::default())
        }
        GithubEndpointError::InvalidResponse => GithubChecksError::InvalidResponse,
    }
}

fn is_rate_limited(headers: &HeaderMap) -> bool {
    headers.contains_key(RETRY_AFTER)
        || unique_header(headers, X_RATE_LIMIT_REMAINING)
            .is_some_and(|value| value.as_bytes() == b"0")
}

fn retry_evidence(headers: &HeaderMap) -> GithubCheckRetryEvidence {
    let retry_after_seconds = unique_header(headers, RETRY_AFTER.as_str())
        .and_then(|value| parse_bounded_decimal(value.as_bytes(), MAX_RETRY_AFTER_SECONDS));
    let rate_limit_reset_at = unique_header(headers, X_RATE_LIMIT_RESET)
        .and_then(|value| parse_bounded_decimal(value.as_bytes(), MAX_RATE_LIMIT_RESET_SECONDS));
    let rate_limit_remaining_zero = unique_header(headers, X_RATE_LIMIT_REMAINING)
        .is_some_and(|value| value.as_bytes() == b"0");
    GithubCheckRetryEvidence {
        retry_after_seconds,
        rate_limit_reset_at,
        rate_limit_remaining_zero,
    }
}

fn unique_header<'a>(
    headers: &'a HeaderMap,
    name: &str,
) -> Option<&'a reqwest::header::HeaderValue> {
    let mut values = headers.get_all(name).iter();
    let first = values.next()?;
    values.next().is_none().then_some(first)
}

fn parse_bounded_decimal(bytes: &[u8], maximum: u64) -> Option<u64> {
    if bytes.is_empty() || bytes.len() > 15 || !bytes.iter().all(u8::is_ascii_digit) {
        return None;
    }
    let raw = std::str::from_utf8(bytes).ok()?;
    let value = raw.parse::<u64>().ok()?;
    (value <= maximum && value.to_string() == raw).then_some(value)
}

fn validate_annotation(
    value: AnnotationResponse,
) -> Result<GithubCheckAnnotation, GithubChecksError> {
    let level = match value.annotation_level.as_str() {
        "failure" => GithubCheckAnnotationLevel::Failure,
        "warning" => GithubCheckAnnotationLevel::Warning,
        "notice" => GithubCheckAnnotationLevel::Notice,
        _ => return Err(GithubChecksError::InvalidResponse),
    };
    GithubCheckAnnotation::new(
        value.path,
        value.start_line,
        value.end_line,
        value.start_column,
        value.end_column,
        level,
        value.message,
        value.title,
    )
    .map_err(|_| GithubChecksError::InvalidResponse)
}

fn next_annotation_page(
    headers: &HeaderMap,
    trusted: &crate::GithubTrustedOrigins,
    expected_path: &str,
    current_page: u64,
) -> Result<Option<Url>, GithubChecksError> {
    let mut next = None;
    for parsed in
        pagination::parse_links(headers).map_err(|_| GithubChecksError::InvalidResponse)?
    {
        let page = validate_annotation_page_url(&parsed.url, trusted, expected_path)?;
        if parsed.is_next {
            if next.is_some() || page != current_page.saturating_add(1) {
                return Err(GithubChecksError::InvalidResponse);
            }
            next = Some(parsed.url);
        }
    }
    Ok(next)
}

fn validate_annotation_page_url(
    url: &Url,
    trusted: &crate::GithubTrustedOrigins,
    expected_path: &str,
) -> Result<u64, GithubChecksError> {
    if !trusted.trusts_api_url(url)
        || !same_origin(trusted.api_base(), url)
        || url.path() != expected_path
        || url.query().is_none()
    {
        return Err(GithubChecksError::InvalidResponse);
    }
    let mut per_page = None;
    let mut page = None;
    for (name, value) in url.query_pairs() {
        let slot = match name.as_ref() {
            "per_page" => &mut per_page,
            "page" => &mut page,
            _ => return Err(GithubChecksError::InvalidResponse),
        };
        if slot.replace(value.into_owned()).is_some() {
            return Err(GithubChecksError::InvalidResponse);
        }
    }
    if per_page.as_deref() != Some("100") {
        return Err(GithubChecksError::InvalidResponse);
    }
    let page = page
        .ok_or(GithubChecksError::InvalidResponse)?
        .parse::<u64>()
        .map_err(|_| GithubChecksError::InvalidResponse)?;
    if page == 0 || page.to_string() != page_value(url)? {
        return Err(GithubChecksError::InvalidResponse);
    }
    Ok(page)
}

fn next_check_run_page(
    headers: &HeaderMap,
    trusted: &crate::GithubTrustedOrigins,
    expected_path: &str,
    identity: &GithubCheckRunIdentity,
    current_page: u64,
) -> Result<Option<Url>, GithubChecksError> {
    let mut next = None;
    for parsed in
        pagination::parse_links(headers).map_err(|_| GithubChecksError::InvalidResponse)?
    {
        let page = validate_check_page_url(&parsed.url, trusted, expected_path, identity)?;
        if parsed.is_next {
            if next.is_some() || page != current_page.saturating_add(1) {
                return Err(GithubChecksError::InvalidResponse);
            }
            next = Some(parsed.url);
        }
    }
    Ok(next)
}

fn validate_check_page_url(
    url: &Url,
    trusted: &crate::GithubTrustedOrigins,
    expected_path: &str,
    identity: &GithubCheckRunIdentity,
) -> Result<u64, GithubChecksError> {
    if !trusted.trusts_api_url(url)
        || !same_origin(trusted.api_base(), url)
        || url.path() != expected_path
        || url.query().is_none()
    {
        return Err(GithubChecksError::InvalidResponse);
    }
    let mut check_name = None;
    let mut filter = None;
    let mut per_page = None;
    let mut page = None;
    for (name, value) in url.query_pairs() {
        let slot = match name.as_ref() {
            "check_name" => &mut check_name,
            "filter" => &mut filter,
            "per_page" => &mut per_page,
            "page" => &mut page,
            _ => return Err(GithubChecksError::InvalidResponse),
        };
        if slot.replace(value.into_owned()).is_some() {
            return Err(GithubChecksError::InvalidResponse);
        }
    }
    if check_name.as_deref() != Some(identity.name.as_str())
        || filter.as_deref() != Some("all")
        || per_page.as_deref() != Some("100")
    {
        return Err(GithubChecksError::InvalidResponse);
    }
    let page = page
        .ok_or(GithubChecksError::InvalidResponse)?
        .parse::<u64>()
        .map_err(|_| GithubChecksError::InvalidResponse)?;
    if page == 0 || page.to_string() != page_value(url)? {
        return Err(GithubChecksError::InvalidResponse);
    }
    Ok(page)
}

fn page_value(url: &Url) -> Result<String, GithubChecksError> {
    let values: Vec<_> = url
        .query_pairs()
        .filter_map(|(name, value)| (name == "page").then_some(value.into_owned()))
        .collect();
    match values.as_slice() {
        [value] => Ok(value.clone()),
        _ => Err(GithubChecksError::InvalidResponse),
    }
}
