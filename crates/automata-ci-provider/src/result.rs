//! Provider-neutral desired results, fenced publication outbox, and publisher port.

use std::{
    fmt,
    future::Future,
    num::{NonZeroU16, NonZeroU32, NonZeroU64},
    pin::Pin,
};

use automata_ci_core::{GitObjectAlgorithm, GitObjectId, JobId, RunId, Sha256Digest, UnixMillis};
use sha2::{Digest as _, Sha256};
use thiserror::Error;
use url::Url;

use crate::{
    ExternalRepositoryIdentity, ExternalResultId, ProviderCapabilities, ProviderCapability,
    ProviderCapabilityKind, ProviderConnectionId, ProviderConnectionManifest,
    ProviderConnectionRevision, ProviderDeliveryId, ProviderLifecycleState, ProviderRepositoryPath,
    ProviderResultSubjectId, ProviderResultWorkerId, StatusHistoryModel,
};

/// Maximum desired-result title bytes.
pub const MAX_PROVIDER_RESULT_TITLE_BYTES: usize = 255;
/// Maximum desired-result summary bytes.
pub const MAX_PROVIDER_RESULT_SUMMARY_BYTES: usize = 64 * 1_024;
/// Maximum annotation records retained for one desired generation.
pub const MAX_PROVIDER_RESULT_ANNOTATIONS: usize = 4_096;
/// Maximum annotation message bytes.
pub const MAX_PROVIDER_RESULT_ANNOTATION_MESSAGE_BYTES: usize = 64 * 1_024;
/// Maximum annotation title bytes.
pub const MAX_PROVIDER_RESULT_ANNOTATION_TITLE_BYTES: usize = 255;
/// Maximum provider-facing details URL bytes.
pub const MAX_PROVIDER_RESULT_DETAILS_URL_BYTES: usize = 8 * 1_024;
/// Maximum claims permitted for one desired generation.
pub const MAX_PROVIDER_RESULT_PUBLICATION_ATTEMPTS: u16 = 64;
/// Maximum exclusive publication lease duration.
pub const MAX_PROVIDER_RESULT_LEASE_MILLIS: u64 = 15 * 60 * 1_000;
/// Maximum requested publication retry delay.
pub const MAX_PROVIDER_RESULT_RETRY_MILLIS: u64 = 24 * 60 * 60 * 1_000;

const RESULT_SUBJECT_DOMAIN: &[u8] = b"automata.provider.result-subject.v1\0";
const RESULT_PROJECTION_DOMAIN: &[u8] = b"automata.provider.result-projection.v1\0";
const RESULT_EVIDENCE_DOMAIN: &[u8] = b"automata.provider.result-evidence.v1\0";

/// Exact Automata subject represented by one provider result.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ProviderResultSubjectKind {
    /// A workflow selected from an authenticated delivery before admission.
    PendingWorkflow {
        /// Authenticated delivery that selected the workflow.
        delivery_id: ProviderDeliveryId,
        /// Canonical repository-relative workflow path.
        workflow_path: ProviderRepositoryPath,
    },
    /// One admitted workflow run.
    WorkflowRun {
        /// Exact Automata workflow run.
        run_id: RunId,
    },
    /// One concrete job within an admitted workflow run.
    Job {
        /// Exact Automata workflow run.
        run_id: RunId,
        /// Exact job within the run.
        job_id: JobId,
    },
}

impl ProviderResultSubjectKind {
    fn hash_into(&self, hash: &mut Sha256) {
        match self {
            Self::PendingWorkflow {
                delivery_id,
                workflow_path,
            } => {
                hash.update([1]);
                hash.update(delivery_id.as_uuid().as_bytes());
                part(hash, workflow_path.as_str().as_bytes());
            }
            Self::WorkflowRun { run_id } => {
                hash.update([2]);
                hash.update(run_id.as_uuid().as_bytes());
            }
            Self::Job { run_id, job_id } => {
                hash.update([3]);
                hash.update(run_id.as_uuid().as_bytes());
                hash.update(job_id.as_uuid().as_bytes());
            }
        }
    }
}

/// Immutable connection, repository, commit, attempt, and Automata result identity.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProviderResultSubject {
    subject_id: ProviderResultSubjectId,
    connection_id: ProviderConnectionId,
    connection_revision: ProviderConnectionRevision,
    connection_digest: Sha256Digest,
    repository: ExternalRepositoryIdentity,
    object: GitObjectId,
    subject: ProviderResultSubjectKind,
    attempt: NonZeroU32,
    created_at: UnixMillis,
    digest: Sha256Digest,
}

impl ProviderResultSubject {
    /// Creates one immutable result identity under an active connection revision.
    ///
    /// # Errors
    ///
    /// Rejects inactive connections, zero attempts, or pre-epoch timestamps.
    pub fn new(
        subject_id: ProviderResultSubjectId,
        connection: &ProviderConnectionManifest,
        object: GitObjectId,
        subject: ProviderResultSubjectKind,
        attempt: u32,
        created_at: UnixMillis,
    ) -> Result<Self, ProviderResultModelError> {
        if connection.state() != ProviderLifecycleState::Active {
            return Err(ProviderResultModelError::InactiveConnection);
        }
        if created_at.get() < 0 {
            return Err(ProviderResultModelError::InvalidTimestamp);
        }
        let attempt = NonZeroU32::new(attempt).ok_or(ProviderResultModelError::InvalidAttempt)?;
        let mut value = Self {
            subject_id,
            connection_id: connection.connection_id(),
            connection_revision: connection.revision(),
            connection_digest: connection.digest(),
            repository: connection.configuration().repository().clone(),
            object,
            subject,
            attempt,
            created_at,
            digest: Sha256Digest::from_bytes([0; 32]),
        };
        value.digest = value.calculate_digest();
        Ok(value)
    }

    fn calculate_digest(&self) -> Sha256Digest {
        let mut hash = Sha256::new();
        hash.update(RESULT_SUBJECT_DOMAIN);
        hash.update(self.subject_id.as_uuid().as_bytes());
        hash.update(self.connection_id.as_uuid().as_bytes());
        hash.update(self.connection_revision.get().to_be_bytes());
        hash.update(self.connection_digest.as_bytes());
        hash.update(self.repository.instance_id().as_uuid().as_bytes());
        part(&mut hash, self.repository.external_id().as_str().as_bytes());
        hash.update([match self.object.algorithm() {
            GitObjectAlgorithm::Sha1 => 1,
            GitObjectAlgorithm::Sha256 => 2,
        }]);
        hash.update(self.object.as_bytes());
        self.subject.hash_into(&mut hash);
        hash.update(self.attempt.get().to_be_bytes());
        hash.update(self.created_at.get().to_be_bytes());
        Sha256Digest::from_bytes(hash.finalize().into())
    }

    /// Returns the durable subject identity.
    #[must_use]
    pub const fn subject_id(&self) -> ProviderResultSubjectId {
        self.subject_id
    }
    /// Returns the exact provider connection.
    #[must_use]
    pub const fn connection_id(&self) -> ProviderConnectionId {
        self.connection_id
    }
    /// Returns the exact connection revision.
    #[must_use]
    pub const fn connection_revision(&self) -> ProviderConnectionRevision {
        self.connection_revision
    }
    /// Returns the connection-manifest digest.
    #[must_use]
    pub const fn connection_digest(&self) -> Sha256Digest {
        self.connection_digest
    }
    /// Returns the instance-scoped repository.
    #[must_use]
    pub const fn repository(&self) -> &ExternalRepositoryIdentity {
        &self.repository
    }
    /// Returns the exact immutable commit.
    #[must_use]
    pub const fn object(&self) -> GitObjectId {
        self.object
    }
    /// Returns the exact Automata subject.
    #[must_use]
    pub const fn subject(&self) -> &ProviderResultSubjectKind {
        &self.subject
    }
    /// Returns the positive physical attempt.
    #[must_use]
    pub const fn attempt(&self) -> u32 {
        self.attempt.get()
    }
    /// Returns the creation time.
    #[must_use]
    pub const fn created_at(&self) -> UnixMillis {
        self.created_at
    }
    /// Returns the canonical subject digest.
    #[must_use]
    pub const fn digest(&self) -> Sha256Digest {
        self.digest
    }
}

macro_rules! bounded_text {
    ($name:ident, $limit:ident, $error:ident, $doc:literal) => {
        #[doc = $doc]
        #[derive(Clone, Eq, PartialEq)]
        pub struct $name(String);

        impl $name {
            /// Creates bounded, trimmed, printable text.
            ///
            /// # Errors
            ///
            /// Rejects empty, untrimmed, control-bearing, or oversized values.
            pub fn new(value: impl Into<String>) -> Result<Self, ProviderResultModelError> {
                let value = value.into();
                if value.is_empty()
                    || value.len() > $limit
                    || value.trim() != value
                    || value.chars().any(char::is_control)
                {
                    return Err(ProviderResultModelError::$error);
                }
                Ok(Self(value))
            }
            /// Returns the validated text.
            #[must_use]
            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str(concat!(stringify!($name), "([REDACTED])"))
            }
        }
    };
}

bounded_text!(
    ProviderResultTitle,
    MAX_PROVIDER_RESULT_TITLE_BYTES,
    InvalidTitle,
    "Bounded printable title retained independently of provider capabilities."
);
bounded_text!(
    ProviderResultAnnotationTitle,
    MAX_PROVIDER_RESULT_ANNOTATION_TITLE_BYTES,
    InvalidAnnotationTitle,
    "Bounded printable annotation title."
);

/// Bounded desired-result summary. Newlines and horizontal tabs are retained.
#[derive(Clone, Eq, PartialEq)]
pub struct ProviderResultSummary(String);

impl ProviderResultSummary {
    /// Creates a bounded summary without unsafe control characters.
    ///
    /// # Errors
    ///
    /// Rejects oversized, untrimmed, or unsafe control-bearing values.
    pub fn new(value: impl Into<String>) -> Result<Self, ProviderResultModelError> {
        let value = value.into();
        if value.len() > MAX_PROVIDER_RESULT_SUMMARY_BYTES
            || value.trim() != value
            || value
                .chars()
                .any(|character| character.is_control() && !matches!(character, '\n' | '\t'))
        {
            return Err(ProviderResultModelError::InvalidSummary);
        }
        Ok(Self(value))
    }
    /// Returns the validated summary.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for ProviderResultSummary {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ProviderResultSummary([REDACTED])")
    }
}

/// Absolute credential-free HTTPS details URL.
#[derive(Clone, Eq, PartialEq)]
pub struct ProviderResultDetailsUrl(Url);

impl ProviderResultDetailsUrl {
    /// Validates a provider-facing details URL.
    ///
    /// # Errors
    ///
    /// Rejects non-HTTPS, relative, query-bearing, credential-bearing, or
    /// fragment-bearing URLs.
    pub fn new(value: Url) -> Result<Self, ProviderResultModelError> {
        if value.as_str().len() > MAX_PROVIDER_RESULT_DETAILS_URL_BYTES
            || value.scheme() != "https"
            || value.host().is_none()
            || !value.username().is_empty()
            || value.password().is_some()
            || value.query().is_some()
            || value.fragment().is_some()
        {
            return Err(ProviderResultModelError::InvalidDetailsUrl);
        }
        Ok(Self(value))
    }
    /// Returns the validated URL.
    #[must_use]
    pub const fn as_url(&self) -> &Url {
        &self.0
    }
}

impl fmt::Debug for ProviderResultDetailsUrl {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ProviderResultDetailsUrl([REDACTED])")
    }
}

/// Bounded multiline annotation message.
#[derive(Clone, Eq, PartialEq)]
pub struct ProviderResultAnnotationMessage(String);

impl ProviderResultAnnotationMessage {
    /// Creates a bounded message while retaining newlines and horizontal tabs.
    ///
    /// # Errors
    ///
    /// Rejects empty, untrimmed, oversized, or unsafe control-bearing values.
    pub fn new(value: impl Into<String>) -> Result<Self, ProviderResultModelError> {
        let value = value.into();
        if value.is_empty()
            || value.len() > MAX_PROVIDER_RESULT_ANNOTATION_MESSAGE_BYTES
            || value.trim() != value
            || value
                .chars()
                .any(|character| character.is_control() && !matches!(character, '\n' | '\t'))
        {
            return Err(ProviderResultModelError::InvalidAnnotationMessage);
        }
        Ok(Self(value))
    }
    /// Returns the validated message.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for ProviderResultAnnotationMessage {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ProviderResultAnnotationMessage([REDACTED])")
    }
}

/// Provider-independent annotation severity.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProviderResultAnnotationLevel {
    /// Informational observation.
    Notice,
    /// Warning that does not itself prove failure.
    Warning,
    /// Error associated with a failed result.
    Failure,
}

/// One repository path and line-range annotation retained by Automata.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProviderResultAnnotation {
    path: ProviderRepositoryPath,
    start_line: NonZeroU32,
    end_line: NonZeroU32,
    level: ProviderResultAnnotationLevel,
    title: ProviderResultAnnotationTitle,
    message: ProviderResultAnnotationMessage,
}

impl ProviderResultAnnotation {
    /// Creates one ordered, nonempty source line range.
    ///
    /// # Errors
    ///
    /// Rejects zero or reversed line ranges.
    pub fn new(
        path: ProviderRepositoryPath,
        start_line: u32,
        end_line: u32,
        level: ProviderResultAnnotationLevel,
        title: ProviderResultAnnotationTitle,
        message: ProviderResultAnnotationMessage,
    ) -> Result<Self, ProviderResultModelError> {
        let start_line =
            NonZeroU32::new(start_line).ok_or(ProviderResultModelError::InvalidAnnotationRange)?;
        let end_line = NonZeroU32::new(end_line)
            .filter(|end| *end >= start_line)
            .ok_or(ProviderResultModelError::InvalidAnnotationRange)?;
        Ok(Self {
            path,
            start_line,
            end_line,
            level,
            title,
            message,
        })
    }
    /// Returns the repository-relative path.
    #[must_use]
    pub const fn path(&self) -> &ProviderRepositoryPath {
        &self.path
    }
    /// Returns the inclusive first line.
    #[must_use]
    pub const fn start_line(&self) -> u32 {
        self.start_line.get()
    }
    /// Returns the inclusive final line.
    #[must_use]
    pub const fn end_line(&self) -> u32 {
        self.end_line.get()
    }
    /// Returns the severity.
    #[must_use]
    pub const fn level(&self) -> ProviderResultAnnotationLevel {
        self.level
    }
    /// Returns the annotation title.
    #[must_use]
    pub const fn title(&self) -> &ProviderResultAnnotationTitle {
        &self.title
    }
    /// Returns the annotation message.
    #[must_use]
    pub const fn message(&self) -> &ProviderResultAnnotationMessage {
        &self.message
    }
}

/// Provider-independent desired lifecycle phase.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProviderResultPhase {
    /// Waiting for admission or execution capacity.
    Queued,
    /// Work is executing.
    Running,
    /// Work reached a terminal conclusion.
    Completed,
}

/// Provider-independent terminal conclusion.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProviderResultConclusion {
    /// Work completed successfully.
    Success,
    /// Workflow work failed.
    Failure,
    /// Infrastructure or provider failure prevented completion.
    Error,
    /// Work was cancelled.
    Cancelled,
    /// Work was deliberately skipped.
    Skipped,
    /// Work exceeded its time budget.
    TimedOut,
    /// Work completed without success or failure.
    Neutral,
    /// Human or operator action is required.
    ActionRequired,
}

/// One immutable desired provider projection generation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DesiredProviderResult {
    generation: NonZeroU64,
    phase: ProviderResultPhase,
    conclusion: Option<ProviderResultConclusion>,
    title: ProviderResultTitle,
    summary: ProviderResultSummary,
    details_url: ProviderResultDetailsUrl,
    annotations: Vec<ProviderResultAnnotation>,
    updated_at: UnixMillis,
    digest: Sha256Digest,
}

impl DesiredProviderResult {
    /// Creates a complete desired generation with strict phase/conclusion binding.
    ///
    /// # Errors
    ///
    /// Rejects zero generations, invalid timestamps, excessive annotations, or
    /// a conclusion outside the completed phase.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        generation: u64,
        phase: ProviderResultPhase,
        conclusion: Option<ProviderResultConclusion>,
        title: ProviderResultTitle,
        summary: ProviderResultSummary,
        details_url: ProviderResultDetailsUrl,
        mut annotations: Vec<ProviderResultAnnotation>,
        updated_at: UnixMillis,
    ) -> Result<Self, ProviderResultModelError> {
        let generation = result_generation(generation)?;
        if updated_at.get() < 0 {
            return Err(ProviderResultModelError::InvalidTimestamp);
        }
        if (phase == ProviderResultPhase::Completed) != conclusion.is_some() {
            return Err(ProviderResultModelError::InvalidPhaseConclusion);
        }
        if annotations.len() > MAX_PROVIDER_RESULT_ANNOTATIONS {
            return Err(ProviderResultModelError::TooManyAnnotations);
        }
        annotations.sort_by(|left, right| {
            (
                left.path.as_str(),
                left.start_line,
                left.end_line,
                annotation_level_code(left.level),
                left.title.as_str(),
                left.message.as_str(),
            )
                .cmp(&(
                    right.path.as_str(),
                    right.start_line,
                    right.end_line,
                    annotation_level_code(right.level),
                    right.title.as_str(),
                    right.message.as_str(),
                ))
        });
        if annotations.windows(2).any(|pair| pair[0] == pair[1]) {
            return Err(ProviderResultModelError::DuplicateAnnotation);
        }
        let mut value = Self {
            generation,
            phase,
            conclusion,
            title,
            summary,
            details_url,
            annotations,
            updated_at,
            digest: Sha256Digest::from_bytes([0; 32]),
        };
        value.digest = value.calculate_digest();
        Ok(value)
    }

    fn calculate_digest(&self) -> Sha256Digest {
        let mut hash = Sha256::new();
        hash.update(RESULT_PROJECTION_DOMAIN);
        hash.update(self.generation.get().to_be_bytes());
        hash.update([
            phase_code(self.phase),
            self.conclusion.map_or(0, conclusion_code),
        ]);
        part(&mut hash, self.title.as_str().as_bytes());
        part(&mut hash, self.summary.as_str().as_bytes());
        part(&mut hash, self.details_url.as_url().as_str().as_bytes());
        hash.update(
            u64::try_from(self.annotations.len())
                .expect("annotation bound fits u64")
                .to_be_bytes(),
        );
        for annotation in &self.annotations {
            part(&mut hash, annotation.path.as_str().as_bytes());
            hash.update(annotation.start_line.get().to_be_bytes());
            hash.update(annotation.end_line.get().to_be_bytes());
            hash.update([annotation_level_code(annotation.level)]);
            part(&mut hash, annotation.title.as_str().as_bytes());
            part(&mut hash, annotation.message.as_str().as_bytes());
        }
        hash.update(self.updated_at.get().to_be_bytes());
        Sha256Digest::from_bytes(hash.finalize().into())
    }
    /// Returns the positive projection generation.
    #[must_use]
    pub const fn generation(&self) -> u64 {
        self.generation.get()
    }
    /// Returns the lifecycle phase.
    #[must_use]
    pub const fn phase(&self) -> ProviderResultPhase {
        self.phase
    }
    /// Returns the terminal conclusion, if completed.
    #[must_use]
    pub const fn conclusion(&self) -> Option<ProviderResultConclusion> {
        self.conclusion
    }
    /// Returns the title.
    #[must_use]
    pub const fn title(&self) -> &ProviderResultTitle {
        &self.title
    }
    /// Returns the summary.
    #[must_use]
    pub const fn summary(&self) -> &ProviderResultSummary {
        &self.summary
    }
    /// Returns the details URL.
    #[must_use]
    pub const fn details_url(&self) -> &ProviderResultDetailsUrl {
        &self.details_url
    }
    /// Returns canonical annotations retained regardless of adapter support.
    #[must_use]
    pub fn annotations(&self) -> &[ProviderResultAnnotation] {
        &self.annotations
    }
    /// Returns the desired update time.
    #[must_use]
    pub const fn updated_at(&self) -> UnixMillis {
        self.updated_at
    }
    /// Returns the canonical desired-generation digest.
    #[must_use]
    pub const fn digest(&self) -> Sha256Digest {
        self.digest
    }
}

/// Provider publication behavior selected by an adapter.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProviderResultPublicationModel {
    /// One rich provider object is reconciled in place.
    MutableRichCheck,
    /// Each desired generation is appended to provider status history.
    AppendOnlyCommitStatus,
}

impl ProviderResultPublicationModel {
    /// Returns whether validated adapter capabilities declare this exact model.
    #[must_use]
    pub fn is_declared_by(self, capabilities: &ProviderCapabilities) -> bool {
        match self {
            Self::MutableRichCheck => capabilities.contains(ProviderCapabilityKind::RichChecks),
            Self::AppendOnlyCommitStatus => matches!(
                capabilities.get(ProviderCapabilityKind::CommitStatus),
                Some(ProviderCapability::CommitStatus(capability))
                    if capability.history_model() == StatusHistoryModel::AppendOnly
            ),
        }
    }
}

/// Deterministic idempotency marker for one exact desired generation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProviderResultMarker(String);

impl ProviderResultMarker {
    fn derive(subject_id: ProviderResultSubjectId, generation: u64) -> Self {
        Self(format!(
            "automata-result:{}:{generation}",
            subject_id.as_uuid()
        ))
    }
    /// Returns the marker adapters must persist and reconcile after response loss.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Exact exclusive publication fence.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProviderResultClaimFence {
    subject_id: ProviderResultSubjectId,
    generation: NonZeroU64,
    worker_id: ProviderResultWorkerId,
    fence: NonZeroU64,
    claimed_at: UnixMillis,
    expires_at: UnixMillis,
}

impl ProviderResultClaimFence {
    /// Rehydrates one exact durable fence.
    ///
    /// # Errors
    ///
    /// Rejects zero numeric values or an invalid bounded lease interval.
    pub fn new(
        subject_id: ProviderResultSubjectId,
        generation: u64,
        worker_id: ProviderResultWorkerId,
        fence: u64,
        claimed_at: UnixMillis,
        expires_at: UnixMillis,
    ) -> Result<Self, ProviderResultModelError> {
        let generation = result_generation(generation)?;
        let fence = NonZeroU64::new(fence).ok_or(ProviderResultModelError::InvalidFence)?;
        let duration = expires_at
            .get()
            .checked_sub(claimed_at.get())
            .and_then(|value| u64::try_from(value).ok());
        if claimed_at.get() < 0
            || duration.is_none_or(|value| value == 0 || value > MAX_PROVIDER_RESULT_LEASE_MILLIS)
        {
            return Err(ProviderResultModelError::InvalidLease);
        }
        Ok(Self {
            subject_id,
            generation,
            worker_id,
            fence,
            claimed_at,
            expires_at,
        })
    }
    /// Returns the result subject identity.
    #[must_use]
    pub const fn subject_id(self) -> ProviderResultSubjectId {
        self.subject_id
    }
    /// Returns the claim-frozen desired generation.
    #[must_use]
    pub const fn generation(self) -> u64 {
        self.generation.get()
    }
    /// Returns the exclusive worker identity.
    #[must_use]
    pub const fn worker_id(self) -> ProviderResultWorkerId {
        self.worker_id
    }
    /// Returns the monotonic fencing token.
    #[must_use]
    pub const fn fence(self) -> u64 {
        self.fence.get()
    }
    /// Returns the exclusive lease start.
    #[must_use]
    pub const fn claimed_at(self) -> UnixMillis {
        self.claimed_at
    }
    /// Returns the exclusive lease deadline.
    #[must_use]
    pub const fn expires_at(self) -> UnixMillis {
        self.expires_at
    }
}

/// One exact desired generation under an exclusive outbox claim.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ClaimedProviderResult {
    subject: ProviderResultSubject,
    desired: DesiredProviderResult,
    marker: ProviderResultMarker,
    claim: ProviderResultClaimFence,
    attempts: NonZeroU16,
}

impl ClaimedProviderResult {
    /// Rehydrates coherent claim-frozen publication work.
    ///
    /// # Errors
    ///
    /// Rejects invalid attempts, stale timestamps, or inconsistent claim fields.
    pub fn new(
        subject: ProviderResultSubject,
        desired: DesiredProviderResult,
        claim: ProviderResultClaimFence,
        attempts: u16,
    ) -> Result<Self, ProviderResultModelError> {
        let attempts = NonZeroU16::new(attempts)
            .filter(|value| value.get() <= MAX_PROVIDER_RESULT_PUBLICATION_ATTEMPTS)
            .ok_or(ProviderResultModelError::InvalidPublicationAttempt)?;
        if claim.subject_id != subject.subject_id
            || claim.generation.get() != desired.generation.get()
            || desired.updated_at < subject.created_at
        {
            return Err(ProviderResultModelError::InvalidClaimBinding);
        }
        let marker = ProviderResultMarker::derive(subject.subject_id, desired.generation());
        Ok(Self {
            subject,
            desired,
            marker,
            claim,
            attempts,
        })
    }
    /// Returns the immutable result subject.
    #[must_use]
    pub const fn subject(&self) -> &ProviderResultSubject {
        &self.subject
    }
    /// Returns the claim-frozen desired generation.
    #[must_use]
    pub const fn desired(&self) -> &DesiredProviderResult {
        &self.desired
    }
    /// Returns the deterministic provider reconciliation marker.
    #[must_use]
    pub const fn marker(&self) -> &ProviderResultMarker {
        &self.marker
    }
    /// Returns the exclusive durable claim.
    #[must_use]
    pub const fn claim(&self) -> ProviderResultClaimFence {
        self.claim
    }
    /// Returns the claim ordinal for this generation.
    #[must_use]
    pub const fn attempts(&self) -> u16 {
        self.attempts.get()
    }
    /// Returns the lease start time.
    #[must_use]
    pub const fn claimed_at(&self) -> UnixMillis {
        self.claim.claimed_at
    }
}

/// Exact provider observation proving one desired generation was reconciled.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProviderResultPublicationEvidence {
    claim: ProviderResultClaimFence,
    model: ProviderResultPublicationModel,
    external_id: Option<ExternalResultId>,
    provider_state_digest: Sha256Digest,
    observed_at: UnixMillis,
    digest: Sha256Digest,
}

impl ProviderResultPublicationEvidence {
    /// Binds sanitized provider evidence to the claim-frozen generation.
    ///
    /// # Errors
    ///
    /// Rejects observations outside the exclusive claim interval.
    pub fn new(
        claimed: &ClaimedProviderResult,
        model: ProviderResultPublicationModel,
        external_id: Option<ExternalResultId>,
        provider_state_digest: Sha256Digest,
        observed_at: UnixMillis,
    ) -> Result<Self, ProviderResultModelError> {
        if observed_at < claimed.claim.claimed_at || observed_at > claimed.claim.expires_at {
            return Err(ProviderResultModelError::InvalidTimestamp);
        }
        let claim = claimed.claim;
        let mut hash = Sha256::new();
        hash.update(RESULT_EVIDENCE_DOMAIN);
        hash.update(claim.subject_id.as_uuid().as_bytes());
        hash.update(claim.generation.get().to_be_bytes());
        hash.update(claim.worker_id.as_uuid().as_bytes());
        hash.update(claim.fence.get().to_be_bytes());
        hash.update(claim.claimed_at.get().to_be_bytes());
        hash.update(claim.expires_at.get().to_be_bytes());
        hash.update([publication_model_code(model)]);
        match &external_id {
            Some(id) => {
                hash.update([1]);
                part(&mut hash, id.as_str().as_bytes());
            }
            None => hash.update([0]),
        }
        hash.update(provider_state_digest.as_bytes());
        hash.update(observed_at.get().to_be_bytes());
        let digest = Sha256Digest::from_bytes(hash.finalize().into());
        Ok(Self {
            claim,
            model,
            external_id,
            provider_state_digest,
            observed_at,
            digest,
        })
    }
    /// Returns the exact result subject.
    #[must_use]
    pub const fn subject_id(&self) -> ProviderResultSubjectId {
        self.claim.subject_id
    }
    /// Returns the exact desired generation.
    #[must_use]
    pub const fn generation(&self) -> u64 {
        self.claim.generation.get()
    }
    /// Returns the exact publication claim that produced the observation.
    #[must_use]
    pub const fn claim(&self) -> ProviderResultClaimFence {
        self.claim
    }
    /// Returns the adapter publication model.
    #[must_use]
    pub const fn model(&self) -> ProviderResultPublicationModel {
        self.model
    }
    /// Returns provider-native result identity, when supplied.
    #[must_use]
    pub const fn external_id(&self) -> Option<&ExternalResultId> {
        self.external_id.as_ref()
    }
    /// Returns the adapter-calculated provider-state digest.
    #[must_use]
    pub const fn provider_state_digest(&self) -> Sha256Digest {
        self.provider_state_digest
    }
    /// Returns the trusted observation time.
    #[must_use]
    pub const fn observed_at(&self) -> UnixMillis {
        self.observed_at
    }
    /// Returns the canonical evidence digest.
    #[must_use]
    pub const fn digest(&self) -> Sha256Digest {
        self.digest
    }
}

/// Saves one first or contiguous desired generation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SaveDesiredProviderResult {
    subject: ProviderResultSubject,
    desired: DesiredProviderResult,
}

impl SaveDesiredProviderResult {
    /// Binds an immutable subject to one desired generation.
    ///
    /// # Errors
    ///
    /// Rejects desired state predating the subject.
    pub fn new(
        subject: ProviderResultSubject,
        desired: DesiredProviderResult,
    ) -> Result<Self, ProviderResultModelError> {
        if desired.updated_at < subject.created_at {
            return Err(ProviderResultModelError::InvalidTimestamp);
        }
        Ok(Self { subject, desired })
    }
    /// Returns the immutable subject.
    #[must_use]
    pub const fn subject(&self) -> &ProviderResultSubject {
        &self.subject
    }
    /// Returns the desired generation.
    #[must_use]
    pub const fn desired(&self) -> &DesiredProviderResult {
        &self.desired
    }
    /// Consumes the command into its durable parts.
    #[must_use]
    pub fn into_parts(self) -> (ProviderResultSubject, DesiredProviderResult) {
        (self.subject, self.desired)
    }
}

/// Requests one connection-specific result publication lease.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ClaimProviderResult {
    connection_id: ProviderConnectionId,
    worker_id: ProviderResultWorkerId,
    claimed_at: UnixMillis,
    lease_millis: u64,
}

impl ClaimProviderResult {
    /// Creates a bounded connection-specific claim request.
    ///
    /// # Errors
    ///
    /// Rejects invalid timestamps and zero or excessive lease durations.
    pub fn new(
        connection_id: ProviderConnectionId,
        worker_id: ProviderResultWorkerId,
        claimed_at: UnixMillis,
        lease_millis: u64,
    ) -> Result<Self, ProviderResultModelError> {
        if claimed_at.get() < 0
            || lease_millis == 0
            || lease_millis > MAX_PROVIDER_RESULT_LEASE_MILLIS
            || claimed_at
                .get()
                .checked_add(i64::try_from(lease_millis).unwrap_or(i64::MAX))
                .is_none()
        {
            return Err(ProviderResultModelError::InvalidLease);
        }
        Ok(Self {
            connection_id,
            worker_id,
            claimed_at,
            lease_millis,
        })
    }
    /// Returns the selected provider connection.
    #[must_use]
    pub const fn connection_id(self) -> ProviderConnectionId {
        self.connection_id
    }
    /// Returns the publication worker.
    #[must_use]
    pub const fn worker_id(self) -> ProviderResultWorkerId {
        self.worker_id
    }
    /// Returns the requested lease start.
    #[must_use]
    pub const fn claimed_at(self) -> UnixMillis {
        self.claimed_at
    }
    /// Returns the requested lease duration.
    #[must_use]
    pub const fn lease_millis(self) -> u64 {
        self.lease_millis
    }
}

/// Completes one exact claim with provider evidence.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CompleteProviderResult {
    claim: ProviderResultClaimFence,
    evidence: ProviderResultPublicationEvidence,
}
impl CompleteProviderResult {
    /// Binds exact provider evidence to an exclusive claim.
    ///
    /// # Errors
    ///
    /// Rejects evidence for another subject, generation, or lease interval.
    pub fn new(
        claim: ProviderResultClaimFence,
        evidence: ProviderResultPublicationEvidence,
    ) -> Result<Self, ProviderResultModelError> {
        if claim != evidence.claim {
            return Err(ProviderResultModelError::InvalidClaimBinding);
        }
        Ok(Self { claim, evidence })
    }
    /// Returns the consumed claim.
    #[must_use]
    pub const fn claim(&self) -> ProviderResultClaimFence {
        self.claim
    }
    /// Returns the provider observation.
    #[must_use]
    pub const fn evidence(&self) -> &ProviderResultPublicationEvidence {
        &self.evidence
    }
}

/// Releases one exact claim for a bounded retry.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RetryProviderResult {
    claim: ProviderResultClaimFence,
    failed_at: UnixMillis,
    retry_at: UnixMillis,
}
impl RetryProviderResult {
    /// Creates a bounded positive retry schedule under one claim.
    ///
    /// # Errors
    ///
    /// Rejects invalid failure times or retry delays.
    pub fn new(
        claim: ProviderResultClaimFence,
        failed_at: UnixMillis,
        retry_at: UnixMillis,
    ) -> Result<Self, ProviderResultModelError> {
        let delay = retry_at
            .get()
            .checked_sub(failed_at.get())
            .filter(|value| *value > 0)
            .and_then(|value| u64::try_from(value).ok())
            .filter(|value| *value <= MAX_PROVIDER_RESULT_RETRY_MILLIS);
        if failed_at < claim.claimed_at || failed_at > claim.expires_at || delay.is_none() {
            return Err(ProviderResultModelError::InvalidRetry);
        }
        Ok(Self {
            claim,
            failed_at,
            retry_at,
        })
    }
    /// Returns the consumed claim.
    #[must_use]
    pub const fn claim(self) -> ProviderResultClaimFence {
        self.claim
    }
    /// Returns the failure observation time.
    #[must_use]
    pub const fn failed_at(self) -> UnixMillis {
        self.failed_at
    }
    /// Returns the next eligible claim time.
    #[must_use]
    pub const fn retry_at(self) -> UnixMillis {
        self.retry_at
    }
}

/// Terminalizes one exact claim after a non-retryable failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FailProviderResult {
    claim: ProviderResultClaimFence,
    failed_at: UnixMillis,
    kind: ProviderResultFailureKind,
}
impl FailProviderResult {
    /// Creates one terminal publication failure under an exact claim.
    ///
    /// # Errors
    ///
    /// Rejects a failure outside the lease interval.
    pub fn new(
        claim: ProviderResultClaimFence,
        failed_at: UnixMillis,
        kind: ProviderResultFailureKind,
    ) -> Result<Self, ProviderResultModelError> {
        if failed_at < claim.claimed_at || failed_at > claim.expires_at {
            return Err(ProviderResultModelError::InvalidTimestamp);
        }
        Ok(Self {
            claim,
            failed_at,
            kind,
        })
    }
    /// Returns the consumed claim.
    #[must_use]
    pub const fn claim(self) -> ProviderResultClaimFence {
        self.claim
    }
    /// Returns the failure time.
    #[must_use]
    pub const fn failed_at(self) -> UnixMillis {
        self.failed_at
    }
    /// Returns the closed failure kind.
    #[must_use]
    pub const fn kind(self) -> ProviderResultFailureKind {
        self.kind
    }
}

/// Closed terminal publication failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProviderResultFailureKind {
    /// The adapter cannot represent the desired result.
    Unsupported,
    /// Provider authentication failed permanently.
    Unauthorized,
    /// Provider authorization denied publication.
    Forbidden,
    /// Provider state or response was malformed.
    InvalidResponse,
    /// Existing provider state conflicts with the marker.
    Conflict,
    /// The generation exhausted its bounded claim attempts.
    AttemptLimit,
}

/// Result of saving a desired generation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProviderResultSaveOutcome {
    /// The first desired generation was stored.
    Inserted,
    /// Exact durable desired state was replayed.
    Unchanged,
    /// A contiguous generation replaced the prior desired state.
    Superseded,
}

/// Boxed future returned by result outbox operations.
pub type ProviderResultFuture<'a, T> =
    Pin<Box<dyn Future<Output = Result<T, ProviderResultRepositoryError>> + Send + 'a>>;

/// Durable current-only desired result and fenced publication outbox.
pub trait ProviderResultRepository: fmt::Debug + Send + Sync {
    /// Stores a first or contiguous desired generation and invalidates older claims.
    fn save_desired(
        &self,
        request: SaveDesiredProviderResult,
    ) -> ProviderResultFuture<'_, ProviderResultSaveOutcome>;
    /// Claims at most one eligible generation for a connection.
    fn claim_result(
        &self,
        request: ClaimProviderResult,
    ) -> ProviderResultFuture<'_, Option<ClaimedProviderResult>>;
    /// Completes one claim with exact provider evidence.
    fn complete_result(&self, request: CompleteProviderResult) -> ProviderResultFuture<'_, ()>;
    /// Releases one claim for a bounded retry.
    fn retry_result(&self, request: RetryProviderResult) -> ProviderResultFuture<'_, ()>;
    /// Terminalizes one claim after permanent failure.
    fn fail_result(&self, request: FailProviderResult) -> ProviderResultFuture<'_, ()>;
}

/// Publisher future borrowing one claim.
pub type ResultPublisherFuture<'a> = Pin<
    Box<
        dyn Future<Output = Result<ProviderResultPublicationEvidence, ResultPublisherError>>
            + Send
            + 'a,
    >,
>;

/// Narrow adapter capability that reconciles one claim-frozen desired generation.
pub trait ResultPublisher: fmt::Debug + Send + Sync {
    /// Returns the exact reconciliation model implemented by this adapter.
    fn model(&self) -> ProviderResultPublicationModel;
    /// Reconciles by deterministic marker before creating or mutating provider state.
    fn publish<'a>(&'a self, claimed: &'a ClaimedProviderResult) -> ResultPublisherFuture<'a>;
}

/// Sanitized adapter publication failure.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum ResultPublisherError {
    /// Transport or provider service is temporarily unavailable.
    #[error("result publisher is temporarily unavailable")]
    Unavailable,
    /// Provider quota is temporarily exhausted.
    #[error("result publisher is rate limited")]
    RateLimited {
        /// Bounded provider retry guidance, when present.
        retry_after: Option<ProviderResultRetryAfter>,
    },
    /// Authentication is missing or invalid.
    #[error("result publisher authentication failed")]
    Unauthorized,
    /// Authentication lacks publication authority.
    #[error("result publisher authorization failed")]
    Forbidden,
    /// Provider response or observed state is malformed.
    #[error("result publisher response is invalid")]
    InvalidResponse,
    /// The adapter cannot represent the desired projection.
    #[error("result publisher cannot represent the desired projection")]
    Unsupported,
    /// Existing provider state conflicts with the deterministic marker.
    #[error("result publisher state conflicts with the deterministic marker")]
    Conflict,
}

/// Bounded provider guidance for retrying a rate-limited publication.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProviderResultRetryAfter(NonZeroU64);

impl ProviderResultRetryAfter {
    /// Creates retry guidance within the common retry bound.
    ///
    /// # Errors
    ///
    /// Rejects zero or excessive delays.
    pub fn new(millis: u64) -> Result<Self, ProviderResultModelError> {
        NonZeroU64::new(millis)
            .filter(|value| value.get() <= MAX_PROVIDER_RESULT_RETRY_MILLIS)
            .map(Self)
            .ok_or(ProviderResultModelError::InvalidRetry)
    }

    /// Returns the suggested retry delay in milliseconds.
    #[must_use]
    pub const fn millis(self) -> u64 {
        self.0.get()
    }
}

impl ResultPublisherError {
    /// Returns whether the durable outbox may schedule a bounded retry.
    #[must_use]
    pub const fn is_retryable(self) -> bool {
        matches!(self, Self::Unavailable | Self::RateLimited { .. })
    }
}

/// Invalid common result model.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum ProviderResultModelError {
    /// New results require an active connection.
    #[error("result connection is not active")]
    InactiveConnection,
    /// A durable timestamp is invalid.
    #[error("result timestamp is invalid")]
    InvalidTimestamp,
    /// Physical attempt must be positive.
    #[error("result attempt is invalid")]
    InvalidAttempt,
    /// Publication claim attempt is outside its hard bound.
    #[error("result publication attempt is invalid")]
    InvalidPublicationAttempt,
    /// Desired generation must be positive and durable.
    #[error("result generation is invalid")]
    InvalidGeneration,
    /// Publication fence must be positive.
    #[error("result claim fence is invalid")]
    InvalidFence,
    /// Claim fields refer to inconsistent work.
    #[error("result claim binding is invalid")]
    InvalidClaimBinding,
    /// Publication lease is invalid or excessive.
    #[error("result publication lease is invalid")]
    InvalidLease,
    /// Retry delay is invalid or excessive.
    #[error("result retry is invalid")]
    InvalidRetry,
    /// Title violates its text bound.
    #[error("result title is invalid")]
    InvalidTitle,
    /// Summary violates its text bound.
    #[error("result summary is invalid")]
    InvalidSummary,
    /// Details URL violates its authority policy.
    #[error("result details URL is invalid")]
    InvalidDetailsUrl,
    /// Annotation title violates its text bound.
    #[error("result annotation title is invalid")]
    InvalidAnnotationTitle,
    /// Annotation message violates its text bound.
    #[error("result annotation message is invalid")]
    InvalidAnnotationMessage,
    /// Annotation line range is invalid.
    #[error("result annotation range is invalid")]
    InvalidAnnotationRange,
    /// Annotation count exceeds the hard bound.
    #[error("too many result annotations")]
    TooManyAnnotations,
    /// Exact duplicate annotations are ambiguous provider work.
    #[error("result annotation is duplicated")]
    DuplicateAnnotation,
    /// Only completed desired state may have a conclusion.
    #[error("result phase and conclusion are inconsistent")]
    InvalidPhaseConclusion,
}

/// Sanitized durable result repository failure.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum ProviderResultRepositoryError {
    /// A generation is stale, noncontiguous, or disagrees with durable state.
    #[error("provider result conflicts with durable state")]
    Conflict,
    /// A claim is stale, expired, or superseded.
    #[error("provider result claim is stale or expired")]
    StaleClaim,
    /// Required subject or generation does not exist.
    #[error("provider result reference does not exist")]
    NotFound,
    /// Durable result bytes violate the common model.
    #[error("provider result storage is corrupt")]
    Corrupt,
    /// Durable result storage is unavailable.
    #[error("provider result repository is unavailable")]
    Unavailable,
}

fn part(hash: &mut Sha256, value: &[u8]) {
    hash.update(
        u64::try_from(value.len())
            .expect("bounded provider result value fits u64")
            .to_be_bytes(),
    );
    hash.update(value);
}
fn result_generation(value: u64) -> Result<NonZeroU64, ProviderResultModelError> {
    NonZeroU64::new(value)
        .filter(|generation| i64::try_from(generation.get()).is_ok())
        .ok_or(ProviderResultModelError::InvalidGeneration)
}
const fn phase_code(value: ProviderResultPhase) -> u8 {
    match value {
        ProviderResultPhase::Queued => 1,
        ProviderResultPhase::Running => 2,
        ProviderResultPhase::Completed => 3,
    }
}
const fn conclusion_code(value: ProviderResultConclusion) -> u8 {
    match value {
        ProviderResultConclusion::Success => 1,
        ProviderResultConclusion::Failure => 2,
        ProviderResultConclusion::Error => 3,
        ProviderResultConclusion::Cancelled => 4,
        ProviderResultConclusion::Skipped => 5,
        ProviderResultConclusion::TimedOut => 6,
        ProviderResultConclusion::Neutral => 7,
        ProviderResultConclusion::ActionRequired => 8,
    }
}
const fn annotation_level_code(value: ProviderResultAnnotationLevel) -> u8 {
    match value {
        ProviderResultAnnotationLevel::Notice => 1,
        ProviderResultAnnotationLevel::Warning => 2,
        ProviderResultAnnotationLevel::Failure => 3,
    }
}
const fn publication_model_code(value: ProviderResultPublicationModel) -> u8 {
    match value {
        ProviderResultPublicationModel::MutableRichCheck => 1,
        ProviderResultPublicationModel::AppendOnlyCommitStatus => 2,
    }
}
