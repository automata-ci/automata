//! Completeness-bearing changed-file evidence for normalized provider triggers.

use std::fmt;

use async_trait::async_trait;
use automata_ci_auth::secret::SecretString;
use automata_ci_core::{Sha256Digest, UnixMillis};
use automata_ci_provider::{
    ExternalRepositoryIdentity, ProviderConnectionId, ProviderConnectionManifest,
    ProviderConnectionRevision, ProviderLifecycleState, ProviderRepositoryPath,
    SealedNormalizedTrigger,
};
use bytes::Bytes;
use sha2::{Digest as _, Sha256};
use thiserror::Error;

use crate::ScmError;

/// Maximum complete changed-file records accepted by the common boundary.
pub const MAX_CHANGED_FILE_COUNT: usize = 100_000;
/// Maximum provider pages represented by one changed-file observation.
pub const MAX_CHANGED_FILE_PAGES: usize = 1_000;
/// Maximum aggregate provider response bytes for one changed-file read.
pub const MAX_CHANGED_FILE_RESPONSE_BYTES: u64 = 64 * 1_024 * 1_024;

const CHANGED_FILE_EVIDENCE_DOMAIN: &[u8] = b"automata.scm.changed-files.v1\0";
const CHANGED_FILE_REQUEST_DOMAIN: &[u8] = b"automata.scm.changed-files.request.v1\0";

/// Independent bounds applied across one changed-file operation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ChangedFileLimits {
    files: usize,
    pages: usize,
    response_bytes: u64,
}

impl ChangedFileLimits {
    /// Creates positive bounds no larger than the common hard ceilings.
    ///
    /// # Errors
    ///
    /// Rejects zero or excessive values.
    pub const fn new(
        maximum_files: usize,
        maximum_pages: usize,
        maximum_response_bytes: u64,
    ) -> Result<Self, ChangedFileLimitsError> {
        if maximum_files == 0
            || maximum_files > MAX_CHANGED_FILE_COUNT
            || maximum_pages == 0
            || maximum_pages > MAX_CHANGED_FILE_PAGES
            || maximum_response_bytes == 0
            || maximum_response_bytes > MAX_CHANGED_FILE_RESPONSE_BYTES
        {
            return Err(ChangedFileLimitsError);
        }
        Ok(Self {
            files: maximum_files,
            pages: maximum_pages,
            response_bytes: maximum_response_bytes,
        })
    }

    /// Returns the complete record ceiling.
    #[must_use]
    pub const fn maximum_files(self) -> usize {
        self.files
    }

    /// Returns the provider page ceiling.
    #[must_use]
    pub const fn maximum_pages(self) -> usize {
        self.pages
    }

    /// Returns the aggregate response-byte ceiling.
    #[must_use]
    pub const fn maximum_response_bytes(self) -> u64 {
        self.response_bytes
    }
}

/// One connection-bound request for changed-file evidence.
pub struct ChangedFileRequest<'request> {
    connection: &'request ProviderConnectionManifest,
    trigger: &'request SealedNormalizedTrigger,
    credential: Option<&'request SecretString>,
    limits: ChangedFileLimits,
    observed_at: UnixMillis,
}

impl<'request> ChangedFileRequest<'request> {
    /// Creates a credential-free changed-file request.
    ///
    /// # Errors
    ///
    /// Rejects inactive connections, pre-epoch observation times, and triggers
    /// for another repository.
    pub fn public(
        connection: &'request ProviderConnectionManifest,
        trigger: &'request SealedNormalizedTrigger,
        limits: ChangedFileLimits,
        observed_at: UnixMillis,
    ) -> Result<Self, ChangedFileRequestError> {
        Self::build(connection, trigger, None, limits, observed_at)
    }

    /// Creates a changed-file request with one explicitly borrowed credential.
    ///
    /// # Errors
    ///
    /// Rejects inactive connections, pre-epoch observation times, and triggers
    /// for another repository.
    pub fn authenticated(
        connection: &'request ProviderConnectionManifest,
        trigger: &'request SealedNormalizedTrigger,
        credential: &'request SecretString,
        limits: ChangedFileLimits,
        observed_at: UnixMillis,
    ) -> Result<Self, ChangedFileRequestError> {
        Self::build(connection, trigger, Some(credential), limits, observed_at)
    }

    fn build(
        connection: &'request ProviderConnectionManifest,
        trigger: &'request SealedNormalizedTrigger,
        credential: Option<&'request SecretString>,
        limits: ChangedFileLimits,
        observed_at: UnixMillis,
    ) -> Result<Self, ChangedFileRequestError> {
        if connection.state() != ProviderLifecycleState::Active {
            return Err(ChangedFileRequestError::InactiveConnection);
        }
        if observed_at.get() < 0 {
            return Err(ChangedFileRequestError::InvalidObservationTime);
        }
        if trigger.trigger().target_repository().identity()
            != connection.configuration().repository()
        {
            return Err(ChangedFileRequestError::RepositoryMismatch);
        }
        Ok(Self {
            connection,
            trigger,
            credential,
            limits,
            observed_at,
        })
    }

    /// Returns the exact active connection revision.
    #[must_use]
    pub const fn connection(&self) -> &ProviderConnectionManifest {
        self.connection
    }

    /// Returns the exact canonical normalized trigger.
    #[must_use]
    pub const fn trigger(&self) -> &SealedNormalizedTrigger {
        self.trigger
    }

    /// Returns the instance-scoped target repository.
    #[must_use]
    pub const fn repository(&self) -> &ExternalRepositoryIdentity {
        self.connection.configuration().repository()
    }

    /// Returns the explicitly borrowed credential, when present.
    #[must_use]
    pub const fn credential(&self) -> Option<&SecretString> {
        self.credential
    }

    /// Returns independent file, page, and response-byte limits.
    #[must_use]
    pub const fn limits(&self) -> ChangedFileLimits {
        self.limits
    }

    /// Returns the trusted observation time bound to resulting evidence.
    #[must_use]
    pub const fn observed_at(&self) -> UnixMillis {
        self.observed_at
    }
}

impl fmt::Debug for ChangedFileRequest<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ChangedFileRequest")
            .field("connection_id", &self.connection.connection_id())
            .field("connection_revision", &self.connection.revision())
            .field("trigger_digest", &self.trigger.digest())
            .field("repository", &self.repository())
            .field("credential", &self.credential.map(|_| "[redacted]"))
            .field("limits", &self.limits)
            .field("observed_at", &self.observed_at)
            .finish()
    }
}

/// One canonical changed-file record, including both sides of a rename.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct ChangedFile {
    current_path: ProviderRepositoryPath,
    previous_path: Option<ProviderRepositoryPath>,
}

impl ChangedFile {
    /// Creates one changed path without rename evidence.
    #[must_use]
    pub const fn changed(current_path: ProviderRepositoryPath) -> Self {
        Self {
            current_path,
            previous_path: None,
        }
    }

    /// Creates one rename with distinct previous and current paths.
    ///
    /// # Errors
    ///
    /// Rejects a rename whose two paths are equal.
    pub fn renamed(
        previous_path: ProviderRepositoryPath,
        current_path: ProviderRepositoryPath,
    ) -> Result<Self, ChangedFileReadError> {
        if previous_path == current_path {
            return Err(ChangedFileReadError::InvalidRename);
        }
        Ok(Self {
            current_path,
            previous_path: Some(previous_path),
        })
    }

    /// Returns the current repository-relative path.
    #[must_use]
    pub const fn current_path(&self) -> &ProviderRepositoryPath {
        &self.current_path
    }

    /// Returns the prior path when this record represents a rename.
    #[must_use]
    pub const fn previous_path(&self) -> Option<&ProviderRepositoryPath> {
        self.previous_path.as_ref()
    }
}

/// Why a comparison is meaningful but cannot be proven complete.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ChangedFileIncompleteReason {
    /// A created ref has no provider-proven comparison base.
    CreatedRef,
    /// A deleted ref has no post-update tree.
    DeletedRef,
    /// A forced update cannot prove the required comparison semantics.
    ForcedUpdate,
    /// The provider reported a gap or divergent comparison history.
    CompareGap,
    /// The operation exhausted its explicit page budget.
    PaginationLimit,
    /// The provider explicitly marked its response as truncated.
    ProviderTruncated,
    /// The provider's documented record window is smaller than the result.
    ProviderRecordLimit,
}

impl ChangedFileIncompleteReason {
    const fn code(self) -> u8 {
        match self {
            Self::CreatedRef => 1,
            Self::DeletedRef => 2,
            Self::ForcedUpdate => 3,
            Self::CompareGap => 4,
            Self::PaginationLimit => 5,
            Self::ProviderTruncated => 6,
            Self::ProviderRecordLimit => 7,
        }
    }
}

/// Why a normalized event has no applicable changed-file comparison.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ChangedFileNotApplicableReason {
    /// The normalized event class does not define a changed-file range.
    EventClass,
    /// The event has no source object against which workflows can be selected.
    NoSourceObject,
}

/// Canonical, connection- and trigger-bound provider observation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ChangedFileEvidence {
    connection_id: ProviderConnectionId,
    connection_revision: ProviderConnectionRevision,
    connection_digest: Sha256Digest,
    trigger_digest: Sha256Digest,
    observed_at: UnixMillis,
    observed_file_count: u64,
    page_count: usize,
    response_bytes: u64,
    digest: Sha256Digest,
}

impl ChangedFileEvidence {
    /// Returns the exact provider connection identity.
    #[must_use]
    pub const fn connection_id(&self) -> ProviderConnectionId {
        self.connection_id
    }

    /// Returns the exact connection revision.
    #[must_use]
    pub const fn connection_revision(&self) -> ProviderConnectionRevision {
        self.connection_revision
    }

    /// Returns the complete connection-manifest digest.
    #[must_use]
    pub const fn connection_digest(&self) -> Sha256Digest {
        self.connection_digest
    }

    /// Returns the canonical normalized-trigger digest.
    #[must_use]
    pub const fn trigger_digest(&self) -> Sha256Digest {
        self.trigger_digest
    }

    /// Returns the trusted observation time.
    #[must_use]
    pub const fn observed_at(&self) -> UnixMillis {
        self.observed_at
    }

    /// Returns the number of provider file records observed.
    #[must_use]
    pub const fn observed_file_count(&self) -> u64 {
        self.observed_file_count
    }

    /// Returns the number of provider response pages represented.
    #[must_use]
    pub const fn page_count(&self) -> usize {
        self.page_count
    }

    /// Returns aggregate bytes authenticated by the page digests.
    #[must_use]
    pub const fn response_bytes(&self) -> u64 {
        self.response_bytes
    }

    /// Returns the domain-separated evidence digest.
    #[must_use]
    pub const fn digest(&self) -> Sha256Digest {
        self.digest
    }
}

/// Bounded digests for every exact provider response page.
#[derive(Debug, Eq, PartialEq)]
pub struct ChangedFilePageEvidence {
    request_digest: Sha256Digest,
    page_digests: Vec<Sha256Digest>,
    response_bytes: u64,
}

/// Incrementally accounts for provider response pages before result decoding.
#[derive(Debug)]
pub struct ChangedFilePageAccumulator {
    request_digest: Sha256Digest,
    limits: ChangedFileLimits,
    page_digests: Vec<Sha256Digest>,
    response_bytes: u64,
    current_digest: Option<Sha256>,
    current_bytes: u64,
    failed: bool,
}

impl ChangedFilePageAccumulator {
    /// Starts page accounting bound to one exact changed-file request.
    #[must_use]
    pub fn new(request: &ChangedFileRequest<'_>) -> Self {
        Self {
            request_digest: changed_file_request_digest(request),
            limits: request.limits,
            page_digests: Vec::new(),
            response_bytes: 0,
            current_digest: None,
            current_bytes: 0,
            failed: false,
        }
    }

    /// Starts one provider response page.
    ///
    /// # Errors
    ///
    /// Rejects nested pages and the first page beyond the page limit. A rejected
    /// accumulator cannot seal.
    pub fn begin_page(&mut self) -> Result<(), ChangedFileReadError> {
        if self.failed || self.current_digest.is_some() {
            self.failed = true;
            return Err(ChangedFileReadError::InvalidPageState);
        }
        if self.page_digests.len() == self.limits.pages {
            self.failed = true;
            return Err(ChangedFileReadError::TooManyPages);
        }
        self.current_digest = Some(Sha256::new());
        self.current_bytes = 0;
        Ok(())
    }

    /// Accounts for one transport chunk without retaining its bytes.
    ///
    /// Empty transport chunks are harmless and ignored.
    ///
    /// # Errors
    ///
    /// Rejects chunks outside an open page or bytes beyond the aggregate
    /// response limit. A rejected accumulator cannot seal.
    pub fn push_chunk(&mut self, bytes: &Bytes) -> Result<(), ChangedFileReadError> {
        if self.failed || self.current_digest.is_none() {
            self.failed = true;
            return Err(ChangedFileReadError::InvalidPageState);
        }
        if bytes.is_empty() {
            return Ok(());
        }
        let Some(next) = self
            .response_bytes
            .checked_add(u64::try_from(bytes.len()).unwrap_or(u64::MAX))
        else {
            self.failed = true;
            return Err(ChangedFileReadError::ResponseTooLarge);
        };
        if next > self.limits.response_bytes {
            self.failed = true;
            return Err(ChangedFileReadError::ResponseTooLarge);
        }
        let Some(current_bytes) = self
            .current_bytes
            .checked_add(u64::try_from(bytes.len()).unwrap_or(u64::MAX))
        else {
            self.failed = true;
            return Err(ChangedFileReadError::ResponseTooLarge);
        };
        let Some(digest) = self.current_digest.as_mut() else {
            self.failed = true;
            return Err(ChangedFileReadError::InvalidPageState);
        };
        self.response_bytes = next;
        self.current_bytes = current_bytes;
        digest.update(bytes);
        Ok(())
    }

    /// Seals the current nonempty page digest.
    ///
    /// # Errors
    ///
    /// Rejects a missing or empty page. A rejected accumulator cannot seal.
    pub fn finish_page(&mut self) -> Result<(), ChangedFileReadError> {
        let Some(digest) = self.current_digest.take() else {
            self.failed = true;
            return Err(ChangedFileReadError::InvalidPageState);
        };
        if self.failed {
            return Err(ChangedFileReadError::InvalidPageState);
        }
        if self.current_bytes == 0 {
            self.failed = true;
            return Err(ChangedFileReadError::EmptyPage);
        }
        self.page_digests
            .push(Sha256Digest::from_bytes(digest.finalize().into()));
        self.current_bytes = 0;
        Ok(())
    }

    /// Seals bounded page digests for complete or incomplete evidence.
    ///
    /// # Errors
    ///
    /// Rejects an accumulator after any page-accounting failure.
    pub fn finish(self) -> Result<ChangedFilePageEvidence, ChangedFileReadError> {
        if self.failed || self.current_digest.is_some() {
            return Err(ChangedFileReadError::InvalidPageEvidence);
        }
        Ok(ChangedFilePageEvidence {
            request_digest: self.request_digest,
            page_digests: self.page_digests,
            response_bytes: self.response_bytes,
        })
    }
}

/// Complete, inapplicable, or explicitly incomplete changed-file evidence.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ChangedFileRead {
    /// Every provider record is represented in canonical path order.
    Complete {
        /// Unique canonical file records.
        files: Vec<ChangedFile>,
        /// Exact provider and request evidence.
        evidence: ChangedFileEvidence,
    },
    /// The normalized event defines no changed-file comparison.
    NotApplicable {
        /// Closed reason the comparison does not apply.
        reason: ChangedFileNotApplicableReason,
    },
    /// A comparison applies but provider evidence cannot prove completeness.
    Incomplete {
        /// Closed incompleteness reason.
        reason: ChangedFileIncompleteReason,
        /// Exact partial provider and request evidence.
        evidence: ChangedFileEvidence,
    },
}

impl ChangedFileRead {
    /// Seals a complete, bounded, unique, canonical file set.
    ///
    /// # Errors
    ///
    /// Rejects duplicate, excessive, or count-inconsistent records and
    /// excessive page evidence.
    pub fn complete(
        request: &ChangedFileRequest<'_>,
        mut files: Vec<ChangedFile>,
        observed_file_count: u64,
        pages: ChangedFilePageEvidence,
    ) -> Result<Self, ChangedFileReadError> {
        if files.len() > request.limits.files
            || u64::try_from(files.len()).ok() != Some(observed_file_count)
        {
            return Err(ChangedFileReadError::InvalidFileCount);
        }
        files.sort();
        if files
            .windows(2)
            .any(|pair| pair[0].current_path == pair[1].current_path)
        {
            return Err(ChangedFileReadError::DuplicatePath);
        }
        let evidence = seal_evidence(
            request,
            observed_file_count,
            pages,
            EvidenceShape::Complete(&files),
        )?;
        Ok(Self::Complete { files, evidence })
    }

    /// Records an event for which no changed-file comparison applies.
    #[must_use]
    pub const fn not_applicable(reason: ChangedFileNotApplicableReason) -> Self {
        Self::NotApplicable { reason }
    }

    /// Seals partial provider evidence without manufacturing a complete path set.
    ///
    /// # Errors
    ///
    /// Rejects excessive page evidence.
    pub fn incomplete(
        request: &ChangedFileRequest<'_>,
        reason: ChangedFileIncompleteReason,
        observed_file_count: u64,
        pages: ChangedFilePageEvidence,
    ) -> Result<Self, ChangedFileReadError> {
        let evidence = seal_evidence(
            request,
            observed_file_count,
            pages,
            EvidenceShape::Incomplete(reason),
        )?;
        Ok(Self::Incomplete { reason, evidence })
    }

    /// Returns complete file records only when completeness was proven.
    #[must_use]
    pub fn complete_files(&self) -> Option<&[ChangedFile]> {
        match self {
            Self::Complete { files, .. } => Some(files),
            Self::NotApplicable { .. } | Self::Incomplete { .. } => None,
        }
    }
}

/// Reads changed-file evidence for one exact normalized trigger.
#[async_trait]
pub trait ChangedFileReader: fmt::Debug + Send + Sync {
    /// Returns a complete, inapplicable, or explicitly incomplete observation.
    ///
    /// Provider pagination and truncation must never be collapsed into a
    /// successful partial list. Credentials are borrowed only for this call.
    ///
    /// # Errors
    ///
    /// Returns a sanitized error for authorization, transport, rate-limit, or
    /// malformed response failures.
    async fn read_changed_files(
        &self,
        request: ChangedFileRequest<'_>,
    ) -> Result<ChangedFileRead, ScmError>;
}

#[derive(Clone, Copy)]
enum EvidenceShape<'files> {
    Complete(&'files [ChangedFile]),
    Incomplete(ChangedFileIncompleteReason),
}

fn seal_evidence(
    request: &ChangedFileRequest<'_>,
    observed_file_count: u64,
    pages: ChangedFilePageEvidence,
    shape: EvidenceShape<'_>,
) -> Result<ChangedFileEvidence, ChangedFileReadError> {
    let ChangedFilePageEvidence {
        request_digest,
        page_digests,
        response_bytes,
    } = pages;
    let complete = matches!(&shape, EvidenceShape::Complete(_));
    if request_digest != changed_file_request_digest(request)
        || page_digests.len() > request.limits.pages
        || response_bytes > request.limits.response_bytes
        || (complete && page_digests.is_empty())
    {
        return Err(ChangedFileReadError::InvalidPageEvidence);
    }
    let mut hash = Sha256::new();
    hash.update(CHANGED_FILE_EVIDENCE_DOMAIN);
    hash.update(request.connection.connection_id().as_uuid().as_bytes());
    hash.update(request.connection.revision().get().to_be_bytes());
    hash.update(request.connection.digest().as_bytes());
    hash.update(request.trigger.digest().as_bytes());
    hash.update(request.observed_at.get().to_be_bytes());
    hash.update(observed_file_count.to_be_bytes());
    hash.update(
        u64::try_from(page_digests.len())
            .expect("changed-file page hard limit fits u64")
            .to_be_bytes(),
    );
    hash.update(response_bytes.to_be_bytes());
    for page_digest in &page_digests {
        hash.update(page_digest.as_bytes());
    }
    match shape {
        EvidenceShape::Complete(files) => {
            hash.update([1]);
            hash.update(
                u64::try_from(files.len())
                    .expect("changed-file hard limit fits u64")
                    .to_be_bytes(),
            );
            for file in files {
                part(&mut hash, file.current_path.as_str().as_bytes());
                match &file.previous_path {
                    Some(previous) => {
                        hash.update([1]);
                        part(&mut hash, previous.as_str().as_bytes());
                    }
                    None => hash.update([0]),
                }
            }
        }
        EvidenceShape::Incomplete(reason) => {
            hash.update([2, reason.code()]);
        }
    }
    Ok(ChangedFileEvidence {
        connection_id: request.connection.connection_id(),
        connection_revision: request.connection.revision(),
        connection_digest: request.connection.digest(),
        trigger_digest: request.trigger.digest(),
        observed_at: request.observed_at,
        observed_file_count,
        page_count: page_digests.len(),
        response_bytes,
        digest: Sha256Digest::from_bytes(hash.finalize().into()),
    })
}

fn changed_file_request_digest(request: &ChangedFileRequest<'_>) -> Sha256Digest {
    let mut hash = Sha256::new();
    hash.update(CHANGED_FILE_REQUEST_DOMAIN);
    hash.update(request.connection.connection_id().as_uuid().as_bytes());
    hash.update(request.connection.revision().get().to_be_bytes());
    hash.update(request.connection.digest().as_bytes());
    hash.update(request.trigger.digest().as_bytes());
    hash.update(
        u64::try_from(request.limits.files)
            .expect("changed-file hard limit fits u64")
            .to_be_bytes(),
    );
    hash.update(
        u64::try_from(request.limits.pages)
            .expect("changed-file page hard limit fits u64")
            .to_be_bytes(),
    );
    hash.update(request.limits.response_bytes.to_be_bytes());
    hash.update(request.observed_at.get().to_be_bytes());
    Sha256Digest::from_bytes(hash.finalize().into())
}

fn part(hash: &mut Sha256, value: &[u8]) {
    hash.update(
        u64::try_from(value.len())
            .expect("provider repository path hard limit fits u64")
            .to_be_bytes(),
    );
    hash.update(value);
}

/// Invalid changed-file limits.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
#[error("changed-file limits are invalid")]
pub struct ChangedFileLimitsError;

/// Invalid connection or trigger binding for a changed-file request.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum ChangedFileRequestError {
    /// New provider reads require an active connection revision.
    #[error("changed-file connection is not active")]
    InactiveConnection,
    /// The normalized target repository differs from the connection repository.
    #[error("changed-file trigger repository does not match its connection")]
    RepositoryMismatch,
    /// Durable provider observations cannot predate the Unix epoch.
    #[error("changed-file observation time is invalid")]
    InvalidObservationTime,
}

/// Invalid changed-file result construction.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum ChangedFileReadError {
    /// A rename repeated the same path on both sides.
    #[error("changed-file rename is invalid")]
    InvalidRename,
    /// A complete result exceeded its limit or disagreed with provider count.
    #[error("changed-file count is invalid")]
    InvalidFileCount,
    /// More than one provider record selected the same current path.
    #[error("changed-file path is duplicated")]
    DuplicatePath,
    /// A provider response page was empty.
    #[error("changed-file response page is empty")]
    EmptyPage,
    /// Provider evidence exceeded the request page limit.
    #[error("changed-file page count exceeds its limit")]
    TooManyPages,
    /// Provider evidence exceeded the aggregate response-byte limit.
    #[error("changed-file response bytes exceed their limit")]
    ResponseTooLarge,
    /// Page evidence failed earlier or belongs to another request.
    #[error("changed-file page evidence is invalid")]
    InvalidPageEvidence,
    /// Page streaming calls were made out of order.
    #[error("changed-file page stream state is invalid")]
    InvalidPageState,
}
