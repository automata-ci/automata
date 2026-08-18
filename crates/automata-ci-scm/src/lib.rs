//! Provider-neutral, immutable source-control snapshot contracts.
//!
//! [`RevisionSpec`] represents the caller's potentially mutable selector, such
//! as a branch or tag. Provider adapters resolve that selector to a
//! [`GitObjectId`](automata_ci_core::GitObjectId) that identifies immutable provider state before they
//! download an archive. The resulting [`RepositorySnapshot`] retains both
//! values, the exact archive bytes, and a locally computed SHA-256 digest.
//! Separately, [`RepositorySource`] is selected for one configured provider
//! instance. It accepts a connection and exact
//! [`GitObjectId`](automata_ci_core::GitObjectId), then returns a
//! [`RepositorySourceArchive`] after proving the provider resolved that exact
//! repository and commit. It has no authority to fall back to mutable selector
//! resolution.
//!
//! Credentials are borrowed only for one [`SnapshotRequest`]. They are redacted
//! from request diagnostics and are never retained in a snapshot or its errors.
//! [`ScmProvider`] implementations must also avoid ambient credentials, reject
//! untrusted redirect targets, and enforce the caller's archive limit while
//! streaming the response.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

/// Provider-neutral workload credential request, result, and failure contracts.
pub mod credential;

mod changed_files;
mod model;
mod port;

pub use changed_files::{
    ChangedFile, ChangedFileEvidence, ChangedFileIncompleteReason, ChangedFileLimits,
    ChangedFileLimitsError, ChangedFileNotApplicableReason, ChangedFilePageAccumulator,
    ChangedFilePageEvidence, ChangedFileRead, ChangedFileReadError, ChangedFileReader,
    ChangedFileRequest, ChangedFileRequestError, MAX_CHANGED_FILE_COUNT, MAX_CHANGED_FILE_PAGES,
    MAX_CHANGED_FILE_RESPONSE_BYTES,
};
pub use model::{
    ArchiveFormat, ArchiveLimits, ArchiveLimitsError, RepositoryId, RepositoryIdError,
    RepositorySnapshot, RepositorySourceArchive, RepositorySourceConnection,
    RepositorySourceRedirectPolicy, RepositorySourceRequest, RevisionError, RevisionSpec,
    ScmProviderId, ScmProviderIdError, SnapshotRequest,
};
pub use port::{RepositorySource, ScmError, ScmErrorKind, ScmProvider};
