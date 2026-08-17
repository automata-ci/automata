//! Provider-neutral, immutable source-control snapshot contracts.
//!
//! [`RevisionSpec`] represents the caller's potentially mutable selector, such
//! as a branch or tag. Provider adapters resolve that selector to a
//! [`GitObjectId`](automata_ci_core::GitObjectId) that identifies immutable provider state before they
//! download an archive. The resulting [`RepositorySnapshot`] retains both
//! values, the exact archive bytes, and a locally computed SHA-256 digest.
//! Separately, [`RepositorySourcePort`] accepts only a
//! [`GitObjectId`](automata_ci_core::GitObjectId) and
//! returns [`RepositorySource`] after proving the provider resolved that exact
//! commit; it has no authority to fall back to mutable selector resolution.
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

mod model;
mod port;

pub use model::{
    ArchiveFormat, ArchiveLimits, ArchiveLimitsError, RepositoryId, RepositoryIdError,
    RepositorySnapshot, RepositorySource, RepositorySourceRequest, RevisionError, RevisionSpec,
    ScmProviderId, ScmProviderIdError, SnapshotRequest,
};
pub use port::{RepositorySourcePort, ScmError, ScmErrorKind, ScmProvider};
