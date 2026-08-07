//! Provider-neutral, immutable source-control snapshot contracts.
//!
//! Provider adapters resolve a user-facing revision to an immutable provider
//! revision before returning archive bytes. Credentials remain request-scoped
//! and are never retained in a snapshot or its errors.

#![forbid(unsafe_code)]

mod model;
mod port;

pub use model::{
    ArchiveFormat, ArchiveLimits, ArchiveLimitsError, RepositoryId, RepositoryIdError,
    RepositorySnapshot, ResolvedRevision, RevisionError, RevisionSpec, ScmProviderId,
    ScmProviderIdError, SnapshotRequest,
};
pub use port::{ScmError, ScmErrorKind, ScmProvider};
