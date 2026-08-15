#![forbid(unsafe_code)]
#![deny(missing_docs)]
//! Crash-durable, content-addressed storage for runner recovery payloads.
//!
//! [`FileSpool`] has no plaintext mode. Construction requires an explicit
//! [`ContentProtector`] adapter, and bytes are protected before they reach the
//! filesystem. A successful [`DurableContentStore::persist`] return carries a
//! [`DurableContentPublication`] that fences reconciliation until its journal
//! mutation succeeds through [`DurableContentPublication::commit_with`]. On
//! recovery, [`DurableContentStore::reconcile`] captures a complete journal
//! retain set after acquiring that same exclusion gate and reclaims all
//! payload-first crash leftovers. Publication exclusion is deliberately
//! process-local: after a crash, the durable journal is the sole authority.

mod error;
mod model;
mod observer;
mod platform;
mod root;
mod store;

pub use error::{
    ContentProtectionError, RetainedContentError, SpoolError, SpoolInvariantError, SpoolRootError,
};
pub use model::{
    ContentCacheKey, ContentCommitmentDomain, ContentKind, DurableContentRef,
    KeyedContentCommitment, ProtectionId, SpoolLimits,
};
pub use observer::{
    NoopSpoolObserver, SpoolCapacityResource, SpoolEvent, SpoolFailureKind, SpoolObserver,
    SpoolOperation, SpoolOperationOutcome, SpoolProtectionOperation, SpoolProtectionOutcome,
};
pub use root::SpoolRoot;
pub use store::{
    ContentCommitFault, ContentCommitFaultInjector, ContentCommitStage, ContentProtector,
    DurableContentPublication, DurableContentStore, FileSpool, FileSpoolOptions,
    NoContentCommitFaults, PublicationCommitFailure, RetainedContentSource,
};

/// Hard upper bound for one plaintext object accepted by any adapter.
pub const MAX_CONTENT_OBJECT_BYTES: u64 = 256 * 1024 * 1024;
/// Hard upper bound for protected bytes managed by one spool.
pub const MAX_CONTENT_SPOOL_BYTES: u64 = 4 * 1024 * 1024 * 1024;
/// Hard upper bound for immutable objects managed by one spool.
pub const MAX_CONTENT_OBJECTS: u32 = 65_536;
