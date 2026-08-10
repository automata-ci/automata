use std::{io, path::PathBuf};

use thiserror::Error;

use crate::{ContentCommitStage, DurableContentRef};

/// Rejected spool-root configuration.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum SpoolRootError {
    /// The configured root is not an absolute host path.
    #[error("runner spool root must be an absolute path")]
    Relative,
    /// The configured root is the host filesystem root.
    #[error("runner spool root cannot be the filesystem root")]
    FilesystemRoot,
    /// The configured path contains a current- or parent-directory component.
    #[error("runner spool root contains a traversal component")]
    Traversal,
    /// The configured path contains a `tmp` hierarchy component.
    #[error("runner spool root cannot be placed in a system temporary hierarchy")]
    TemporaryHierarchy,
    /// XDG-based construction received an empty state-home path.
    #[error("XDG state home must be supplied explicitly and cannot be empty")]
    MissingXdgStateHome,
}

/// Invalid bounded content metadata or spool limits.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum SpoolInvariantError {
    /// A protection identifier was empty, oversized, or not filename-safe.
    #[error("content protection identifier is invalid")]
    InvalidProtectionId,
    /// A cache key was malformed or inconsistent with its content receipt.
    #[error("content cache key is invalid or does not match its content identity")]
    InvalidCacheKey,
    /// Plaintext exceeds either the configured or global per-object bound.
    #[error("content exceeds the hard object-size limit")]
    ObjectTooLarge,
    /// A capacity limit is zero, incoherent, overflowing, or above a hard bound.
    #[error("spool limits are zero, inverted, or exceed hard bounds")]
    InvalidLimits,
    /// Protected output expanded beyond the configured per-object allowance.
    #[error("protected content exceeds the configured expansion limit")]
    ProtectionOverheadExceeded,
    /// Opened plaintext does not match the size and digest in its durable receipt.
    #[error("content bytes do not match their durable size or SHA-256 identity")]
    ContentMismatch,
}

/// Secret-free error returned by a content-protection adapter.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum ContentProtectionError {
    /// The required protection key or configured decrypt-only key is unavailable.
    #[error("content protection key is unavailable")]
    KeyUnavailable,
    /// Authenticated opening rejected altered or incorrectly protected bytes.
    #[error("protected content authentication failed")]
    AuthenticationFailed,
    /// Protection failed without a more specific safe-to-report category.
    #[error("content protection operation failed")]
    Failed,
}

/// Secret-free failure returned while capturing a complete durable retain set.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum RetainedContentError {
    /// A complete authoritative retain-set snapshot could not be captured.
    #[error("durable content retain set is temporarily unavailable")]
    Unavailable,
}

/// Typed storage, protection, capacity, and commit failures.
///
/// Variants never contain plaintext or protection-key material. The I/O
/// variant intentionally retains a local host path and operating-system error
/// for operator diagnosis; callers must not expose those details across an
/// untrusted boundary without applying their own sanitization policy.
#[derive(Debug, Error)]
pub enum SpoolError {
    /// The configured spool root violated host-path policy.
    #[error(transparent)]
    Root(#[from] SpoolRootError),
    /// Content metadata or capacity limits violated a bounded invariant.
    #[error(transparent)]
    Invariant(#[from] SpoolInvariantError),
    /// The configured protection adapter returned a secret-free failure.
    #[error(transparent)]
    Protection(#[from] ContentProtectionError),
    /// Another process holds the exclusive lock for this spool root.
    #[error("another process already owns the runner content spool lock")]
    AlreadyLocked,
    /// The current operating system has no secure filesystem implementation.
    #[error("the runner content spool has no filesystem adapter for this platform")]
    UnsupportedPlatform,
    /// A path component or directory entry violated the no-follow root boundary.
    #[error("spool path is a symlink, non-directory component, or escaped the configured root")]
    PathSecurity,
    /// An object, aggregate byte, object-count, or arithmetic capacity bound was exceeded.
    #[error("runner content spool capacity is exhausted")]
    CapacityExhausted,
    /// Reconciliation or removal encountered a payload awaiting journal adoption.
    #[error("content reconciliation is fenced by an in-flight journal publication")]
    PublicationsInFlight,
    /// Publication could not begin while reconciliation held its exclusive gate.
    #[error("content publication is fenced by an active reconciliation")]
    ReconciliationInProgress,
    /// The journal adapter could not provide a complete authoritative retain set.
    #[error(transparent)]
    RetainedContent(#[from] RetainedContentError),
    /// A referenced durable object was absent from the spool.
    #[error("durable content is missing from the spool")]
    ContentMissing,
    /// A content rename occurred but its durable directory outcome is uncertain.
    ///
    /// Close the poisoned handle, reopen the spool, and re-persist the same
    /// plaintext before attempting journal adoption.
    #[error("content commit outcome is unknown; reopen and re-persist before continuing")]
    CommitOutcomeUnknown,
    /// Removal changed the directory but its durable outcome is uncertain.
    #[error("content removal outcome is unknown; reopen before continuing: {reference:?}")]
    RemovalOutcomeUnknown {
        /// The non-secret immutable identity whose removal must be reconciled.
        reference: DurableContentRef,
    },
    /// Reconciliation removed at least one object before its outcome became uncertain.
    #[error("content reconciliation outcome is unknown; reopen before continuing")]
    ReconciliationOutcomeUnknown,
    /// This in-memory handle cannot safely continue after an uncertain mutation.
    #[error("content spool is poisoned after an uncertain commit; close and reopen it")]
    Poisoned,
    /// A deterministic test injector interrupted the named commit stage.
    #[error("content commit fault injected at {0:?}")]
    InjectedFault(ContentCommitStage),
    /// A host-filesystem operation failed with its local diagnostic context.
    #[error("content spool I/O failed during {operation} at {path:?}: {source}")]
    Io {
        /// Fixed, non-secret name of the failed filesystem operation.
        operation: &'static str,
        /// Local host path involved in the failure.
        path: PathBuf,
        /// Underlying operating-system I/O error.
        #[source]
        source: io::Error,
    },
}

impl SpoolError {
    pub(crate) fn io(operation: &'static str, path: PathBuf, source: io::Error) -> Self {
        Self::Io {
            operation,
            path,
            source,
        }
    }
}
