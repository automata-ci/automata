use std::{io, path::PathBuf};

use thiserror::Error;

use crate::{ContentCommitStage, DurableContentRef};

/// Rejected spool-root configuration.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum SpoolRootError {
    #[error("runner spool root must be an absolute path")]
    Relative,
    #[error("runner spool root cannot be the filesystem root")]
    FilesystemRoot,
    #[error("runner spool root contains a traversal component")]
    Traversal,
    #[error("runner spool root cannot be placed in a system temporary hierarchy")]
    TemporaryHierarchy,
    #[error("XDG state home must be supplied explicitly and cannot be empty")]
    MissingXdgStateHome,
}

/// Invalid bounded content metadata or spool limits.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum SpoolInvariantError {
    #[error("content protection identifier is invalid")]
    InvalidProtectionId,
    #[error("content cache key is invalid or does not match its content identity")]
    InvalidCacheKey,
    #[error("content exceeds the hard object-size limit")]
    ObjectTooLarge,
    #[error("spool limits are zero, inverted, or exceed hard bounds")]
    InvalidLimits,
    #[error("protected content exceeds the configured expansion limit")]
    ProtectionOverheadExceeded,
    #[error("content bytes do not match their durable size or SHA-256 identity")]
    ContentMismatch,
}

/// Secret-free error returned by a content-protection adapter.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum ContentProtectionError {
    #[error("content protection key is unavailable")]
    KeyUnavailable,
    #[error("protected content authentication failed")]
    AuthenticationFailed,
    #[error("content protection operation failed")]
    Failed,
}

/// Secret-free failure returned while capturing a complete durable retain set.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum RetainedContentError {
    #[error("durable content retain set is temporarily unavailable")]
    Unavailable,
}

/// Typed storage, protection, capacity, and commit failures.
#[derive(Debug, Error)]
pub enum SpoolError {
    #[error(transparent)]
    Root(#[from] SpoolRootError),
    #[error(transparent)]
    Invariant(#[from] SpoolInvariantError),
    #[error(transparent)]
    Protection(#[from] ContentProtectionError),
    #[error("another process already owns the runner content spool lock")]
    AlreadyLocked,
    #[error("the runner content spool has no filesystem adapter for this platform")]
    UnsupportedPlatform,
    #[error("spool path is a symlink, non-directory component, or escaped the configured root")]
    PathSecurity,
    #[error("runner content spool capacity is exhausted")]
    CapacityExhausted,
    #[error("content reconciliation is fenced by an in-flight journal publication")]
    PublicationsInFlight,
    #[error("content publication is fenced by an active reconciliation")]
    ReconciliationInProgress,
    #[error(transparent)]
    RetainedContent(#[from] RetainedContentError),
    #[error("durable content is missing from the spool")]
    ContentMissing,
    #[error("content commit outcome is unknown; reopen and re-persist before continuing")]
    CommitOutcomeUnknown,
    #[error("content removal outcome is unknown; reopen before continuing: {reference:?}")]
    RemovalOutcomeUnknown { reference: DurableContentRef },
    #[error("content reconciliation outcome is unknown; reopen before continuing")]
    ReconciliationOutcomeUnknown,
    #[error("content spool is poisoned after an uncertain commit; close and reopen it")]
    Poisoned,
    #[error("content commit fault injected at {0:?}")]
    InjectedFault(ContentCommitStage),
    #[error("content spool I/O failed during {operation} at {path:?}: {source}")]
    Io {
        operation: &'static str,
        path: PathBuf,
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
