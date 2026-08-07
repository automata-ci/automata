use automata_runner_runtime::{ExecutorError, ExecutorErrorKind};
use thiserror::Error;

/// Sanitized failure returned by an executor dependency port.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
#[error("GitHub executor dependency failed: {kind:?}")]
pub struct PortError {
    kind: PortErrorKind,
}

impl PortError {
    /// Constructs a secret-free dependency failure.
    #[must_use]
    pub const fn new(kind: PortErrorKind) -> Self {
        Self { kind }
    }

    /// Returns the stable failure category.
    #[must_use]
    pub const fn kind(self) -> PortErrorKind {
        self.kind
    }
}

/// Stable dependency failure categories.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PortErrorKind {
    /// Requested data does not exist.
    NotFound,
    /// Credentials do not authorize the request.
    PermissionDenied,
    /// A dependency is temporarily unavailable.
    Unavailable,
    /// Data contradicted an immutable or bounded contract.
    InvalidData,
    /// A configured resource limit was exhausted.
    ResourceExhausted,
    /// The operation is not implemented by the selected adapter.
    Unsupported,
    /// An internal adapter invariant failed.
    Internal,
}

/// Sanitized action preparation failure.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
#[error("GitHub action preparation failed: {kind:?}")]
pub struct ActionPreparationError {
    kind: ActionPreparationErrorKind,
}

impl ActionPreparationError {
    /// Constructs a secret-free action failure.
    #[must_use]
    pub const fn new(kind: ActionPreparationErrorKind) -> Self {
        Self { kind }
    }

    /// Returns the stable failure category.
    #[must_use]
    pub const fn kind(self) -> ActionPreparationErrorKind {
        self.kind
    }
}

/// Stable action preparation failure categories.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ActionPreparationErrorKind {
    /// Only immutable repository actions are supported by this slice.
    UnsupportedReference,
    /// The immutable repository action could not be resolved.
    Resolution,
    /// Immutable archive content could not be loaded or verified.
    Content,
    /// Action metadata is malformed or unsupported.
    Metadata,
    /// Only metadata-driven JavaScript actions are supported by this slice.
    UnsupportedExecution,
    /// Action content exceeded an execution boundary.
    ResourceExhausted,
    /// A dependency refused credentials.
    PermissionDenied,
    /// An internal adapter invariant failed.
    Internal,
}

/// Internal secret-free executor failure used before the runner boundary.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
#[error("GitHub job executor failed: {kind:?}")]
pub struct ExecutorAdapterError {
    kind: ExecutorAdapterErrorKind,
}

impl ExecutorAdapterError {
    pub(crate) const fn new(kind: ExecutorAdapterErrorKind) -> Self {
        Self { kind }
    }

    pub(crate) const fn kind(self) -> ExecutorAdapterErrorKind {
        self.kind
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ExecutorAdapterErrorKind {
    InvalidJob,
    Unsupported,
    ResourceExhausted,
    PermissionDenied,
    Unavailable,
    TimedOut,
    Cancelled,
    Internal,
}

impl From<ExecutorAdapterError> for ExecutorError {
    fn from(value: ExecutorAdapterError) -> Self {
        let kind = match value.kind() {
            ExecutorAdapterErrorKind::InvalidJob => ExecutorErrorKind::InvalidJob,
            ExecutorAdapterErrorKind::Unsupported => ExecutorErrorKind::Unsupported,
            ExecutorAdapterErrorKind::ResourceExhausted => ExecutorErrorKind::ResourceExhausted,
            ExecutorAdapterErrorKind::PermissionDenied => ExecutorErrorKind::PermissionDenied,
            ExecutorAdapterErrorKind::Unavailable => ExecutorErrorKind::Unavailable,
            ExecutorAdapterErrorKind::TimedOut => ExecutorErrorKind::TimedOut,
            ExecutorAdapterErrorKind::Cancelled => ExecutorErrorKind::Cancelled,
            ExecutorAdapterErrorKind::Internal => ExecutorErrorKind::Internal,
        };
        Self::new(kind)
    }
}
