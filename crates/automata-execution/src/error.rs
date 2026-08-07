use std::fmt;

use thiserror::Error;

use crate::SandboxHandle;

/// Rejected provider-neutral value construction.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum ValueError {
    #[error("provider identifier is invalid")]
    InvalidProviderId,
    #[error("sandbox generation must be non-zero and durably representable")]
    InvalidSandboxGeneration,
    #[error("opaque sandbox handle is invalid")]
    InvalidSandboxHandle,
    #[error("immutable image reference must end in one exact sha256 digest")]
    InvalidImmutableImage,
    #[error("sandbox target path is invalid for its declared platform")]
    InvalidTargetPath,
    #[error("execution argv is empty, oversized, or contains an invalid value")]
    InvalidExecutionArgv,
    #[error("execution environment name is invalid")]
    InvalidEnvironmentName,
    #[error("execution environment value is oversized or contains a nul byte")]
    InvalidEnvironmentValue,
    #[error("execution environment is duplicated or exceeds its aggregate bound")]
    InvalidExecutionEnvironment,
    #[error("resource limits are zero, incoherent, or exceed hard bounds")]
    InvalidResourceLimits,
    #[error("operation timeout is zero or exceeds the hard bound")]
    InvalidTimeout,
    #[error("operation output or copy limit is zero or exceeds the hard bound")]
    InvalidByteLimit,
    #[error("provider capability set is empty, duplicated, or oversized")]
    InvalidCapabilities,
}

/// Whether a failed mutating provider operation is proven not to have changed
/// external state or requires recovery inspection.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum OperationOutcome {
    KnownNoEffect,
    Uncertain,
}

/// Stable stage at which a sandbox-provider operation failed.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum ProviderStage {
    Validate,
    CreateWorkspace,
    CreateNetwork,
    CreateSandbox,
    CreateContainer,
    Start,
    Attach,
    Inspect,
    VerifyOwnership,
    DestroyContainer,
    DestroySandbox,
    DestroyNetwork,
    DestroyWorkspace,
}

/// Bounded provider failure classification; raw backend diagnostics and
/// credentials cannot enter this model.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum ProviderErrorKind {
    UnsupportedPlatform,
    UnsupportedCapability,
    Cancelled,
    TimedOut,
    AdapterUnavailable,
    InvalidConfiguration,
    NotFound,
    Conflict,
    OwnershipMismatch,
    InvalidState,
    OutputLimitExceeded,
    BackendRejected,
    LocalStorage,
}

/// Secret-free sandbox-provider failure with optional opaque recovery handle.
#[derive(Clone, Eq, PartialEq)]
pub struct ProviderError {
    kind: ProviderErrorKind,
    stage: ProviderStage,
    outcome: OperationOutcome,
    recovery_handle: Option<SandboxHandle>,
}

impl ProviderError {
    #[must_use]
    pub const fn new(
        kind: ProviderErrorKind,
        stage: ProviderStage,
        outcome: OperationOutcome,
        recovery_handle: Option<SandboxHandle>,
    ) -> Self {
        Self {
            kind,
            stage,
            outcome,
            recovery_handle,
        }
    }

    #[must_use]
    pub const fn kind(&self) -> ProviderErrorKind {
        self.kind
    }

    #[must_use]
    pub const fn stage(&self) -> ProviderStage {
        self.stage
    }

    #[must_use]
    pub const fn outcome(&self) -> OperationOutcome {
        self.outcome
    }

    #[must_use]
    pub const fn recovery_handle(&self) -> Option<&SandboxHandle> {
        self.recovery_handle.as_ref()
    }
}

impl fmt::Debug for ProviderError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProviderError")
            .field("kind", &self.kind)
            .field("stage", &self.stage)
            .field("outcome", &self.outcome)
            .field("recovery_handle", &self.recovery_handle)
            .finish()
    }
}

impl fmt::Display for ProviderError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "sandbox provider failed during {:?}: {:?} ({:?})",
            self.stage, self.kind, self.outcome
        )
    }
}

impl std::error::Error for ProviderError {}

/// Stable execution-endpoint operation stage.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum ExecutionStage {
    Exec,
    Signal,
    Wait,
    CopyTo,
    CopyFrom,
}

/// Bounded execution failure classification.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum ExecutionErrorKind {
    UnsupportedCapability,
    InvalidEnvironment,
    Cancelled,
    TimedOut,
    NotFound,
    OwnershipMismatch,
    InvalidState,
    OutputLimitExceeded,
    BackendRejected,
    LocalStorage,
}

/// Secret-free execution failure.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
#[error("execution endpoint failed during {stage:?}: {kind:?}")]
pub struct ExecutionError {
    kind: ExecutionErrorKind,
    stage: ExecutionStage,
}

impl ExecutionError {
    #[must_use]
    pub const fn new(kind: ExecutionErrorKind, stage: ExecutionStage) -> Self {
        Self { kind, stage }
    }

    #[must_use]
    pub const fn kind(self) -> ExecutionErrorKind {
        self.kind
    }

    #[must_use]
    pub const fn stage(self) -> ExecutionStage {
        self.stage
    }
}
