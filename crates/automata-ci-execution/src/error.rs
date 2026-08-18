use std::fmt;

use thiserror::Error;

use crate::SandboxHandle;

/// Rejected provider-neutral value construction.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum ValueError {
    /// A provider identifier was empty, oversized, or not portable ASCII.
    #[error("provider identifier is invalid")]
    InvalidProviderId,
    /// A sandbox generation was zero or could not fit the durable domain.
    #[error("sandbox generation must be non-zero and durably representable")]
    InvalidSandboxGeneration,
    /// A provider or container handle was empty, oversized, or not portable.
    #[error("opaque sandbox handle is invalid")]
    InvalidSandboxHandle,
    /// An image reference was mutable, malformed, ambiguous, or oversized.
    #[error("immutable image reference must end in one exact sha256 digest")]
    InvalidImmutableImage,
    /// A path was not a normalized absolute path for its target platform.
    #[error("sandbox target path is invalid for its declared platform")]
    InvalidTargetPath,
    /// An argv vector contained a nul byte or exceeded a count or byte bound.
    #[error("execution argv is oversized or contains an invalid value")]
    InvalidExecutionArgv,
    /// An environment name was empty, malformed, or outside its hard bound.
    #[error("execution environment name is invalid")]
    InvalidEnvironmentName,
    /// An environment value contained a nul byte or exceeded its hard bound.
    #[error("execution environment value is oversized or contains a nul byte")]
    InvalidEnvironmentValue,
    /// An environment contained duplicate names or exceeded aggregate bounds.
    #[error("execution environment is duplicated or exceeds its aggregate bound")]
    InvalidExecutionEnvironment,
    /// One or more requested resource limits were zero or outside hard bounds.
    #[error("resource limits are zero, incoherent, or exceed hard bounds")]
    InvalidResourceLimits,
    /// An operation timeout was zero or longer than the global maximum.
    #[error("operation timeout is zero or exceeds the hard bound")]
    InvalidTimeout,
    /// An output/copy bound was invalid or a payload exceeded the hard maximum.
    #[error("operation output or copy limit is zero or exceeds the hard bound")]
    InvalidByteLimit,
    /// Captured process output was unordered, structurally incomplete, or malformed.
    #[error("execution output record sequence is invalid")]
    InvalidExecutionOutput,
    /// A capability declaration was empty, duplicated, or oversized.
    #[error("provider capability set is empty, duplicated, or oversized")]
    InvalidCapabilities,
    /// A service request or discovered service view violated its invariants.
    #[error("service container request or discovery data is invalid")]
    InvalidServiceContainer,
}

/// Whether a failed mutating provider operation is proven not to have changed
/// external state or requires recovery inspection.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum OperationOutcome {
    /// The adapter proved that the failed operation made no external change.
    KnownNoEffect,
    /// The adapter cannot prove whether the failed operation changed state.
    ///
    /// Callers must reconcile through the exact recovery handle or retry the
    /// same idempotently identified request; they must not treat this as an
    /// absent resource.
    Uncertain,
}

/// Stable stage at which a sandbox-provider operation failed.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum ProviderStage {
    /// Provider-side request and policy validation.
    Validate,
    /// Creation of the sandbox-owned workspace.
    CreateWorkspace,
    /// Creation of the sandbox-owned network boundary.
    CreateNetwork,
    /// Creation of the provider's whole-job isolation boundary.
    CreateSandbox,
    /// Creation of a lower-level container resource.
    CreateContainer,
    /// Starting the sandbox's primary workload.
    Start,
    /// Attaching an execution endpoint to an owned sandbox.
    Attach,
    /// Reading current backend state for an exact handle.
    Inspect,
    /// Verifying that a backend resource belongs to the expected sandbox.
    VerifyOwnership,
    /// Removing a sandbox-owned lower-level container.
    DestroyContainer,
    /// Removing the provider's whole-job isolation boundary.
    DestroySandbox,
    /// Removing the sandbox-owned network boundary.
    DestroyNetwork,
    /// Removing the sandbox-owned workspace.
    DestroyWorkspace,
}

/// Bounded provider failure classification; raw backend diagnostics and
/// credentials cannot enter this model.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum ProviderErrorKind {
    /// The adapter cannot realize the requested target platform.
    UnsupportedPlatform,
    /// The adapter did not advertise or cannot honor a requested capability.
    UnsupportedCapability,
    /// Cooperative cancellation was observed before completion.
    Cancelled,
    /// The bounded operation did not complete before its deadline.
    TimedOut,
    /// The provider backend or its local control channel is unavailable.
    AdapterUnavailable,
    /// Provider configuration cannot safely realize the request.
    InvalidConfiguration,
    /// The exact provider-owned resource does not exist.
    NotFound,
    /// Existing external state conflicts with the idempotent request.
    Conflict,
    /// A resource exists but is not owned by the expected sandbox identity.
    OwnershipMismatch,
    /// The owned resource exists in a state that disallows the operation.
    InvalidState,
    /// Captured or transferred bytes would exceed the caller's hard limit.
    OutputLimitExceeded,
    /// The backend rejected an otherwise valid operation.
    BackendRejected,
    /// Runner-local durable or temporary storage failed.
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
    /// Creates a bounded, secret-free provider failure.
    ///
    /// A recovery handle should be present only when it identifies the exact
    /// resource needed to reconcile an [`OperationOutcome::Uncertain`]
    /// mutation. The constructor deliberately performs no backend inspection.
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
    /// Returns the stable failure classification.
    pub const fn kind(&self) -> ProviderErrorKind {
        self.kind
    }

    #[must_use]
    /// Returns the lifecycle stage at which the failure occurred.
    pub const fn stage(&self) -> ProviderStage {
        self.stage
    }

    #[must_use]
    /// Returns whether a failed mutation is known to have had no effect.
    pub const fn outcome(&self) -> OperationOutcome {
        self.outcome
    }

    #[must_use]
    /// Returns the opaque handle available for exact recovery inspection.
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
    /// Executing one literal argv request.
    Exec,
    /// Signalling the primary workload.
    Signal,
    /// Waiting for the primary workload to terminate.
    Wait,
    /// Copying bounded bytes into the sandbox.
    CopyTo,
    /// Copying bounded bytes out of the sandbox.
    CopyFrom,
}

/// Bounded execution failure classification.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum ExecutionErrorKind {
    /// The attached endpoint does not support the requested operation.
    UnsupportedCapability,
    /// The execution environment violates provider-specific policy.
    InvalidEnvironment,
    /// Cooperative cancellation was observed before completion.
    Cancelled,
    /// The bounded operation did not complete before its deadline.
    TimedOut,
    /// The attached sandbox or requested target no longer exists.
    NotFound,
    /// The resource no longer belongs to the attached sandbox identity.
    OwnershipMismatch,
    /// The sandbox is not in a state that permits the operation.
    InvalidState,
    /// Captured or transferred bytes would exceed the request's hard limit.
    OutputLimitExceeded,
    /// The caller's incremental output sink rejected an observed record.
    OutputRejected,
    /// The execution backend rejected an otherwise valid operation.
    BackendRejected,
    /// Runner-local durable or temporary storage failed.
    LocalStorage,
}

/// Secret-free execution failure.
///
/// Endpoint requests carry operation identifiers as correlation keys for a
/// caller-owned exact-request replay boundary; they do not make a raw endpoint
/// retryable. Adapters must not embed raw backend diagnostics, command output,
/// paths, environment values, or copied payloads in this error.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
#[error("execution endpoint failed during {stage:?}: {kind:?}")]
pub struct ExecutionError {
    kind: ExecutionErrorKind,
    stage: ExecutionStage,
}

impl ExecutionError {
    /// Creates a bounded, secret-free endpoint failure.
    #[must_use]
    pub const fn new(kind: ExecutionErrorKind, stage: ExecutionStage) -> Self {
        Self { kind, stage }
    }

    #[must_use]
    /// Returns the stable failure classification.
    pub const fn kind(self) -> ExecutionErrorKind {
        self.kind
    }

    #[must_use]
    /// Returns the endpoint operation that failed.
    pub const fn stage(self) -> ExecutionStage {
        self.stage
    }
}
