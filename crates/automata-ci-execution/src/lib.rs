#![forbid(unsafe_code)]
#![deny(missing_docs)]
//! Provider-neutral contracts for whole-job sandboxes and command execution.
//!
//! A [`SandboxProvider`] owns job-level isolation and any service containers
//! attached to it. [`ExecutionEndpoint`] is the only interface used to execute
//! inside an attached sandbox. Service discovery crosses the boundary through
//! [`ServiceContainerBindings`] and opaque [`ContainerHandle`] values rather
//! than backend-specific container operations.
//!
//! # Trust boundary
//!
//! Values crossing into a provider are bounded and validated, but adapters
//! still own enforcement of the requested capabilities, resource limits,
//! filesystem policy, and network isolation. Paths are sandbox target paths,
//! never host paths. Provider and container handles are opaque ownership
//! tokens; callers must not parse them or substitute backend identifiers.
//!
//! Sandbox-provider mutations carry an [`OperationId`] for exact, idempotent
//! lifecycle replay. When a lifecycle backend might have changed external
//! state, a [`ProviderError`] reports [`OperationOutcome::Uncertain`] and may
//! carry a recovery handle. Callers must reconcile or retry that exact
//! lifecycle request rather than assuming it had no effect.
//!
//! Execution-endpoint requests also carry an [`OperationId`], but a raw
//! endpoint adapter may be attempt-once. Callers that can retry must install a
//! durable decorator that binds the identifier to the complete request and its
//! protected result. Direct callers must not retry a raw endpoint operation
//! after an ambiguous return.
//!
//! Environment values, argv entries, copied bytes, output, health commands,
//! and opaque handles are redacted from selected `Debug` implementations.
//! Their explicit accessors still expose the underlying data, so consumers
//! must keep those values out of logs and durable diagnostics.

mod capability;
mod endpoint;
mod error;
mod runtime_service;
mod sandbox;
mod service;
mod value;

pub use automata_ci_core::{
    AttemptId, EnvironmentProfile, EnvironmentProfileId, FencingToken, JobId, JobIrVersion,
    JobResourceAllocation, LeaseGuard, LeaseId, OperationId, ResourceCapacity, RunId, RunnerId,
    RunnerSessionId, SANDBOX_AUTHORIZATIONS_SCHEMA_VERSION, SandboxAuthorization,
    SandboxAuthorizationError, SandboxAuthorizationName, SandboxAuthorizations, Sha256Digest,
};
pub use capability::{ProviderCapabilities, SandboxCapability};
pub use endpoint::{
    Cancellation, CancellationDisposition, CopyFromRequest, CopyToRequest, EnvironmentName,
    EnvironmentValue, EnvironmentVariable, ExecutionArgv, ExecutionCommand, ExecutionEndpoint,
    ExecutionEnvironment, ExecutionOutput, ExecutionOutputRecord, ExecutionOutputSink,
    ExecutionOutputSinkError, ExecutionOutputStream, ExecutionSignal, ExecutionTermination,
    MAX_ENDPOINT_OPERATIONS_PER_JOB, NeverCancelled, SignalRequest, WaitRequest,
    discard_execution_output,
};
pub use error::{
    ExecutionError, ExecutionErrorKind, ExecutionStage, OperationOutcome, ProviderError,
    ProviderErrorKind, ProviderStage, ValueError,
};
pub use runtime_service::{
    MAX_RUNTIME_SERVICE_ROUTES, RuntimeServiceProtocol, RuntimeServiceRoute, RuntimeServiceRoutes,
};
pub use sandbox::{
    DestroyDisposition, DestroySandbox, SandboxCustody, SandboxExecutionBinding, SandboxInspection,
    SandboxProvider, SandboxRecord, SandboxSpec, SandboxState,
};
pub use service::{
    ContainerHandle, ServiceContainerBinding, ServiceContainerBindings, ServiceContainerSpec,
    ServiceContainerSpecs, ServiceHealthOverrides, ServiceHealthPolicy, ServiceNetwork,
    ServicePort, ServicePortBinding, ServiceTransportProtocol,
};
pub use value::{
    ImmutableImage, NetworkPolicy, ProviderId, ResourceLimits, RootFilesystemPolicy,
    SandboxEnvironment, SandboxGeneration, SandboxHandle, SandboxLaunch, SandboxPrivilegePolicy,
    TargetPath, TargetPlatform,
};

/// Maximum encoded length, in bytes, of an opaque provider or container handle.
pub const MAX_SANDBOX_HANDLE_BYTES: usize = 192;
/// Maximum encoded length, in bytes, of an immutable image reference.
pub const MAX_IMAGE_REFERENCE_BYTES: usize = 512;
/// Maximum number of literal arguments, excluding the executable path.
pub const MAX_EXECUTION_ARGUMENTS: usize = 4_096;
/// Maximum aggregate bytes in the executable path and literal arguments.
pub const MAX_EXECUTION_ARGV_BYTES: usize = 1024 * 1024;
/// Maximum aggregate captured stdout and stderr bytes for one command.
pub const MAX_EXECUTION_OUTPUT_BYTES: usize = 16 * 1024 * 1024;
/// Maximum bytes carried by one ordered execution-output data record.
pub const MAX_EXECUTION_OUTPUT_RECORD_BYTES: usize = 64 * 1024;
/// Maximum ordered data and end-of-stream records retained for one command.
pub const MAX_EXECUTION_OUTPUT_RECORDS: usize = 65_536;
/// Maximum payload bytes transferred by one copy operation.
pub const MAX_COPY_BYTES: usize = 16 * 1024 * 1024;
