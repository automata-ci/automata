#![forbid(unsafe_code)]
//! Provider-neutral contracts for whole-job sandboxes and command execution.
//!
//! A [`SandboxProvider`] owns job-level isolation. [`ExecutionEndpoint`] is the
//! only interface used to execute inside an attached sandbox. The optional
//! [`ContainerEngine`] port is deliberately separate: Firecracker, Kubernetes,
//! native-process, and future platform providers need not pretend to be
//! container engines.

mod capability;
mod container;
mod endpoint;
mod error;
mod sandbox;
mod value;

pub use automata_core::{EnvironmentProfile, EnvironmentProfileId, OperationId, Sha256Digest};
pub use capability::{ProviderCapabilities, SandboxCapability};
pub use container::{
    ContainerCreateRequest, ContainerEngine, ContainerEngineCapabilities, ContainerHandle,
    ContainerInspection, ContainerRecord, ContainerState,
};
pub use endpoint::{
    Cancellation, CopyFromRequest, CopyToRequest, EnvironmentName, EnvironmentValue,
    EnvironmentVariable, ExecutionArgv, ExecutionCommand, ExecutionEndpoint, ExecutionEnvironment,
    ExecutionOutput, ExecutionSignal, ExecutionTermination, NeverCancelled, SignalRequest,
    WaitRequest,
};
pub use error::{
    ExecutionError, ExecutionErrorKind, ExecutionStage, OperationOutcome, ProviderError,
    ProviderErrorKind, ProviderStage, ValueError,
};
pub use sandbox::{
    DestroyDisposition, DestroySandbox, SandboxInspection, SandboxProvider, SandboxRecord,
    SandboxSpec, SandboxState,
};
pub use value::{
    ImmutableImage, NetworkPolicy, ProviderId, ResourceLimits, RootFilesystemPolicy,
    SandboxEnvironment, SandboxGeneration, SandboxHandle, SandboxPrivilegePolicy, TargetPath,
    TargetPlatform,
};

/// Maximum opaque provider handle length.
pub const MAX_SANDBOX_HANDLE_BYTES: usize = 192;
/// Maximum immutable image reference length.
pub const MAX_IMAGE_REFERENCE_BYTES: usize = 512;
/// Maximum execution argument count.
pub const MAX_EXECUTION_ARGUMENTS: usize = 4_096;
/// Maximum aggregate execution argv bytes.
pub const MAX_EXECUTION_ARGV_BYTES: usize = 1024 * 1024;
/// Maximum captured stdout plus stderr bytes requested from an endpoint.
pub const MAX_EXECUTION_OUTPUT_BYTES: usize = 16 * 1024 * 1024;
/// Maximum bytes transferred by one copy operation.
pub const MAX_COPY_BYTES: usize = 16 * 1024 * 1024;
