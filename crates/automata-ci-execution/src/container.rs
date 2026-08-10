use std::fmt;

use crate::{
    Cancellation, ExecutionEndpoint, NetworkPolicy, OperationId, ProviderError, ResourceLimits,
    SandboxEnvironment, SandboxGeneration, SandboxState, ValueError,
};

/// Opaque handle used only below the optional container-engine boundary.
#[derive(Clone, Eq, Hash, PartialEq)]
pub struct ContainerHandle(String);

impl ContainerHandle {
    /// Creates a bounded portable engine token.
    ///
    /// # Errors
    ///
    /// Rejects empty, oversized, or path-like tokens.
    pub fn new(value: impl Into<String>) -> Result<Self, ValueError> {
        let value = value.into();
        let valid = !value.is_empty()
            && value.len() <= crate::MAX_SANDBOX_HANDLE_BYTES
            && value
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b"._-".contains(&byte));
        valid
            .then_some(Self(value))
            .ok_or(ValueError::InvalidSandboxHandle)
    }

    /// Borrows the engine-owned token.
    ///
    /// Consumers must treat this value as opaque and must not derive host
    /// paths, container names, or authorization decisions from its contents.
    #[must_use]
    pub fn opaque(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for ContainerHandle {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ContainerHandle([OPAQUE])")
    }
}

/// Explicit optional engine abilities, distinct from job-sandbox abilities.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ContainerEngineCapabilities {
    exec: bool,
    copy: bool,
}

impl ContainerEngineCapabilities {
    /// Declares whether the engine supports command execution and byte copies.
    #[must_use]
    pub const fn new(exec: bool, copy: bool) -> Self {
        Self { exec, copy }
    }

    /// Returns whether attached containers support command execution.
    #[must_use]
    pub const fn exec(self) -> bool {
        self.exec
    }

    /// Returns whether attached containers support bounded copy operations.
    #[must_use]
    pub const fn copy(self) -> bool {
        self.copy
    }
}

/// Lower-level immutable container request for container-based providers.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ContainerCreateRequest {
    operation_id: OperationId,
    generation: SandboxGeneration,
    profile: SandboxEnvironment,
    network: NetworkPolicy,
    resources: ResourceLimits,
}

impl ContainerCreateRequest {
    /// Creates an exact, idempotently identified lower-level request.
    ///
    /// The generation fences reuse of any engine resource recovered for this
    /// request. The profile, network policy, and resource limits are the
    /// scheduler-authorized values the engine must enforce.
    #[must_use]
    pub const fn new(
        operation_id: OperationId,
        generation: SandboxGeneration,
        profile: SandboxEnvironment,
        network: NetworkPolicy,
        resources: ResourceLimits,
    ) -> Self {
        Self {
            operation_id,
            generation,
            profile,
            network,
            resources,
        }
    }

    /// Returns the stable identifier used for exact create replay.
    #[must_use]
    pub const fn operation_id(&self) -> OperationId {
        self.operation_id
    }

    /// Returns the generation that fences resource reuse.
    #[must_use]
    pub const fn generation(&self) -> SandboxGeneration {
        self.generation
    }

    /// Returns the exact attested launch environment.
    #[must_use]
    pub const fn profile(&self) -> &SandboxEnvironment {
        &self.profile
    }

    /// Returns the network-isolation policy the engine must enforce.
    #[must_use]
    pub const fn network(&self) -> NetworkPolicy {
        self.network
    }

    /// Returns the hard resource limits the engine must enforce.
    #[must_use]
    pub const fn resources(&self) -> ResourceLimits {
        self.resources
    }
}

/// Successful lower-level engine create/replay.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ContainerRecord {
    handle: ContainerHandle,
    state: ContainerState,
}

impl ContainerRecord {
    /// Records the handle and state returned by a successful create or replay.
    #[must_use]
    pub const fn new(handle: ContainerHandle, state: ContainerState) -> Self {
        Self { handle, state }
    }

    /// Returns the opaque engine handle for subsequent exact operations.
    #[must_use]
    pub const fn handle(&self) -> &ContainerHandle {
        &self.handle
    }

    /// Returns the state reached by the create or replay.
    #[must_use]
    pub const fn state(&self) -> ContainerState {
        self.state
    }
}

/// Lower-level engine state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ContainerState {
    /// No engine resource exists for the exact handle.
    Absent,
    /// The resource exists but its primary workload has not started.
    Created,
    /// The resource's primary workload is running.
    Running,
    /// The resource exists and its primary workload has stopped.
    Stopped,
}

impl From<ContainerState> for SandboxState {
    fn from(value: ContainerState) -> Self {
        match value {
            ContainerState::Absent => Self::Absent,
            ContainerState::Created => Self::Created,
            ContainerState::Running => Self::Running,
            ContainerState::Stopped => Self::Stopped,
        }
    }
}

/// Current lower-level engine view.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ContainerInspection {
    handle: ContainerHandle,
    state: ContainerState,
}

impl ContainerInspection {
    /// Records the current state recovered for an exact engine handle.
    #[must_use]
    pub const fn new(handle: ContainerHandle, state: ContainerState) -> Self {
        Self { handle, state }
    }

    /// Returns the exact opaque handle that was inspected.
    #[must_use]
    pub const fn handle(&self) -> &ContainerHandle {
        &self.handle
    }

    /// Returns the engine state observed for the handle.
    #[must_use]
    pub const fn state(&self) -> ContainerState {
        self.state
    }
}

/// Optional object-safe low-level port for providers implemented with a
/// container engine. It is intentionally not a supertrait of
/// [`crate::SandboxProvider`].
pub trait ContainerEngine: fmt::Debug + Send + Sync {
    /// Returns the fixed optional operations implemented by this adapter.
    fn capabilities(&self) -> ContainerEngineCapabilities;

    /// Creates or exactly replays a container.
    ///
    /// Reusing an operation identifier with different request material must
    /// fail closed. A successful replay returns the same owned resource rather
    /// than creating a second container.
    ///
    /// # Errors
    ///
    /// Returns a typed provider failure.
    fn create_container(
        &self,
        request: &ContainerCreateRequest,
        cancellation: &dyn Cancellation,
    ) -> Result<ContainerRecord, ProviderError>;

    /// Starts an owned container idempotently.
    ///
    /// Implementations must verify that `handle` belongs to their ownership
    /// domain before mutation.
    ///
    /// # Errors
    ///
    /// Returns a typed provider failure.
    fn start_container(
        &self,
        handle: &ContainerHandle,
        cancellation: &dyn Cancellation,
    ) -> Result<ContainerRecord, ProviderError>;

    /// Inspects an exact engine token without broad resource enumeration.
    ///
    /// # Errors
    ///
    /// Returns a typed provider failure.
    fn inspect_container(
        &self,
        handle: &ContainerHandle,
        cancellation: &dyn Cancellation,
    ) -> Result<ContainerInspection, ProviderError>;

    /// Attaches the engine execution endpoint after exact ownership checks.
    ///
    /// # Errors
    ///
    /// Returns a typed provider failure.
    fn attach_container(
        &self,
        handle: &ContainerHandle,
        cancellation: &dyn Cancellation,
    ) -> Result<Box<dyn ExecutionEndpoint>, ProviderError>;

    /// Removes an exact owned container idempotently.
    ///
    /// Implementations must bind `operation_id` to this exact request, verify
    /// ownership immediately before deletion, and never use global prune or
    /// label-wide deletion.
    ///
    /// # Errors
    ///
    /// Returns a typed provider failure.
    fn remove_container(
        &self,
        operation_id: OperationId,
        handle: &ContainerHandle,
        cancellation: &dyn Cancellation,
    ) -> Result<(), ProviderError>;
}
