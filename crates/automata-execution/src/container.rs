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
    #[must_use]
    pub const fn new(exec: bool, copy: bool) -> Self {
        Self { exec, copy }
    }

    #[must_use]
    pub const fn exec(self) -> bool {
        self.exec
    }

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

    #[must_use]
    pub const fn operation_id(&self) -> OperationId {
        self.operation_id
    }

    #[must_use]
    pub const fn generation(&self) -> SandboxGeneration {
        self.generation
    }

    #[must_use]
    pub const fn profile(&self) -> &SandboxEnvironment {
        &self.profile
    }

    #[must_use]
    pub const fn network(&self) -> NetworkPolicy {
        self.network
    }

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
    #[must_use]
    pub const fn new(handle: ContainerHandle, state: ContainerState) -> Self {
        Self { handle, state }
    }

    #[must_use]
    pub const fn handle(&self) -> &ContainerHandle {
        &self.handle
    }

    #[must_use]
    pub const fn state(&self) -> ContainerState {
        self.state
    }
}

/// Lower-level engine state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ContainerState {
    Absent,
    Created,
    Running,
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
    #[must_use]
    pub const fn new(handle: ContainerHandle, state: ContainerState) -> Self {
        Self { handle, state }
    }

    #[must_use]
    pub const fn handle(&self) -> &ContainerHandle {
        &self.handle
    }

    #[must_use]
    pub const fn state(&self) -> ContainerState {
        self.state
    }
}

/// Optional object-safe low-level port for providers implemented with a
/// container engine. It is intentionally not a supertrait of
/// [`crate::SandboxProvider`].
pub trait ContainerEngine: fmt::Debug + Send + Sync {
    fn capabilities(&self) -> ContainerEngineCapabilities;

    /// Creates or exactly replays a container.
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
    /// # Errors
    ///
    /// Returns a typed provider failure.
    fn start_container(
        &self,
        handle: &ContainerHandle,
        cancellation: &dyn Cancellation,
    ) -> Result<ContainerRecord, ProviderError>;

    /// Inspects an exact engine token.
    ///
    /// # Errors
    ///
    /// Returns a typed provider failure.
    fn inspect_container(
        &self,
        handle: &ContainerHandle,
        cancellation: &dyn Cancellation,
    ) -> Result<ContainerInspection, ProviderError>;

    /// Attaches the engine execution endpoint.
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
