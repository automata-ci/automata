use std::fmt;

use crate::{
    Cancellation, EnvironmentProfile, ExecutionEndpoint, NetworkPolicy, OperationId,
    ProviderCapabilities, ProviderError, ProviderId, ResourceLimits, RootFilesystemPolicy,
    SandboxEnvironment, SandboxGeneration, SandboxHandle, SandboxPrivilegePolicy, TargetPath,
};

/// Immutable whole-job sandbox request. The profile is exact and contains no
/// hosted-label resolution or mutable image reference.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SandboxSpec {
    operation_id: OperationId,
    generation: SandboxGeneration,
    profile: SandboxEnvironment,
    workspace: TargetPath,
    network: NetworkPolicy,
    root_filesystem: RootFilesystemPolicy,
    privilege: SandboxPrivilegePolicy,
    resources: ResourceLimits,
}

impl SandboxSpec {
    #[must_use]
    pub const fn new(
        operation_id: OperationId,
        generation: SandboxGeneration,
        profile: SandboxEnvironment,
        workspace: TargetPath,
        network: NetworkPolicy,
        root_filesystem: RootFilesystemPolicy,
        resources: ResourceLimits,
    ) -> Self {
        Self {
            operation_id,
            generation,
            profile,
            workspace,
            network,
            root_filesystem,
            privilege: SandboxPrivilegePolicy::Unprivileged,
            resources,
        }
    }

    /// Selects process privilege inside the provider's isolation boundary.
    #[must_use]
    pub const fn with_privilege(mut self, privilege: SandboxPrivilegePolicy) -> Self {
        self.privilege = privilege;
        self
    }

    /// Selects root-filesystem mutability for a profile-specific launch.
    #[must_use]
    pub const fn with_root_filesystem(mut self, root_filesystem: RootFilesystemPolicy) -> Self {
        self.root_filesystem = root_filesystem;
        self
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

    /// Returns the exact per-job workspace target mounted by the provider.
    #[must_use]
    pub const fn workspace(&self) -> &TargetPath {
        &self.workspace
    }

    #[must_use]
    pub const fn network(&self) -> NetworkPolicy {
        self.network
    }

    #[must_use]
    pub const fn root_filesystem(&self) -> RootFilesystemPolicy {
        self.root_filesystem
    }

    #[must_use]
    pub const fn privilege(&self) -> SandboxPrivilegePolicy {
        self.privilege
    }

    #[must_use]
    pub const fn resources(&self) -> ResourceLimits {
        self.resources
    }
}

/// Provider-neutral sandbox lifecycle state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SandboxState {
    Absent,
    Created,
    Running,
    Stopped,
    Degraded,
}

/// Successful create/replay result.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SandboxRecord {
    handle: SandboxHandle,
    generation: SandboxGeneration,
    profile: EnvironmentProfile,
    state: SandboxState,
}

impl SandboxRecord {
    #[must_use]
    pub const fn new(
        handle: SandboxHandle,
        generation: SandboxGeneration,
        profile: EnvironmentProfile,
        state: SandboxState,
    ) -> Self {
        Self {
            handle,
            generation,
            profile,
            state,
        }
    }

    #[must_use]
    pub const fn handle(&self) -> &SandboxHandle {
        &self.handle
    }

    #[must_use]
    pub const fn generation(&self) -> SandboxGeneration {
        self.generation
    }

    #[must_use]
    pub const fn profile(&self) -> &EnvironmentProfile {
        &self.profile
    }

    #[must_use]
    pub const fn state(&self) -> SandboxState {
        self.state
    }
}

/// Current provider-neutral recovery view.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SandboxInspection {
    handle: SandboxHandle,
    generation: SandboxGeneration,
    profile: EnvironmentProfile,
    state: SandboxState,
}

impl SandboxInspection {
    #[must_use]
    pub const fn new(
        handle: SandboxHandle,
        generation: SandboxGeneration,
        profile: EnvironmentProfile,
        state: SandboxState,
    ) -> Self {
        Self {
            handle,
            generation,
            profile,
            state,
        }
    }

    #[must_use]
    pub const fn handle(&self) -> &SandboxHandle {
        &self.handle
    }

    #[must_use]
    pub const fn generation(&self) -> SandboxGeneration {
        self.generation
    }

    #[must_use]
    pub const fn profile(&self) -> &EnvironmentProfile {
        &self.profile
    }

    #[must_use]
    pub const fn state(&self) -> SandboxState {
        self.state
    }
}

/// Idempotently identified exact destroy request.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DestroySandbox {
    operation_id: OperationId,
    handle: SandboxHandle,
    generation: SandboxGeneration,
}

impl DestroySandbox {
    #[must_use]
    pub const fn new(
        operation_id: OperationId,
        handle: SandboxHandle,
        generation: SandboxGeneration,
    ) -> Self {
        Self {
            operation_id,
            handle,
            generation,
        }
    }

    #[must_use]
    pub const fn operation_id(&self) -> OperationId {
        self.operation_id
    }

    #[must_use]
    pub const fn handle(&self) -> &SandboxHandle {
        &self.handle
    }

    #[must_use]
    pub const fn generation(&self) -> SandboxGeneration {
        self.generation
    }
}

/// Idempotent destroy outcome.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DestroyDisposition {
    Destroyed,
    AlreadyAbsent,
}

/// Provider-neutral, object-safe whole-job isolation port.
pub trait SandboxProvider: fmt::Debug + Send + Sync {
    fn provider_id(&self) -> &ProviderId;
    fn capabilities(&self) -> &ProviderCapabilities;

    /// Creates or exactly replays one sandbox operation.
    ///
    /// # Errors
    ///
    /// Returns a typed, secret-free provider failure. Uncertain mutations carry
    /// an opaque recovery handle.
    fn create(
        &self,
        spec: &SandboxSpec,
        cancellation: &dyn Cancellation,
    ) -> Result<SandboxRecord, ProviderError>;

    /// Attaches an execution endpoint after ownership inspection.
    ///
    /// # Errors
    ///
    /// Returns a typed provider failure for stale/foreign/missing sandboxes.
    fn attach(
        &self,
        handle: &SandboxHandle,
        cancellation: &dyn Cancellation,
    ) -> Result<Box<dyn ExecutionEndpoint>, ProviderError>;

    /// Inspects an exact opaque handle without exposing backend identifiers.
    ///
    /// # Errors
    ///
    /// Returns a typed provider failure for stale/foreign/corrupt state.
    fn inspect(
        &self,
        handle: &SandboxHandle,
        cancellation: &dyn Cancellation,
    ) -> Result<SandboxInspection, ProviderError>;

    /// Verifies ownership immediately before exact deletion. Implementations
    /// must never use global prune operations.
    ///
    /// # Errors
    ///
    /// Returns a typed provider failure, retaining uncertain external state for
    /// idempotent retry.
    fn destroy(
        &self,
        request: &DestroySandbox,
        cancellation: &dyn Cancellation,
    ) -> Result<DestroyDisposition, ProviderError>;
}
