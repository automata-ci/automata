use std::fmt;

use crate::{
    Cancellation, EnvironmentProfile, ExecutionEndpoint, NetworkPolicy, OperationId,
    ProviderCapabilities, ProviderError, ProviderId, ResourceLimits, RootFilesystemPolicy,
    SandboxEnvironment, SandboxGeneration, SandboxHandle, SandboxPrivilegePolicy,
    ServiceContainerBindings, ServiceContainerSpecs, TargetPath,
};
use automata_ci_core::JobResourceAllocation;

/// Immutable whole-job sandbox request. The profile is exact and contains no
/// hosted-label resolution or mutable image reference.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SandboxSpec {
    operation_id: OperationId,
    generation: SandboxGeneration,
    profile: SandboxEnvironment,
    workspace: TargetPath,
    scratch: Option<TargetPath>,
    network: NetworkPolicy,
    root_filesystem: RootFilesystemPolicy,
    privilege: SandboxPrivilegePolicy,
    resources: ResourceLimits,
    resource_allocation: Option<JobResourceAllocation>,
    services: ServiceContainerSpecs,
}

impl SandboxSpec {
    /// Creates an exact whole-job sandbox request.
    ///
    /// The operation identifier makes create replayable, while `generation`
    /// fences reuse of any recovered handle. Providers must enforce the
    /// attested profile, target workspace, network, root-filesystem policy,
    /// and hard resource limits as one request.
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
            scratch: None,
            network,
            root_filesystem,
            privilege: SandboxPrivilegePolicy::Unprivileged,
            resources,
            resource_allocation: None,
            services: ServiceContainerSpecs::empty(),
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

    /// Selects the exact provider-owned per-attempt scratch root.
    ///
    /// Process and VM providers use this allowlist entry for command files and
    /// other bounded execution material outside the job workspace.
    #[must_use]
    pub fn with_scratch(mut self, scratch: TargetPath) -> Self {
        self.scratch = Some(scratch);
        self
    }

    /// Returns the stable identifier used for exact create replay.
    #[must_use]
    pub const fn operation_id(&self) -> OperationId {
        self.operation_id
    }

    /// Returns the generation that fences sandbox-handle reuse.
    #[must_use]
    pub const fn generation(&self) -> SandboxGeneration {
        self.generation
    }

    /// Returns the exact content-attested launch environment.
    #[must_use]
    pub const fn profile(&self) -> &SandboxEnvironment {
        &self.profile
    }

    /// Returns the exact per-job workspace target mounted by the provider.
    #[must_use]
    pub const fn workspace(&self) -> &TargetPath {
        &self.workspace
    }

    /// Returns the optional provider-owned per-attempt scratch root.
    #[must_use]
    pub const fn scratch(&self) -> Option<&TargetPath> {
        self.scratch.as_ref()
    }

    /// Returns the requested network-isolation policy.
    #[must_use]
    pub const fn network(&self) -> NetworkPolicy {
        self.network
    }

    /// Returns the requested root-filesystem mutability policy.
    #[must_use]
    pub const fn root_filesystem(&self) -> RootFilesystemPolicy {
        self.root_filesystem
    }

    /// Returns the requested in-sandbox privilege policy.
    #[must_use]
    pub const fn privilege(&self) -> SandboxPrivilegePolicy {
        self.privilege
    }

    /// Returns mandatory hard whole-job resource limits.
    #[must_use]
    pub const fn resources(&self) -> ResourceLimits {
        self.resources
    }

    /// Attaches the complete placement-request and enforcement-limit contract.
    ///
    /// Providers that support request-aware placement consume this value;
    /// providers that only enforce hard limits continue to use [`Self::resources`].
    #[must_use]
    pub const fn with_resource_allocation(mut self, allocation: JobResourceAllocation) -> Self {
        self.resource_allocation = Some(allocation);
        self
    }

    /// Returns the complete request/limit contract, when selected by the workflow.
    #[must_use]
    pub const fn resource_allocation(&self) -> Option<JobResourceAllocation> {
        self.resource_allocation
    }

    /// Returns whether placement-aware and provider-neutral hard limits agree.
    ///
    /// Providers must reject two disagreeing CPU or memory limits instead of
    /// silently choosing one. PID limits remain represented only by
    /// [`Self::resources`].
    #[must_use]
    pub const fn has_coherent_resource_contract(&self) -> bool {
        let Some(allocation) = self.resource_allocation else {
            return true;
        };
        let resources = self.resources();
        allocation.limits().cpu_millis() == resources.cpu_millis()
            && allocation.limits().memory_bytes() == resources.memory_bytes()
    }

    /// Adds services which the provider must create, make healthy, and own as
    /// part of this exact sandbox generation.
    #[must_use]
    pub fn with_services(mut self, services: ServiceContainerSpecs) -> Self {
        self.services = services;
        self
    }

    /// Returns service containers owned by this sandbox generation.
    #[must_use]
    pub const fn services(&self) -> &ServiceContainerSpecs {
        &self.services
    }
}

/// Provider-neutral sandbox lifecycle state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SandboxState {
    /// No provider resource exists for the exact handle.
    Absent,
    /// The isolation boundary exists but its primary workload has not started.
    Created,
    /// The sandbox's primary workload is running.
    Running,
    /// The sandbox exists and its primary workload has stopped.
    Stopped,
    /// The sandbox exists but one or more required resources are unhealthy or
    /// cannot be reconciled into a normal lifecycle state.
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
    /// Records the identity and state returned by successful create or replay.
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

    /// Returns the opaque provider handle for exact follow-up operations.
    #[must_use]
    pub const fn handle(&self) -> &SandboxHandle {
        &self.handle
    }

    /// Returns the generation bound to the provider resource.
    #[must_use]
    pub const fn generation(&self) -> SandboxGeneration {
        self.generation
    }

    /// Returns the exact admitted environment-profile attestation.
    #[must_use]
    pub const fn profile(&self) -> &EnvironmentProfile {
        &self.profile
    }

    /// Returns the lifecycle state reached by create or replay.
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
    /// Records the current recovery view for one exact provider handle.
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

    /// Returns the exact opaque handle that was inspected.
    #[must_use]
    pub const fn handle(&self) -> &SandboxHandle {
        &self.handle
    }

    /// Returns the generation observed on the provider resource.
    #[must_use]
    pub const fn generation(&self) -> SandboxGeneration {
        self.generation
    }

    /// Returns the exact environment-profile attestation on the resource.
    #[must_use]
    pub const fn profile(&self) -> &EnvironmentProfile {
        &self.profile
    }

    /// Returns the provider-neutral lifecycle state observed during recovery.
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
    /// Creates an exact, idempotently identified destroy request.
    ///
    /// Both the opaque handle and generation must match the provider-owned
    /// resource before deletion is allowed.
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

    /// Returns the stable identifier used for exact destroy replay.
    #[must_use]
    pub const fn operation_id(&self) -> OperationId {
        self.operation_id
    }

    /// Returns the opaque provider handle selected for deletion.
    #[must_use]
    pub const fn handle(&self) -> &SandboxHandle {
        &self.handle
    }

    /// Returns the generation that must match before deletion.
    #[must_use]
    pub const fn generation(&self) -> SandboxGeneration {
        self.generation
    }
}

/// Idempotent destroy outcome.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DestroyDisposition {
    /// The exact owned sandbox and its subordinate resources were removed.
    Destroyed,
    /// The exact sandbox was already absent, so no deletion was necessary.
    AlreadyAbsent,
}

/// Provider-neutral, object-safe whole-job isolation port.
pub trait SandboxProvider: fmt::Debug + Send + Sync {
    /// Returns the stable identifier for this provider implementation.
    fn provider_id(&self) -> &ProviderId;
    /// Returns the provider's fixed, explicit capability declaration.
    fn capabilities(&self) -> &ProviderCapabilities;

    /// Creates or exactly replays one sandbox operation.
    ///
    /// Reusing an operation identifier with different request material must
    /// fail closed. A successful replay returns the same generation-fenced
    /// resource rather than creating another sandbox.
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
    /// The returned endpoint must remain bound to the exact handle and expose
    /// only operations supported by the provider's capability declaration.
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
    /// Inspection must be scoped to the supplied handle and must not rely on
    /// broad enumeration or caller parsing of the opaque token.
    ///
    /// # Errors
    ///
    /// Returns a typed provider failure for stale/foreign/corrupt state.
    fn inspect(
        &self,
        handle: &SandboxHandle,
        cancellation: &dyn Cancellation,
    ) -> Result<SandboxInspection, ProviderError>;

    /// Returns the complete healthy service discovery view for an owned,
    /// running sandbox. Providers advertising `ServiceContainers` must make
    /// sandbox creation wait for configured health checks and must retain this
    /// view across process restart. Destroying the sandbox must remove every
    /// service and its private network.
    ///
    /// # Errors
    ///
    /// Returns a typed provider failure for stale, unhealthy, foreign, or
    /// unsupported service state.
    fn service_bindings(
        &self,
        _handle: &SandboxHandle,
        _cancellation: &dyn Cancellation,
    ) -> Result<ServiceContainerBindings, ProviderError> {
        Err(ProviderError::new(
            crate::ProviderErrorKind::UnsupportedCapability,
            crate::ProviderStage::Inspect,
            crate::OperationOutcome::KnownNoEffect,
            None,
        ))
    }

    /// Verifies ownership immediately before exact deletion. Implementations
    /// must match the request's generation and never use global prune
    /// operations. A successful return covers subordinate services, networks,
    /// workspaces, and provider resources owned by that sandbox generation.
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
