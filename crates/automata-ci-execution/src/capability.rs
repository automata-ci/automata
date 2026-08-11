use crate::ValueError;

const MAX_CAPABILITIES: usize = 32;

/// Explicit behavior supported by one sandbox-provider adapter.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum SandboxCapability {
    /// Owns one isolation boundary for the complete lifetime of a job.
    WholeJob,
    /// Reattaches to an already-created, provider-owned sandbox.
    Attach,
    /// Recovers the current state of an exact opaque sandbox handle.
    Inspect,
    /// Executes literal argv requests without an implicit shell.
    Exec,
    /// Delivers the portable signals supported by [`crate::ExecutionSignal`].
    Signal,
    /// Waits for the sandbox's primary workload to terminate.
    Wait,
    /// Copies bounded bytes into a sandbox target path.
    CopyTo,
    /// Copies bounded bytes out of a sandbox target path.
    CopyFrom,
    /// Injects validated process-environment variables at execution time.
    EnvironmentInjection,
    /// Enforces a sandbox with networking completely disabled.
    NetworkDisabled,
    /// Enforces an isolated network that permits provider-controlled egress.
    PrivateEgress,
    /// Runs a trusted workload on the host network without network isolation.
    HostNetwork,
    /// Launches workloads with a read-only root filesystem.
    ReadOnlyRootFilesystem,
    /// Launches workloads with a writable root filesystem.
    WritableRootFilesystem,
    /// Runs a trusted workload against the host filesystem without root isolation.
    HostFilesystem,
    /// Runs a trusted workload as the provider process host identity without
    /// token, credential, or privilege attenuation.
    HostIdentity,
    /// Supplies an administrative identity confined to the sandbox boundary.
    Administrator,
    /// Isolates sandbox identities with a user namespace or equivalent.
    UserNamespace,
    /// Enforces the requested memory, CPU, and process limits as hard limits.
    ResourceLimits,
    /// Creates, health-checks, discovers, and destroys services with a sandbox.
    ServiceContainers,
    /// A policy-filtered Docker Engine API is scoped to one sandbox.
    DockerCompatibleApi,
}

/// Sorted, unique, bounded provider capability set.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProviderCapabilities(Vec<SandboxCapability>);

impl ProviderCapabilities {
    /// Builds a strict capability set.
    ///
    /// # Errors
    ///
    /// Rejects empty, duplicated, or oversized declarations.
    pub fn new(values: impl IntoIterator<Item = SandboxCapability>) -> Result<Self, ValueError> {
        let mut values: Vec<_> = values.into_iter().collect();
        if values.is_empty() || values.len() > MAX_CAPABILITIES {
            return Err(ValueError::InvalidCapabilities);
        }
        values.sort_unstable();
        if values.windows(2).any(|pair| pair[0] == pair[1]) {
            return Err(ValueError::InvalidCapabilities);
        }
        Ok(Self(values))
    }

    #[must_use]
    /// Returns whether the declaration contains `capability`.
    pub fn supports(&self, capability: SandboxCapability) -> bool {
        self.0.binary_search(&capability).is_ok()
    }

    #[must_use]
    /// Returns capabilities in stable sorted order.
    pub fn values(&self) -> &[SandboxCapability] {
        &self.0
    }
}
