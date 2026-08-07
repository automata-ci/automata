use crate::ValueError;

const MAX_CAPABILITIES: usize = 32;

/// Explicit behavior supported by one sandbox-provider adapter.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum SandboxCapability {
    WholeJob,
    Attach,
    Inspect,
    Exec,
    Signal,
    Wait,
    CopyTo,
    CopyFrom,
    EnvironmentInjection,
    NetworkDisabled,
    PrivateEgress,
    ReadOnlyRootFilesystem,
    WritableRootFilesystem,
    Administrator,
    UserNamespace,
    ResourceLimits,
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
    pub fn supports(&self, capability: SandboxCapability) -> bool {
        self.0.binary_search(&capability).is_ok()
    }

    #[must_use]
    pub fn values(&self) -> &[SandboxCapability] {
        &self.0
    }
}
