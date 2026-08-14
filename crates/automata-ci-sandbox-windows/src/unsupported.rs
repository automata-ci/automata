use std::{
    fmt,
    path::{Path, PathBuf},
    time::Duration,
};

use automata_ci_execution::{
    Cancellation, DestroyDisposition, DestroySandbox, ProviderCapabilities, ProviderError,
    ProviderErrorKind, ProviderId, ProviderStage, SandboxHandle, SandboxInspection,
    SandboxProvider, SandboxRecord, SandboxSpec, Sha256Digest, TargetPath,
};

/// Closed host configuration for the Hyper-V Windows container provider.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WindowsHyperVContainerProviderOptions {
    state_root: PathBuf,
    runtime_executable: PathBuf,
    runtime_sha256: Sha256Digest,
    guest_agent_path: TargetPath,
    operation_timeout: Duration,
}

impl WindowsHyperVContainerProviderOptions {
    /// Creates a syntactically complete configuration on an unsupported host.
    ///
    /// # Errors
    ///
    /// Always rejects because Hyper-V Windows containers require Windows.
    pub fn new(
        _state_root: impl Into<PathBuf>,
        _runtime_executable: impl Into<PathBuf>,
        _runtime_sha256: Sha256Digest,
        _guest_agent_path: TargetPath,
    ) -> Result<Self, ProviderError> {
        Err(unsupported(ProviderStage::Validate))
    }

    /// Replaces the lifecycle timeout on a configuration that cannot exist on
    /// this platform.
    ///
    /// # Errors
    ///
    /// Always rejects because Hyper-V Windows containers require Windows.
    pub fn with_operation_timeout(self, _timeout: Duration) -> Result<Self, ProviderError> {
        Err(unsupported(ProviderStage::Validate))
    }

    /// Returns the configured state root.
    #[must_use]
    pub fn state_root(&self) -> &Path {
        &self.state_root
    }

    /// Returns the configured runtime executable.
    #[must_use]
    pub fn runtime_executable(&self) -> &Path {
        &self.runtime_executable
    }

    /// Returns the configured runtime digest.
    #[must_use]
    pub const fn runtime_sha256(&self) -> Sha256Digest {
        self.runtime_sha256
    }

    /// Returns the in-image guest-agent path.
    #[must_use]
    pub const fn guest_agent_path(&self) -> &TargetPath {
        &self.guest_agent_path
    }

    /// Returns the configured operation timeout.
    #[must_use]
    pub const fn operation_timeout(&self) -> Duration {
        self.operation_timeout
    }
}

/// Unsupported-platform placeholder for the Windows-only provider.
pub struct WindowsHyperVContainerProvider {
    provider_id: ProviderId,
    capabilities: ProviderCapabilities,
}

impl WindowsHyperVContainerProvider {
    /// Rejects provider construction on non-Windows hosts.
    ///
    /// # Errors
    ///
    /// Always returns [`ProviderErrorKind::UnsupportedPlatform`].
    pub fn open(_options: WindowsHyperVContainerProviderOptions) -> Result<Self, ProviderError> {
        Err(unsupported(ProviderStage::Validate))
    }
}

impl fmt::Debug for WindowsHyperVContainerProvider {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("WindowsHyperVContainerProvider")
            .field("provider_id", &self.provider_id)
            .finish_non_exhaustive()
    }
}

impl SandboxProvider for WindowsHyperVContainerProvider {
    fn provider_id(&self) -> &ProviderId {
        &self.provider_id
    }

    fn capabilities(&self) -> &ProviderCapabilities {
        &self.capabilities
    }

    fn create(
        &self,
        _spec: &SandboxSpec,
        _cancellation: &dyn Cancellation,
    ) -> Result<SandboxRecord, ProviderError> {
        Err(unsupported(ProviderStage::CreateSandbox))
    }

    fn attach(
        &self,
        _handle: &SandboxHandle,
        _cancellation: &dyn Cancellation,
    ) -> Result<Box<dyn automata_ci_execution::ExecutionEndpoint>, ProviderError> {
        Err(unsupported(ProviderStage::Attach))
    }

    fn inspect(
        &self,
        _handle: &SandboxHandle,
        _cancellation: &dyn Cancellation,
    ) -> Result<SandboxInspection, ProviderError> {
        Err(unsupported(ProviderStage::Inspect))
    }

    fn destroy(
        &self,
        _request: &DestroySandbox,
        _cancellation: &dyn Cancellation,
    ) -> Result<DestroyDisposition, ProviderError> {
        Err(unsupported(ProviderStage::DestroySandbox))
    }
}

fn unsupported(stage: ProviderStage) -> ProviderError {
    ProviderError::new(
        ProviderErrorKind::UnsupportedPlatform,
        stage,
        automata_ci_execution::OperationOutcome::KnownNoEffect,
        None,
    )
}
