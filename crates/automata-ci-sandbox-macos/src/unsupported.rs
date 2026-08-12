use std::{fmt, path::PathBuf};

use automata_ci_execution::{
    Cancellation, DestroyDisposition, DestroySandbox, ExecutionEndpoint, OperationOutcome,
    ProviderCapabilities, ProviderError, ProviderErrorKind, ProviderId, ProviderStage,
    SandboxInspection, SandboxProvider, SandboxRecord, SandboxSpec,
};

/// macOS provider configuration placeholder on unsupported hosts.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MacosSandboxProviderOptions;

impl MacosSandboxProviderOptions {
    /// Rejects macOS provider configuration on a non-macOS host.
    ///
    /// # Errors
    ///
    /// Always returns `UnsupportedPlatform`.
    pub fn new(
        _provider_root: impl Into<PathBuf>,
        _supervisor_executable: impl Into<PathBuf>,
    ) -> Result<Self, ProviderError> {
        Err(unsupported(ProviderStage::Validate))
    }
}

/// macOS sandbox provider placeholder on unsupported hosts.
pub struct MacosSandboxProvider {
    provider_id: ProviderId,
    capabilities: ProviderCapabilities,
}

impl MacosSandboxProvider {
    /// Rejects provider startup on a non-macOS host.
    ///
    /// # Errors
    ///
    /// Always returns `UnsupportedPlatform`.
    pub fn open(_options: MacosSandboxProviderOptions) -> Result<Self, ProviderError> {
        Err(unsupported(ProviderStage::Validate))
    }
}

impl fmt::Debug for MacosSandboxProvider {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MacosSandboxProvider")
            .field("provider_id", &self.provider_id)
            .field("capabilities", &self.capabilities)
            .finish()
    }
}

impl SandboxProvider for MacosSandboxProvider {
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
        _handle: &automata_ci_execution::SandboxHandle,
        _cancellation: &dyn Cancellation,
    ) -> Result<Box<dyn ExecutionEndpoint>, ProviderError> {
        Err(unsupported(ProviderStage::Attach))
    }

    fn inspect(
        &self,
        _handle: &automata_ci_execution::SandboxHandle,
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

/// Rejects the hidden supervisor command on a non-macOS host.
///
/// # Errors
///
/// Always returns an unsupported-platform I/O error.
pub fn run_supervisor() -> std::io::Result<()> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "macOS supervisor is unavailable",
    ))
}

const fn unsupported(stage: ProviderStage) -> ProviderError {
    ProviderError::new(
        ProviderErrorKind::UnsupportedPlatform,
        stage,
        OperationOutcome::KnownNoEffect,
        None,
    )
}
