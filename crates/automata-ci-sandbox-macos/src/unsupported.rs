use std::{fmt, path::PathBuf, time::Duration};

use automata_ci_execution::{
    Cancellation, DestroyDisposition, DestroySandbox, ExecutionEndpoint, OperationOutcome,
    ProviderCapabilities, ProviderError, ProviderErrorKind, ProviderId, ProviderStage,
    SandboxInspection, SandboxProvider, SandboxRecord, SandboxSpec, Sha256Digest,
};

/// macOS virtualization options are unavailable on non-macOS hosts.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MacosVirtualizationProviderOptions;

impl MacosVirtualizationProviderOptions {
    /// Rejects Virtualization.framework configuration on a non-macOS host.
    ///
    /// # Errors
    ///
    /// Always returns `UnsupportedPlatform`.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        _provider_root: impl Into<PathBuf>,
        _helper_executable: impl Into<PathBuf>,
        _helper_digest: Sha256Digest,
        _helper_code_requirement: String,
        _template_manifest: impl Into<PathBuf>,
        _template_manifest_digest: Sha256Digest,
        _storage_volume_uuid: &str,
        _storage_quota_bytes: u64,
        _boot_timeout: Duration,
        _stop_timeout: Duration,
    ) -> Result<Self, ProviderError> {
        Err(unsupported(ProviderStage::Validate))
    }
}

/// Virtualization.framework provider placeholder on unsupported hosts.
pub struct MacosVirtualizationProvider {
    provider_id: ProviderId,
    capabilities: ProviderCapabilities,
}

impl MacosVirtualizationProvider {
    /// Rejects provider startup on a non-macOS host.
    ///
    /// # Errors
    ///
    /// Always returns `UnsupportedPlatform`.
    pub fn open(_options: MacosVirtualizationProviderOptions) -> Result<Self, ProviderError> {
        Err(unsupported(ProviderStage::Validate))
    }
}

impl fmt::Debug for MacosVirtualizationProvider {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MacosVirtualizationProvider")
            .field("provider_id", &self.provider_id)
            .field("capabilities", &self.capabilities)
            .finish()
    }
}

impl SandboxProvider for MacosVirtualizationProvider {
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

const fn unsupported(stage: ProviderStage) -> ProviderError {
    ProviderError::new(
        ProviderErrorKind::UnsupportedPlatform,
        stage,
        OperationOutcome::KnownNoEffect,
        None,
    )
}
