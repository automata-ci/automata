use std::{
    fmt,
    path::{Path, PathBuf},
};

use automata_ci_execution::{
    Cancellation, DestroyDisposition, DestroySandbox, ExecutionEndpoint, OperationOutcome,
    ProviderCapabilities, ProviderError, ProviderErrorKind, ProviderId, ProviderStage,
    SandboxHandle, SandboxInspection, SandboxProvider, SandboxRecord, SandboxSpec,
};

/// Native Windows provider configuration placeholder on non-Windows targets.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WindowsSandboxProviderOptions {
    provider_root: PathBuf,
}

impl WindowsSandboxProviderOptions {
    /// Rejects construction because this build cannot host Windows processes.
    ///
    /// # Errors
    ///
    /// Always returns [`ProviderErrorKind::UnsupportedPlatform`].
    pub fn new(provider_root: impl Into<PathBuf>) -> Result<Self, ProviderError> {
        let _ = provider_root.into();
        Err(unsupported(ProviderStage::Validate))
    }

    /// Returns the configured root when a value is supplied internally.
    #[must_use]
    pub fn provider_root(&self) -> &Path {
        &self.provider_root
    }
}

/// Unavailable native Windows provider on a non-Windows target.
#[derive(Clone)]
pub struct WindowsSandboxProvider {
    provider_id: ProviderId,
    capabilities: ProviderCapabilities,
}

impl WindowsSandboxProvider {
    /// Rejects provider startup on every non-Windows target.
    ///
    /// # Errors
    ///
    /// Always returns [`ProviderErrorKind::UnsupportedPlatform`].
    pub fn open(_options: WindowsSandboxProviderOptions) -> Result<Self, ProviderError> {
        Err(unsupported(ProviderStage::Validate))
    }
}

impl fmt::Debug for WindowsSandboxProvider {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("WindowsSandboxProvider")
            .field("provider_id", &self.provider_id)
            .field("capabilities", &self.capabilities)
            .finish_non_exhaustive()
    }
}

impl SandboxProvider for WindowsSandboxProvider {
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
        Err(unsupported(ProviderStage::Validate))
    }

    fn attach(
        &self,
        _handle: &SandboxHandle,
        _cancellation: &dyn Cancellation,
    ) -> Result<Box<dyn ExecutionEndpoint>, ProviderError> {
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
        OperationOutcome::KnownNoEffect,
        None,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn options_fail_closed_off_windows() {
        let error = WindowsSandboxProviderOptions::new("C:\\automata")
            .expect_err("non-Windows provider must be unavailable");
        assert_eq!(error.kind(), ProviderErrorKind::UnsupportedPlatform);
    }
}
