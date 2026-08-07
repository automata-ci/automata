use std::path::PathBuf;

use thiserror::Error;

use automata_execution::{
    OperationOutcome, ProviderError, ProviderErrorKind, ProviderStage, SandboxHandle,
};

/// Invalid Podman adapter configuration.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum PodmanConfigurationError {
    #[error("Podman executable path must be absolute, normalized, and non-empty")]
    InvalidBinary,
    #[error("Podman process environment contains an unsafe path or value")]
    InvalidProcessEnvironment,
    #[error("Podman operation limits are zero or exceed hard bounds")]
    InvalidLimits,
    #[error("Podman host-gateway alias must be a non-localhost DNS hostname")]
    InvalidHostGatewayAlias,
    #[error("Podman adapter has no implementation for this platform")]
    UnsupportedPlatform,
    #[error("Podman local state setup failed")]
    StateSetup,
    #[error("attempt-scoped Docker API could not be started safely")]
    JobEngineUnavailable,
}

/// Rejected explicit local state root.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum PodmanStateRootError {
    #[error("Podman state root must be absolute")]
    Relative,
    #[error("Podman state root cannot be the filesystem root")]
    FilesystemRoot,
    #[error("Podman state root must be normalized without traversal")]
    Traversal,
    #[error("Podman state root cannot be in a system temporary hierarchy")]
    TemporaryHierarchy,
    #[error("Podman state root must already exist as its exact canonical path")]
    NotCanonical,
    #[error("Podman state root is not an owner-only directory")]
    NotOwnerOnly,
    #[error("Podman state root contains a symlink or unsafe filesystem object")]
    PathSecurity,
    #[error("Podman transfer output exceeds its declared byte limit")]
    TransferLimitExceeded,
    #[error("another adapter already owns the Podman state-root lock")]
    AlreadyLocked,
    #[error("Podman state-root I/O failed during {operation} at {path:?}")]
    Io {
        operation: &'static str,
        path: PathBuf,
    },
    #[error("Podman state roots are unsupported on this platform")]
    UnsupportedPlatform,
}

/// Adapter construction failure before any Podman mutation.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum PodmanOpenError {
    #[error(transparent)]
    Configuration(#[from] PodmanConfigurationError),
    #[error(transparent)]
    StateRoot(#[from] PodmanStateRootError),
}

pub(crate) mod provider_error {
    use super::{OperationOutcome, ProviderError, ProviderErrorKind, ProviderStage, SandboxHandle};

    pub(crate) const fn known(kind: ProviderErrorKind, stage: ProviderStage) -> ProviderError {
        ProviderError::new(kind, stage, OperationOutcome::KnownNoEffect, None)
    }

    pub(crate) fn uncertain(
        kind: ProviderErrorKind,
        stage: ProviderStage,
        handle: SandboxHandle,
    ) -> ProviderError {
        ProviderError::new(kind, stage, OperationOutcome::Uncertain, Some(handle))
    }

    pub(crate) const fn invalid_state(stage: ProviderStage) -> ProviderError {
        known(ProviderErrorKind::InvalidState, stage)
    }

    pub(crate) const fn ownership_mismatch(stage: ProviderStage) -> ProviderError {
        known(ProviderErrorKind::OwnershipMismatch, stage)
    }

    pub(crate) const fn local_storage(stage: ProviderStage) -> ProviderError {
        known(ProviderErrorKind::LocalStorage, stage)
    }
}
