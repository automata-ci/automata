use std::path::PathBuf;

use thiserror::Error;

use automata_ci_execution::{
    OperationOutcome, ProviderError, ProviderErrorKind, ProviderStage, SandboxHandle,
};

/// Invalid Podman adapter configuration.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum PodmanConfigurationError {
    /// The Podman executable was not an absolute normalized non-root path.
    #[error("Podman executable path must be absolute, normalized, and non-empty")]
    InvalidBinary,
    /// A process path, helper, generated configuration, or host launch gate was unsafe.
    #[error("Podman process environment contains an unsafe path or value")]
    InvalidProcessEnvironment,
    /// An operation deadline, command deadline, or output bound was incoherent.
    #[error("Podman operation limits are zero or exceed hard bounds")]
    InvalidLimits,
    /// A requested host-gateway name was not an eligible explicit DNS hostname.
    #[error("Podman host-gateway alias must be a non-localhost DNS hostname")]
    InvalidHostGatewayAlias,
    /// The current operating system cannot provide this adapter's safety contract.
    #[error("Podman adapter has no implementation for this platform")]
    UnsupportedPlatform,
    /// Private generated state could not be materialized or validated exactly.
    #[error("Podman local state setup failed")]
    StateSetup,
    /// The attempt-scoped Docker-compatible proxy could not be bound safely.
    #[error("attempt-scoped Docker API could not be started safely")]
    JobEngineUnavailable,
    /// The immutable service-proxy image was absent or failed local verification.
    #[error("configured service proxy helper is not locally available and verified")]
    ServiceProxyUnavailable,
}

/// Rejected explicit local state root.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum PodmanStateRootError {
    /// The configured state root was not absolute.
    #[error("Podman state root must be absolute")]
    Relative,
    /// The configured state root named the filesystem root itself.
    #[error("Podman state root cannot be the filesystem root")]
    FilesystemRoot,
    /// The configured path contained current- or parent-directory traversal.
    #[error("Podman state root must be normalized without traversal")]
    Traversal,
    /// The state root was placed beneath a system temporary hierarchy.
    #[error("Podman state root cannot be in a system temporary hierarchy")]
    TemporaryHierarchy,
    /// Canonicalization did not reproduce the exact configured state-root path.
    #[error("Podman state root must already exist as its exact canonical path")]
    NotCanonical,
    /// The directory was not owned by the effective user with owner-only mode.
    #[error("Podman state root is not an owner-only directory")]
    NotOwnerOnly,
    /// Descriptor inspection found a symlink, wrong type, or unsafe ownership or mode.
    #[error("Podman state root contains a symlink or unsafe filesystem object")]
    PathSecurity,
    /// A bounded copy operation declared or produced more bytes than allowed.
    #[error("Podman transfer output exceeds its declared byte limit")]
    TransferLimitExceeded,
    /// Another live provider instance holds the exclusive state-root lock.
    #[error("another adapter already owns the Podman state-root lock")]
    AlreadyLocked,
    /// A local state operation failed without retaining backend output or payload bytes.
    #[error("Podman state-root I/O failed during {operation} at {path:?}")]
    Io {
        /// Closed static operation label for the failed filesystem step.
        operation: &'static str,
        /// Local state path involved in the failed operation.
        path: PathBuf,
    },
    /// The platform cannot enforce the required descriptor and ownership checks.
    #[error("Podman state roots are unsupported on this platform")]
    UnsupportedPlatform,
}

/// Adapter construction failure before any Podman mutation.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum PodmanOpenError {
    /// Trusted configuration or a host launch admission gate was invalid.
    #[error(transparent)]
    Configuration(#[from] PodmanConfigurationError),
    /// The explicit private state root failed validation or exclusive locking.
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
