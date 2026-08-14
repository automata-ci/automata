use automata_ci_execution::{
    ExecutionError, ExecutionErrorKind, ExecutionStage, OperationOutcome, ProviderError,
    ProviderErrorKind, ProviderStage, SandboxHandle,
};

pub(crate) fn provider(
    kind: ProviderErrorKind,
    stage: ProviderStage,
    outcome: OperationOutcome,
    recovery_handle: Option<SandboxHandle>,
) -> ProviderError {
    ProviderError::new(kind, stage, outcome, recovery_handle)
}

pub(crate) fn known(kind: ProviderErrorKind, stage: ProviderStage) -> ProviderError {
    provider(kind, stage, OperationOutcome::KnownNoEffect, None)
}

pub(crate) fn uncertain(
    kind: ProviderErrorKind,
    stage: ProviderStage,
    handle: SandboxHandle,
) -> ProviderError {
    provider(kind, stage, OperationOutcome::Uncertain, Some(handle))
}

pub(crate) const fn execution(kind: ExecutionErrorKind, stage: ExecutionStage) -> ExecutionError {
    ExecutionError::new(kind, stage)
}

pub(crate) const fn provider_to_execution(kind: ProviderErrorKind) -> ExecutionErrorKind {
    match kind {
        ProviderErrorKind::Cancelled => ExecutionErrorKind::Cancelled,
        ProviderErrorKind::TimedOut => ExecutionErrorKind::TimedOut,
        ProviderErrorKind::NotFound => ExecutionErrorKind::NotFound,
        ProviderErrorKind::OwnershipMismatch => ExecutionErrorKind::OwnershipMismatch,
        ProviderErrorKind::InvalidState => ExecutionErrorKind::InvalidState,
        ProviderErrorKind::OutputLimitExceeded => ExecutionErrorKind::OutputLimitExceeded,
        ProviderErrorKind::LocalStorage => ExecutionErrorKind::LocalStorage,
        ProviderErrorKind::UnsupportedPlatform
        | ProviderErrorKind::UnsupportedCapability
        | ProviderErrorKind::AdapterUnavailable
        | ProviderErrorKind::InvalidConfiguration
        | ProviderErrorKind::Conflict
        | ProviderErrorKind::BackendRejected => ExecutionErrorKind::BackendRejected,
    }
}
