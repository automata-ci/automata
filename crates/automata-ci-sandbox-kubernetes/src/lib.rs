#![forbid(unsafe_code)]
#![deny(missing_docs)]
//! Kubernetes-backed sandbox lifecycle and execution provider.

mod config;
mod endpoint;
mod objects;
mod provider;

pub use config::{
    KubernetesConfigurationError, KubernetesSandboxConfig, VerifiedEphemeralStorageEnforcement,
    VerifiedNetworkIsolation, VerifiedProcessLimitEnforcement,
};
pub use provider::KubernetesSandboxProvider;

use automata_ci_execution::{OperationOutcome, ProviderError, ProviderErrorKind, ProviderStage};

/// Stable provider identifier for this adapter generation.
// foundation-governance: derived-contract owner=sandbox kind=storage-namespace
pub const KUBERNETES_PROVIDER_ID: &str = "kubernetes-v1";
/// Smallest job memory limit that leaves bounded space for the in-Pod guest.
pub const MINIMUM_KUBERNETES_SANDBOX_MEMORY_BYTES: u64 = 256 * 1_024 * 1_024;

fn invalid_configuration(stage: ProviderStage) -> ProviderError {
    ProviderError::new(
        ProviderErrorKind::InvalidConfiguration,
        stage,
        OperationOutcome::KnownNoEffect,
        None,
    )
}
