use async_trait::async_trait;
use thiserror::Error;

use automata_ci_store::RepositoryOperationError;

/// Failures from the narrow runner-capability admission boundary.
#[derive(Debug, Error)]
pub enum RunnerCapabilityAdmissionError {
    /// The durable repository operation failed.
    #[error(transparent)]
    Operation(#[from] RepositoryOperationError),
    /// Durable inventory conflicts with a currently composed resource.
    #[error("durable runner inventory conflicts with current {resource}")]
    ConfigurationDrift {
        /// The unavailable or incompatible resource.
        resource: &'static str,
    },
    /// Durable inventory violates an internal invariant.
    #[error("durable runner inventory violates an Automata invariant")]
    CorruptData,
}

impl RunnerCapabilityAdmissionError {
    /// Wraps an infrastructure failure at the repository boundary.
    #[must_use]
    pub fn operation(source: impl std::error::Error + Send + Sync + 'static) -> Self {
        RepositoryOperationError::from_source(source).into()
    }

    /// Reports durable inventory drift for a named resource.
    #[must_use]
    pub const fn drift(resource: &'static str) -> Self {
        Self::ConfigurationDrift { resource }
    }
}

/// Server-owned readiness gates for capability-bearing runner inventory.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct RunnerCapabilityReadiness {
    workload_oidc: bool,
}

impl RunnerCapabilityReadiness {
    /// Returns the fail-closed set used when no optional product is ready.
    #[must_use]
    pub const fn unavailable() -> Self {
        Self {
            workload_oidc: false,
        }
    }

    /// Admits Actions-compatible workload OIDC after composition proves it ready.
    #[must_use]
    pub const fn with_workload_oidc(mut self) -> Self {
        self.workload_oidc = true;
        self
    }

    /// Returns whether OIDC-bearing runner inventory may remain active.
    #[must_use]
    pub const fn workload_oidc(self) -> bool {
        self.workload_oidc
    }
}

/// Startup admission check for durable capability-bearing runner inventory.
#[async_trait]
pub trait RunnerCapabilityAdmissionRepository: Send + Sync {
    /// Verifies durable runner capabilities against products ready on this replica.
    async fn verify_runner_capability_readiness(
        &self,
        readiness: RunnerCapabilityReadiness,
    ) -> Result<(), RunnerCapabilityAdmissionError>;
}
