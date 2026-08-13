use async_trait::async_trait;
use thiserror::Error;

use crate::RepositoryOperationError;

/// Failures from the narrow runner-capability admission boundary.
#[derive(Debug, Error)]
pub enum RunnerCapabilityAdmissionError {
    #[error(transparent)]
    Operation(#[from] RepositoryOperationError),
    #[error("durable runner inventory conflicts with current {resource}")]
    ConfigurationDrift { resource: &'static str },
    #[error("durable runner inventory violates an Automata invariant")]
    CorruptData,
}

impl RunnerCapabilityAdmissionError {
    #[must_use]
    pub fn operation(source: impl std::error::Error + Send + Sync + 'static) -> Self {
        RepositoryOperationError::from_source(source).into()
    }

    #[must_use]
    pub const fn drift(resource: &'static str) -> Self {
        Self::ConfigurationDrift { resource }
    }
}

/// Server-owned readiness gates for capability-bearing runner inventory.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct RunnerCapabilityReadiness {
    github_oidc: bool,
}

impl RunnerCapabilityReadiness {
    /// Returns the fail-closed set used when no optional product is ready.
    #[must_use]
    pub const fn unavailable() -> Self {
        Self { github_oidc: false }
    }

    /// Admits GitHub-compatible workload OIDC after composition proves it ready.
    #[must_use]
    pub const fn with_github_oidc(mut self) -> Self {
        self.github_oidc = true;
        self
    }

    /// Returns whether OIDC-bearing runner inventory may remain active.
    #[must_use]
    pub const fn github_oidc(self) -> bool {
        self.github_oidc
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
