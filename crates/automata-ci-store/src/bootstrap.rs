use async_trait::async_trait;
use automata_ci_core::UnixMillis;
use thiserror::Error;

use crate::{RepositoryOperationError, TenantScope};

/// Idempotent request to make an authenticated tenant scope durable.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EnsureTenant {
    tenant: TenantScope,
    created_at: UnixMillis,
}

impl EnsureTenant {
    #[must_use]
    pub const fn new(tenant: TenantScope, created_at: UnixMillis) -> Self {
        Self { tenant, created_at }
    }

    #[must_use]
    pub const fn tenant(&self) -> &TenantScope {
        &self.tenant
    }

    #[must_use]
    pub const fn created_at(&self) -> UnixMillis {
        self.created_at
    }
}

/// Failures from the narrow product-readiness storage boundary.
#[derive(Debug, Error)]
pub enum ProductBootstrapStoreError {
    #[error(transparent)]
    Operation(#[from] RepositoryOperationError),
    #[error("durable runner inventory conflicts with current {resource}")]
    ConfigurationDrift { resource: &'static str },
    #[error("durable runner inventory violates an Automata invariant")]
    CorruptData,
}

impl ProductBootstrapStoreError {
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

/// Startup persistence and readiness checks that are independent of enrollment.
#[async_trait]
pub trait ProductBootstrapRepository: Send + Sync {
    /// Verifies durable runner capabilities with all optional products unavailable.
    async fn verify_runner_capability_admission(&self) -> Result<(), ProductBootstrapStoreError> {
        self.verify_runner_capability_readiness(RunnerCapabilityReadiness::unavailable())
            .await
    }

    /// Verifies durable runner capabilities against products ready on this replica.
    async fn verify_runner_capability_readiness(
        &self,
        readiness: RunnerCapabilityReadiness,
    ) -> Result<(), ProductBootstrapStoreError>;

    /// Creates the tenant when absent and otherwise leaves it unchanged.
    async fn ensure_tenant(&self, request: EnsureTenant) -> Result<(), ProductBootstrapStoreError>;
}
