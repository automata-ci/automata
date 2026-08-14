use async_trait::async_trait;
use automata_ci_core::{RunId, UnixMillis};
use thiserror::Error;

use crate::{ProviderDeliveryId, RepositoryId, StoreError, TenantScope};

/// Maximum provider delivery identifier accepted by the conformance lookup.
pub const MAX_CONFORMANCE_DELIVERY_ID_BYTES: usize = 255;

const MAX_PROVIDER_NAME_BYTES: usize = 128;

/// Exact tenant/repository/provider delivery coordinate used by conformance reads.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConformanceDeliveryQuery {
    tenant: TenantScope,
    repository_id: RepositoryId,
    provider: String,
    delivery_id: String,
}

impl ConformanceDeliveryQuery {
    /// Creates a bounded, repository-scoped external delivery lookup.
    ///
    /// # Errors
    ///
    /// Rejects provider names outside the portable provider alphabet and empty,
    /// untrimmed, control-bearing, or oversized external delivery identifiers.
    pub fn new(
        tenant: TenantScope,
        repository_id: RepositoryId,
        provider: impl Into<String>,
        delivery_id: impl Into<String>,
    ) -> Result<Self, ConformanceReadValueError> {
        let provider = provider.into();
        let delivery_id = delivery_id.into();
        if provider.is_empty()
            || provider.len() > MAX_PROVIDER_NAME_BYTES
            || !provider.bytes().all(|character| {
                character.is_ascii_alphanumeric() || matches!(character, b'-' | b'_' | b':' | b'.')
            })
        {
            return Err(ConformanceReadValueError::InvalidProvider);
        }
        if delivery_id.is_empty()
            || delivery_id.len() > MAX_CONFORMANCE_DELIVERY_ID_BYTES
            || delivery_id.trim() != delivery_id
            || delivery_id.chars().any(char::is_control)
        {
            return Err(ConformanceReadValueError::InvalidDeliveryId);
        }
        Ok(Self {
            tenant,
            repository_id,
            provider,
            delivery_id,
        })
    }

    /// Returns the authenticated tenant that bounds the lookup.
    #[must_use]
    pub const fn tenant(&self) -> &TenantScope {
        &self.tenant
    }

    /// Returns the exact Automata repository beneath the tenant.
    #[must_use]
    pub const fn repository_id(&self) -> RepositoryId {
        self.repository_id
    }

    /// Returns the canonical provider name.
    #[must_use]
    pub fn provider(&self) -> &str {
        &self.provider
    }

    /// Returns the provider-assigned external delivery identifier.
    #[must_use]
    pub fn delivery_id(&self) -> &str {
        &self.delivery_id
    }
}

/// Durable lifecycle exposed for an accepted provider delivery.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConformanceDeliveryState {
    /// Accepted and eligible for its first processing attempt.
    Pending,
    /// Held by one live delivery-processing fence.
    Claimed,
    /// Waiting for a bounded retry after a failed attempt.
    RetryPending,
    /// Terminal with a complete ordered workflow outcome set.
    Completed,
    /// Terminally rejected before workflow outcomes could be committed.
    Rejected,
}

/// One independently observable workflow outcome beneath a delivery.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ConformanceWorkflowOutcome {
    /// The workflow was admitted as one exact durable run.
    Admitted {
        /// Exact admitted workflow-run identity.
        run_id: RunId,
    },
    /// Selection deliberately omitted the workflow.
    Skipped {
        /// Stable machine reason for the selection decision.
        reason: String,
    },
    /// Selection or admission failed terminally.
    Failed {
        /// Stable machine class of the failure.
        failure_kind: String,
    },
}

/// Path-keyed result for one candidate workflow.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConformanceWorkflowResult {
    workflow_path: String,
    outcome: ConformanceWorkflowOutcome,
}

impl ConformanceWorkflowResult {
    #[cfg(feature = "adapter-spi")]
    #[must_use]
    pub(crate) fn new(workflow_path: String, outcome: ConformanceWorkflowOutcome) -> Self {
        Self {
            workflow_path,
            outcome,
        }
    }

    /// Returns the repository-relative workflow source path.
    #[must_use]
    pub fn workflow_path(&self) -> &str {
        &self.workflow_path
    }

    /// Returns the terminal selection or admission outcome.
    #[must_use]
    pub const fn outcome(&self) -> &ConformanceWorkflowOutcome {
        &self.outcome
    }
}

/// Stable delivery state and its complete terminal workflow outcome set.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConformanceDelivery {
    id: ProviderDeliveryId,
    external_delivery_id: String,
    state: ConformanceDeliveryState,
    attempts: u16,
    accepted_at: UnixMillis,
    completed_at: Option<UnixMillis>,
    workflows: Vec<ConformanceWorkflowResult>,
}

impl ConformanceDelivery {
    #[cfg(feature = "adapter-spi")]
    #[allow(clippy::too_many_arguments)]
    #[must_use]
    pub(crate) fn new(
        id: ProviderDeliveryId,
        external_delivery_id: String,
        state: ConformanceDeliveryState,
        attempts: u16,
        accepted_at: UnixMillis,
        completed_at: Option<UnixMillis>,
        workflows: Vec<ConformanceWorkflowResult>,
    ) -> Self {
        Self {
            id,
            external_delivery_id,
            state,
            attempts,
            accepted_at,
            completed_at,
            workflows,
        }
    }

    /// Returns Automata's durable internal delivery identity.
    #[must_use]
    pub const fn id(&self) -> ProviderDeliveryId {
        self.id
    }

    /// Returns the provider-assigned external delivery identity.
    #[must_use]
    pub fn external_delivery_id(&self) -> &str {
        &self.external_delivery_id
    }

    /// Returns the current durable delivery lifecycle.
    #[must_use]
    pub const fn state(&self) -> ConformanceDeliveryState {
        self.state
    }

    /// Returns the number of processing attempts already started.
    #[must_use]
    pub const fn attempts(&self) -> u16 {
        self.attempts
    }

    /// Returns the immutable delivery acceptance time.
    #[must_use]
    pub const fn accepted_at(&self) -> UnixMillis {
        self.accepted_at
    }

    /// Returns the terminal completion time when workflow outcomes exist.
    #[must_use]
    pub const fn completed_at(&self) -> Option<UnixMillis> {
        self.completed_at
    }

    /// Returns the complete path-sorted terminal workflow outcome set.
    #[must_use]
    pub fn workflows(&self) -> &[ConformanceWorkflowResult] {
        &self.workflows
    }
}

/// Invalid untrusted conformance lookup input.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum ConformanceReadValueError {
    /// The provider did not use the portable provider-name grammar.
    #[error("provider name is invalid")]
    InvalidProvider,
    /// The external delivery identity was empty, unsafe, or oversized.
    #[error("external provider delivery ID is invalid")]
    InvalidDeliveryId,
}

/// Backend-neutral supported reads for conformance tooling.
#[async_trait]
pub trait ConformanceReadRepository: std::fmt::Debug + Send + Sync {
    /// Resolves one external provider delivery beneath its exact tenant and
    /// repository. Missing and cross-scope coordinates return `Ok(None)`.
    async fn get_conformance_delivery(
        &self,
        query: &ConformanceDeliveryQuery,
    ) -> Result<Option<ConformanceDelivery>, StoreError>;
}

#[cfg(test)]
mod tests {
    use uuid::Uuid;

    use super::*;

    fn query(delivery_id: &str) -> Result<ConformanceDeliveryQuery, ConformanceReadValueError> {
        ConformanceDeliveryQuery::new(
            TenantScope::from_authenticated_tenant_id("tenant-a").expect("tenant"),
            RepositoryId::from_uuid(Uuid::from_u128(1)),
            "github",
            delivery_id,
        )
    }

    #[test]
    fn external_delivery_coordinates_are_bounded_before_storage() {
        assert_eq!(
            query("delivery-1").expect("query").delivery_id(),
            "delivery-1"
        );
        assert_eq!(query(""), Err(ConformanceReadValueError::InvalidDeliveryId));
        assert_eq!(
            query(" delivery-1"),
            Err(ConformanceReadValueError::InvalidDeliveryId)
        );
        assert_eq!(
            query(&"a".repeat(MAX_CONFORMANCE_DELIVERY_ID_BYTES + 1)),
            Err(ConformanceReadValueError::InvalidDeliveryId)
        );
    }
}
