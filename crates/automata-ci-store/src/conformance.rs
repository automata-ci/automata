use async_trait::async_trait;
use automata_ci_core::{RunId, UnixMillis};
use thiserror::Error;

use crate::{ProviderDeliveryId, RepositoryId, StoreError, TenantScope};

/// Maximum provider delivery identifier accepted by the conformance lookup.
pub const MAX_CONFORMANCE_DELIVERY_ID_BYTES: usize = 512;
/// Maximum external repository identifier accepted by conformance lookup.
pub const MAX_CONFORMANCE_EXTERNAL_REPOSITORY_ID_BYTES: usize = 512;

const MAX_PROVIDER_NAME_BYTES: usize = 64;

/// Exact tenant/provider repository coordinate used by conformance reads.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConformanceRepositoryQuery {
    tenant: TenantScope,
    provider: String,
    external_repository_id: String,
}

impl ConformanceRepositoryQuery {
    /// Creates a bounded provider-neutral repository lookup.
    ///
    /// # Errors
    ///
    /// Rejects noncanonical provider names and invalid external repository IDs.
    pub fn new(
        tenant: TenantScope,
        provider: impl Into<String>,
        external_repository_id: impl Into<String>,
    ) -> Result<Self, ConformanceReadValueError> {
        let provider = provider.into();
        let external_repository_id = external_repository_id.into();
        if provider.is_empty()
            || provider.len() > MAX_PROVIDER_NAME_BYTES
            || !provider.bytes().enumerate().all(|(index, character)| {
                character.is_ascii_lowercase()
                    || character.is_ascii_digit()
                    || (index > 0 && character == b'-')
            })
            || !provider
                .as_bytes()
                .last()
                .is_some_and(u8::is_ascii_alphanumeric)
        {
            return Err(ConformanceReadValueError::InvalidProvider);
        }
        validate_external_id(
            &external_repository_id,
            MAX_CONFORMANCE_EXTERNAL_REPOSITORY_ID_BYTES,
        )
        .map_err(|()| ConformanceReadValueError::InvalidRepositoryId)?;
        Ok(Self {
            tenant,
            provider,
            external_repository_id,
        })
    }

    /// Returns the authenticated tenant that bounds the lookup.
    #[must_use]
    pub const fn tenant(&self) -> &TenantScope {
        &self.tenant
    }

    /// Returns the canonical provider type.
    #[must_use]
    pub fn provider(&self) -> &str {
        &self.provider
    }

    /// Returns the provider-native repository identity.
    #[must_use]
    pub fn external_repository_id(&self) -> &str {
        &self.external_repository_id
    }
}

/// Exact tenant/repository/provider delivery coordinate used by conformance reads.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConformanceDeliveryQuery {
    repository: ConformanceRepositoryQuery,
    repository_id: RepositoryId,
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
        repository: ConformanceRepositoryQuery,
        repository_id: RepositoryId,
        delivery_id: impl Into<String>,
    ) -> Result<Self, ConformanceReadValueError> {
        let delivery_id = delivery_id.into();
        validate_external_id(&delivery_id, MAX_CONFORMANCE_DELIVERY_ID_BYTES)
            .map_err(|()| ConformanceReadValueError::InvalidDeliveryId)?;
        Ok(Self {
            repository,
            repository_id,
            delivery_id,
        })
    }

    /// Returns the authenticated tenant that bounds the lookup.
    #[must_use]
    pub const fn tenant(&self) -> &TenantScope {
        self.repository.tenant()
    }

    /// Returns the exact Automata repository beneath the tenant.
    #[must_use]
    pub const fn repository_id(&self) -> RepositoryId {
        self.repository_id
    }

    /// Returns the canonical provider name.
    #[must_use]
    pub fn provider(&self) -> &str {
        self.repository.provider()
    }

    /// Returns the provider-native repository identity.
    #[must_use]
    pub fn external_repository_id(&self) -> &str {
        self.repository.external_repository_id()
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
    /// Terminal processing failure.
    Failed,
    /// Rejected during provider normalization before processing began.
    Rejected,
}

/// Path-keyed admitted workflow beneath one provider delivery.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConformanceWorkflowResult {
    workflow_path: String,
    run_id: RunId,
}

impl ConformanceWorkflowResult {
    #[cfg(feature = "adapter-spi")]
    #[must_use]
    pub(crate) fn new(workflow_path: String, run_id: RunId) -> Self {
        Self {
            workflow_path,
            run_id,
        }
    }

    /// Returns the repository-relative workflow source path.
    #[must_use]
    pub fn workflow_path(&self) -> &str {
        &self.workflow_path
    }

    /// Returns the admitted workflow-run identity.
    #[must_use]
    pub const fn run_id(&self) -> RunId {
        self.run_id
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
    /// The provider-native repository identity was invalid.
    #[error("external provider repository ID is invalid")]
    InvalidRepositoryId,
    /// The external delivery identity was empty, unsafe, or oversized.
    #[error("external provider delivery ID is invalid")]
    InvalidDeliveryId,
}

/// Backend-neutral supported reads for conformance tooling.
#[async_trait]
pub trait ConformanceReadRepository: std::fmt::Debug + Send + Sync {
    /// Resolves one internal repository beneath an exact tenant/provider coordinate.
    async fn resolve_conformance_repository(
        &self,
        query: &ConformanceRepositoryQuery,
    ) -> Result<Option<RepositoryId>, StoreError>;

    /// Resolves one external provider delivery beneath its exact tenant and
    /// repository. Missing and cross-scope coordinates return `Ok(None)`.
    async fn get_conformance_delivery(
        &self,
        query: &ConformanceDeliveryQuery,
    ) -> Result<Option<ConformanceDelivery>, StoreError>;
}

fn validate_external_id(value: &str, max_bytes: usize) -> Result<(), ()> {
    if value.is_empty()
        || value.len() > max_bytes
        || value.trim() != value
        || value.chars().any(char::is_control)
    {
        return Err(());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use uuid::Uuid;

    use super::*;

    fn query(delivery_id: &str) -> Result<ConformanceDeliveryQuery, ConformanceReadValueError> {
        ConformanceDeliveryQuery::new(
            ConformanceRepositoryQuery::new(
                TenantScope::from_authenticated_tenant_id("tenant-a").expect("tenant"),
                "github",
                "42",
            )?,
            RepositoryId::from_uuid(Uuid::from_u128(1)),
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
        let tenant = TenantScope::from_authenticated_tenant_id("tenant-a").expect("tenant");
        assert!(ConformanceRepositoryQuery::new(tenant.clone(), "forgejo", "42").is_ok());
        assert_eq!(
            ConformanceRepositoryQuery::new(tenant.clone(), "Forgejo", "42"),
            Err(ConformanceReadValueError::InvalidProvider)
        );
        assert_eq!(
            ConformanceRepositoryQuery::new(tenant, "forgejo", " 42"),
            Err(ConformanceReadValueError::InvalidRepositoryId)
        );
    }
}
