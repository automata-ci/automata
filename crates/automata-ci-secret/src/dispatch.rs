use std::sync::Arc;

use thiserror::Error;

use crate::{
    provider::{
        CreateSecretVersionRequest, CreatedSecretVersion, DestroySecretVersionRequest,
        ProviderCapability, ProviderError, ProviderHealth, ProviderLease, ProviderOperationContext,
        ReconcileCreateSecretVersionOutcome, ReconcileCreateSecretVersionRequest,
        RenewProviderLeaseRequest, ResolveSecretVersionRequest, ResolvedSecretVersion,
        RevokeProviderLeaseRequest, SecretProvider, SecretProviderId,
    },
    registry::SecretProviderRegistry,
};

impl SecretProviderRegistry {
    /// Dispatches one health observation to the exact registered provider.
    ///
    /// The registry never substitutes its default provider for a missing ID.
    ///
    /// # Errors
    ///
    /// Returns [`SecretProviderDispatchError::Rejected`] when the exact provider
    /// is not registered, or preserves the provider's sanitized failure.
    pub async fn dispatch_health(
        &self,
        provider_id: &SecretProviderId,
        context: &ProviderOperationContext,
    ) -> Result<ProviderHealth, SecretProviderDispatchError> {
        let provider = self.dispatch_provider(provider_id, &[])?;
        provider.health(context).await.map_err(Into::into)
    }

    /// Dispatches one immutable-version creation to the exact registered provider.
    ///
    /// The request, including its non-cloneable plaintext value, moves across
    /// the provider boundary exactly once. Dispatch does not retry, reconcile,
    /// replace request identities, or fall back to the default provider.
    ///
    /// # Errors
    ///
    /// Rejects the operation before provider I/O unless the exact provider
    /// advertises [`ProviderCapability::CreateVersion`], and otherwise preserves
    /// the provider's sanitized failure.
    pub async fn dispatch_create_version(
        &self,
        provider_id: &SecretProviderId,
        request: CreateSecretVersionRequest,
    ) -> Result<CreatedSecretVersion, SecretProviderDispatchError> {
        let provider = self.dispatch_provider(provider_id, &[ProviderCapability::CreateVersion])?;
        provider.create_version(request).await.map_err(Into::into)
    }

    /// Dispatches value-free reconciliation of one exact create intent.
    ///
    /// Reconciliation invokes only the provider's reconciliation operation. It
    /// never delegates to creation, generates another request identity, retries,
    /// or treats absence as write authority.
    ///
    /// # Errors
    ///
    /// Rejects the operation before provider I/O unless the exact provider
    /// advertises both create and reconciliation support, and otherwise
    /// preserves the provider's sanitized failure.
    pub async fn dispatch_reconcile_create_version(
        &self,
        provider_id: &SecretProviderId,
        request: ReconcileCreateSecretVersionRequest,
    ) -> Result<ReconcileCreateSecretVersionOutcome, SecretProviderDispatchError> {
        let provider = self.dispatch_provider(
            provider_id,
            &[
                ProviderCapability::CreateVersion,
                ProviderCapability::ReconcileCreateVersion,
            ],
        )?;
        provider
            .reconcile_create_version(request)
            .await
            .map_err(Into::into)
    }

    /// Dispatches exact-version resolution to the exact registered provider.
    ///
    /// Resolution is a mandatory provider operation, so it has no optional
    /// capability gate. A missing ID is still rejected without consulting the
    /// default provider.
    ///
    /// # Errors
    ///
    /// Returns [`SecretProviderDispatchError::Rejected`] when the exact provider
    /// is not registered, or preserves the provider's sanitized failure.
    pub async fn dispatch_resolve_version(
        &self,
        provider_id: &SecretProviderId,
        request: ResolveSecretVersionRequest,
    ) -> Result<ResolvedSecretVersion, SecretProviderDispatchError> {
        let provider = self.dispatch_provider(provider_id, &[])?;
        provider.resolve_version(request).await.map_err(Into::into)
    }

    /// Dispatches exact-version destruction to the exact registered provider.
    ///
    /// # Errors
    ///
    /// Rejects the operation before provider I/O unless the exact provider
    /// advertises [`ProviderCapability::DestroyVersion`], and otherwise
    /// preserves the provider's sanitized failure.
    pub async fn dispatch_destroy_version(
        &self,
        provider_id: &SecretProviderId,
        request: DestroySecretVersionRequest,
    ) -> Result<(), SecretProviderDispatchError> {
        let provider =
            self.dispatch_provider(provider_id, &[ProviderCapability::DestroyVersion])?;
        provider.destroy_version(request).await.map_err(Into::into)
    }

    /// Dispatches renewal of one exact dynamic lease to its registered provider.
    ///
    /// Dispatch performs no scheduling, expiry interpretation, retry, or
    /// durable receipt handling.
    ///
    /// # Errors
    ///
    /// Rejects the operation before provider I/O unless the exact provider
    /// advertises both dynamic leases and renewal, and otherwise preserves the
    /// provider's sanitized failure.
    pub async fn dispatch_renew_lease(
        &self,
        provider_id: &SecretProviderId,
        request: RenewProviderLeaseRequest,
    ) -> Result<ProviderLease, SecretProviderDispatchError> {
        let provider = self.dispatch_provider(
            provider_id,
            &[
                ProviderCapability::DynamicLeases,
                ProviderCapability::RenewLeases,
            ],
        )?;
        provider.renew_lease(request).await.map_err(Into::into)
    }

    /// Dispatches revocation of one exact dynamic lease to its registered provider.
    ///
    /// Dispatch performs no retry, cleanup scheduling, or durable completion.
    ///
    /// # Errors
    ///
    /// Rejects the operation before provider I/O unless the exact provider
    /// advertises both dynamic leases and revocation, and otherwise preserves
    /// the provider's sanitized failure.
    pub async fn dispatch_revoke_lease(
        &self,
        provider_id: &SecretProviderId,
        request: RevokeProviderLeaseRequest,
    ) -> Result<(), SecretProviderDispatchError> {
        let provider = self.dispatch_provider(
            provider_id,
            &[
                ProviderCapability::DynamicLeases,
                ProviderCapability::RevokeLeases,
            ],
        )?;
        provider.revoke_lease(request).await.map_err(Into::into)
    }

    fn dispatch_provider(
        &self,
        provider_id: &SecretProviderId,
        required: &[ProviderCapability],
    ) -> Result<Arc<dyn SecretProvider>, SecretProviderDispatchError> {
        let provider = self
            .provider(provider_id)
            .ok_or(SecretProviderDispatchError::Rejected)?;
        if provider.provider_id() != provider_id
            || required
                .iter()
                .any(|capability| !provider.capabilities().supports(*capability))
        {
            return Err(SecretProviderDispatchError::Rejected);
        }
        Ok(provider)
    }
}

/// Closed failure from exact secret-provider dispatch.
///
/// Missing providers and unsupported optional operations intentionally collapse
/// into one non-enumerating rejection. Provider failures retain only the
/// adapter's already-sanitized closed classification and retry guidance.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum SecretProviderDispatchError {
    /// The exact provider or its required optional capability is unavailable.
    #[error("secret provider dispatch rejected the operation")]
    Rejected,
    /// The selected provider returned its sanitized operation failure.
    #[error(transparent)]
    Provider(#[from] ProviderError),
}
