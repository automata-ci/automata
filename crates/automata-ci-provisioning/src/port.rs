use std::{fmt, future::Future, pin::Pin};

use thiserror::Error;

use crate::{
    ApplyGithubProviderConfigurationResult, ApplyGithubProviderRunnerPolicyResult,
    ApplyTenantEntitlementResult, ApplyTenantGithubRepositoriesResult,
    AuthorizedApplyGithubProviderConfiguration, AuthorizedApplyGithubProviderRunnerPolicy,
    AuthorizedApplyTenantEntitlement, AuthorizedApplyTenantGithubRepositories,
    AuthorizedListTenantUsage, AuthorizedProvisionTenant, EntitlementFailure,
    GithubProviderConfigurationFailure, GithubProviderDesiredState,
    GithubProviderDesiredStateFailure, GithubProviderRunnerPolicyFailure, ProvisionTenantResult,
    ProvisioningAuthority, ProvisioningFailure, TenantGithubRepositoriesFailure, TenantUsagePage,
    UsageExportFailure,
};

const MAX_CERTIFICATE_COUNT: usize = 32;
const MAX_CERTIFICATE_DER_BYTES: usize = 1024 * 1024;
const MAX_CERTIFICATE_CHAIN_DER_BYTES: usize = 4 * 1024 * 1024;

/// Bounded peer-certificate evidence supplied by an mTLS transport.
///
/// TLS chain, validity, and client-auth verification must occur before this
/// evidence reaches the application authenticator. Private keys never cross
/// this boundary.
pub struct WorkloadAuthenticationEvidence {
    certificate_chain_der: Vec<Vec<u8>>,
}

impl WorkloadAuthenticationEvidence {
    /// Creates bounded leaf-first certificate evidence.
    ///
    /// # Errors
    ///
    /// Rejects empty, oversized, or excessive certificate chains.
    pub fn new(
        certificate_chain_der: Vec<Vec<u8>>,
    ) -> Result<Self, ProvisioningAuthenticationError> {
        let total_bytes = certificate_chain_der
            .iter()
            .try_fold(0_usize, |total, certificate| {
                if certificate.is_empty() || certificate.len() > MAX_CERTIFICATE_DER_BYTES {
                    return None;
                }
                total.checked_add(certificate.len())
            });
        if certificate_chain_der.is_empty()
            || certificate_chain_der.len() > MAX_CERTIFICATE_COUNT
            || total_bytes.is_none_or(|total| total > MAX_CERTIFICATE_CHAIN_DER_BYTES)
        {
            return Err(ProvisioningAuthenticationError::InvalidEvidence);
        }
        Ok(Self {
            certificate_chain_der,
        })
    }

    /// Returns the verified peer chain in leaf-first DER form.
    pub fn certificate_chain_der(&self) -> &[Vec<u8>] {
        &self.certificate_chain_der
    }
}

impl fmt::Debug for WorkloadAuthenticationEvidence {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("WorkloadAuthenticationEvidence")
            .field("certificate_count", &self.certificate_chain_der.len())
            .finish_non_exhaustive()
    }
}

/// Boxed workload authentication operation.
pub type ProvisioningAuthenticationFuture<'a> = Pin<
    Box<
        dyn Future<Output = Result<ProvisioningAuthority, ProvisioningAuthenticationError>>
            + Send
            + 'a,
    >,
>;

/// Maps already TLS-verified evidence to one stable configured authority.
pub trait ProvisioningWorkloadAuthenticator: fmt::Debug + Send + Sync {
    /// Authenticates a fresh request's peer certificate evidence.
    fn authenticate<'a>(
        &'a self,
        evidence: &'a WorkloadAuthenticationEvidence,
    ) -> ProvisioningAuthenticationFuture<'a>;
}

/// Sanitized workload authentication failures.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum ProvisioningAuthenticationError {
    /// The TLS transport supplied malformed or unbounded evidence.
    #[error("workload authentication evidence is invalid")]
    InvalidEvidence,
    /// No configured workload authority trusts this credential.
    #[error("the workload credential is not trusted")]
    Untrusted,
    /// The credential is known but no longer active.
    #[error("the workload credential has expired")]
    Expired,
    /// The authority directory could not answer safely.
    #[error("the workload authenticator is unavailable")]
    Unavailable,
}

/// Boxed durable tenant provisioning operation.
pub type TenantProvisioningFuture<'a> =
    Pin<Box<dyn Future<Output = Result<ProvisionTenantResult, ProvisioningFailure>> + Send + 'a>>;

/// Atomic, idempotent application port for one Core shard.
///
/// Implementations must commit the operation receipt, tenant, external
/// principal mapping, membership, built-in owner binding, audit event, and
/// stable response in one durable transaction. Exact retries return the stored
/// response without repeating effects.
pub trait TenantProvisioner: fmt::Debug + Send + Sync {
    /// Applies one authorized tenant provisioning command.
    fn provision(&self, request: AuthorizedProvisionTenant) -> TenantProvisioningFuture<'_>;
}

/// Boxed durable tenant entitlement operation.
pub type EntitlementApplicationFuture<'a> = Pin<
    Box<dyn Future<Output = Result<ApplyTenantEntitlementResult, EntitlementFailure>> + Send + 'a>,
>;

/// Atomic, idempotent tenant entitlement application port.
///
/// Implementations must verify the tenant's durable external-management
/// binding, reject stale revisions, and commit the current snapshot and stable
/// operation response in one transaction.
pub trait TenantEntitlementApplier: fmt::Debug + Send + Sync {
    /// Applies one authorized complete entitlement snapshot.
    fn apply(&self, request: AuthorizedApplyTenantEntitlement) -> EntitlementApplicationFuture<'_>;
}

/// Boxed shard-wide GitHub provider configuration application.
pub type GithubProviderConfigurationApplicationFuture<'a> = Pin<
    Box<
        dyn Future<
                Output = Result<
                    ApplyGithubProviderConfigurationResult,
                    GithubProviderConfigurationFailure,
                >,
            > + Send
            + 'a,
    >,
>;

/// Atomic, idempotent application port for the shard-wide GitHub App configuration.
///
/// Implementations must encrypt both credentials before persistence and commit
/// the complete configuration, monotonically increasing revision, current
/// pointer, and stable operation receipt in one transaction.
pub trait GithubProviderConfigurationApplier: fmt::Debug + Send + Sync {
    /// Applies one authorized complete provider configuration.
    fn apply(
        &self,
        request: AuthorizedApplyGithubProviderConfiguration,
    ) -> GithubProviderConfigurationApplicationFuture<'_>;
}

/// Boxed credential-preserving GitHub runner-policy application.
pub type GithubProviderRunnerPolicyApplicationFuture<'a> = Pin<
    Box<
        dyn Future<
                Output = Result<
                    ApplyGithubProviderRunnerPolicyResult,
                    GithubProviderRunnerPolicyFailure,
                >,
            > + Send
            + 'a,
    >,
>;

/// Atomic, idempotent application port for the shard-wide GitHub runner policy.
///
/// Implementations must retain the current encrypted provider credentials,
/// reject an absent provider configuration, and commit the policy, shared
/// configuration revision, current pointer, and operation receipt atomically.
pub trait GithubProviderRunnerPolicyApplier: fmt::Debug + Send + Sync {
    /// Applies one authorized complete runner-policy replacement.
    fn apply(
        &self,
        request: AuthorizedApplyGithubProviderRunnerPolicy,
    ) -> GithubProviderRunnerPolicyApplicationFuture<'_>;
}

/// Boxed tenant GitHub repository desired-set application.
pub type TenantGithubRepositoriesApplicationFuture<'a> = Pin<
    Box<
        dyn Future<
                Output = Result<
                    ApplyTenantGithubRepositoriesResult,
                    TenantGithubRepositoriesFailure,
                >,
            > + Send
            + 'a,
    >,
>;

/// Atomic, idempotent application port for one complete tenant repository set.
///
/// Omission is authoritative: a successful revision replaces the complete
/// desired set for that tenant. Implementations retain durable operation
/// receipts for replay while exposing only current desired state to the provider
/// runtime.
pub trait TenantGithubRepositoriesApplier: fmt::Debug + Send + Sync {
    /// Applies one authorized complete tenant repository selection.
    fn apply(
        &self,
        request: AuthorizedApplyTenantGithubRepositories,
    ) -> TenantGithubRepositoriesApplicationFuture<'_>;
}

/// Boxed load of the current database-backed GitHub provider desired state.
pub type GithubProviderDesiredStateLoadFuture<'a> = Pin<
    Box<
        dyn Future<
                Output = Result<
                    Option<GithubProviderDesiredState>,
                    GithubProviderDesiredStateFailure,
                >,
            > + Send
            + 'a,
    >,
>;

/// Read port for one transactionally consistent provider desired-state snapshot.
pub trait GithubProviderDesiredStateReader: fmt::Debug + Send + Sync {
    /// Loads the current provider configuration and all current tenant sets.
    ///
    /// `None` means no shard-wide provider configuration has been installed.
    fn load(&self) -> GithubProviderDesiredStateLoadFuture<'_>;
}

/// Boxed durable tenant usage-export operation.
pub type UsageExportFuture<'a> =
    Pin<Box<dyn Future<Output = Result<TenantUsagePage, UsageExportFailure>> + Send + 'a>>;

/// Stable cursor-pull port for immutable execution-accounting facts.
///
/// Implementations must scope both cursors and events to the authenticated
/// authority, return events in stable append order, and never reuse an event ID
/// for different facts. A consumer can therefore commit event ingestion and
/// its continuation cursor atomically for at-least-once delivery.
pub trait TenantUsageExporter: fmt::Debug + Send + Sync {
    /// Lists one authority-scoped page after the request's exclusive cursor.
    fn list(&self, request: AuthorizedListTenantUsage) -> UsageExportFuture<'_>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn evidence_is_bounded_and_redacted() {
        let evidence = WorkloadAuthenticationEvidence::new(vec![vec![1, 2, 3]]).unwrap();
        assert_eq!(evidence.certificate_chain_der(), &[vec![1, 2, 3]]);
        let debug = format!("{evidence:?}");
        assert!(debug.contains("certificate_count: 1"));
        assert!(!debug.contains("1, 2, 3"));

        assert_eq!(
            WorkloadAuthenticationEvidence::new(Vec::new()).unwrap_err(),
            ProvisioningAuthenticationError::InvalidEvidence
        );
        assert_eq!(
            WorkloadAuthenticationEvidence::new(vec![Vec::new()]).unwrap_err(),
            ProvisioningAuthenticationError::InvalidEvidence
        );
    }
}
