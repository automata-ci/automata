use std::{fmt, future::Future, pin::Pin};

use thiserror::Error;

use crate::{
    AuthorizedProvisionWorkspace, ProvisionWorkspaceResult, ProvisioningAuthority,
    ProvisioningFailure,
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

/// Boxed durable workspace provisioning operation.
pub type WorkspaceProvisioningFuture<'a> = Pin<
    Box<dyn Future<Output = Result<ProvisionWorkspaceResult, ProvisioningFailure>> + Send + 'a>,
>;

/// Atomic, idempotent application port for one Core shard.
///
/// Implementations must commit the operation receipt, tenant, external
/// principal mapping, membership, built-in owner binding, audit event, and
/// stable response in one durable transaction. Exact retries return the stored
/// response without repeating effects.
pub trait WorkspaceProvisioner: fmt::Debug + Send + Sync {
    /// Applies one authorized workspace provisioning command.
    fn provision(&self, request: AuthorizedProvisionWorkspace) -> WorkspaceProvisioningFuture<'_>;
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
