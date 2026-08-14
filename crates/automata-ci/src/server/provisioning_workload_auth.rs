use std::fmt;

use automata_ci_provisioning::{
    ProvisioningAuthenticationError, ProvisioningAuthenticationFuture, ProvisioningAuthority,
    ProvisioningWorkloadAuthenticator, WorkloadAuthenticationEvidence,
};
use sha2::{Digest as _, Sha256};
use subtle::ConstantTimeEq as _;

/// Maps a TLS-verified leaf certificate to one deployment-configured authority.
///
/// The dedicated client CA establishes the management trust domain. Exact leaf
/// pins narrow that domain to the intended workload and permit bounded overlap
/// during certificate rotation without changing the durable authority ID.
pub(crate) struct PinnedProvisioningWorkloadAuthenticator {
    authority: ProvisioningAuthority,
    client_certificate_sha256: Vec<[u8; 32]>,
}

impl PinnedProvisioningWorkloadAuthenticator {
    pub(crate) fn new(
        authority: ProvisioningAuthority,
        client_certificate_sha256: Vec<[u8; 32]>,
    ) -> Self {
        debug_assert!(!client_certificate_sha256.is_empty());
        Self {
            authority,
            client_certificate_sha256,
        }
    }
}

impl fmt::Debug for PinnedProvisioningWorkloadAuthenticator {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PinnedProvisioningWorkloadAuthenticator")
            .field("authority", &self.authority)
            .field(
                "client_certificate_count",
                &self.client_certificate_sha256.len(),
            )
            .finish_non_exhaustive()
    }
}

impl ProvisioningWorkloadAuthenticator for PinnedProvisioningWorkloadAuthenticator {
    fn authenticate<'a>(
        &'a self,
        evidence: &'a WorkloadAuthenticationEvidence,
    ) -> ProvisioningAuthenticationFuture<'a> {
        let result = evidence
            .certificate_chain_der()
            .first()
            .map(Sha256::digest)
            .filter(|received| {
                self.client_certificate_sha256
                    .iter()
                    .any(|expected| bool::from(expected.as_slice().ct_eq(received.as_slice())))
            })
            .map(|_| self.authority.clone())
            .ok_or(ProvisioningAuthenticationError::Untrusted);
        Box::pin(async move { result })
    }
}

#[cfg(test)]
mod tests {
    use automata_ci_provisioning::{DelegatedActorIssuer, ProvisioningAuthorityId, ShardId};

    use super::*;

    fn authority() -> ProvisioningAuthority {
        ProvisioningAuthority::new(
            ProvisioningAuthorityId::new("automata-cloud").unwrap(),
            ShardId::new("shard-a").unwrap(),
            DelegatedActorIssuer::new("https://cloud.example.test").unwrap(),
        )
    }

    #[tokio::test]
    async fn exact_leaf_pin_returns_the_stable_configured_authority() {
        let leaf = b"verified leaf certificate DER".to_vec();
        let expected: [u8; 32] = Sha256::digest(&leaf).into();
        let authenticator =
            PinnedProvisioningWorkloadAuthenticator::new(authority(), vec![expected]);
        let evidence = WorkloadAuthenticationEvidence::new(vec![leaf, vec![1, 2, 3]]).unwrap();

        assert_eq!(
            authenticator.authenticate(&evidence).await.unwrap(),
            authority()
        );
    }

    #[tokio::test]
    async fn a_tls_verified_but_unpinned_leaf_is_rejected() {
        let expected: [u8; 32] = Sha256::digest(b"allowed leaf").into();
        let authenticator =
            PinnedProvisioningWorkloadAuthenticator::new(authority(), vec![expected]);
        let evidence =
            WorkloadAuthenticationEvidence::new(vec![b"different leaf".to_vec()]).unwrap();

        assert_eq!(
            authenticator.authenticate(&evidence).await.unwrap_err(),
            ProvisioningAuthenticationError::Untrusted
        );
    }

    #[test]
    fn debug_output_does_not_disclose_certificate_fingerprints() {
        let fingerprint = [0xabu8; 32];
        let authenticator =
            PinnedProvisioningWorkloadAuthenticator::new(authority(), vec![fingerprint]);
        let debug = format!("{authenticator:?}");

        assert!(debug.contains("client_certificate_count: 1"));
        assert!(!debug.contains("ab, ab"));
    }
}
