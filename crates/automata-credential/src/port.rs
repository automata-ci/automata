use async_trait::async_trait;
use automata_scm::ScmProviderId;

use crate::{CredentialError, IssuedRepositoryCredential, RepositoryCredentialRequest};

/// Issues exact-scope, short-lived credentials for isolated workloads.
///
/// Implementations must not expose or place provider root credentials in the
/// result. They must fail closed if the provider grants a different repository,
/// permission set, or validity interval than requested. Implementations must not
/// cache and share one issued secret across distinct workload identities.
#[async_trait]
pub trait RepositoryCredentialBroker: std::fmt::Debug + Send + Sync {
    /// Stable provider identifier handled by this adapter.
    fn provider_id(&self) -> &ScmProviderId;

    /// Issues a credential bound to the complete request.
    async fn issue(
        &self,
        request: &RepositoryCredentialRequest,
    ) -> Result<IssuedRepositoryCredential, CredentialError>;
}
