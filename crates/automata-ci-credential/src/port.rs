use async_trait::async_trait;
use automata_ci_scm::ScmProviderId;

use crate::{CredentialError, IssuedRepositoryCredential, RepositoryCredentialRequest};

/// Issues exact-scope, short-lived credentials for isolated workloads.
///
/// Implementations must not expose or place provider root credentials in the
/// result. They must fail closed if the provider grants a different repository,
/// permission set, or validity interval than requested. Implementations must not
/// cache and share one issued secret across distinct workload identities.
///
/// This boundary models issuance only. It does not make the request an
/// idempotency key and does not confirm provider-side revocation. Adapters whose
/// providers can leave a credential live after an ambiguous mint must use a
/// lifecycle-aware API that retains the secret until revocation is confirmed or
/// its lease expires.
#[async_trait]
pub trait RepositoryCredentialBroker: std::fmt::Debug + Send + Sync {
    /// Returns the stable provider identifier handled by this adapter.
    fn provider_id(&self) -> &ScmProviderId;

    /// Issues a credential bound to the complete request.
    ///
    /// A successful result must name the same workload, sole repository
    /// audience, exact permission set, and required remaining lease lifetime as
    /// `request`. Each call may perform a provider-side mint; callers must not
    /// assume that replay is idempotent or that an error proves no credential
    /// was created.
    ///
    /// # Errors
    ///
    /// Returns a sanitized [`CredentialError`] when the request is rejected or
    /// issuance cannot complete safely. Provider response bodies, assertions,
    /// and credential material must never be placed in the error or diagnostics.
    async fn issue(
        &self,
        request: &RepositoryCredentialRequest,
    ) -> Result<IssuedRepositoryCredential, CredentialError>;
}
