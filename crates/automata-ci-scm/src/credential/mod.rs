//! Provider-neutral workload credential requests, results, and failures.
//!
//! These contracts deliberately separate short-lived repository credentials from
//! human login credentials and provider root keys. A request binds a validated
//! workload, repository, permission set, and validity floor; an issued result
//! remains bound to that exact request.
//!
//! Provider integrations should define lifecycle-adequate ports once their mint
//! ambiguity and secret-custody semantics are known rather than reuse a
//! speculative generic broker.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

mod error;
mod model;

pub use error::{CredentialError, CredentialErrorKind};
pub use model::{
    CredentialProvenance, IssuedRepositoryCredential, MinimumValidity, ModelError, PermissionLevel,
    PermissionName, PermissionSet, ProviderResourceId, RepositoryCredentialRequest,
    RepositoryScope, WorkloadIdentity,
};
