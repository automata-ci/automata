//! Provider-neutral, least-privilege workload credential contracts.
//!
//! The broker boundary deliberately separates short-lived repository credentials
//! from human login credentials and provider root keys. A broker implementation
//! receives a validated workload, repository, permission set, and validity floor;
//! its result remains bound to that exact request.

#![forbid(unsafe_code)]

mod error;
mod model;
mod port;

pub use error::{CredentialError, CredentialErrorKind};
pub use model::{
    CredentialProvenance, IssuedRepositoryCredential, MinimumValidity, PermissionLevel,
    PermissionName, PermissionSet, ProviderResourceId, RepositoryCredentialRequest,
    RepositoryScope, WorkloadIdentity,
};
pub use port::RepositoryCredentialBroker;
