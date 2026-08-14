//! `PostgreSQL` persistence adapters for human login transactions and sessions.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

mod delegated_actor;
mod github_mapping_management;
mod github_membership;
mod installation;
mod login;
/// Transactional human-RBAC management adapter.
pub mod management;
mod provider_tokens;
mod request_auth;
mod session;
mod sign_in;
mod support;

pub use delegated_actor::PostgresDelegatedActorResolver;
pub use github_mapping_management::PostgresGithubMappingManagementRepository;
pub use github_membership::PostgresGithubMembershipRepository;
pub use installation::PostgresInstallationRepository;
pub use login::PostgresLoginTransactionRepository;
pub use management::PostgresHumanRbacManagementRepository;
pub use provider_tokens::PostgresProviderTokenVault;
pub use request_auth::PostgresRequestAuthenticationResolver;
pub use session::PostgresHumanSessionRepository;
pub use sign_in::PostgresHumanSignInFinalizer;
