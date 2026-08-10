//! GitHub App installation-token adapter for workload repository credentials.
//!
//! The App private key is used only in-process to sign a short-lived assertion.
//! Every token request selects exactly one stable repository ID and an exact
//! permission map. Provider-side effects are exposed only through a move-only
//! lifecycle outcome so a caller cannot discard an ambiguous or revocable mint.
//!
//! Production HTTP requests remain beneath one configured HTTPS API base,
//! ignore ambient proxies, and do not follow redirects. Responses, tokens,
//! assertions, keys, timeouts, and retry hints are bounded. A successful mint
//! must echo the exact repository and permission scope requested before its
//! credential can be used. Callers renew by performing a new, independently
//! reconciled mint before the conservative expiration; this crate never
//! refreshes a token implicitly. All public failures are sanitized
//! classifications that omit provider bodies, URLs, keys, assertions, and
//! bearer tokens.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

mod adapter;
mod authority_coordinator;
mod authority_issuer;
mod config;
mod response;
mod runtime_authority;
mod runtime_authority_lifecycle;
mod server_service_authority;
mod signer;

pub use adapter::{GithubAppBrokerConstructionError, GithubAppCredentialBroker};
pub use authority_coordinator::{
    GithubJobRuntimeAuthorityRequestValueError, GithubRuntimeAuthorityCommitSupervisor,
    GithubRuntimeAuthorityCommitSupervisorError, GithubRuntimeAuthorityCoordinationOutcome,
    GithubRuntimeAuthorityCoordinatorClock, GithubRuntimeAuthorityCoordinatorError,
    GithubRuntimeAuthorityMintBroker, GithubRuntimeAuthorityMintCoordinator,
    GithubRuntimeAuthorityRequestResolver, GithubRuntimeAuthorityResolutionError,
    GithubRuntimeAuthorityResolutionValueError, PendingGithubRuntimeAuthorityCommit,
    PendingGithubRuntimeAuthorityCommitError, PinnedGithubRuntimeAuthorityMintBroker,
    PinnedGithubRuntimeAuthorityMintBrokerError, ResolvedGithubRuntimeAuthorityRequest,
    SystemGithubRuntimeAuthorityCoordinatorClock, github_job_runtime_authority_request,
    github_runtime_authority_workload_identity,
};
pub use authority_issuer::{
    GITHUB_REPOSITORY_AUTHORITY_NAMESPACE, GITHUB_REPOSITORY_RUNTIME_AUTHORITY,
    GithubRepositoryRuntimeAuthorityIssuer, GithubRuntimeAuthorityIdentityResolutionError,
    GithubRuntimeAuthorityIdentityResolutionValueError, GithubRuntimeAuthorityIdentityResolver,
    GithubRuntimeAuthorityIssuerConfigurationError, ResolvedGithubRuntimeAuthorityIdentity,
};
pub use automata_ci_credential::ProviderResourceId as GithubAppIssuer;
pub use config::{
    GITHUB_API_VERSION, GithubAppConfigurationError, GithubAppCredentialConfig,
    GithubAppHttpLimits, GithubInstallationId,
};
pub use runtime_authority::{
    GithubInstallationTokenCandidateError, GithubInstallationTokenIndeterminate,
    GithubInstallationTokenIndeterminateReason, GithubInstallationTokenMintOutcome,
    GithubInstallationTokenRevocationCandidate, GithubInstallationTokenRevocationFailure,
    GithubInstallationTokenRevocationFailureKind, GithubInstallationTokenRevocationOutcome,
    GithubInstallationTokenRevokePending, GithubReadyInstallationToken,
};
pub use runtime_authority_lifecycle::{
    GithubRuntimeAuthorityLifecycleBroker, GithubRuntimeAuthorityLifecycleBrokerRouter,
    GithubRuntimeAuthorityLifecycleBrokerRouterError, GithubRuntimeAuthorityLifecycleCoordinator,
    GithubRuntimeAuthorityLifecycleError, GithubRuntimeAuthorityLifecycleOutcome,
    GithubRuntimeAuthorityLifecycleSupervisor, GithubRuntimeAuthorityLifecycleSupervisorError,
    GithubRuntimeAuthorityRevocationOutcome, PendingGithubRuntimeAuthorityLifecycleCommit,
    PendingGithubRuntimeAuthorityLifecycleCommitError,
};
pub use server_service_authority::{
    GithubServerServiceCoordinationOutcome, GithubServerServiceCoordinatorClock,
    GithubServerServiceCoordinatorError, GithubServerServiceCredential,
    GithubServerServiceCredentialBroker, GithubServerServiceCredentialCoordinator,
    GithubServerServiceCredentialIssuer, GithubServerServiceCredentialRepository,
    GithubServerServiceCredentialRequestResolver, GithubServerServiceHandoffBinding,
    GithubServerServiceHandoffError, GithubServerServiceHandoffReleaseOutcome,
    GithubServerServiceInstallationRouter, GithubServerServiceInstallationRouterError,
    GithubServerServiceMintCutoffEvidence, GithubServerServiceMintCutoffOutcome,
    GithubServerServiceResolutionError, GithubServerServiceResolutionValueError,
    MAX_GITHUB_SERVER_SERVICE_INSTALLATION_BROKERS, PendingGithubServerServiceCorruptionCleanup,
    PendingGithubServerServiceHandoffRelease, PendingGithubServerServiceMintCommit,
    PendingGithubServerServiceRevocationCommit, ResolvedGithubServerServiceCredentialRequest,
    SystemGithubServerServiceCoordinatorClock, github_server_service_credential_request,
    github_server_service_workload_identity,
};
pub use signer::GithubAppKeyError;
