//! GitHub App human authentication protocol and membership snapshots.

mod flow;
mod login_service;
mod membership_store;
mod model;
mod port;
mod role_mapping;
mod transaction_state;

pub use flow::{
    DeviceAuthorization, DeviceAuthorizationParts, DeviceAuthorizationStatus, DevicePollOutcome,
    GithubAppProtocol, GithubFlowError, WebAuthorization, WebAuthorizationTransaction,
    WebAuthorizationTransactionParts,
};
pub use login_service::{
    GITHUB_LOGIN_PROOF_KEY_BYTES, GITHUB_MEMBERSHIP_OBSERVATION_TTL_SECONDS,
    GithubBrowserBindingCookie, GithubDeviceLoginPollOutcome, GithubDeviceLoginStart,
    GithubDevicePollCredential, GithubInstallationAuthentication,
    GithubInstallationDevicePollOutcome, GithubLoginCompletion, GithubLoginConfigurationError,
    GithubLoginError, GithubLoginProofKey, GithubLoginProofKeyring, GithubLoginProofKeyringError,
    GithubLoginService, GithubLoginSessionLifetimes, GithubWebCallbackPurpose, GithubWebLoginStart,
    InvalidGithubLoginProof, MAX_GITHUB_LOGIN_COLLISION_ATTEMPTS, MAX_GITHUB_LOGIN_PROOF_KEYS,
};
pub use membership_store::{
    GithubMembershipObservation, GithubMembershipPersistenceFuture, GithubMembershipRepository,
    GithubMembershipRepositoryError, GithubMembershipRequestError, GithubMembershipSnapshotId,
    MAX_GITHUB_MEMBERSHIP_OBSERVATIONS, PersistGithubMembershipSnapshot,
    PersistGithubMembershipSnapshotOutcome,
};
pub use model::{
    DeviceCodeRequest, DeviceCodeResponse, DeviceTokenPollRequest, GithubAppConfig, GithubClientId,
    GithubConfigurationError, GithubCurrentUserRequest, GithubDevicePollResponse, GithubEndpoints,
    GithubTokenResponse, GithubUser, GithubWebCallback, RefreshTokenRequest,
    WebTokenExchangeRequest,
};
pub use port::{
    GithubAppAuthenticationProvider, GithubEndpoint, GithubEndpointError, GithubEndpointFuture,
};
pub use role_mapping::{
    GithubMembershipSnapshot, GithubOrganizationId, GithubOrganizationLogin,
    GithubOrganizationMembership, GithubOrganizationMembershipRole, GithubRoleMappingError,
    GithubTeam, GithubTeamId, GithubTeamSlug,
};
pub use transaction_state::{
    GithubDeviceTransactionMetadata, GithubTransactionStateCodec, GithubTransactionStateError,
};
