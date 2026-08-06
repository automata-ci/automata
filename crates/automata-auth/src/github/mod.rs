//! GitHub App human authentication protocol and explicit RBAC mapping.

mod flow;
mod model;
mod port;
mod role_mapping;

pub use flow::{
    DeviceAuthorization, DeviceAuthorizationStatus, DevicePollOutcome, GithubAppProtocol,
    GithubFlowError, WebAuthorization, WebAuthorizationTransaction,
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
    GithubMembershipSnapshot, GithubOrganizationName, GithubRoleMapper, GithubRoleMapping,
    GithubRoleMappingError, GithubRoleSource, GithubTeam, GithubTeamSlug,
};
