use std::{fmt, future::Future, pin::Pin, sync::Arc};

use thiserror::Error;

use crate::{
    human::{
        AuthenticatedHuman, AuthenticationFuture, AuthenticationProvider,
        AuthenticationProviderError, PrincipalId, ProviderCredential, ProviderId, ProviderSubject,
    },
    time::Clock,
};

use super::{
    DeviceCodeRequest, DeviceCodeResponse, DeviceTokenPollRequest, GithubCurrentUserRequest,
    GithubDevicePollResponse, GithubMembershipSnapshot, GithubTokenResponse, GithubUser,
    RefreshTokenRequest, WebTokenExchangeRequest,
};

pub type GithubEndpointFuture<'a, T> =
    Pin<Box<dyn Future<Output = Result<T, GithubEndpointError>> + Send + 'a>>;

/// Typed asynchronous boundary around GitHub's HTTP API.
///
/// A production adapter is responsible for form encoding, JSON decoding, timeouts,
/// TLS, response size limits, and GitHub API version headers. Tests can implement
/// this trait without opening sockets.
pub trait GithubEndpoint: fmt::Debug + Send + Sync {
    fn exchange_web_code<'a>(
        &'a self,
        request: WebTokenExchangeRequest<'a>,
    ) -> GithubEndpointFuture<'a, GithubTokenResponse>;

    fn request_device_code<'a>(
        &'a self,
        request: DeviceCodeRequest<'a>,
    ) -> GithubEndpointFuture<'a, DeviceCodeResponse>;

    fn poll_device_token<'a>(
        &'a self,
        request: DeviceTokenPollRequest<'a>,
    ) -> GithubEndpointFuture<'a, GithubDevicePollResponse>;

    fn refresh_token<'a>(
        &'a self,
        request: RefreshTokenRequest<'a>,
    ) -> GithubEndpointFuture<'a, GithubTokenResponse>;

    fn current_user<'a>(
        &'a self,
        request: GithubCurrentUserRequest<'a>,
    ) -> GithubEndpointFuture<'a, GithubUser>;

    fn memberships<'a>(
        &'a self,
        request: GithubCurrentUserRequest<'a>,
    ) -> GithubEndpointFuture<'a, GithubMembershipSnapshot>;
}

#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum GithubEndpointError {
    #[error("GitHub rejected the credential")]
    Unauthorized,
    #[error("GitHub denied the operation")]
    Forbidden,
    #[error("GitHub rate limit was exceeded")]
    RateLimited { retry_after_seconds: Option<u64> },
    #[error("GitHub endpoint is unavailable")]
    Unavailable,
    #[error("GitHub returned an invalid or oversized response")]
    InvalidResponse,
}

/// First human authentication provider adapter. It uses a freshly exchanged GitHub
/// token only to re-fetch the stable GitHub user ID; the token is not an Automata
/// bearer credential.
pub struct GithubAppAuthenticationProvider {
    provider_id: ProviderId,
    endpoint: Arc<dyn GithubEndpoint>,
    clock: Arc<dyn Clock>,
}

impl GithubAppAuthenticationProvider {
    pub fn new(
        provider_id: ProviderId,
        endpoint: Arc<dyn GithubEndpoint>,
        clock: Arc<dyn Clock>,
    ) -> Self {
        Self {
            provider_id,
            endpoint,
            clock,
        }
    }
}

impl fmt::Debug for GithubAppAuthenticationProvider {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GithubAppAuthenticationProvider")
            .field("provider_id", &self.provider_id)
            .finish_non_exhaustive()
    }
}

impl AuthenticationProvider for GithubAppAuthenticationProvider {
    fn provider_id(&self) -> &ProviderId {
        &self.provider_id
    }

    fn authenticate<'a>(&'a self, credential: &'a ProviderCredential) -> AuthenticationFuture<'a> {
        Box::pin(async move {
            if credential.provider_id() != &self.provider_id {
                return Err(AuthenticationProviderError::WrongProvider);
            }
            let user = self
                .endpoint
                .current_user(GithubCurrentUserRequest {
                    access_token: credential.access_token(),
                })
                .await
                .map_err(map_endpoint_authentication_error)?;
            validate_user(&user)?;
            let provider_subject = ProviderSubject::new(user.id.to_string())
                .map_err(|_| AuthenticationProviderError::InvalidResponse)?;
            let principal_id =
                PrincipalId::new(format!("{}:{}", self.provider_id.as_str(), user.id))
                    .map_err(|_| AuthenticationProviderError::InvalidResponse)?;
            AuthenticatedHuman::new(
                principal_id,
                self.provider_id.clone(),
                provider_subject,
                user.login,
                user.name,
                self.clock.now(),
            )
            .map_err(|_| AuthenticationProviderError::InvalidResponse)
        })
    }
}

fn validate_user(user: &GithubUser) -> Result<(), AuthenticationProviderError> {
    if user.id == 0
        || user.login.is_empty()
        || user.login.len() > 255
        || user.login.chars().any(char::is_control)
        || user
            .name
            .as_ref()
            .is_some_and(|name| name.len() > 1_024 || name.chars().any(char::is_control))
    {
        return Err(AuthenticationProviderError::InvalidResponse);
    }
    Ok(())
}

fn map_endpoint_authentication_error(error: GithubEndpointError) -> AuthenticationProviderError {
    match error {
        GithubEndpointError::Unauthorized | GithubEndpointError::Forbidden => {
            AuthenticationProviderError::Rejected
        }
        GithubEndpointError::InvalidResponse => AuthenticationProviderError::InvalidResponse,
        GithubEndpointError::RateLimited { .. } | GithubEndpointError::Unavailable => {
            AuthenticationProviderError::Unavailable
        }
    }
}
