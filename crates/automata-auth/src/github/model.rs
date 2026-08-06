use std::fmt;

use serde::Deserialize;
use thiserror::Error;
use url::Url;

use crate::{
    human::ProviderId,
    secret::{OAuthState, PkceVerifier, SecretString},
    vault::ProviderRefreshToken,
};

#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct GithubClientId(String);

impl GithubClientId {
    /// Creates a validated GitHub App client ID.
    ///
    /// # Errors
    ///
    /// Returns an error for an empty, oversized, or non-alphanumeric client ID.
    pub fn new(value: impl Into<String>) -> Result<Self, GithubConfigurationError> {
        let value = value.into();
        if value.is_empty()
            || value.len() > 255
            || !value
                .bytes()
                .all(|character| character.is_ascii_alphanumeric())
        {
            return Err(GithubConfigurationError::InvalidClientId);
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GithubEndpoints {
    authorization: Url,
    device_code: Url,
    access_token: Url,
}

impl GithubEndpoints {
    /// Returns GitHub.com's public authorization endpoints.
    ///
    /// # Errors
    ///
    /// Returns an error only if the compile-time endpoint constants cease to parse
    /// or satisfy the endpoint invariants.
    pub fn github_dot_com() -> Result<Self, GithubConfigurationError> {
        Self::new(
            Url::parse("https://github.com/login/oauth/authorize")?,
            Url::parse("https://github.com/login/device/code")?,
            Url::parse("https://github.com/login/oauth/access_token")?,
        )
    }

    /// Creates a trusted, same-origin GitHub OAuth endpoint set.
    ///
    /// # Errors
    ///
    /// Returns an error unless every endpoint is a query-free HTTPS URL without
    /// user info or a fragment and all endpoints share an origin.
    pub fn new(
        authorization: Url,
        device_code: Url,
        access_token: Url,
    ) -> Result<Self, GithubConfigurationError> {
        for endpoint in [&authorization, &device_code, &access_token] {
            validate_https_endpoint(endpoint)?;
        }
        if !same_origin(&authorization, &device_code) || !same_origin(&authorization, &access_token)
        {
            return Err(GithubConfigurationError::EndpointOriginMismatch);
        }
        Ok(Self {
            authorization,
            device_code,
            access_token,
        })
    }

    pub fn authorization(&self) -> &Url {
        &self.authorization
    }

    pub fn device_code(&self) -> &Url {
        &self.device_code
    }

    pub fn access_token(&self) -> &Url {
        &self.access_token
    }

    pub(crate) fn trusts_verification_uri(&self, uri: &Url) -> bool {
        uri.scheme() == "https"
            && uri.username().is_empty()
            && uri.password().is_none()
            && uri.fragment().is_none()
            && same_origin(&self.device_code, uri)
    }
}

fn validate_https_endpoint(endpoint: &Url) -> Result<(), GithubConfigurationError> {
    if endpoint.scheme() != "https"
        || endpoint.host_str().is_none()
        || !endpoint.username().is_empty()
        || endpoint.password().is_some()
        || endpoint.query().is_some()
        || endpoint.fragment().is_some()
    {
        return Err(GithubConfigurationError::InvalidEndpoint);
    }
    Ok(())
}

fn same_origin(left: &Url, right: &Url) -> bool {
    left.scheme() == right.scheme()
        && left.host_str() == right.host_str()
        && left.port_or_known_default() == right.port_or_known_default()
}

pub struct GithubAppConfig {
    provider_id: ProviderId,
    client_id: GithubClientId,
    client_secret: SecretString,
    callback_uri: Url,
    endpoints: GithubEndpoints,
    web_transaction_ttl_seconds: u64,
    allow_signup: bool,
}

impl GithubAppConfig {
    /// Creates validated GitHub App authentication configuration.
    ///
    /// # Errors
    ///
    /// Returns an error for an unsafe callback URI or transaction TTL outside the
    /// supported range.
    pub fn new(
        provider_id: ProviderId,
        client_id: GithubClientId,
        client_secret: SecretString,
        callback_uri: Url,
        endpoints: GithubEndpoints,
        web_transaction_ttl_seconds: u64,
    ) -> Result<Self, GithubConfigurationError> {
        validate_callback_uri(&callback_uri)?;
        if !(60..=1_800).contains(&web_transaction_ttl_seconds) {
            return Err(GithubConfigurationError::InvalidTransactionTtl);
        }
        Ok(Self {
            provider_id,
            client_id,
            client_secret,
            callback_uri,
            endpoints,
            web_transaction_ttl_seconds,
            allow_signup: false,
        })
    }

    #[must_use]
    pub fn with_signup(mut self, allow_signup: bool) -> Self {
        self.allow_signup = allow_signup;
        self
    }

    pub fn provider_id(&self) -> &ProviderId {
        &self.provider_id
    }

    pub fn client_id(&self) -> &GithubClientId {
        &self.client_id
    }

    pub(crate) fn client_secret(&self) -> &SecretString {
        &self.client_secret
    }

    pub fn callback_uri(&self) -> &Url {
        &self.callback_uri
    }

    pub fn endpoints(&self) -> &GithubEndpoints {
        &self.endpoints
    }

    pub const fn web_transaction_ttl_seconds(&self) -> u64 {
        self.web_transaction_ttl_seconds
    }

    pub const fn allow_signup(&self) -> bool {
        self.allow_signup
    }
}

impl fmt::Debug for GithubAppConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GithubAppConfig")
            .field("provider_id", &self.provider_id)
            .field("client_id", &self.client_id)
            .field("client_secret", &"[REDACTED]")
            .field("callback_uri", &self.callback_uri)
            .field("endpoints", &self.endpoints)
            .field(
                "web_transaction_ttl_seconds",
                &self.web_transaction_ttl_seconds,
            )
            .field("allow_signup", &self.allow_signup)
            .finish()
    }
}

fn validate_callback_uri(uri: &Url) -> Result<(), GithubConfigurationError> {
    let is_https = uri.scheme() == "https";
    let is_loopback_http = uri.scheme() == "http"
        && uri.host().is_some_and(|host| match host {
            url::Host::Domain(domain) => domain.eq_ignore_ascii_case("localhost"),
            url::Host::Ipv4(address) => address.is_loopback(),
            url::Host::Ipv6(address) => address.is_loopback(),
        });
    if (!is_https && !is_loopback_http)
        || uri.host_str().is_none()
        || !uri.username().is_empty()
        || uri.password().is_some()
        || uri.query().is_some()
        || uri.fragment().is_some()
    {
        return Err(GithubConfigurationError::InvalidCallbackUri);
    }
    Ok(())
}

#[derive(Debug, Error)]
pub enum GithubConfigurationError {
    #[error("GitHub client ID is invalid")]
    InvalidClientId,
    #[error("GitHub OAuth endpoints must be query-free HTTPS URLs without user info or fragments")]
    InvalidEndpoint,
    #[error("GitHub OAuth endpoints must share an origin")]
    EndpointOriginMismatch,
    #[error("callback URI must be HTTPS, or HTTP on a loopback host, without query or fragment")]
    InvalidCallbackUri,
    #[error("web authorization transaction TTL must be between 60 and 1800 seconds")]
    InvalidTransactionTtl,
    #[error("URL is invalid: {0}")]
    InvalidUrl(#[from] url::ParseError),
}

pub struct WebTokenExchangeRequest<'a> {
    pub endpoint: &'a Url,
    pub client_id: &'a GithubClientId,
    pub client_secret: &'a SecretString,
    pub code: &'a SecretString,
    pub redirect_uri: &'a Url,
    pub code_verifier: &'a PkceVerifier,
}

impl fmt::Debug for WebTokenExchangeRequest<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("WebTokenExchangeRequest")
            .field("endpoint", self.endpoint)
            .field("client_id", self.client_id)
            .field("client_secret", &"[REDACTED]")
            .field("code", &"[REDACTED]")
            .field("redirect_uri", self.redirect_uri)
            .field("code_verifier", &"[REDACTED]")
            .finish()
    }
}

#[derive(Clone, Copy, Debug)]
pub struct DeviceCodeRequest<'a> {
    pub endpoint: &'a Url,
    pub client_id: &'a GithubClientId,
}

pub struct DeviceTokenPollRequest<'a> {
    pub endpoint: &'a Url,
    pub client_id: &'a GithubClientId,
    pub device_code: &'a SecretString,
}

impl fmt::Debug for DeviceTokenPollRequest<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DeviceTokenPollRequest")
            .field("endpoint", self.endpoint)
            .field("client_id", self.client_id)
            .field("device_code", &"[REDACTED]")
            .finish()
    }
}

pub struct RefreshTokenRequest<'a> {
    pub endpoint: &'a Url,
    pub client_id: &'a GithubClientId,
    /// GitHub requires this for web-flow grants and permits omission for device grants.
    pub client_secret: Option<&'a SecretString>,
    pub refresh_token: &'a ProviderRefreshToken,
}

impl fmt::Debug for RefreshTokenRequest<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RefreshTokenRequest")
            .field("endpoint", self.endpoint)
            .field("client_id", self.client_id)
            .field(
                "client_secret",
                &self.client_secret.as_ref().map(|_| "[REDACTED]"),
            )
            .field("refresh_token", &"[REDACTED]")
            .finish()
    }
}

pub struct GithubCurrentUserRequest<'a> {
    pub access_token: &'a SecretString,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
pub struct GithubUser {
    pub id: u64,
    pub login: String,
    pub name: Option<String>,
}

impl fmt::Debug for GithubCurrentUserRequest<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GithubCurrentUserRequest")
            .field("access_token", &"[REDACTED]")
            .finish()
    }
}

#[derive(Deserialize)]
pub struct DeviceCodeResponse {
    pub device_code: SecretString,
    pub user_code: SecretString,
    pub verification_uri: Url,
    pub expires_in: u64,
    pub interval: u64,
}

impl fmt::Debug for DeviceCodeResponse {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DeviceCodeResponse")
            .field("device_code", &"[REDACTED]")
            .field("user_code", &"[REDACTED]")
            .field("verification_uri", &self.verification_uri)
            .field("expires_in", &self.expires_in)
            .field("interval", &self.interval)
            .finish()
    }
}

#[derive(Deserialize)]
pub struct GithubTokenResponse {
    pub access_token: SecretString,
    pub expires_in: Option<u64>,
    pub refresh_token: Option<SecretString>,
    pub refresh_token_expires_in: Option<u64>,
    #[serde(default)]
    pub scope: String,
    pub token_type: String,
}

impl fmt::Debug for GithubTokenResponse {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GithubTokenResponse")
            .field("access_token", &"[REDACTED]")
            .field("expires_in", &self.expires_in)
            .field(
                "refresh_token",
                &self.refresh_token.as_ref().map(|_| "[REDACTED]"),
            )
            .field("refresh_token_expires_in", &self.refresh_token_expires_in)
            .field("scope", &self.scope)
            .field("token_type", &self.token_type)
            .finish()
    }
}

#[derive(Debug)]
pub enum GithubDevicePollResponse {
    Token(GithubTokenResponse),
    AuthorizationPending,
    SlowDown,
    AccessDenied,
    ExpiredToken,
    IncorrectDeviceCode,
}

pub enum GithubWebCallback {
    Authorized {
        code: SecretString,
        state: SecretString,
    },
    Denied {
        error: String,
        state: SecretString,
    },
}

impl GithubWebCallback {
    pub(crate) fn state(&self) -> &SecretString {
        match self {
            Self::Authorized { state, .. } | Self::Denied { state, .. } => state,
        }
    }
}

impl fmt::Debug for GithubWebCallback {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Authorized { .. } => formatter
                .debug_struct("GithubWebCallback::Authorized")
                .field("code", &"[REDACTED]")
                .field("state", &"[REDACTED]")
                .finish(),
            Self::Denied { error, .. } => formatter
                .debug_struct("GithubWebCallback::Denied")
                .field(
                    "error",
                    &if error.is_empty() {
                        "missing"
                    } else {
                        "present"
                    },
                )
                .field("state", &"[REDACTED]")
                .finish(),
        }
    }
}

pub(crate) fn append_web_authorization_query(
    mut endpoint: Url,
    config: &GithubAppConfig,
    state: &OAuthState,
    verifier: &PkceVerifier,
) -> Url {
    let challenge = verifier.challenge_s256();
    endpoint
        .query_pairs_mut()
        .append_pair("client_id", config.client_id().as_str())
        .append_pair("redirect_uri", config.callback_uri().as_str())
        .append_pair("state", state.expose_secret())
        .append_pair("code_challenge", challenge.as_str())
        .append_pair("code_challenge_method", "S256")
        .append_pair(
            "allow_signup",
            if config.allow_signup() {
                "true"
            } else {
                "false"
            },
        );
    endpoint
}
