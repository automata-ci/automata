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
/// A validated GitHub App OAuth client identifier.
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

    /// Returns the validated client identifier.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
/// Trusted same-origin endpoints used by GitHub OAuth flows.
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

    /// Returns the browser authorization endpoint.
    pub fn authorization(&self) -> &Url {
        &self.authorization
    }

    /// Returns the device-code issuance endpoint.
    pub fn device_code(&self) -> &Url {
        &self.device_code
    }

    /// Returns the access-token exchange endpoint.
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

/// Validated configuration for GitHub App human authentication.
pub struct GithubAppConfig {
    provider_id: ProviderId,
    client_id: GithubClientId,
    client_secret: SecretString,
    callback_uri: Url,
    endpoints: GithubEndpoints,
    web_transaction_ttl_seconds: u64,
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
        })
    }

    /// Returns the provider identity associated with this GitHub App.
    pub fn provider_id(&self) -> &ProviderId {
        &self.provider_id
    }

    /// Returns the GitHub App OAuth client identifier.
    pub fn client_id(&self) -> &GithubClientId {
        &self.client_id
    }

    pub(crate) fn client_secret(&self) -> &SecretString {
        &self.client_secret
    }

    /// Returns the validated OAuth callback URI.
    pub fn callback_uri(&self) -> &Url {
        &self.callback_uri
    }

    /// Returns the trusted OAuth endpoint set.
    pub fn endpoints(&self) -> &GithubEndpoints {
        &self.endpoints
    }

    /// Returns the lifetime of a web authorization transaction, in seconds.
    pub const fn web_transaction_ttl_seconds(&self) -> u64 {
        self.web_transaction_ttl_seconds
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
/// A validation failure in GitHub App authentication configuration.
pub enum GithubConfigurationError {
    /// The GitHub App client identifier is empty, oversized, or not alphanumeric.
    #[error("GitHub client ID is invalid")]
    InvalidClientId,
    /// An OAuth endpoint is not a safe query-free HTTPS URL.
    #[error("GitHub OAuth endpoints must be query-free HTTPS URLs without user info or fragments")]
    InvalidEndpoint,
    /// The configured OAuth endpoints do not share one origin.
    #[error("GitHub OAuth endpoints must share an origin")]
    EndpointOriginMismatch,
    /// The callback URI is not safe for a web authorization response.
    #[error("callback URI must be HTTPS, or HTTP on a loopback host, without query or fragment")]
    InvalidCallbackUri,
    /// The web authorization transaction lifetime is outside the supported range.
    #[error("web authorization transaction TTL must be between 60 and 1800 seconds")]
    InvalidTransactionTtl,
    /// A configured URL could not be parsed.
    #[error("URL is invalid: {0}")]
    InvalidUrl(#[from] url::ParseError),
}

/// Inputs for exchanging a web authorization code for GitHub tokens.
pub struct WebTokenExchangeRequest<'a> {
    /// The trusted access-token endpoint.
    pub endpoint: &'a Url,
    /// The GitHub App client identifier.
    pub client_id: &'a GithubClientId,
    /// The GitHub App client secret.
    pub client_secret: &'a SecretString,
    /// The one-time authorization code returned by GitHub.
    pub code: &'a SecretString,
    /// The callback URI bound to the authorization transaction.
    pub redirect_uri: &'a Url,
    /// The PKCE verifier bound to the authorization transaction.
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
/// Inputs for requesting a GitHub device authorization code.
pub struct DeviceCodeRequest<'a> {
    /// The trusted device-code endpoint.
    pub endpoint: &'a Url,
    /// The GitHub App client identifier.
    pub client_id: &'a GithubClientId,
}

/// Inputs for polling a GitHub device authorization transaction.
pub struct DeviceTokenPollRequest<'a> {
    /// The trusted access-token endpoint.
    pub endpoint: &'a Url,
    /// The GitHub App client identifier.
    pub client_id: &'a GithubClientId,
    /// The secret device code identifying the pending transaction.
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

/// Inputs for refreshing a GitHub OAuth access token.
pub struct RefreshTokenRequest<'a> {
    /// The trusted access-token endpoint.
    pub endpoint: &'a Url,
    /// The GitHub App client identifier.
    pub client_id: &'a GithubClientId,
    /// GitHub requires this for web-flow grants and permits omission for device grants.
    pub client_secret: Option<&'a SecretString>,
    /// The protected provider refresh token to exchange.
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

/// Inputs for loading the GitHub identity associated with an access token.
pub struct GithubCurrentUserRequest<'a> {
    /// The access token used only to authenticate the identity request.
    pub access_token: &'a SecretString,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
/// The stable identity and display metadata returned for a GitHub user.
pub struct GithubUser {
    /// The stable numeric GitHub user identifier.
    pub id: u64,
    /// The current GitHub account login.
    pub login: String,
    /// The optional current display name.
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
/// A GitHub device authorization response.
pub struct DeviceCodeResponse {
    /// The secret code used when polling the device transaction.
    pub device_code: SecretString,
    /// The secret short code displayed to the user.
    pub user_code: SecretString,
    /// The trusted GitHub page where the user enters the code.
    pub verification_uri: Url,
    /// The device transaction lifetime, in seconds.
    pub expires_in: u64,
    /// The minimum initial polling interval, in seconds.
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
/// Tokens and metadata returned by a successful GitHub OAuth exchange.
pub struct GithubTokenResponse {
    /// The secret provider access token.
    pub access_token: SecretString,
    /// The optional access-token lifetime, in seconds.
    pub expires_in: Option<u64>,
    /// The optional secret provider refresh token.
    pub refresh_token: Option<SecretString>,
    /// The optional refresh-token lifetime, in seconds.
    pub refresh_token_expires_in: Option<u64>,
    #[serde(default)]
    /// The provider-reported OAuth scope string.
    pub scope: String,
    /// The provider-reported token type.
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
/// A normalized result from polling a GitHub device authorization transaction.
pub enum GithubDevicePollResponse {
    /// GitHub issued tokens for the completed transaction.
    Token(GithubTokenResponse),
    /// The user has not completed authorization yet.
    AuthorizationPending,
    /// GitHub requires a slower polling interval.
    SlowDown,
    /// The user denied the authorization request.
    AccessDenied,
    /// The device transaction expired.
    ExpiredToken,
    /// The supplied device code does not identify a valid transaction.
    IncorrectDeviceCode,
}

/// The security-relevant outcome of a GitHub web authorization callback.
pub enum GithubWebCallback {
    /// GitHub returned an authorization code and the transaction state.
    Authorized {
        /// The one-time secret authorization code.
        code: SecretString,
        /// The secret transaction state returned by GitHub.
        state: SecretString,
    },
    /// GitHub denied authorization and returned the transaction state.
    Denied {
        /// The provider's bounded denial classification.
        error: String,
        /// The secret transaction state returned by GitHub.
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
        .append_pair("allow_signup", "false");
    endpoint
}
