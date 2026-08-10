use std::{fmt, time::Duration};

use automata_ci_credential::ProviderResourceId;
use reqwest::header::HeaderValue;
use thiserror::Error;
use url::{Host, Url};

/// GitHub REST API version sent with every broker request.
pub const GITHUB_API_VERSION: &str = "2026-03-10";

const DEFAULT_MAX_RESPONSE_BYTES: usize = 256 * 1_024;
const MAX_RESPONSE_BYTES: usize = 1_048_576;
const MAX_TIMEOUT: Duration = Duration::from_mins(5);
const MAX_USER_AGENT_BYTES: usize = 256;
const MAX_ISSUER_BYTES: usize = 128;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
/// Bounded response-size and wall-clock limits for GitHub HTTP operations.
///
/// These limits apply before response metadata is trusted. The default allows
/// 256 KiB, five seconds to connect, and twenty seconds for a complete request.
pub struct GithubAppHttpLimits {
    pub(crate) max_response_bytes: usize,
    pub(crate) connect_timeout: Duration,
    pub(crate) request_timeout: Duration,
}

impl GithubAppHttpLimits {
    /// Creates bounded response and wall-clock limits.
    ///
    /// # Errors
    ///
    /// Rejects zero or excessive values and connect timeouts longer than the
    /// complete request timeout.
    pub fn new(
        max_response_bytes: usize,
        connect_timeout: Duration,
        request_timeout: Duration,
    ) -> Result<Self, GithubAppConfigurationError> {
        if max_response_bytes == 0 || max_response_bytes > MAX_RESPONSE_BYTES {
            return Err(GithubAppConfigurationError::InvalidResponseByteLimit);
        }
        if connect_timeout.is_zero()
            || request_timeout.is_zero()
            || connect_timeout > request_timeout
            || request_timeout > MAX_TIMEOUT
        {
            return Err(GithubAppConfigurationError::InvalidTimeout);
        }
        Ok(Self {
            max_response_bytes,
            connect_timeout,
            request_timeout,
        })
    }
}

impl Default for GithubAppHttpLimits {
    fn default() -> Self {
        Self {
            max_response_bytes: DEFAULT_MAX_RESPONSE_BYTES,
            connect_timeout: Duration::from_secs(5),
            request_timeout: Duration::from_secs(20),
        }
    }
}

/// Nonzero GitHub App installation identifier.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GithubInstallationId(u64);

impl GithubInstallationId {
    /// Creates an installation identifier.
    ///
    /// # Errors
    ///
    /// Rejects zero.
    pub const fn new(value: u64) -> Result<Self, GithubAppConfigurationError> {
        if value == 0 {
            return Err(GithubAppConfigurationError::InvalidInstallationId);
        }
        Ok(Self(value))
    }

    #[must_use]
    /// Returns the validated, nonzero numeric installation identifier.
    pub const fn get(self) -> u64 {
        self.0
    }
}

#[derive(Clone)]
/// Validated identity, installation, origin, and resource bounds for a broker.
///
/// The API base is both an endpoint prefix and a fixed-origin trust boundary.
/// Derived mint and revocation URLs must remain below that prefix on the same
/// scheme, host, and effective port. The issuer identifies the GitHub App that
/// signs requests; the installation ID selects the installation whose exact
/// repository-scoped credentials may be minted.
pub struct GithubAppCredentialConfig {
    pub(crate) api_base: Url,
    pub(crate) issuer: ProviderResourceId,
    pub(crate) installation_id: GithubInstallationId,
    pub(crate) user_agent: HeaderValue,
    pub(crate) limits: GithubAppHttpLimits,
    pub(crate) transport_security: TransportSecurity,
}

impl GithubAppCredentialConfig {
    /// Creates an HTTPS-only GitHub or GitHub Enterprise configuration.
    ///
    /// `api_base` must be a credential-free base URL ending in `/`; a GitHub
    /// Enterprise Server base such as `https://github.example/api/v3/` is valid.
    /// The issuer should normally be the GitHub App client ID.
    ///
    /// # Errors
    ///
    /// Rejects an untrusted URL, invalid issuer, or invalid user agent.
    pub fn new(
        api_base: Url,
        issuer: ProviderResourceId,
        installation_id: GithubInstallationId,
        user_agent: &str,
        limits: GithubAppHttpLimits,
    ) -> Result<Self, GithubAppConfigurationError> {
        Self::validated(
            api_base,
            issuer,
            installation_id,
            user_agent,
            limits,
            TransportSecurity::HttpsOnly,
        )
    }

    /// Returns a public GitHub.com configuration.
    ///
    /// # Errors
    ///
    /// Rejects an invalid issuer, installation identifier, or user agent.
    pub fn github_dot_com(
        issuer: ProviderResourceId,
        installation_id: GithubInstallationId,
        user_agent: &str,
    ) -> Result<Self, GithubAppConfigurationError> {
        let api_base = Url::parse("https://api.github.com/")
            .map_err(|_| GithubAppConfigurationError::InvalidApiBase)?;
        Self::new(
            api_base,
            issuer,
            installation_id,
            user_agent,
            GithubAppHttpLimits::default(),
        )
    }

    /// Explicit test escape hatch. HTTP is accepted only for a loopback origin.
    ///
    /// # Errors
    ///
    /// Applies the same validation as production in addition to the loopback-only
    /// transport requirement.
    #[doc(hidden)]
    pub fn new_for_loopback_testing(
        api_base: Url,
        issuer: ProviderResourceId,
        installation_id: GithubInstallationId,
        user_agent: &str,
        limits: GithubAppHttpLimits,
    ) -> Result<Self, GithubAppConfigurationError> {
        Self::validated(
            api_base,
            issuer,
            installation_id,
            user_agent,
            limits,
            TransportSecurity::LoopbackHttp,
        )
    }

    fn validated(
        api_base: Url,
        issuer: ProviderResourceId,
        installation_id: GithubInstallationId,
        user_agent: &str,
        limits: GithubAppHttpLimits,
        transport_security: TransportSecurity,
    ) -> Result<Self, GithubAppConfigurationError> {
        validate_api_base(&api_base, transport_security)?;
        validate_issuer(&issuer)?;
        let user_agent = validate_user_agent(user_agent)?;
        Ok(Self {
            api_base,
            issuer,
            installation_id,
            user_agent,
            limits,
            transport_security,
        })
    }

    #[must_use]
    /// Returns the credential-free fixed-origin GitHub API base URL.
    pub const fn api_base(&self) -> &Url {
        &self.api_base
    }

    #[must_use]
    /// Returns the stable GitHub App issuer used in signed assertions.
    pub const fn issuer(&self) -> &ProviderResourceId {
        &self.issuer
    }

    #[must_use]
    /// Returns the exact GitHub App installation selected by this config.
    pub const fn installation_id(&self) -> GithubInstallationId {
        self.installation_id
    }

    #[must_use]
    /// Returns the validated HTTP response and timeout bounds.
    pub const fn limits(&self) -> GithubAppHttpLimits {
        self.limits
    }

    pub(crate) fn trusts_api_url(&self, endpoint: &Url) -> bool {
        valid_endpoint(endpoint, self.transport_security)
            && same_origin(&self.api_base, endpoint)
            && endpoint.path().starts_with(self.api_base.path())
            && endpoint.query().is_none()
    }
}

impl fmt::Debug for GithubAppCredentialConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GithubAppCredentialConfig")
            .field("api_base", &self.api_base)
            .field("issuer", &self.issuer)
            .field("installation_id", &self.installation_id)
            .field("user_agent", &self.user_agent)
            .field("limits", &self.limits)
            .field("transport_security", &self.transport_security)
            .finish()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum TransportSecurity {
    HttpsOnly,
    LoopbackHttp,
}

fn validate_api_base(
    api_base: &Url,
    security: TransportSecurity,
) -> Result<(), GithubAppConfigurationError> {
    if !valid_endpoint(api_base, security)
        || api_base.cannot_be_a_base()
        || !api_base.path().ends_with('/')
        || api_base.query().is_some()
    {
        return Err(GithubAppConfigurationError::InvalidApiBase);
    }
    Ok(())
}

fn valid_endpoint(endpoint: &Url, security: TransportSecurity) -> bool {
    let valid_scheme = match security {
        TransportSecurity::HttpsOnly => endpoint.scheme() == "https",
        TransportSecurity::LoopbackHttp => {
            endpoint.scheme() == "http"
                && endpoint
                    .host()
                    .as_ref()
                    .is_some_and(|host| is_loopback_host(host))
        }
    };
    valid_scheme
        && endpoint.host_str().is_some()
        && endpoint.username().is_empty()
        && endpoint.password().is_none()
        && endpoint.fragment().is_none()
}

fn is_loopback_host(host: &Host<&str>) -> bool {
    match host {
        Host::Domain(domain) => domain.eq_ignore_ascii_case("localhost"),
        Host::Ipv4(address) => address.is_loopback(),
        Host::Ipv6(address) => address.is_loopback(),
    }
}

fn validate_issuer(issuer: &ProviderResourceId) -> Result<(), GithubAppConfigurationError> {
    let value = issuer.as_str();
    if value.len() > MAX_ISSUER_BYTES
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
    {
        return Err(GithubAppConfigurationError::InvalidIssuer);
    }
    Ok(())
}

fn validate_user_agent(value: &str) -> Result<HeaderValue, GithubAppConfigurationError> {
    if value.is_empty() || value.len() > MAX_USER_AGENT_BYTES {
        return Err(GithubAppConfigurationError::InvalidUserAgent);
    }
    HeaderValue::from_str(value).map_err(|_| GithubAppConfigurationError::InvalidUserAgent)
}

fn same_origin(left: &Url, right: &Url) -> bool {
    left.scheme() == right.scheme()
        && left.host_str() == right.host_str()
        && left.port_or_known_default() == right.port_or_known_default()
}

#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
/// Sanitized reason a GitHub App broker configuration could not be accepted.
///
/// Variants deliberately omit the rejected URL, identity, user agent, and
/// lower-level HTTP client error.
pub enum GithubAppConfigurationError {
    /// The API base is not a credential-free, query-free trusted base URL.
    #[error("GitHub API base URL is invalid")]
    InvalidApiBase,
    /// The App issuer is empty, too long, or contains unsupported characters.
    #[error("GitHub App issuer is invalid")]
    InvalidIssuer,
    /// The installation identifier is zero.
    #[error("GitHub App installation identifier is invalid")]
    InvalidInstallationId,
    /// The maximum response size is zero or exceeds the hard one-MiB ceiling.
    #[error("GitHub HTTP response byte limit is invalid")]
    InvalidResponseByteLimit,
    /// A timeout is zero, inconsistent, or exceeds the five-minute ceiling.
    #[error("GitHub HTTP timeout is invalid")]
    InvalidTimeout,
    /// The user agent is empty, oversized, or not a valid HTTP header value.
    #[error("GitHub HTTP user agent is invalid")]
    InvalidUserAgent,
    /// The hardened, redirect-free and proxy-free HTTP client could not be built.
    #[error("GitHub HTTP client construction failed")]
    ClientConstructionFailed,
}
