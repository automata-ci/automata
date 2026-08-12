use std::{fmt, time::Duration};

use reqwest::header::HeaderValue;
use thiserror::Error;
use url::{Host, Url};

/// GitHub REST API version sent on every authenticated API request.
pub const GITHUB_API_VERSION: &str = "2026-03-10";

const DEFAULT_MAX_RESPONSE_BYTES: usize = 1_048_576;
const DEFAULT_MAX_PAGES: usize = 128;
const DEFAULT_MAX_MEMBERSHIPS: usize = 10_000;
const MAX_RESPONSE_BYTES: usize = 16 * 1_048_576;
const MAX_PAGES: usize = 1_024;
const MAX_MEMBERSHIPS: usize = 100_000;
const MAX_TIMEOUT: Duration = Duration::from_mins(5);
const MAX_USER_AGENT_LENGTH: usize = 256;

/// Hard response, pagination, membership, and timeout ceilings for GitHub HTTP calls.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GithubHttpLimits {
    pub(crate) max_response_bytes: usize,
    pub(crate) max_pages: usize,
    pub(crate) max_memberships: usize,
    pub(crate) connect_timeout: Duration,
    pub(crate) request_timeout: Duration,
}

impl GithubHttpLimits {
    /// Creates bounded transport and pagination limits.
    ///
    /// # Errors
    ///
    /// Returns an error for zero or excessive limits, or when the connect timeout
    /// is longer than the complete request timeout.
    pub fn new(
        max_response_bytes: usize,
        max_pages: usize,
        max_memberships: usize,
        connect_timeout: Duration,
        request_timeout: Duration,
    ) -> Result<Self, GithubHttpConfigurationError> {
        if max_response_bytes == 0 || max_response_bytes > MAX_RESPONSE_BYTES {
            return Err(GithubHttpConfigurationError::InvalidResponseByteLimit);
        }
        if max_pages == 0 || max_pages > MAX_PAGES {
            return Err(GithubHttpConfigurationError::InvalidPageLimit);
        }
        if max_memberships == 0 || max_memberships > MAX_MEMBERSHIPS {
            return Err(GithubHttpConfigurationError::InvalidMembershipLimit);
        }
        if connect_timeout.is_zero()
            || request_timeout.is_zero()
            || connect_timeout > request_timeout
            || request_timeout > MAX_TIMEOUT
        {
            return Err(GithubHttpConfigurationError::InvalidTimeout);
        }
        Ok(Self {
            max_response_bytes,
            max_pages,
            max_memberships,
            connect_timeout,
            request_timeout,
        })
    }

    /// Returns the complete per-request timeout enforced by the HTTP client.
    #[must_use]
    pub const fn request_timeout(self) -> Duration {
        self.request_timeout
    }
}

impl Default for GithubHttpLimits {
    fn default() -> Self {
        Self {
            max_response_bytes: DEFAULT_MAX_RESPONSE_BYTES,
            max_pages: DEFAULT_MAX_PAGES,
            max_memberships: DEFAULT_MAX_MEMBERSHIPS,
            connect_timeout: Duration::from_secs(5),
            request_timeout: Duration::from_secs(20),
        }
    }
}

/// Validated OAuth and REST origins plus the bounded transport policy they share.
#[derive(Clone)]
pub struct GithubTrustedOrigins {
    pub(crate) oauth_origin: Url,
    pub(crate) api_base: Url,
    pub(crate) user_agent: HeaderValue,
    pub(crate) limits: GithubHttpLimits,
    pub(crate) transport_security: TransportSecurity,
}

impl GithubTrustedOrigins {
    /// Creates a production GitHub endpoint policy. Both origins must use HTTPS.
    ///
    /// `oauth_origin` must be an origin URL such as `https://github.com/`.
    /// `api_base` may include a path prefix, such as a GitHub Enterprise Server
    /// `https://github.example/api/v3/` base.
    ///
    /// # Errors
    ///
    /// Returns an error unless both URLs and the user agent satisfy the trust
    /// invariants.
    pub fn new(
        oauth_origin: Url,
        api_base: Url,
        user_agent: &str,
        limits: GithubHttpLimits,
    ) -> Result<Self, GithubHttpConfigurationError> {
        Self::validated(
            oauth_origin,
            api_base,
            user_agent,
            limits,
            TransportSecurity::HttpsOnly,
        )
    }

    /// Returns the public GitHub.com origin policy.
    ///
    /// # Errors
    ///
    /// Returns an error only if a compile-time URL or the supplied user agent is
    /// invalid.
    pub fn github_dot_com(user_agent: &str) -> Result<Self, GithubHttpConfigurationError> {
        Self::new(
            Url::parse("https://github.com/")
                .map_err(|_| GithubHttpConfigurationError::InvalidOAuthOrigin)?,
            Url::parse("https://api.github.com/")
                .map_err(|_| GithubHttpConfigurationError::InvalidApiBase)?,
            user_agent,
            GithubHttpLimits::default(),
        )
    }

    /// Returns the exact trusted origin used for OAuth endpoints.
    pub fn oauth_origin(&self) -> &Url {
        &self.oauth_origin
    }

    /// Returns the trusted REST API base, including any enterprise path prefix.
    pub fn api_base(&self) -> &Url {
        &self.api_base
    }

    /// Returns the response, pagination, membership, and timeout ceilings.
    pub const fn limits(&self) -> GithubHttpLimits {
        self.limits
    }

    pub(crate) fn loopback_emulator(
        oauth_origin: Url,
        api_base: Url,
        user_agent: &str,
        limits: GithubHttpLimits,
    ) -> Result<Self, GithubHttpConfigurationError> {
        Self::validated(
            oauth_origin,
            api_base,
            user_agent,
            limits,
            TransportSecurity::LoopbackHttp,
        )
    }

    fn validated(
        oauth_origin: Url,
        api_base: Url,
        user_agent: &str,
        limits: GithubHttpLimits,
        transport_security: TransportSecurity,
    ) -> Result<Self, GithubHttpConfigurationError> {
        validate_oauth_origin(&oauth_origin, transport_security)?;
        validate_api_base(&api_base, transport_security)?;
        let user_agent = validate_user_agent(user_agent)?;
        Ok(Self {
            oauth_origin,
            api_base,
            user_agent,
            limits,
            transport_security,
        })
    }

    pub(crate) fn trusts_oauth_endpoint(&self, endpoint: &Url) -> bool {
        valid_endpoint(endpoint, self.transport_security)
            && same_origin(&self.oauth_origin, endpoint)
            && endpoint.query().is_none()
    }

    pub(crate) fn trusts_verification_uri(&self, endpoint: &Url) -> bool {
        valid_endpoint(endpoint, self.transport_security)
            && same_origin(&self.oauth_origin, endpoint)
    }

    pub(crate) fn trusts_api_url(&self, endpoint: &Url) -> bool {
        valid_endpoint(endpoint, self.transport_security)
            && same_origin(&self.api_base, endpoint)
            && endpoint.path().starts_with(self.api_base.path())
    }

    pub(crate) fn validate_archive_origin(
        &self,
        origin: &Url,
    ) -> Result<(), GithubHttpConfigurationError> {
        if !valid_endpoint(origin, self.transport_security)
            || origin.path() != "/"
            || origin.query().is_some()
        {
            return Err(GithubHttpConfigurationError::InvalidArchiveOrigin);
        }
        Ok(())
    }
}

impl fmt::Debug for GithubTrustedOrigins {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GithubTrustedOrigins")
            .field("oauth_origin", &self.oauth_origin)
            .field("api_base", &self.api_base)
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

fn validate_oauth_origin(
    origin: &Url,
    security: TransportSecurity,
) -> Result<(), GithubHttpConfigurationError> {
    if !valid_endpoint(origin, security) || origin.path() != "/" || origin.query().is_some() {
        return Err(GithubHttpConfigurationError::InvalidOAuthOrigin);
    }
    Ok(())
}

fn validate_api_base(
    api_base: &Url,
    security: TransportSecurity,
) -> Result<(), GithubHttpConfigurationError> {
    if !valid_endpoint(api_base, security)
        || !api_base.path().ends_with('/')
        || api_base.query().is_some()
        || api_base.cannot_be_a_base()
    {
        return Err(GithubHttpConfigurationError::InvalidApiBase);
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
        Host::Domain(domain) => {
            domain.eq_ignore_ascii_case("localhost")
                || domain
                    .to_ascii_lowercase()
                    .strip_suffix(".localhost")
                    .is_some_and(|prefix| !prefix.is_empty())
        }
        Host::Ipv4(address) => address.is_loopback(),
        Host::Ipv6(address) => address.is_loopback(),
    }
}

pub(crate) fn same_origin(left: &Url, right: &Url) -> bool {
    left.scheme() == right.scheme()
        && left.host_str() == right.host_str()
        && left.port_or_known_default() == right.port_or_known_default()
}

fn validate_user_agent(user_agent: &str) -> Result<HeaderValue, GithubHttpConfigurationError> {
    if user_agent.is_empty() || user_agent.len() > MAX_USER_AGENT_LENGTH {
        return Err(GithubHttpConfigurationError::InvalidUserAgent);
    }
    HeaderValue::from_str(user_agent).map_err(|_| GithubHttpConfigurationError::InvalidUserAgent)
}

/// Failure to construct a bounded, fixed-origin GitHub HTTP policy or client.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum GithubHttpConfigurationError {
    /// The OAuth origin is not an exact credential-free HTTPS origin.
    #[error("the trusted GitHub OAuth origin is invalid")]
    InvalidOAuthOrigin,
    /// The REST API base violates the trusted URL or path-prefix policy.
    #[error("the trusted GitHub API base is invalid")]
    InvalidApiBase,
    /// The repository-archive origin violates the credential-free origin policy.
    #[error("the trusted GitHub archive origin is invalid")]
    InvalidArchiveOrigin,
    /// The user-agent value is empty, oversized, or not a valid HTTP header value.
    #[error("the GitHub HTTP user agent is invalid")]
    InvalidUserAgent,
    /// The per-response byte ceiling is zero or exceeds the supported maximum.
    #[error("the GitHub response byte limit is invalid")]
    InvalidResponseByteLimit,
    /// The pagination ceiling is zero or exceeds the supported maximum.
    #[error("the GitHub pagination page limit is invalid")]
    InvalidPageLimit,
    /// The aggregate membership ceiling is zero or exceeds the supported maximum.
    #[error("the GitHub membership item limit is invalid")]
    InvalidMembershipLimit,
    /// A timeout is zero, inverted, or exceeds the supported maximum.
    #[error("the GitHub HTTP timeout configuration is invalid")]
    InvalidTimeout,
    /// The hardened HTTP client could not be built without weakening its policy.
    #[error("the hardened GitHub HTTP client could not be constructed")]
    ClientConstructionFailed,
}
