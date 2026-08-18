use std::fmt;

use automata_ci_auth::{
    github::{
        DeviceCodeRequest, DeviceCodeResponse, DeviceTokenPollRequest, GithubCurrentUserRequest,
        GithubDevicePollResponse, GithubEndpoint, GithubEndpointError, GithubEndpointFuture,
        GithubMembershipSnapshot, GithubOrganizationId, GithubOrganizationLogin,
        GithubOrganizationMembership, GithubOrganizationMembershipRole, GithubTeam, GithubTeamId,
        GithubTeamSlug, GithubTokenResponse, GithubUser, RefreshTokenRequest,
        WebTokenExchangeRequest,
    },
    secret::SecretString,
};
use reqwest::{
    Client, RequestBuilder, StatusCode,
    header::{ACCEPT, AUTHORIZATION, HeaderMap, HeaderValue},
    redirect::Policy,
};
use serde::{Deserialize, Serialize};
use url::Url;
use zeroize::Zeroizing;

use automata_ci_scm::ScmProviderId;

use crate::{
    config::{
        GITHUB_API_VERSION, GithubHttpConfigurationError, GithubHttpLimits, GithubTrustedOrigins,
        TransportSecurity,
    },
    pagination::{PageBudget, PageKind, next_page},
    response::{JsonResponse, decode_json, read_json_response},
};

const ACCEPT_API_JSON: &str = "application/vnd.github+json";
const ACCEPT_OAUTH_JSON: &str = "application/json";
const X_GITHUB_API_VERSION: &str = "x-github-api-version";
const DEVICE_GRANT: &str = "urn:ietf:params:oauth:grant-type:device_code";
const MAX_LOGIN_LENGTH: usize = 255;
const MAX_DISPLAY_NAME_LENGTH: usize = 1_024;
const MAX_SCOPE_LENGTH: usize = 65_536;
const MAX_TOKEN_TYPE_LENGTH: usize = 32;
const MAX_DEVICE_EXPIRATION_SECONDS: u64 = 86_400;
const MAX_DEVICE_POLL_INTERVAL_SECONDS: u64 = 3_600;

/// Hardened fixed-origin adapter for GitHub OAuth, REST, and archive operations.
#[derive(Clone)]
pub struct GithubHttpEndpoint {
    pub(crate) client: Client,
    pub(crate) trusted: GithubTrustedOrigins,
    pub(crate) archive_origin: Url,
    pub(crate) scm_provider_id: ScmProviderId,
}

impl GithubHttpEndpoint {
    /// Builds a hardened production client using rustls and public `WebPKI` roots.
    /// Redirects and ambient proxy discovery are disabled.
    ///
    /// # Errors
    ///
    /// Returns an error when the HTTP client cannot be constructed.
    pub fn new(trusted: GithubTrustedOrigins) -> Result<Self, GithubHttpConfigurationError> {
        let archive_origin = default_archive_origin(&trusted)?;
        Self::build(trusted, archive_origin)
    }

    /// Builds a production client with an explicit trusted archive origin.
    ///
    /// This is required when a GitHub Enterprise installation redirects
    /// repository archives to a different HTTPS origin. Credentials are never
    /// forwarded to that origin.
    ///
    /// # Errors
    ///
    /// Returns an error unless `archive_origin` is a credential-free origin
    /// under the exact transport class already selected by `trusted`, or the
    /// client cannot be constructed.
    pub fn new_with_archive_origin(
        trusted: GithubTrustedOrigins,
        archive_origin: Url,
    ) -> Result<Self, GithubHttpConfigurationError> {
        Self::build(trusted, archive_origin)
    }

    /// Builds the public GitHub.com production client with default limits.
    ///
    /// # Errors
    ///
    /// Returns an error for an invalid user agent or client construction failure.
    pub fn github_dot_com(user_agent: &str) -> Result<Self, GithubHttpConfigurationError> {
        Self::new(GithubTrustedOrigins::github_dot_com(user_agent)?)
    }

    /// Builds a deterministic GitHub protocol emulator client on loopback HTTP.
    ///
    /// This is an explicit isolated-deployment transport. It rejects every
    /// non-loopback host and never falls back to a production origin.
    ///
    /// # Errors
    ///
    /// Returns an error unless both URLs are loopback HTTP URLs satisfying the same
    /// origin/base invariants as production configuration.
    pub fn new_for_loopback_emulator(
        oauth_origin: Url,
        api_base: Url,
        user_agent: &str,
        limits: GithubHttpLimits,
    ) -> Result<Self, GithubHttpConfigurationError> {
        let trusted =
            GithubTrustedOrigins::loopback_emulator(oauth_origin, api_base, user_agent, limits)?;
        let archive_origin = default_archive_origin(&trusted)?;
        Self::build(trusted, archive_origin)
    }

    /// Builds an isolated emulator client for a container-mapped `.invalid` host.
    ///
    /// Reserved `.invalid` names fail DNS closed when the explicit runtime host
    /// mapping is absent. Redirects and ambient proxy discovery remain disabled.
    ///
    /// # Errors
    ///
    /// Returns an error unless both URLs are HTTP URLs beneath `.invalid` and
    /// satisfy the same origin/base invariants as production configuration.
    pub fn new_for_mapped_emulator(
        oauth_origin: Url,
        api_base: Url,
        user_agent: &str,
        limits: GithubHttpLimits,
    ) -> Result<Self, GithubHttpConfigurationError> {
        let trusted =
            GithubTrustedOrigins::mapped_emulator(oauth_origin, api_base, user_agent, limits)?;
        let archive_origin = default_archive_origin(&trusted)?;
        Self::build(trusted, archive_origin)
    }

    /// Returns the validated origin and resource-limit policy used by this client.
    pub fn trusted_origins(&self) -> &GithubTrustedOrigins {
        &self.trusted
    }

    fn build(
        trusted: GithubTrustedOrigins,
        archive_origin: Url,
    ) -> Result<Self, GithubHttpConfigurationError> {
        trusted.validate_archive_origin(&archive_origin)?;
        let mut default_headers = HeaderMap::new();
        default_headers.insert(reqwest::header::USER_AGENT, trusted.user_agent.clone());
        default_headers.insert(
            X_GITHUB_API_VERSION,
            HeaderValue::from_static(GITHUB_API_VERSION),
        );
        let mut builder = Client::builder()
            .default_headers(default_headers)
            .redirect(Policy::none())
            .retry(reqwest::retry::never())
            .connect_timeout(trusted.limits.connect_timeout)
            .timeout(trusted.limits.request_timeout)
            .no_proxy();
        if trusted.transport_security == TransportSecurity::HttpsOnly {
            builder = builder.https_only(true);
        }
        let client = builder
            .build()
            .map_err(|_| GithubHttpConfigurationError::ClientConstructionFailed)?;
        Ok(Self {
            client,
            trusted,
            archive_origin,
            scm_provider_id: ScmProviderId::new("github")
                .map_err(|_| GithubHttpConfigurationError::ClientConstructionFailed)?,
        })
    }

    fn oauth_request(&self, endpoint: &Url) -> Result<RequestBuilder, GithubEndpointError> {
        if !self.trusted.trusts_oauth_endpoint(endpoint) {
            return Err(GithubEndpointError::InvalidResponse);
        }
        Ok(self
            .client
            .post(endpoint.clone())
            .header(ACCEPT, ACCEPT_OAUTH_JSON))
    }

    fn api_get(
        &self,
        endpoint: Url,
        token: &SecretString,
    ) -> Result<RequestBuilder, GithubEndpointError> {
        if !self.trusted.trusts_api_url(&endpoint) {
            return Err(GithubEndpointError::InvalidResponse);
        }
        let authorization = authorization_header(token)?;
        Ok(self
            .client
            .get(endpoint)
            .header(ACCEPT, ACCEPT_API_JSON)
            .header(AUTHORIZATION, authorization))
    }

    fn api_url(&self, relative: &str) -> Result<Url, GithubEndpointError> {
        let url = self
            .trusted
            .api_base
            .join(relative)
            .map_err(|_| GithubEndpointError::InvalidResponse)?;
        if !self.trusted.trusts_api_url(&url) {
            return Err(GithubEndpointError::InvalidResponse);
        }
        Ok(url)
    }

    async fn execute(
        &self,
        request: RequestBuilder,
        permit_oauth_bad_request: bool,
    ) -> Result<JsonResponse, GithubEndpointError> {
        let response = request
            .send()
            .await
            .map_err(|_| GithubEndpointError::Unavailable)?;
        read_json_response(
            response,
            self.trusted.limits.max_response_bytes,
            permit_oauth_bad_request,
        )
        .await
    }

    async fn oauth_form<T: Serialize + ?Sized>(
        &self,
        endpoint: &Url,
        form: &T,
    ) -> Result<JsonResponse, GithubEndpointError> {
        let request = self.oauth_request(endpoint)?.form(form);
        self.execute(request, true).await
    }

    async fn exchange_web_code_inner(
        &self,
        request: WebTokenExchangeRequest<'_>,
    ) -> Result<GithubTokenResponse, GithubEndpointError> {
        let form = [
            ("client_id", request.client_id.as_str()),
            ("client_secret", request.client_secret.expose_secret()),
            ("code", request.code.expose_secret()),
            ("redirect_uri", request.redirect_uri.as_str()),
            ("code_verifier", request.code_verifier.expose_secret()),
        ];
        let response = self.oauth_form(request.endpoint, &form).await?;
        token_response(&response, OAuthOperation::WebExchange)
    }

    async fn request_device_code_inner(
        &self,
        request: DeviceCodeRequest<'_>,
    ) -> Result<DeviceCodeResponse, GithubEndpointError> {
        let form = [("client_id", request.client_id.as_str())];
        let response = self.oauth_form(request.endpoint, &form).await?;
        device_code_response(&response, &self.trusted)
    }

    async fn poll_device_token_inner(
        &self,
        request: DeviceTokenPollRequest<'_>,
    ) -> Result<GithubDevicePollResponse, GithubEndpointError> {
        let form = [
            ("client_id", request.client_id.as_str()),
            ("device_code", request.device_code.expose_secret()),
            ("grant_type", DEVICE_GRANT),
        ];
        let response = self.oauth_form(request.endpoint, &form).await?;
        device_poll_response(&response)
    }

    async fn refresh_token_inner(
        &self,
        request: RefreshTokenRequest<'_>,
    ) -> Result<GithubTokenResponse, GithubEndpointError> {
        let mut form = vec![
            ("client_id", request.client_id.as_str()),
            ("grant_type", "refresh_token"),
            ("refresh_token", request.refresh_token.expose_secret()),
        ];
        if let Some(client_secret) = request.client_secret {
            form.push(("client_secret", client_secret.expose_secret()));
        }
        let response = self.oauth_form(request.endpoint, &form).await?;
        token_response(&response, OAuthOperation::Refresh)
    }

    async fn current_user_inner(
        &self,
        request: GithubCurrentUserRequest<'_>,
    ) -> Result<GithubUser, GithubEndpointError> {
        let endpoint = self.api_url("user")?;
        let http_request = self.api_get(endpoint, request.access_token)?;
        let response = self.execute(http_request, false).await?;
        require_ok(&response)?;
        let user: GithubUser = decode_json(&response.body)?;
        validate_user(&user)?;
        Ok(user)
    }

    async fn memberships_inner(
        &self,
        request: GithubCurrentUserRequest<'_>,
    ) -> Result<GithubMembershipSnapshot, GithubEndpointError> {
        let mut budget = PageBudget::new(
            self.trusted.limits.max_pages,
            self.trusted.limits.max_memberships,
        );
        let organizations = self
            .active_organizations(request.access_token, &mut budget)
            .await?;
        let teams = self.teams(request.access_token, &mut budget).await?;
        GithubMembershipSnapshot::new(organizations, teams)
            .map_err(|_| GithubEndpointError::InvalidResponse)
    }

    async fn active_organizations(
        &self,
        token: &SecretString,
        budget: &mut PageBudget,
    ) -> Result<Vec<GithubOrganizationMembership>, GithubEndpointError> {
        let mut endpoint = self.api_url("user/memberships/orgs")?;
        endpoint
            .query_pairs_mut()
            .append_pair("state", "active")
            .append_pair("per_page", "100");
        let expected_path = endpoint.path().to_owned();
        let mut organizations = Vec::new();
        loop {
            budget.visit(&endpoint)?;
            let response = self.execute(self.api_get(endpoint, token)?, false).await?;
            require_ok(&response)?;
            let memberships: Vec<OrganizationMembership> = decode_json(&response.body)?;
            budget.consume_items(memberships.len())?;
            for membership in memberships {
                if membership.state != MembershipState::Active {
                    return Err(GithubEndpointError::InvalidResponse);
                }
                organizations.push(GithubOrganizationMembership::new(
                    GithubOrganizationId::new(membership.organization.id)
                        .map_err(|_| GithubEndpointError::InvalidResponse)?,
                    GithubOrganizationLogin::new(membership.organization.login)
                        .map_err(|_| GithubEndpointError::InvalidResponse)?,
                    membership.role,
                ));
            }
            let Some(next) = next_page(
                &response.headers,
                &self.trusted,
                &expected_path,
                PageKind::ActiveOrganizations,
            )?
            else {
                break;
            };
            endpoint = next;
        }
        Ok(organizations)
    }

    async fn teams(
        &self,
        token: &SecretString,
        budget: &mut PageBudget,
    ) -> Result<Vec<GithubTeam>, GithubEndpointError> {
        let mut endpoint = self.api_url("user/teams")?;
        endpoint.query_pairs_mut().append_pair("per_page", "100");
        let expected_path = endpoint.path().to_owned();
        let mut teams = Vec::new();
        loop {
            budget.visit(&endpoint)?;
            let response = self.execute(self.api_get(endpoint, token)?, false).await?;
            require_ok(&response)?;
            let memberships: Vec<TeamMembership> = decode_json(&response.body)?;
            budget.consume_items(memberships.len())?;
            for membership in memberships {
                teams.push(GithubTeam::new(
                    GithubTeamId::new(membership.id)
                        .map_err(|_| GithubEndpointError::InvalidResponse)?,
                    GithubOrganizationId::new(membership.organization.id)
                        .map_err(|_| GithubEndpointError::InvalidResponse)?,
                    GithubOrganizationLogin::new(membership.organization.login)
                        .map_err(|_| GithubEndpointError::InvalidResponse)?,
                    GithubTeamSlug::new(membership.slug)
                        .map_err(|_| GithubEndpointError::InvalidResponse)?,
                ));
            }
            let Some(next) = next_page(
                &response.headers,
                &self.trusted,
                &expected_path,
                PageKind::Teams,
            )?
            else {
                break;
            };
            endpoint = next;
        }
        Ok(teams)
    }
}

impl fmt::Debug for GithubHttpEndpoint {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GithubHttpEndpoint")
            .field("trusted", &self.trusted)
            .field("archive_origin", &self.archive_origin)
            .field("scm_provider_id", &self.scm_provider_id)
            .finish_non_exhaustive()
    }
}

impl GithubEndpoint for GithubHttpEndpoint {
    fn exchange_web_code<'a>(
        &'a self,
        request: WebTokenExchangeRequest<'a>,
    ) -> GithubEndpointFuture<'a, GithubTokenResponse> {
        Box::pin(self.exchange_web_code_inner(request))
    }

    fn request_device_code<'a>(
        &'a self,
        request: DeviceCodeRequest<'a>,
    ) -> GithubEndpointFuture<'a, DeviceCodeResponse> {
        Box::pin(self.request_device_code_inner(request))
    }

    fn poll_device_token<'a>(
        &'a self,
        request: DeviceTokenPollRequest<'a>,
    ) -> GithubEndpointFuture<'a, GithubDevicePollResponse> {
        Box::pin(self.poll_device_token_inner(request))
    }

    fn refresh_token<'a>(
        &'a self,
        request: RefreshTokenRequest<'a>,
    ) -> GithubEndpointFuture<'a, GithubTokenResponse> {
        Box::pin(self.refresh_token_inner(request))
    }

    fn current_user<'a>(
        &'a self,
        request: GithubCurrentUserRequest<'a>,
    ) -> GithubEndpointFuture<'a, GithubUser> {
        Box::pin(self.current_user_inner(request))
    }

    fn memberships<'a>(
        &'a self,
        request: GithubCurrentUserRequest<'a>,
    ) -> GithubEndpointFuture<'a, GithubMembershipSnapshot> {
        Box::pin(self.memberships_inner(request))
    }
}

pub(crate) fn authorization_header(
    token: &SecretString,
) -> Result<HeaderValue, GithubEndpointError> {
    let mut raw = Zeroizing::new(String::with_capacity(
        "Bearer ".len() + token.expose_secret().len(),
    ));
    raw.push_str("Bearer ");
    raw.push_str(token.expose_secret());
    let mut header =
        HeaderValue::from_str(raw.as_str()).map_err(|_| GithubEndpointError::InvalidResponse)?;
    header.set_sensitive(true);
    Ok(header)
}

fn default_archive_origin(
    trusted: &GithubTrustedOrigins,
) -> Result<Url, GithubHttpConfigurationError> {
    if trusted.api_base.scheme() == "https"
        && trusted.api_base.host_str() == Some("api.github.com")
        && trusted.api_base.port().is_none()
    {
        return Url::parse("https://codeload.github.com/")
            .map_err(|_| GithubHttpConfigurationError::InvalidArchiveOrigin);
    }

    let mut origin = trusted.api_base.clone();
    origin.set_path("/");
    origin.set_query(None);
    origin.set_fragment(None);
    Ok(origin)
}

fn require_ok(response: &JsonResponse) -> Result<(), GithubEndpointError> {
    if response.status != StatusCode::OK {
        return Err(GithubEndpointError::InvalidResponse);
    }
    Ok(())
}

#[derive(Clone, Copy)]
enum OAuthOperation {
    WebExchange,
    Refresh,
}

#[derive(Deserialize)]
struct OAuthEnvelope {
    access_token: Option<SecretString>,
    expires_in: Option<u64>,
    refresh_token: Option<SecretString>,
    refresh_token_expires_in: Option<u64>,
    scope: Option<String>,
    token_type: Option<String>,
    error: Option<String>,
}

#[derive(Deserialize)]
struct DeviceCodeEnvelope {
    device_code: Option<SecretString>,
    user_code: Option<SecretString>,
    verification_uri: Option<Url>,
    expires_in: Option<u64>,
    interval: Option<u64>,
    error: Option<String>,
}

fn device_code_response(
    response: &JsonResponse,
    trusted: &GithubTrustedOrigins,
) -> Result<DeviceCodeResponse, GithubEndpointError> {
    let envelope: DeviceCodeEnvelope = decode_json(&response.body)?;
    if let Some(error) = envelope.error.as_deref() {
        if has_device_code_material(&envelope) {
            return Err(GithubEndpointError::InvalidResponse);
        }
        return Err(map_oauth_error(error, OAuthOperation::WebExchange));
    }
    if response.status != StatusCode::OK {
        return Err(GithubEndpointError::InvalidResponse);
    }
    let response = DeviceCodeResponse {
        device_code: envelope
            .device_code
            .ok_or(GithubEndpointError::InvalidResponse)?,
        user_code: envelope
            .user_code
            .ok_or(GithubEndpointError::InvalidResponse)?,
        verification_uri: envelope
            .verification_uri
            .ok_or(GithubEndpointError::InvalidResponse)?,
        expires_in: envelope
            .expires_in
            .ok_or(GithubEndpointError::InvalidResponse)?,
        interval: envelope
            .interval
            .ok_or(GithubEndpointError::InvalidResponse)?,
    };
    validate_device_code_response(&response, trusted)?;
    Ok(response)
}

fn has_device_code_material(envelope: &DeviceCodeEnvelope) -> bool {
    envelope.device_code.is_some()
        || envelope.user_code.is_some()
        || envelope.verification_uri.is_some()
        || envelope.expires_in.is_some()
        || envelope.interval.is_some()
}

fn token_response(
    response: &JsonResponse,
    operation: OAuthOperation,
) -> Result<GithubTokenResponse, GithubEndpointError> {
    let envelope: OAuthEnvelope = decode_json(&response.body)?;
    if let Some(error) = envelope.error.as_deref() {
        if has_token_material(&envelope) {
            return Err(GithubEndpointError::InvalidResponse);
        }
        return Err(map_oauth_error(error, operation));
    }
    if response.status != StatusCode::OK {
        return Err(GithubEndpointError::InvalidResponse);
    }
    into_token_response(envelope)
}

fn device_poll_response(
    response: &JsonResponse,
) -> Result<GithubDevicePollResponse, GithubEndpointError> {
    let envelope: OAuthEnvelope = decode_json(&response.body)?;
    if let Some(error) = envelope.error.as_deref() {
        if has_token_material(&envelope) {
            return Err(GithubEndpointError::InvalidResponse);
        }
        return match error {
            "authorization_pending" => Ok(GithubDevicePollResponse::AuthorizationPending),
            "slow_down" => Ok(GithubDevicePollResponse::SlowDown),
            "access_denied" => Ok(GithubDevicePollResponse::AccessDenied),
            "expired_token" => Ok(GithubDevicePollResponse::ExpiredToken),
            "incorrect_device_code" | "bad_verification_code" => {
                Ok(GithubDevicePollResponse::IncorrectDeviceCode)
            }
            _ => Err(map_oauth_error(error, OAuthOperation::WebExchange)),
        };
    }
    if response.status != StatusCode::OK {
        return Err(GithubEndpointError::InvalidResponse);
    }
    into_token_response(envelope).map(GithubDevicePollResponse::Token)
}

fn has_token_material(envelope: &OAuthEnvelope) -> bool {
    envelope.access_token.is_some()
        || envelope.expires_in.is_some()
        || envelope.refresh_token.is_some()
        || envelope.refresh_token_expires_in.is_some()
        || envelope.scope.is_some()
        || envelope.token_type.is_some()
}

fn into_token_response(
    envelope: OAuthEnvelope,
) -> Result<GithubTokenResponse, GithubEndpointError> {
    let access_token = envelope
        .access_token
        .ok_or(GithubEndpointError::InvalidResponse)?;
    let token_type = envelope
        .token_type
        .ok_or(GithubEndpointError::InvalidResponse)?;
    if token_type.is_empty()
        || token_type.len() > MAX_TOKEN_TYPE_LENGTH
        || !token_type.eq_ignore_ascii_case("bearer")
        || token_type.chars().any(char::is_control)
        || envelope.scope.as_ref().is_some_and(|scope| {
            scope.len() > MAX_SCOPE_LENGTH || scope.chars().any(char::is_control)
        })
        || envelope.expires_in == Some(0)
        || envelope.refresh_token_expires_in == Some(0)
        || envelope.refresh_token.is_some() != envelope.refresh_token_expires_in.is_some()
        || envelope.expires_in.is_some() != envelope.refresh_token.is_some()
    {
        return Err(GithubEndpointError::InvalidResponse);
    }
    Ok(GithubTokenResponse {
        access_token,
        expires_in: envelope.expires_in,
        refresh_token: envelope.refresh_token,
        refresh_token_expires_in: envelope.refresh_token_expires_in,
        scope: envelope.scope.unwrap_or_default(),
        token_type,
    })
}

fn map_oauth_error(error: &str, operation: OAuthOperation) -> GithubEndpointError {
    match error {
        "incorrect_client_credentials" | "unverified_user_email" | "access_denied" => {
            GithubEndpointError::Unauthorized
        }
        "bad_verification_code" if matches!(operation, OAuthOperation::WebExchange) => {
            GithubEndpointError::Unauthorized
        }
        "bad_refresh_token" if matches!(operation, OAuthOperation::Refresh) => {
            GithubEndpointError::Unauthorized
        }
        "expired_token" => GithubEndpointError::Unauthorized,
        _ => GithubEndpointError::InvalidResponse,
    }
}

fn validate_device_code_response(
    response: &DeviceCodeResponse,
    trusted: &GithubTrustedOrigins,
) -> Result<(), GithubEndpointError> {
    if response.expires_in == 0
        || response.expires_in > MAX_DEVICE_EXPIRATION_SECONDS
        || response.interval == 0
        || response.interval > MAX_DEVICE_POLL_INTERVAL_SECONDS
        || !trusted.trusts_verification_uri(&response.verification_uri)
    {
        return Err(GithubEndpointError::InvalidResponse);
    }
    Ok(())
}

fn validate_user(user: &GithubUser) -> Result<(), GithubEndpointError> {
    if user.id == 0
        || user.login.is_empty()
        || user.login.len() > MAX_LOGIN_LENGTH
        || user.login.chars().any(char::is_control)
        || user.name.as_ref().is_some_and(|name| {
            name.len() > MAX_DISPLAY_NAME_LENGTH || name.chars().any(char::is_control)
        })
    {
        return Err(GithubEndpointError::InvalidResponse);
    }
    Ok(())
}

#[derive(Deserialize)]
struct OrganizationMembership {
    state: MembershipState,
    role: GithubOrganizationMembershipRole,
    organization: Organization,
}

#[derive(Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
enum MembershipState {
    Active,
    Pending,
}

#[derive(Deserialize)]
struct Organization {
    id: i64,
    login: String,
}

#[derive(Deserialize)]
struct TeamMembership {
    id: i64,
    slug: String,
    organization: Organization,
}
