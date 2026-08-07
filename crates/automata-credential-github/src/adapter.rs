use std::{collections::BTreeMap, fmt, sync::Arc};

use automata_auth::{
    secret::SecretString,
    time::{Clock, SystemClock, UnixTimestamp},
};
use automata_credential::{
    CredentialError, CredentialErrorKind, CredentialProvenance, IssuedRepositoryCredential,
    PermissionSet, ProviderResourceId, RepositoryCredentialBroker, RepositoryCredentialRequest,
};
use automata_scm::ScmProviderId;
use reqwest::{
    Client,
    header::{ACCEPT, AUTHORIZATION, HeaderMap, HeaderValue, USER_AGENT},
    redirect::Policy,
};
use serde::Serialize;
use time::{OffsetDateTime, format_description::well_known::Rfc3339};
use url::Url;
use zeroize::Zeroizing;

use crate::{
    config::{
        GITHUB_API_VERSION, GithubAppConfigurationError, GithubAppCredentialConfig,
        TransportSecurity,
    },
    response::{decode_token_response, require_created_and_read},
    signer::{GithubAppJwtSigner, GithubAppKeyError},
};

const ACCEPT_API_JSON: &str = "application/vnd.github+json";
const X_GITHUB_API_VERSION: &str = "x-github-api-version";
const MAX_REQUEST_BODY_BYTES: usize = 16 * 1_024;
const MAX_TOKEN_BYTES: usize = 16 * 1_024;
const MAX_TOKEN_LIFETIME_SECONDS: u64 = 3_600;
const MAX_PROVIDER_CLOCK_SKEW_SECONDS: u64 = 60;
const MAX_REPOSITORY_COMPONENT_BYTES: usize = 100;

pub struct GithubAppCredentialBroker {
    config: GithubAppCredentialConfig,
    client: Client,
    signer: GithubAppJwtSigner,
    clock: Arc<dyn Clock>,
    provider_id: ScmProviderId,
}

impl GithubAppCredentialBroker {
    /// Builds a production broker using the system clock.
    ///
    /// The supplied PEM is decoded into bounded DER storage that is zeroized on
    /// drop. Provider assertions and signature buffers are also zeroized.
    ///
    /// # Errors
    ///
    /// Rejects invalid key material or a client configuration that cannot be
    /// instantiated.
    pub fn new(
        config: GithubAppCredentialConfig,
        private_key_pem: &SecretString,
    ) -> Result<Self, GithubAppBrokerConstructionError> {
        Self::with_clock(config, private_key_pem, Arc::new(SystemClock))
    }

    /// Builds a broker with an injectable clock for deterministic integration
    /// tests and controlled deployments.
    ///
    /// # Errors
    ///
    /// Rejects invalid key material or a client configuration that cannot be
    /// instantiated.
    #[doc(hidden)]
    pub fn with_clock(
        config: GithubAppCredentialConfig,
        private_key_pem: &SecretString,
        clock: Arc<dyn Clock>,
    ) -> Result<Self, GithubAppBrokerConstructionError> {
        let signer = GithubAppJwtSigner::from_pem(private_key_pem, config.issuer.clone())?;
        let mut headers = HeaderMap::new();
        headers.insert(USER_AGENT, config.user_agent.clone());
        headers.insert(
            X_GITHUB_API_VERSION,
            HeaderValue::from_static(GITHUB_API_VERSION),
        );
        let mut client = Client::builder()
            .default_headers(headers)
            .redirect(Policy::none())
            .connect_timeout(config.limits.connect_timeout)
            .timeout(config.limits.request_timeout)
            .no_proxy();
        if config.transport_security == TransportSecurity::HttpsOnly {
            client = client.https_only(true);
        }
        let client = client
            .build()
            .map_err(|_| GithubAppConfigurationError::ClientConstructionFailed)?;
        let provider_id = ScmProviderId::new("github")
            .map_err(|_| GithubAppConfigurationError::ClientConstructionFailed)?;
        Ok(Self {
            config,
            client,
            signer,
            clock,
            provider_id,
        })
    }

    fn access_token_url(&self) -> Result<Url, CredentialError> {
        let mut endpoint = self.config.api_base.clone();
        let mut segments = endpoint
            .path_segments_mut()
            .map_err(|()| CredentialError::new(CredentialErrorKind::InvalidRequest))?;
        segments.pop_if_empty();
        segments.push("app");
        segments.push("installations");
        segments.push(&self.config.installation_id.get().to_string());
        segments.push("access_tokens");
        drop(segments);
        if !self.config.trusts_api_url(&endpoint) {
            return Err(CredentialError::new(CredentialErrorKind::InvalidRequest));
        }
        Ok(endpoint)
    }

    fn validate_request(
        &self,
        request: &RepositoryCredentialRequest,
    ) -> Result<u64, CredentialError> {
        if request.repository().provider() != &self.provider_id {
            return Err(CredentialError::new(
                CredentialErrorKind::UnsupportedProvider,
            ));
        }
        let repository_id = request
            .repository()
            .stable_id()
            .as_str()
            .parse::<u64>()
            .ok()
            .filter(|value| *value != 0)
            .ok_or_else(|| CredentialError::new(CredentialErrorKind::InvalidRequest))?;
        github_repository_components(request.repository().repository().as_str())?;
        Ok(repository_id)
    }

    async fn issue_inner(
        &self,
        request: &RepositoryCredentialRequest,
    ) -> Result<IssuedRepositoryCredential, CredentialError> {
        let repository_id = self.validate_request(request)?;
        let start = self.clock.now();
        let assertion = self.signer.sign(start).map_err(map_signing_error)?;
        let authorization = bearer_header(assertion.expose_secret())?;
        let wire_request = InstallationTokenRequest::new(repository_id, request.permissions());
        let body = serde_json::to_vec(&wire_request)
            .map_err(|_| CredentialError::new(CredentialErrorKind::InvalidRequest))?;
        if body.len() > MAX_REQUEST_BODY_BYTES {
            return Err(CredentialError::new(CredentialErrorKind::InvalidRequest));
        }
        let response = self
            .client
            .post(self.access_token_url()?)
            .header(ACCEPT, ACCEPT_API_JSON)
            .header(AUTHORIZATION, authorization)
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .body(body)
            .send()
            .await
            .map_err(|_| CredentialError::new(CredentialErrorKind::Unavailable))?;
        let body =
            require_created_and_read(response, self.config.limits.max_response_bytes).await?;
        let token_response = decode_token_response(&body)?;
        drop(body);
        let issued_at = self.clock.now();
        self.validate_response(request, repository_id, issued_at, token_response)
    }

    fn validate_response(
        &self,
        request: &RepositoryCredentialRequest,
        repository_id: u64,
        issued_at: UnixTimestamp,
        response: crate::response::InstallationTokenResponse,
    ) -> Result<IssuedRepositoryCredential, CredentialError> {
        if response.token.expose_secret().len() > MAX_TOKEN_BYTES
            || !response
                .token
                .expose_secret()
                .bytes()
                .all(|byte| byte.is_ascii_graphic())
        {
            return Err(CredentialError::new(CredentialErrorKind::InvalidResponse));
        }
        if response.repository_selection != "selected" || response.repositories.len() != 1 {
            return Err(CredentialError::new(
                CredentialErrorKind::RepositoryMismatch,
            ));
        }
        let repository = response
            .repositories
            .first()
            .ok_or_else(|| CredentialError::new(CredentialErrorKind::RepositoryMismatch))?;
        if repository.id != repository_id
            || !repository
                .full_name
                .eq_ignore_ascii_case(request.repository().repository().as_str())
            || github_repository_components(&repository.full_name).is_err()
        {
            return Err(CredentialError::new(
                CredentialErrorKind::RepositoryMismatch,
            ));
        }
        let returned_permissions = response.permissions.into_inner();
        if &returned_permissions != request.permissions() {
            return Err(CredentialError::new(
                CredentialErrorKind::PermissionMismatch,
            ));
        }
        let expires_at = parse_expiration(&response.expires_at)?;
        let maximum_expiry = issued_at
            .checked_add(MAX_TOKEN_LIFETIME_SECONDS + MAX_PROVIDER_CLOCK_SKEW_SECONDS)
            .map_err(|_| CredentialError::new(CredentialErrorKind::InvalidResponse))?;
        if expires_at > maximum_expiry {
            return Err(CredentialError::new(CredentialErrorKind::InvalidResponse));
        }
        let provenance = CredentialProvenance::new(
            self.provider_id.clone(),
            self.config.issuer.clone(),
            ProviderResourceId::new(self.config.installation_id.get().to_string())
                .map_err(|_| CredentialError::new(CredentialErrorKind::InvalidResponse))?,
        );
        IssuedRepositoryCredential::new(response.token, request, issued_at, expires_at, provenance)
            .map_err(|_| CredentialError::new(CredentialErrorKind::Expired))
    }
}

#[async_trait::async_trait]
impl RepositoryCredentialBroker for GithubAppCredentialBroker {
    fn provider_id(&self) -> &ScmProviderId {
        &self.provider_id
    }

    async fn issue(
        &self,
        request: &RepositoryCredentialRequest,
    ) -> Result<IssuedRepositoryCredential, CredentialError> {
        self.issue_inner(request).await
    }
}

impl fmt::Debug for GithubAppCredentialBroker {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GithubAppCredentialBroker")
            .field("config", &self.config)
            .field("signer", &self.signer)
            .field("clock", &self.clock)
            .field("provider_id", &self.provider_id)
            .finish_non_exhaustive()
    }
}

#[derive(Serialize)]
struct InstallationTokenRequest<'a> {
    repository_ids: [u64; 1],
    permissions: BTreeMap<&'a str, &'static str>,
}

impl<'a> InstallationTokenRequest<'a> {
    fn new(repository_id: u64, permissions: &'a PermissionSet) -> Self {
        Self {
            repository_ids: [repository_id],
            permissions: permissions
                .iter()
                .map(|(name, level)| (name.as_str(), level.as_str()))
                .collect(),
        }
    }
}

fn bearer_header(assertion: &str) -> Result<HeaderValue, CredentialError> {
    let mut value = Zeroizing::new(String::with_capacity("Bearer ".len() + assertion.len()));
    value.push_str("Bearer ");
    value.push_str(assertion);
    let mut header = HeaderValue::from_str(&value)
        .map_err(|_| CredentialError::new(CredentialErrorKind::InvalidRequest))?;
    header.set_sensitive(true);
    Ok(header)
}

fn parse_expiration(value: &str) -> Result<UnixTimestamp, CredentialError> {
    let timestamp = OffsetDateTime::parse(value, &Rfc3339)
        .map_err(|_| CredentialError::new(CredentialErrorKind::InvalidResponse))?
        .unix_timestamp();
    let seconds = u64::try_from(timestamp)
        .map_err(|_| CredentialError::new(CredentialErrorKind::InvalidResponse))?;
    Ok(UnixTimestamp::from_seconds(seconds))
}

fn github_repository_components(repository: &str) -> Result<(&str, &str), CredentialError> {
    let mut components = repository.split('/');
    let owner = components.next().unwrap_or_default();
    let name = components.next().unwrap_or_default();
    if components.next().is_some()
        || !valid_repository_component(owner)
        || !valid_repository_component(name)
        || name
            .get(name.len().saturating_sub(4)..)
            .is_some_and(|suffix| suffix.eq_ignore_ascii_case(".git"))
    {
        return Err(CredentialError::new(CredentialErrorKind::InvalidRequest));
    }
    Ok((owner, name))
}

fn valid_repository_component(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_REPOSITORY_COMPONENT_BYTES
        && !matches!(value, "." | "..")
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
}

fn map_signing_error(error: GithubAppKeyError) -> CredentialError {
    let kind = match error {
        GithubAppKeyError::ClockOutOfRange => CredentialErrorKind::Unavailable,
        GithubAppKeyError::InvalidPrivateKey | GithubAppKeyError::SigningFailed => {
            CredentialErrorKind::Unavailable
        }
    };
    CredentialError::new(kind)
}

#[derive(Debug, thiserror::Error)]
pub enum GithubAppBrokerConstructionError {
    #[error(transparent)]
    Configuration(#[from] GithubAppConfigurationError),
    #[error(transparent)]
    PrivateKey(#[from] GithubAppKeyError),
}
