use std::{collections::BTreeMap, fmt, sync::Arc};

use automata_ci_auth::{
    secret::SecretString,
    time::{Clock, SystemClock, UnixTimestamp},
};
use automata_ci_credential::{
    CredentialError, CredentialErrorKind, CredentialProvenance, PermissionLevel, PermissionSet,
    ProviderResourceId, RepositoryCredentialRequest,
};
use automata_ci_scm::ScmProviderId;
use reqwest::{
    Client, StatusCode,
    header::{ACCEPT, AUTHORIZATION, HeaderMap, HeaderValue, USER_AGENT},
    redirect::Policy,
};
use serde::Serialize;
use sha2::{Digest as _, Sha256};
use time::{OffsetDateTime, format_description::well_known::Rfc3339};
use url::Url;
use zeroize::Zeroizing;

use crate::{
    config::{
        GITHUB_API_VERSION, GithubAppConfigurationError, GithubAppCredentialConfig,
        TransportSecurity, whole_milliseconds,
    },
    response::{
        CreatedBodyCompletion, RecoveredInstallationToken, decode_token_response,
        definitive_mint_rejection, is_rate_limited, read_created_response, recover_expiration,
        recover_installation_token, retry_after_seconds,
    },
    runtime_authority::{
        GithubInstallationTokenIndeterminate, GithubInstallationTokenIndeterminateReason,
        GithubInstallationTokenMintOutcome, GithubInstallationTokenRevocationCandidate,
        GithubInstallationTokenRevocationFailure, GithubInstallationTokenRevocationFailureKind,
        GithubInstallationTokenRevocationOutcome, GithubInstallationTokenRevokePending,
        GithubReadyInstallationToken,
    },
    signer::{GithubAppJwtSigner, GithubAppKeyError},
};

const ACCEPT_API_JSON: &str = "application/vnd.github+json";
const X_GITHUB_API_VERSION: &str = "x-github-api-version";
const MAX_REQUEST_BODY_BYTES: usize = 16 * 1_024;
const MAX_TOKEN_LIFETIME_SECONDS: u64 = 3_600;
const MAX_PROVIDER_CLOCK_SKEW_SECONDS: u64 = 60;
const MAX_REPOSITORY_COMPONENT_BYTES: usize = 100;
const BROKER_POLICY_FINGERPRINT_DOMAIN: &[u8] = b"automata-ci/github-app-broker-policy/v2\0";

struct ValidatedResponseMetadata {
    provider_expires_at: UnixTimestamp,
    conservative_expires_at: UnixTimestamp,
    provenance: CredentialProvenance,
}

struct ResponseValidationFailure {
    error: CredentialError,
    provider_expires_at: Option<UnixTimestamp>,
    conservative_expires_at: Option<UnixTimestamp>,
}

struct PreparedMintRequest {
    repository_id: u64,
    endpoint: Url,
    authorization: HeaderValue,
    body: Vec<u8>,
}

/// GitHub App installation-token client with a fixed network and identity scope.
///
/// The broker signs short-lived JWT assertions in memory and sends requests
/// only to endpoints derived beneath the configured API base. Redirects and
/// ambient proxies are disabled. Every mint is restricted to one numeric
/// repository ID and the request's exact permission map; returned metadata is
/// validated against both before a token becomes ready. [`fmt::Debug`] redacts
/// the private key and does not expose assertions or bearer tokens.
pub struct GithubAppCredentialBroker {
    config: GithubAppCredentialConfig,
    client: Client,
    signer: GithubAppJwtSigner,
    clock: Arc<dyn Clock>,
    provider_id: ScmProviderId,
}

fn github_http_client_builder(config: &GithubAppCredentialConfig) -> reqwest::ClientBuilder {
    let mut headers = HeaderMap::new();
    headers.insert(USER_AGENT, config.user_agent.clone());
    headers.insert(
        X_GITHUB_API_VERSION,
        HeaderValue::from_static(GITHUB_API_VERSION),
    );
    let client = Client::builder()
        .default_headers(headers)
        .redirect(Policy::none())
        .connect_timeout(config.limits.connect_timeout)
        .timeout(config.limits.request_timeout)
        .retry(reqwest::retry::never())
        .no_proxy();
    if config.transport_security == TransportSecurity::HttpsOnly {
        client.https_only(true)
    } else {
        client
    }
}

impl GithubAppCredentialBroker {
    pub(crate) const fn mint_request_timeout(&self) -> std::time::Duration {
        self.config.limits.request_timeout
    }

    pub(crate) const fn mint_installation_id(&self) -> u64 {
        self.config.installation_id.get()
    }

    pub(crate) fn app_jwt_issuer_value(&self) -> &str {
        self.config.issuer.as_str()
    }

    /// Returns SHA-256 over the exact DER `SubjectPublicKeyInfo` of the App key.
    ///
    /// This public evidence is derived from the same validated PKCS#1 or PKCS#8
    /// private key retained by the signer. It is never accepted from callers
    /// and does not expose private-key material.
    #[must_use]
    pub const fn app_key_spki_sha256(&self) -> automata_ci_store::Sha256Digest {
        self.signer.app_key_spki_sha256()
    }

    /// Returns a canonical fingerprint of the non-secret provider policy.
    ///
    /// The digest binds the exact credential-free API base, pinned GitHub API
    /// version, user agent, response ceiling, connect and complete-request
    /// timeouts, and transport-security mode. App issuer, installation, and key
    /// SPKI remain distinct immutable identity fields and are intentionally not
    /// folded into this policy evidence.
    ///
    /// # Panics
    ///
    /// Panics only if crate-internal code bypasses [`crate::GithubAppHttpLimits`]
    /// validation and constructs a fractional-millisecond timeout.
    #[must_use]
    pub fn broker_policy_fingerprint(&self) -> automata_ci_store::Sha256Digest {
        let mut digest = Sha256::new();
        digest.update(BROKER_POLICY_FINGERPRINT_DOMAIN);
        update_fingerprint_part(&mut digest, self.config.api_base.as_str().as_bytes());
        update_fingerprint_part(&mut digest, GITHUB_API_VERSION.as_bytes());
        update_fingerprint_part(&mut digest, self.config.user_agent.as_bytes());
        update_fingerprint_part(
            &mut digest,
            &u64::try_from(self.config.limits.max_response_bytes)
                .unwrap_or(u64::MAX)
                .to_be_bytes(),
        );
        update_fingerprint_part(
            &mut digest,
            &whole_milliseconds(self.config.limits.connect_timeout)
                .expect("validated connect timeout is an exact whole-millisecond value")
                .to_be_bytes(),
        );
        update_fingerprint_part(
            &mut digest,
            &whole_milliseconds(self.config.limits.request_timeout)
                .expect("validated request timeout is an exact whole-millisecond value")
                .to_be_bytes(),
        );
        update_fingerprint_part(
            &mut digest,
            match self.config.transport_security {
                TransportSecurity::HttpsOnly => b"https_only",
                TransportSecurity::LoopbackHttp => b"loopback_http",
            },
        );
        automata_ci_store::Sha256Digest::from_bytes(digest.finalize().into())
    }

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
        let client = github_http_client_builder(&config)
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

    /// Performs exactly one provider-side installation-token mint attempt.
    ///
    /// The result forces callers to account for every side-effectful outcome.
    /// In particular, a uniquely recoverable token is always returned as either
    /// `Ready` or `RevokePending`; it is never discarded behind an error.
    pub async fn mint_once(
        &self,
        request: &RepositoryCredentialRequest,
    ) -> GithubInstallationTokenMintOutcome {
        let prepared = match self.prepare_mint(request) {
            Ok(prepared) => prepared,
            Err(error) => return GithubInstallationTokenMintOutcome::Rejected(error),
        };
        let Ok(response) = self
            .client
            .post(prepared.endpoint)
            .header(ACCEPT, ACCEPT_API_JSON)
            .header(AUTHORIZATION, prepared.authorization)
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .body(prepared.body)
            .send()
            .await
        else {
            return indeterminate(GithubInstallationTokenIndeterminateReason::Transport);
        };
        if response.status() != StatusCode::CREATED {
            return mint_status_outcome(response.status(), response.headers());
        }
        let response = read_created_response(response, self.config.limits.max_response_bytes).await;
        self.created_response_outcome(request, prepared.repository_id, &response)
    }

    fn prepare_mint(
        &self,
        request: &RepositoryCredentialRequest,
    ) -> Result<PreparedMintRequest, CredentialError> {
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
        Ok(PreparedMintRequest {
            repository_id,
            endpoint: self.access_token_url()?,
            authorization,
            body,
        })
    }

    fn created_response_outcome(
        &self,
        request: &RepositoryCredentialRequest,
        repository_id: u64,
        response: &crate::response::CreatedResponseBody,
    ) -> GithubInstallationTokenMintOutcome {
        let recovered = recover_installation_token(&response.body);
        match recovered {
            RecoveredInstallationToken::Unique(secret) => self.unique_token_outcome(
                request,
                repository_id,
                response,
                GithubInstallationTokenRevocationCandidate::new(secret),
            ),
            RecoveredInstallationToken::Ambiguous => {
                indeterminate(GithubInstallationTokenIndeterminateReason::AmbiguousToken)
            }
            RecoveredInstallationToken::Missing => indeterminate(missing_token_reason(
                response.completion,
                GithubInstallationTokenIndeterminateReason::MissingToken,
            )),
            RecoveredInstallationToken::Unrecoverable => indeterminate(missing_token_reason(
                response.completion,
                GithubInstallationTokenIndeterminateReason::MalformedResponse,
            )),
        }
    }

    fn unique_token_outcome(
        &self,
        request: &RepositoryCredentialRequest,
        repository_id: u64,
        response: &crate::response::CreatedResponseBody,
        candidate: GithubInstallationTokenRevocationCandidate,
    ) -> GithubInstallationTokenMintOutcome {
        let issued_at = self.clock.now();
        let (provider_expires_at, conservative_expires_at) =
            recovered_expirations(&response.body, issued_at);
        let Ok(decoded) = decode_token_response(&response.body) else {
            return revoke_pending(
                candidate,
                CredentialErrorKind::InvalidResponse,
                provider_expires_at,
                conservative_expires_at,
            );
        };
        let validation =
            self.validate_response_metadata(request, repository_id, issued_at, decoded);
        let metadata_invalid =
            response.completion != CreatedBodyCompletion::Complete || !response.metadata_valid;
        match validation {
            Ok(validated) if !metadata_invalid => {
                GithubInstallationTokenMintOutcome::Ready(GithubReadyInstallationToken::new(
                    candidate,
                    request.clone(),
                    issued_at,
                    validated.provider_expires_at,
                    validated.conservative_expires_at,
                    validated.provenance,
                ))
            }
            Ok(validated) => revoke_pending(
                candidate,
                CredentialErrorKind::InvalidResponse,
                Some(validated.provider_expires_at),
                Some(validated.conservative_expires_at),
            ),
            Err(failure) => GithubInstallationTokenMintOutcome::RevokePending(
                GithubInstallationTokenRevokePending::new(
                    candidate,
                    failure.error,
                    failure.provider_expires_at,
                    failure.conservative_expires_at,
                ),
            ),
        }
    }

    fn validate_response_metadata(
        &self,
        request: &RepositoryCredentialRequest,
        repository_id: u64,
        issued_at: UnixTimestamp,
        response: crate::response::InstallationTokenResponse,
    ) -> Result<ValidatedResponseMetadata, ResponseValidationFailure> {
        let maximum_expiry = issued_at
            .checked_add(MAX_TOKEN_LIFETIME_SECONDS + MAX_PROVIDER_CLOCK_SKEW_SECONDS)
            .ok();
        let provider_expires_at = parse_expiration(&response.expires_at)
            .ok()
            .filter(|expiration| maximum_expiry.is_some_and(|maximum| *expiration <= maximum));
        let conservative_expires_at = provider_expires_at.and_then(conservative_expiration);
        let failure = |error| ResponseValidationFailure {
            error,
            provider_expires_at,
            conservative_expires_at,
        };
        if response.repository_selection != "selected" || response.repositories.len() != 1 {
            return Err(failure(CredentialError::new(
                CredentialErrorKind::RepositoryMismatch,
            )));
        }
        let repository = response.repositories.first().ok_or_else(|| {
            failure(CredentialError::new(
                CredentialErrorKind::RepositoryMismatch,
            ))
        })?;
        if repository.id != repository_id
            || !repository
                .full_name
                .eq_ignore_ascii_case(request.repository().repository().as_str())
            || github_repository_components(&repository.full_name).is_err()
        {
            return Err(failure(CredentialError::new(
                CredentialErrorKind::RepositoryMismatch,
            )));
        }
        let returned_permissions = response.permissions.into_inner();
        if !permissions_match_github_response(request.permissions(), &returned_permissions) {
            return Err(failure(CredentialError::new(
                CredentialErrorKind::PermissionMismatch,
            )));
        }
        let provider_expires_at = provider_expires_at
            .ok_or_else(|| failure(CredentialError::new(CredentialErrorKind::InvalidResponse)))?;
        let conservative_expires_at = conservative_expires_at
            .ok_or_else(|| failure(CredentialError::new(CredentialErrorKind::InvalidResponse)))?;
        let required_expiry = issued_at
            .checked_add(request.minimum_validity().as_seconds())
            .map_err(|_| failure(CredentialError::new(CredentialErrorKind::InvalidResponse)))?;
        if conservative_expires_at < required_expiry {
            return Err(failure(CredentialError::new(CredentialErrorKind::Expired)));
        }
        let provenance = CredentialProvenance::new(
            self.provider_id.clone(),
            self.config.issuer.clone(),
            ProviderResourceId::new(self.config.installation_id.get().to_string())
                .map_err(|_| failure(CredentialError::new(CredentialErrorKind::InvalidResponse)))?,
        );
        Ok(ValidatedResponseMetadata {
            provider_expires_at,
            conservative_expires_at,
            provenance,
        })
    }

    /// Attempts to revoke one exact recovered installation token.
    ///
    /// Only a `204 No Content` result confirms revocation. Every other outcome
    /// retains the caller-owned candidate for retry or expiry reconciliation.
    pub async fn revoke(
        &self,
        candidate: &GithubInstallationTokenRevocationCandidate,
    ) -> GithubInstallationTokenRevocationOutcome {
        let Ok(endpoint) = self.revocation_url() else {
            return unconfirmed_revocation(
                GithubInstallationTokenRevocationFailureKind::InvalidResponse,
            );
        };
        let Ok(authorization) = bearer_header(candidate.secret().expose_secret()) else {
            return unconfirmed_revocation(
                GithubInstallationTokenRevocationFailureKind::InvalidResponse,
            );
        };
        let Ok(response) = self
            .client
            .delete(endpoint)
            .header(ACCEPT, ACCEPT_API_JSON)
            .header(AUTHORIZATION, authorization)
            .send()
            .await
        else {
            return unconfirmed_revocation(GithubInstallationTokenRevocationFailureKind::Retryable);
        };
        let failure = match response.status() {
            StatusCode::NO_CONTENT => {
                return GithubInstallationTokenRevocationOutcome::Confirmed;
            }
            StatusCode::UNAUTHORIZED => GithubInstallationTokenRevocationFailure::new(
                GithubInstallationTokenRevocationFailureKind::Unauthorized,
            ),
            StatusCode::TOO_MANY_REQUESTS => {
                GithubInstallationTokenRevocationFailure::rate_limited(retry_after_seconds(
                    response.headers(),
                ))
            }
            StatusCode::FORBIDDEN if is_rate_limited(response.headers()) => {
                GithubInstallationTokenRevocationFailure::rate_limited(retry_after_seconds(
                    response.headers(),
                ))
            }
            StatusCode::REQUEST_TIMEOUT | StatusCode::TOO_EARLY => {
                GithubInstallationTokenRevocationFailure::new(
                    GithubInstallationTokenRevocationFailureKind::Retryable,
                )
            }
            status if status.is_server_error() => GithubInstallationTokenRevocationFailure::new(
                GithubInstallationTokenRevocationFailureKind::Retryable,
            ),
            _ => GithubInstallationTokenRevocationFailure::new(
                GithubInstallationTokenRevocationFailureKind::InvalidResponse,
            ),
        };
        GithubInstallationTokenRevocationOutcome::Unconfirmed(failure)
    }

    fn revocation_url(&self) -> Result<Url, CredentialError> {
        let mut endpoint = self.config.api_base.clone();
        let mut segments = endpoint
            .path_segments_mut()
            .map_err(|()| CredentialError::new(CredentialErrorKind::InvalidRequest))?;
        segments.pop_if_empty();
        segments.push("installation");
        segments.push("token");
        drop(segments);
        if !self.config.trusts_api_url(&endpoint) {
            return Err(CredentialError::new(CredentialErrorKind::InvalidRequest));
        }
        Ok(endpoint)
    }
}

fn permissions_match_github_response(requested: &PermissionSet, returned: &PermissionSet) -> bool {
    if returned == requested {
        return true;
    }
    if returned.len() != requested.len().saturating_add(1) {
        return false;
    }

    returned.iter().all(|(returned_name, returned_level)| {
        if returned_name.as_str() == "metadata" {
            return returned_level == PermissionLevel::Read;
        }
        requested.iter().any(|(requested_name, requested_level)| {
            requested_name == returned_name && requested_level == returned_level
        })
    })
}

fn update_fingerprint_part(digest: &mut Sha256, value: &[u8]) {
    digest.update(u64::try_from(value.len()).unwrap_or(u64::MAX).to_be_bytes());
    digest.update(value);
}

fn mint_status_outcome(
    status: StatusCode,
    headers: &HeaderMap,
) -> GithubInstallationTokenMintOutcome {
    if let Some(error) = definitive_mint_rejection(status, headers) {
        return GithubInstallationTokenMintOutcome::Rejected(error);
    }
    let reason = if status.is_server_error() {
        GithubInstallationTokenIndeterminateReason::ProviderUnavailable
    } else {
        GithubInstallationTokenIndeterminateReason::UnexpectedStatus
    };
    indeterminate(reason)
}

fn indeterminate(
    reason: GithubInstallationTokenIndeterminateReason,
) -> GithubInstallationTokenMintOutcome {
    GithubInstallationTokenMintOutcome::Indeterminate(GithubInstallationTokenIndeterminate::new(
        reason,
    ))
}

const fn missing_token_reason(
    completion: CreatedBodyCompletion,
    complete_reason: GithubInstallationTokenIndeterminateReason,
) -> GithubInstallationTokenIndeterminateReason {
    match completion {
        CreatedBodyCompletion::Complete => complete_reason,
        CreatedBodyCompletion::Truncated => {
            GithubInstallationTokenIndeterminateReason::TruncatedResponse
        }
        CreatedBodyCompletion::TooLarge => {
            GithubInstallationTokenIndeterminateReason::ResponseTooLarge
        }
    }
}

fn revoke_pending(
    candidate: GithubInstallationTokenRevocationCandidate,
    reason: CredentialErrorKind,
    provider_expires_at: Option<UnixTimestamp>,
    conservative_expires_at: Option<UnixTimestamp>,
) -> GithubInstallationTokenMintOutcome {
    GithubInstallationTokenMintOutcome::RevokePending(GithubInstallationTokenRevokePending::new(
        candidate,
        CredentialError::new(reason),
        provider_expires_at,
        conservative_expires_at,
    ))
}

const fn unconfirmed_revocation(
    kind: GithubInstallationTokenRevocationFailureKind,
) -> GithubInstallationTokenRevocationOutcome {
    GithubInstallationTokenRevocationOutcome::Unconfirmed(
        GithubInstallationTokenRevocationFailure::new(kind),
    )
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

fn conservative_expiration(expiration: UnixTimestamp) -> Option<UnixTimestamp> {
    expiration
        .as_seconds()
        .checked_sub(MAX_PROVIDER_CLOCK_SKEW_SECONDS)
        .map(UnixTimestamp::from_seconds)
}

fn recovered_expirations(
    body: &[u8],
    issued_at: UnixTimestamp,
) -> (Option<UnixTimestamp>, Option<UnixTimestamp>) {
    let maximum_expiry = issued_at
        .checked_add(MAX_TOKEN_LIFETIME_SECONDS + MAX_PROVIDER_CLOCK_SKEW_SECONDS)
        .ok();
    let provider_expires_at = recover_expiration(body)
        .and_then(|expiration| parse_expiration(&expiration).ok())
        .filter(|expiration| maximum_expiry.is_some_and(|maximum| *expiration <= maximum));
    (
        provider_expires_at,
        provider_expires_at.and_then(conservative_expiration),
    )
}

pub(crate) fn github_repository_components(
    repository: &str,
) -> Result<(&str, &str), CredentialError> {
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
/// Sanitized failure to construct a [`GithubAppCredentialBroker`].
pub enum GithubAppBrokerConstructionError {
    /// Configuration or hardened HTTP-client validation failed.
    #[error(transparent)]
    Configuration(#[from] GithubAppConfigurationError),
    /// The bounded PEM key was invalid or unusable for RS256 signing.
    #[error(transparent)]
    PrivateKey(#[from] GithubAppKeyError),
}

#[cfg(test)]
#[path = "../tests/support/protocol_nack.rs"]
mod protocol_nack;
