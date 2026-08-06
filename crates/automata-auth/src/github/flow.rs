use std::{collections::BTreeSet, fmt};

use thiserror::Error;
use url::Url;

use crate::{
    human::{ProviderId, ProviderSubject},
    secret::{OAuthState, PkceVerifier, RandomnessError, SecretString, SecureRandom},
    time::{TimeError, UnixTimestamp},
    vault::{
        ProviderAccessToken, ProviderGrantKind, ProviderRefreshToken, ProviderTokenMetadata,
        ProviderTokenSet,
    },
};

use super::{
    DeviceCodeRequest, DeviceTokenPollRequest, GithubAppConfig, GithubDevicePollResponse,
    GithubEndpoint, GithubEndpointError, GithubTokenResponse, GithubWebCallback,
    RefreshTokenRequest, WebTokenExchangeRequest, model::append_web_authorization_query,
};

const DEVICE_SLOW_DOWN_SECONDS: u64 = 5;
const MAX_DEVICE_FLOW_SECONDS: u64 = 3_600;
const MAX_DEVICE_POLL_INTERVAL_SECONDS: u64 = 300;

#[derive(Debug)]
pub struct GithubAppProtocol {
    config: GithubAppConfig,
}

impl GithubAppProtocol {
    pub const fn new(config: GithubAppConfig) -> Self {
        Self { config }
    }

    pub const fn config(&self) -> &GithubAppConfig {
        &self.config
    }

    /// Begins a state-bound, S256 PKCE browser authorization transaction.
    ///
    /// # Errors
    ///
    /// Returns an error when secure randomness or timestamp arithmetic fails.
    pub fn begin_web(
        &self,
        random: &dyn SecureRandom,
        now: UnixTimestamp,
    ) -> Result<WebAuthorization, GithubFlowError> {
        let state = OAuthState::generate(random)?;
        let verifier = PkceVerifier::generate(random)?;
        let expires_at = now.checked_add(self.config.web_transaction_ttl_seconds())?;
        let authorization_url = append_web_authorization_query(
            self.config.endpoints().authorization().clone(),
            &self.config,
            &state,
            &verifier,
        );
        Ok(WebAuthorization {
            authorization_url,
            transaction: WebAuthorizationTransaction {
                state,
                verifier,
                expires_at,
            },
        })
    }

    /// Validates and consumes a callback before exchanging its one-use code.
    ///
    /// # Errors
    ///
    /// Returns an error for expired or untrusted callbacks, denial, endpoint
    /// failures, or malformed token responses.
    pub async fn complete_web(
        &self,
        endpoint: &dyn GithubEndpoint,
        transaction: WebAuthorizationTransaction,
        callback: &GithubWebCallback,
        now: UnixTimestamp,
    ) -> Result<ProviderTokenSet, GithubFlowError> {
        if now >= transaction.expires_at {
            return Err(GithubFlowError::WebTransactionExpired);
        }
        if !transaction.state.matches(callback.state().expose_secret()) {
            return Err(GithubFlowError::StateMismatch);
        }
        let code = match callback {
            GithubWebCallback::Authorized { code, .. } => code,
            GithubWebCallback::Denied { .. } => {
                return Err(GithubFlowError::AuthorizationDenied);
            }
        };
        let response = endpoint
            .exchange_web_code(WebTokenExchangeRequest {
                endpoint: self.config.endpoints().access_token(),
                client_id: self.config.client_id(),
                client_secret: self.config.client_secret(),
                code,
                redirect_uri: self.config.callback_uri(),
                code_verifier: &transaction.verifier,
            })
            .await?;
        token_set_from_response(
            response,
            self.config.provider_id().clone(),
            None,
            ProviderGrantKind::BrowserAuthorizationCode,
            now,
        )
    }

    /// Requests and validates a new CLI device authorization.
    ///
    /// # Errors
    ///
    /// Returns an error for endpoint failures, unsafe verification URLs, invalid
    /// timing values, or timestamp overflow.
    pub async fn begin_device(
        &self,
        endpoint: &dyn GithubEndpoint,
        now: UnixTimestamp,
    ) -> Result<DeviceAuthorization, GithubFlowError> {
        let response = endpoint
            .request_device_code(DeviceCodeRequest {
                endpoint: self.config.endpoints().device_code(),
                client_id: self.config.client_id(),
            })
            .await?;
        if response.expires_in == 0
            || response.expires_in > MAX_DEVICE_FLOW_SECONDS
            || response.interval == 0
            || response.interval > MAX_DEVICE_POLL_INTERVAL_SECONDS
            || !self
                .config
                .endpoints()
                .trusts_verification_uri(&response.verification_uri)
        {
            return Err(GithubFlowError::InvalidProviderResponse);
        }
        let expires_at = now.checked_add(response.expires_in)?;
        let next_poll_at = now.checked_add(response.interval)?;
        Ok(DeviceAuthorization {
            device_code: response.device_code,
            user_code: response.user_code,
            verification_uri: response.verification_uri,
            expires_at,
            next_poll_at,
            poll_interval_seconds: response.interval,
            status: DeviceAuthorizationStatus::Pending,
        })
    }

    /// Polls a pending device authorization no faster than GitHub permits.
    ///
    /// # Errors
    ///
    /// Returns an error when polling is early or terminal, the endpoint fails, the
    /// device code is invalid, or a token response is malformed.
    pub async fn poll_device(
        &self,
        endpoint: &dyn GithubEndpoint,
        authorization: &mut DeviceAuthorization,
        now: UnixTimestamp,
    ) -> Result<DevicePollOutcome, GithubFlowError> {
        if authorization.status != DeviceAuthorizationStatus::Pending {
            return Err(GithubFlowError::DeviceFlowTerminal);
        }
        if now >= authorization.expires_at {
            authorization.status = DeviceAuthorizationStatus::Expired;
            return Ok(DevicePollOutcome::Expired);
        }
        if now < authorization.next_poll_at {
            return Err(GithubFlowError::PollTooEarly {
                next_poll_at: authorization.next_poll_at,
            });
        }

        // Advance before I/O so transient endpoint failures cannot produce a tight loop.
        authorization.next_poll_at = now.checked_add(authorization.poll_interval_seconds)?;
        let response = endpoint
            .poll_device_token(DeviceTokenPollRequest {
                endpoint: self.config.endpoints().access_token(),
                client_id: self.config.client_id(),
                device_code: &authorization.device_code,
            })
            .await?;

        match response {
            GithubDevicePollResponse::AuthorizationPending => Ok(DevicePollOutcome::Pending {
                next_poll_at: authorization.next_poll_at,
            }),
            GithubDevicePollResponse::SlowDown => {
                authorization.poll_interval_seconds = authorization
                    .poll_interval_seconds
                    .checked_add(DEVICE_SLOW_DOWN_SECONDS)
                    .ok_or(TimeError::Overflow)?;
                authorization.next_poll_at =
                    now.checked_add(authorization.poll_interval_seconds)?;
                Ok(DevicePollOutcome::Pending {
                    next_poll_at: authorization.next_poll_at,
                })
            }
            GithubDevicePollResponse::AccessDenied => {
                authorization.status = DeviceAuthorizationStatus::Denied;
                Ok(DevicePollOutcome::Denied)
            }
            GithubDevicePollResponse::ExpiredToken => {
                authorization.status = DeviceAuthorizationStatus::Expired;
                Ok(DevicePollOutcome::Expired)
            }
            GithubDevicePollResponse::IncorrectDeviceCode => {
                authorization.status = DeviceAuthorizationStatus::Denied;
                Err(GithubFlowError::InvalidDeviceCode)
            }
            GithubDevicePollResponse::Token(response) => {
                let tokens = token_set_from_response(
                    response,
                    self.config.provider_id().clone(),
                    None,
                    ProviderGrantKind::DeviceAuthorization,
                    now,
                )?;
                authorization.status = DeviceAuthorizationStatus::Complete;
                Ok(DevicePollOutcome::Complete(tokens))
            }
        }
    }

    /// Refreshes expiring GitHub user credentials. Callers must persist the returned
    /// rotating refresh token with `ProviderTokenVault::replace_if_version`.
    ///
    /// # Errors
    ///
    /// Returns an error if refresh is unavailable or expired, the token belongs to
    /// another provider, GitHub fails, or GitHub returns invalid rotation data.
    pub async fn refresh(
        &self,
        endpoint: &dyn GithubEndpoint,
        current: &ProviderTokenSet,
        now: UnixTimestamp,
    ) -> Result<ProviderTokenSet, GithubFlowError> {
        let refresh_token = current
            .refresh_token()
            .ok_or(GithubFlowError::RefreshUnavailable)?;
        if current
            .metadata()
            .refresh_expires_at()
            .is_some_and(|expiry| expiry <= now)
        {
            return Err(GithubFlowError::RefreshExpired);
        }
        if current.metadata().provider_id() != self.config.provider_id() {
            return Err(GithubFlowError::WrongProvider);
        }
        let client_secret = match current.metadata().grant_kind() {
            ProviderGrantKind::BrowserAuthorizationCode => Some(self.config.client_secret()),
            ProviderGrantKind::DeviceAuthorization => None,
        };
        let response = endpoint
            .refresh_token(RefreshTokenRequest {
                endpoint: self.config.endpoints().access_token(),
                client_id: self.config.client_id(),
                client_secret,
                refresh_token,
            })
            .await?;
        let replacement = token_set_from_response(
            response,
            self.config.provider_id().clone(),
            current.metadata().provider_subject().cloned(),
            current.metadata().grant_kind(),
            now,
        )?;
        if replacement.refresh_token().is_none() {
            return Err(GithubFlowError::InvalidProviderResponse);
        }
        Ok(replacement)
    }
}

pub struct WebAuthorization {
    authorization_url: Url,
    transaction: WebAuthorizationTransaction,
}

impl WebAuthorization {
    pub fn authorization_url(&self) -> &Url {
        &self.authorization_url
    }

    pub fn into_transaction(self) -> WebAuthorizationTransaction {
        self.transaction
    }

    pub fn transaction(&self) -> &WebAuthorizationTransaction {
        &self.transaction
    }
}

impl fmt::Debug for WebAuthorization {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("WebAuthorization")
            .field("authorization_origin", &self.authorization_url.origin())
            .field("authorization_path", &self.authorization_url.path())
            .field("authorization_query", &"[REDACTED]")
            .field("transaction", &self.transaction)
            .finish()
    }
}

pub struct WebAuthorizationTransaction {
    state: OAuthState,
    verifier: PkceVerifier,
    expires_at: UnixTimestamp,
}

impl WebAuthorizationTransaction {
    pub fn state_secret(&self) -> &str {
        self.state.expose_secret()
    }

    pub const fn expires_at(&self) -> UnixTimestamp {
        self.expires_at
    }
}

impl fmt::Debug for WebAuthorizationTransaction {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("WebAuthorizationTransaction")
            .field("state", &"[REDACTED]")
            .field("verifier", &"[REDACTED]")
            .field("expires_at", &self.expires_at)
            .finish()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DeviceAuthorizationStatus {
    Pending,
    Complete,
    Denied,
    Expired,
}

pub struct DeviceAuthorization {
    device_code: SecretString,
    user_code: SecretString,
    verification_uri: Url,
    expires_at: UnixTimestamp,
    next_poll_at: UnixTimestamp,
    poll_interval_seconds: u64,
    status: DeviceAuthorizationStatus,
}

impl DeviceAuthorization {
    /// Explicitly exposes the short-lived code the CLI must show to the user.
    pub fn user_code(&self) -> &str {
        self.user_code.expose_secret()
    }

    pub fn verification_uri(&self) -> &Url {
        &self.verification_uri
    }

    pub const fn expires_at(&self) -> UnixTimestamp {
        self.expires_at
    }

    pub const fn next_poll_at(&self) -> UnixTimestamp {
        self.next_poll_at
    }

    pub const fn poll_interval_seconds(&self) -> u64 {
        self.poll_interval_seconds
    }

    pub const fn status(&self) -> DeviceAuthorizationStatus {
        self.status
    }
}

impl fmt::Debug for DeviceAuthorization {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DeviceAuthorization")
            .field("device_code", &"[REDACTED]")
            .field("user_code", &"[REDACTED]")
            .field("verification_uri", &self.verification_uri)
            .field("expires_at", &self.expires_at)
            .field("next_poll_at", &self.next_poll_at)
            .field("poll_interval_seconds", &self.poll_interval_seconds)
            .field("status", &self.status)
            .finish()
    }
}

#[derive(Debug)]
pub enum DevicePollOutcome {
    Pending { next_poll_at: UnixTimestamp },
    Complete(ProviderTokenSet),
    Denied,
    Expired,
}

fn token_set_from_response(
    response: GithubTokenResponse,
    provider_id: ProviderId,
    provider_subject: Option<ProviderSubject>,
    grant_kind: ProviderGrantKind,
    now: UnixTimestamp,
) -> Result<ProviderTokenSet, GithubFlowError> {
    if !response.token_type.eq_ignore_ascii_case("bearer")
        || response.expires_in == Some(0)
        || response.refresh_token_expires_in == Some(0)
        || response.refresh_token.is_some() != response.refresh_token_expires_in.is_some()
    {
        return Err(GithubFlowError::InvalidProviderResponse);
    }
    let access_expires_at = response
        .expires_in
        .map(|seconds| now.checked_add(seconds))
        .transpose()?;
    let refresh_expires_at = response
        .refresh_token_expires_in
        .map(|seconds| now.checked_add(seconds))
        .transpose()?;
    let scopes = parse_scopes(&response.scope)?;
    let metadata = ProviderTokenMetadata::new(
        provider_id,
        provider_subject,
        grant_kind,
        "bearer",
        scopes,
        now,
        access_expires_at,
        refresh_expires_at,
    )
    .map_err(|_| GithubFlowError::InvalidProviderResponse)?;
    ProviderTokenSet::new(
        ProviderAccessToken::new(response.access_token),
        response.refresh_token.map(ProviderRefreshToken::new),
        metadata,
    )
    .map_err(|_| GithubFlowError::InvalidProviderResponse)
}

fn parse_scopes(value: &str) -> Result<BTreeSet<String>, GithubFlowError> {
    let scopes = value
        .split([',', ' '])
        .filter(|scope| !scope.is_empty())
        .map(str::to_owned)
        .collect::<BTreeSet<_>>();
    if scopes
        .iter()
        .any(|scope| scope.len() > 255 || scope.chars().any(char::is_control))
    {
        return Err(GithubFlowError::InvalidProviderResponse);
    }
    Ok(scopes)
}

#[derive(Debug, Error)]
pub enum GithubFlowError {
    #[error("secure randomness is unavailable")]
    Randomness(#[from] RandomnessError),
    #[error("timestamp arithmetic failed")]
    Time(#[from] TimeError),
    #[error("GitHub endpoint operation failed")]
    Endpoint(#[from] GithubEndpointError),
    #[error("web authorization transaction expired")]
    WebTransactionExpired,
    #[error("OAuth state did not match; the callback is untrusted")]
    StateMismatch,
    #[error("the user denied GitHub authorization")]
    AuthorizationDenied,
    #[error("GitHub returned an invalid authorization response")]
    InvalidProviderResponse,
    #[error("device authorization was already terminal")]
    DeviceFlowTerminal,
    #[error("device flow was polled before {next_poll_at:?}")]
    PollTooEarly { next_poll_at: UnixTimestamp },
    #[error("GitHub rejected the device code")]
    InvalidDeviceCode,
    #[error("the provider token has no refresh credential")]
    RefreshUnavailable,
    #[error("the provider refresh credential expired")]
    RefreshExpired,
    #[error("provider token belongs to a different provider")]
    WrongProvider,
}
