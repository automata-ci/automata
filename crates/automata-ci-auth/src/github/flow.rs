use std::{collections::BTreeSet, fmt};

use serde::{Deserialize, Serialize};
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

/// Provider protocol for state-bound browser and device authorization flows.
#[derive(Debug)]
pub struct GithubAppProtocol {
    config: GithubAppConfig,
}

impl GithubAppProtocol {
    /// Creates the protocol around one validated GitHub App configuration.
    #[must_use]
    pub const fn new(config: GithubAppConfig) -> Self {
        Self { config }
    }

    /// Returns the fixed provider identity, endpoints, client, and callback policy.
    #[must_use]
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
                created_at: now,
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
        if now < transaction.created_at {
            return Err(GithubFlowError::InvalidPersistedTransaction);
        }
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
            created_at: now,
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
            .await;
        if response.is_err() && authorization.next_poll_at >= authorization.expires_at {
            authorization.status = DeviceAuthorizationStatus::Expired;
            return Ok(DevicePollOutcome::Expired);
        }
        let response = response?;

        match response {
            GithubDevicePollResponse::AuthorizationPending => {
                if authorization.next_poll_at >= authorization.expires_at {
                    authorization.status = DeviceAuthorizationStatus::Expired;
                    Ok(DevicePollOutcome::Expired)
                } else {
                    Ok(DevicePollOutcome::Pending {
                        next_poll_at: authorization.next_poll_at,
                    })
                }
            }
            GithubDevicePollResponse::SlowDown => {
                authorization.poll_interval_seconds = authorization
                    .poll_interval_seconds
                    .checked_add(DEVICE_SLOW_DOWN_SECONDS)
                    .ok_or(TimeError::Overflow)?;
                authorization.next_poll_at =
                    now.checked_add(authorization.poll_interval_seconds)?;
                if authorization.next_poll_at >= authorization.expires_at {
                    authorization.status = DeviceAuthorizationStatus::Expired;
                    Ok(DevicePollOutcome::Expired)
                } else {
                    Ok(DevicePollOutcome::Pending {
                        next_poll_at: authorization.next_poll_at,
                    })
                }
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

/// Browser authorization URL paired with its one-use secret transaction.
pub struct WebAuthorization {
    authorization_url: Url,
    transaction: WebAuthorizationTransaction,
}

impl WebAuthorization {
    /// Returns the trusted provider URL including secret OAuth state and challenge.
    pub fn authorization_url(&self) -> &Url {
        &self.authorization_url
    }

    /// Consumes the response and returns its secret transaction for persistence.
    pub fn into_transaction(self) -> WebAuthorizationTransaction {
        self.transaction
    }

    /// Borrows the secret transaction without exposing its verifier.
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

/// One-use browser state and PKCE verifier with a bounded lifetime.
pub struct WebAuthorizationTransaction {
    state: OAuthState,
    verifier: PkceVerifier,
    created_at: UnixTimestamp,
    expires_at: UnixTimestamp,
}

impl WebAuthorizationTransaction {
    /// Explicitly exposes OAuth state only for constant-time callback matching.
    pub fn state_secret(&self) -> &str {
        self.state.expose_secret()
    }

    /// Returns the exclusive callback deadline.
    pub const fn expires_at(&self) -> UnixTimestamp {
        self.expires_at
    }

    /// Returns when the authorization transaction was created.
    pub const fn created_at(&self) -> UnixTimestamp {
        self.created_at
    }

    /// Restores a decrypted durable transaction without exposing its fields.
    ///
    /// # Errors
    ///
    /// Rejects non-generated state or a lifetime outside GitHub's configured
    /// browser transaction bounds.
    pub fn from_parts(parts: WebAuthorizationTransactionParts) -> Result<Self, GithubFlowError> {
        let lifetime = parts
            .expires_at
            .as_seconds()
            .checked_sub(parts.created_at.as_seconds())
            .ok_or(GithubFlowError::InvalidPersistedTransaction)?;
        if !parts.state.has_generated_shape() || !(60..=1_800).contains(&lifetime) {
            return Err(GithubFlowError::InvalidPersistedTransaction);
        }
        Ok(Self {
            state: parts.state,
            verifier: parts.verifier,
            created_at: parts.created_at,
            expires_at: parts.expires_at,
        })
    }

    /// Splits a transaction for authenticated encryption by its repository adapter.
    #[must_use]
    pub fn into_parts(self) -> WebAuthorizationTransactionParts {
        WebAuthorizationTransactionParts::new(
            self.state,
            self.verifier,
            self.created_at,
            self.expires_at,
        )
    }
}

impl fmt::Debug for WebAuthorizationTransaction {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("WebAuthorizationTransaction")
            .field("state", &"[REDACTED]")
            .field("verifier", &"[REDACTED]")
            .field("created_at", &self.created_at)
            .field("expires_at", &self.expires_at)
            .finish()
    }
}

/// Secret-bearing browser transaction parts for encrypted durable round trips.
///
/// This type intentionally implements neither `Serialize` nor `Clone`.
pub struct WebAuthorizationTransactionParts {
    state: OAuthState,
    verifier: PkceVerifier,
    created_at: UnixTimestamp,
    expires_at: UnixTimestamp,
}

impl WebAuthorizationTransactionParts {
    /// Creates secret-bearing parts for an authenticated repository round trip.
    #[must_use]
    pub const fn new(
        state: OAuthState,
        verifier: PkceVerifier,
        created_at: UnixTimestamp,
        expires_at: UnixTimestamp,
    ) -> Self {
        Self {
            state,
            verifier,
            created_at,
            expires_at,
        }
    }

    /// Returns the one-use OAuth state secret.
    #[must_use]
    pub const fn state(&self) -> &OAuthState {
        &self.state
    }

    /// Returns the one-use S256 PKCE verifier.
    #[must_use]
    pub const fn verifier(&self) -> &PkceVerifier {
        &self.verifier
    }

    /// Returns the exclusive callback deadline.
    #[must_use]
    pub const fn expires_at(&self) -> UnixTimestamp {
        self.expires_at
    }

    /// Returns when the transaction was created.
    #[must_use]
    pub const fn created_at(&self) -> UnixTimestamp {
        self.created_at
    }

    /// Consumes all parts for authenticated encoding without cloning secrets.
    pub fn into_parts(self) -> (OAuthState, PkceVerifier, UnixTimestamp, UnixTimestamp) {
        (self.state, self.verifier, self.created_at, self.expires_at)
    }
}

impl fmt::Debug for WebAuthorizationTransactionParts {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("WebAuthorizationTransactionParts")
            .field("state", &"[REDACTED]")
            .field("verifier", &"[REDACTED]")
            .field("created_at", &self.created_at)
            .field("expires_at", &self.expires_at)
            .finish()
    }
}

/// Durable state of one GitHub device authorization.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DeviceAuthorizationStatus {
    /// Provider authorization is incomplete and may be polled at its deadline.
    Pending,
    /// A provider token was issued and the device code is consumed.
    Complete,
    /// Authorization was denied or the device code was rejected.
    Denied,
    /// The bounded device authorization lifetime elapsed.
    Expired,
}

/// Secret device/user codes plus validated provider polling state.
pub struct DeviceAuthorization {
    device_code: SecretString,
    user_code: SecretString,
    verification_uri: Url,
    created_at: UnixTimestamp,
    expires_at: UnixTimestamp,
    next_poll_at: UnixTimestamp,
    poll_interval_seconds: u64,
    status: DeviceAuthorizationStatus,
}

impl DeviceAuthorization {
    /// Restores decrypted durable device state after revalidating public metadata.
    ///
    /// # Errors
    ///
    /// Rejects an untrusted verification origin, invalid poll interval, or
    /// impossible persisted deadline.
    pub fn from_parts(
        parts: DeviceAuthorizationParts,
        trusted_endpoints: &super::GithubEndpoints,
    ) -> Result<Self, GithubFlowError> {
        let lifetime = parts
            .expires_at
            .as_seconds()
            .checked_sub(parts.created_at.as_seconds())
            .ok_or(GithubFlowError::InvalidPersistedTransaction)?;
        if lifetime == 0
            || lifetime > MAX_DEVICE_FLOW_SECONDS
            || parts.next_poll_at < parts.created_at
            || parts.poll_interval_seconds == 0
            || parts.poll_interval_seconds > MAX_DEVICE_FLOW_SECONDS
            || !trusted_endpoints.trusts_verification_uri(&parts.verification_uri)
        {
            return Err(GithubFlowError::InvalidPersistedTransaction);
        }
        Ok(Self {
            device_code: parts.device_code,
            user_code: parts.user_code,
            verification_uri: parts.verification_uri,
            created_at: parts.created_at,
            expires_at: parts.expires_at,
            next_poll_at: parts.next_poll_at,
            poll_interval_seconds: parts.poll_interval_seconds,
            status: parts.status,
        })
    }

    /// Explicitly exposes the short-lived code the CLI must show to the user.
    pub fn user_code(&self) -> &str {
        self.user_code.expose_secret()
    }

    /// Returns the provider URL at which the user authorizes the device.
    pub fn verification_uri(&self) -> &Url {
        &self.verification_uri
    }

    /// Returns the exclusive device authorization deadline.
    pub const fn expires_at(&self) -> UnixTimestamp {
        self.expires_at
    }

    /// Returns when the device authorization was created.
    pub const fn created_at(&self) -> UnixTimestamp {
        self.created_at
    }

    /// Returns the earliest trusted-clock instant for the next poll.
    pub const fn next_poll_at(&self) -> UnixTimestamp {
        self.next_poll_at
    }

    /// Returns the current provider-mandated polling interval.
    pub const fn poll_interval_seconds(&self) -> u64 {
        self.poll_interval_seconds
    }

    /// Returns the current durable device-flow state.
    pub const fn status(&self) -> DeviceAuthorizationStatus {
        self.status
    }

    /// Splits device state for authenticated encryption by its repository adapter.
    #[must_use]
    pub fn into_parts(self) -> DeviceAuthorizationParts {
        DeviceAuthorizationParts::new(
            self.device_code,
            self.user_code,
            self.verification_uri,
            self.created_at,
            self.expires_at,
            self.next_poll_at,
            self.poll_interval_seconds,
            self.status,
        )
    }
}

impl fmt::Debug for DeviceAuthorization {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DeviceAuthorization")
            .field("device_code", &"[REDACTED]")
            .field("user_code", &"[REDACTED]")
            .field("verification_uri", &self.verification_uri)
            .field("created_at", &self.created_at)
            .field("expires_at", &self.expires_at)
            .field("next_poll_at", &self.next_poll_at)
            .field("poll_interval_seconds", &self.poll_interval_seconds)
            .field("status", &self.status)
            .finish()
    }
}

/// Secret-bearing device transaction parts for encrypted durable round trips.
///
/// This type intentionally implements neither `Serialize` nor `Clone`.
pub struct DeviceAuthorizationParts {
    device_code: SecretString,
    user_code: SecretString,
    verification_uri: Url,
    created_at: UnixTimestamp,
    expires_at: UnixTimestamp,
    next_poll_at: UnixTimestamp,
    poll_interval_seconds: u64,
    status: DeviceAuthorizationStatus,
}

impl DeviceAuthorizationParts {
    /// Creates secret-bearing parts for an authenticated repository round trip.
    #[must_use]
    #[allow(clippy::too_many_arguments)]
    pub const fn new(
        device_code: SecretString,
        user_code: SecretString,
        verification_uri: Url,
        created_at: UnixTimestamp,
        expires_at: UnixTimestamp,
        next_poll_at: UnixTimestamp,
        poll_interval_seconds: u64,
        status: DeviceAuthorizationStatus,
    ) -> Self {
        Self {
            device_code,
            user_code,
            verification_uri,
            created_at,
            expires_at,
            next_poll_at,
            poll_interval_seconds,
            status,
        }
    }

    /// Returns the provider device-code secret.
    #[must_use]
    pub const fn device_code(&self) -> &SecretString {
        &self.device_code
    }

    /// Returns the short-lived user-code secret.
    #[must_use]
    pub const fn user_code(&self) -> &SecretString {
        &self.user_code
    }

    /// Returns the validated provider verification URL.
    #[must_use]
    pub const fn verification_uri(&self) -> &Url {
        &self.verification_uri
    }

    /// Returns the exclusive device authorization deadline.
    #[must_use]
    pub const fn expires_at(&self) -> UnixTimestamp {
        self.expires_at
    }

    /// Returns when the device authorization was created.
    #[must_use]
    pub const fn created_at(&self) -> UnixTimestamp {
        self.created_at
    }

    /// Returns the earliest trusted-clock instant for the next poll.
    #[must_use]
    pub const fn next_poll_at(&self) -> UnixTimestamp {
        self.next_poll_at
    }

    /// Returns the current provider-mandated polling interval.
    #[must_use]
    pub const fn poll_interval_seconds(&self) -> u64 {
        self.poll_interval_seconds
    }

    /// Returns the current durable device-flow state.
    #[must_use]
    pub const fn status(&self) -> DeviceAuthorizationStatus {
        self.status
    }

    #[allow(clippy::type_complexity)]
    /// Consumes all parts for authenticated encoding without cloning secrets.
    pub fn into_parts(
        self,
    ) -> (
        SecretString,
        SecretString,
        Url,
        UnixTimestamp,
        UnixTimestamp,
        UnixTimestamp,
        u64,
        DeviceAuthorizationStatus,
    ) {
        (
            self.device_code,
            self.user_code,
            self.verification_uri,
            self.created_at,
            self.expires_at,
            self.next_poll_at,
            self.poll_interval_seconds,
            self.status,
        )
    }
}

impl fmt::Debug for DeviceAuthorizationParts {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DeviceAuthorizationParts")
            .field("device_code", &"[REDACTED]")
            .field("user_code", &"[REDACTED]")
            .field("verification_uri", &self.verification_uri)
            .field("created_at", &self.created_at)
            .field("expires_at", &self.expires_at)
            .field("next_poll_at", &self.next_poll_at)
            .field("poll_interval_seconds", &self.poll_interval_seconds)
            .field("status", &self.status)
            .finish()
    }
}

/// Result of one correctly timed device-authorization poll.
#[derive(Debug)]
pub enum DevicePollOutcome {
    /// Provider authorization is incomplete.
    Pending {
        /// Earliest trusted-clock instant for the next poll.
        next_poll_at: UnixTimestamp,
    },
    /// Authorization completed and returned provider credentials.
    Complete(ProviderTokenSet),
    /// The user or provider denied authorization.
    Denied,
    /// The device-authorization lifetime elapsed.
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
    let metadata = ProviderTokenMetadata::builder(provider_id, grant_kind, "bearer", now)
        .provider_subject(provider_subject)
        .scopes(scopes)
        .access_expires_at(access_expires_at)
        .refresh_expires_at(refresh_expires_at)
        .build()
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

/// Sanitized failure while executing a GitHub authorization protocol.
#[derive(Debug, Error)]
pub enum GithubFlowError {
    /// Cryptographically secure randomness could not be obtained.
    #[error("secure randomness is unavailable")]
    Randomness(#[from] RandomnessError),
    /// Trusted timestamp arithmetic overflowed.
    #[error("timestamp arithmetic failed")]
    Time(#[from] TimeError),
    /// The fixed provider endpoint returned a typed failure.
    #[error("GitHub endpoint operation failed")]
    Endpoint(#[from] GithubEndpointError),
    /// The browser callback arrived after the transaction deadline.
    #[error("web authorization transaction expired")]
    WebTransactionExpired,
    /// Callback state did not match the one-use transaction secret.
    #[error("OAuth state did not match; the callback is untrusted")]
    StateMismatch,
    /// The user denied the browser authorization request.
    #[error("the user denied GitHub authorization")]
    AuthorizationDenied,
    /// Provider data is malformed, oversized, or internally inconsistent.
    #[error("GitHub returned an invalid authorization response")]
    InvalidProviderResponse,
    /// Decrypted durable transaction state violates current invariants.
    #[error("persisted GitHub login transaction violates an invariant")]
    InvalidPersistedTransaction,
    /// A terminal device authorization was polled again.
    #[error("device authorization was already terminal")]
    DeviceFlowTerminal,
    /// The caller polled before the provider-mandated deadline.
    #[error("device flow was polled before {next_poll_at:?}")]
    PollTooEarly {
        /// Earliest trusted-clock instant at which polling is permitted.
        next_poll_at: UnixTimestamp,
    },
    /// GitHub rejected the device code as incorrect.
    #[error("GitHub rejected the device code")]
    InvalidDeviceCode,
    /// The current provider token set has no refresh credential.
    #[error("the provider token has no refresh credential")]
    RefreshUnavailable,
    /// The provider refresh credential is expired.
    #[error("the provider refresh credential expired")]
    RefreshExpired,
    /// The token set belongs to a different configured provider.
    #[error("provider token belongs to a different provider")]
    WrongProvider,
}
