use std::fmt;

use thiserror::Error;
use url::Url;

use crate::{
    login::LoginTransactionState,
    secret::{OAuthState, PkceVerifier, SecretBytes, SecretString},
    time::UnixTimestamp,
};

use super::{
    DeviceAuthorization, DeviceAuthorizationParts, DeviceAuthorizationStatus, GithubEndpoints,
    WebAuthorizationTransaction, WebAuthorizationTransactionParts,
    flow::MAX_DEVICE_POLL_INTERVAL_SECONDS,
};

const WEB_HEADER: &[u8; 8] = b"AUTWST02";
const DEVICE_HEADER: &[u8; 8] = b"AUTDST02";
const MAX_DEVICE_CODE_BYTES: usize = 4_096;

/// Single current-format codec for provider state held under repository encryption.
#[derive(Clone, Copy, Debug, Default)]
pub struct GithubTransactionStateCodec;

impl GithubTransactionStateCodec {
    /// Encodes one browser state/PKCE transaction for authenticated encryption.
    ///
    /// # Errors
    ///
    /// Rejects fields that cannot fit the bounded current binary format.
    pub fn encode_web(
        transaction: WebAuthorizationTransaction,
    ) -> Result<LoginTransactionState, GithubTransactionStateError> {
        let (state, verifier, _, _) = transaction.into_parts().into_parts();
        // The repository validates caller time and rebases the durable lifetime to
        // database time. Persist only provider secrets so that rebase cannot make
        // an otherwise valid transaction reject its own encrypted state.
        let mut encoded = Vec::with_capacity(128);
        encoded.extend_from_slice(WEB_HEADER);
        push_string(&mut encoded, state.expose_secret())?;
        push_string(&mut encoded, verifier.expose_secret())?;
        state_from_bytes(encoded)
    }

    /// Restores browser secrets using database-authoritative durable times.
    ///
    /// # Errors
    ///
    /// Rejects old, cross-kind, malformed, oversized, or trailing-byte state.
    pub fn decode_web(
        state: LoginTransactionState,
        created_at: UnixTimestamp,
        expires_at: UnixTimestamp,
    ) -> Result<WebAuthorizationTransaction, GithubTransactionStateError> {
        let secret = state.into_secret();
        let mut decoder = Decoder::new(secret.expose_secret());
        decoder.expect_header(WEB_HEADER)?;
        let oauth_state = decoder.read_secret_string()?;
        let verifier = decoder.read_secret_string()?;
        decoder.finish()?;
        let oauth_state = OAuthState::from_generated_secret(oauth_state)
            .map_err(|_| GithubTransactionStateError::InvalidState)?;
        let verifier = PkceVerifier::from_secret(verifier)
            .map_err(|_| GithubTransactionStateError::InvalidState)?;
        WebAuthorizationTransaction::from_parts(WebAuthorizationTransactionParts::new(
            oauth_state,
            verifier,
            created_at,
            expires_at,
        ))
        .map_err(|_| GithubTransactionStateError::InvalidState)
    }

    /// Splits a pending device authorization into encrypted provider state and
    /// the separately encrypted/display metadata required by the durable login row.
    ///
    /// # Errors
    ///
    /// Rejects terminal or persistence-incompatible device state.
    pub fn encode_device(
        authorization: DeviceAuthorization,
    ) -> Result<(LoginTransactionState, GithubDeviceTransactionMetadata), GithubTransactionStateError>
    {
        let (
            device_code,
            user_code,
            verification_uri,
            created_at,
            expires_at,
            next_poll_at,
            poll_interval_seconds,
            status,
        ) = authorization.into_parts().into_parts();
        if status != DeviceAuthorizationStatus::Pending
            || device_code.expose_secret().len() > MAX_DEVICE_CODE_BYTES
        {
            return Err(GithubTransactionStateError::InvalidState);
        }
        let poll_interval_milliseconds = poll_interval_seconds
            .checked_mul(1_000)
            .ok_or(GithubTransactionStateError::InvalidMetadata)?;
        let metadata = GithubDeviceTransactionMetadata::new(
            user_code,
            verification_uri.to_string(),
            created_at,
            expires_at,
            next_poll_at,
            poll_interval_milliseconds,
        )?;
        // Poll deadlines are rebased to database time after a row lock is
        // acquired. The encrypted state therefore contains only the provider
        // secret; the repository owns the validated durable schedule.
        let mut encoded =
            Vec::with_capacity(DEVICE_HEADER.len() + 2 + device_code.expose_secret().len());
        encoded.extend_from_slice(DEVICE_HEADER);
        push_string(&mut encoded, device_code.expose_secret())?;
        Ok((state_from_bytes(encoded)?, metadata))
    }

    /// Restores pending device secrets using database-authoritative durable metadata.
    ///
    /// # Errors
    ///
    /// Rejects old, cross-kind, malformed, trailing-byte state and untrusted
    /// verification origins.
    pub fn decode_device(
        state: LoginTransactionState,
        metadata: GithubDeviceTransactionMetadata,
        trusted_endpoints: &GithubEndpoints,
    ) -> Result<DeviceAuthorization, GithubTransactionStateError> {
        let secret = state.into_secret();
        let mut decoder = Decoder::new(secret.expose_secret());
        decoder.expect_header(DEVICE_HEADER)?;
        let device_code = decoder.read_secret_string()?;
        decoder.finish()?;
        if device_code.expose_secret().len() > MAX_DEVICE_CODE_BYTES {
            return Err(GithubTransactionStateError::InvalidState);
        }
        let verification_uri = Url::parse(&metadata.verification_uri)
            .map_err(|_| GithubTransactionStateError::InvalidMetadata)?;
        let parts = DeviceAuthorizationParts::new(
            device_code,
            metadata.user_code,
            verification_uri,
            metadata.created_at,
            metadata.expires_at,
            metadata.next_poll_at,
            metadata.poll_interval_milliseconds / 1_000,
            DeviceAuthorizationStatus::Pending,
        );
        DeviceAuthorization::from_parts(parts, trusted_endpoints)
            .map_err(|_| GithubTransactionStateError::InvalidState)
    }
}

/// Database-authoritative device metadata stored beside encrypted provider state.
///
/// The user code remains secret-bearing. This value implements neither `Clone`
/// nor serialization and its debug representation redacts the code.
pub struct GithubDeviceTransactionMetadata {
    user_code: SecretString,
    verification_uri: String,
    created_at: UnixTimestamp,
    expires_at: UnixTimestamp,
    next_poll_at: UnixTimestamp,
    poll_interval_milliseconds: u64,
}

impl GithubDeviceTransactionMetadata {
    /// Creates exact durable device metadata.
    ///
    /// # Errors
    ///
    /// Rejects metadata that cannot satisfy both GitHub and login persistence bounds.
    pub fn new(
        user_code: SecretString,
        verification_uri: impl Into<String>,
        created_at: UnixTimestamp,
        expires_at: UnixTimestamp,
        next_poll_at: UnixTimestamp,
        poll_interval_milliseconds: u64,
    ) -> Result<Self, GithubTransactionStateError> {
        let verification_uri = verification_uri.into();
        if poll_interval_milliseconds == 0
            || !poll_interval_milliseconds.is_multiple_of(1_000)
            || poll_interval_milliseconds / 1_000 > MAX_DEVICE_POLL_INTERVAL_SECONDS
            || created_at >= expires_at
            || next_poll_at <= created_at
            || next_poll_at >= expires_at
            || user_code.expose_secret().is_empty()
            || user_code.expose_secret().len() > 64
            || user_code.expose_secret().chars().any(char::is_whitespace)
            || verification_uri.len() > 2_048
            || !verification_uri.starts_with("https://")
            || verification_uri.chars().any(char::is_control)
        {
            return Err(GithubTransactionStateError::InvalidMetadata);
        }
        Ok(Self {
            user_code,
            verification_uri,
            created_at,
            expires_at,
            next_poll_at,
            poll_interval_milliseconds,
        })
    }

    /// Returns the durable transaction creation instant.
    #[must_use]
    pub const fn created_at(&self) -> UnixTimestamp {
        self.created_at
    }

    /// Returns the exclusive transaction-expiration instant.
    #[must_use]
    pub const fn expires_at(&self) -> UnixTimestamp {
        self.expires_at
    }

    /// Returns the earliest instant at which the next provider poll is allowed.
    #[must_use]
    pub const fn next_poll_at(&self) -> UnixTimestamp {
        self.next_poll_at
    }

    /// Returns the durable polling interval in milliseconds.
    #[must_use]
    pub const fn poll_interval_milliseconds(&self) -> u64 {
        self.poll_interval_milliseconds
    }

    #[allow(clippy::type_complexity)]
    /// Consumes the metadata for atomic persistence without exposing it through
    /// serialization or cloning.
    pub fn into_parts(
        self,
    ) -> (
        SecretString,
        String,
        UnixTimestamp,
        UnixTimestamp,
        UnixTimestamp,
        u64,
    ) {
        (
            self.user_code,
            self.verification_uri,
            self.created_at,
            self.expires_at,
            self.next_poll_at,
            self.poll_interval_milliseconds,
        )
    }
}

impl fmt::Debug for GithubDeviceTransactionMetadata {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GithubDeviceTransactionMetadata")
            .field("user_code", &"[REDACTED]")
            .field("verification_uri", &self.verification_uri)
            .field("created_at", &self.created_at)
            .field("expires_at", &self.expires_at)
            .field("next_poll_at", &self.next_poll_at)
            .field(
                "poll_interval_milliseconds",
                &self.poll_interval_milliseconds,
            )
            .finish()
    }
}

fn state_from_bytes(bytes: Vec<u8>) -> Result<LoginTransactionState, GithubTransactionStateError> {
    SecretBytes::new(bytes)
        .map(LoginTransactionState::new)
        .map_err(|_| GithubTransactionStateError::InvalidState)
}

fn push_string(destination: &mut Vec<u8>, value: &str) -> Result<(), GithubTransactionStateError> {
    let length = u16::try_from(value.len()).map_err(|_| GithubTransactionStateError::TooLarge)?;
    destination.extend_from_slice(&length.to_be_bytes());
    destination.extend_from_slice(value.as_bytes());
    Ok(())
}

struct Decoder<'a> {
    remaining: &'a [u8],
}

impl<'a> Decoder<'a> {
    const fn new(remaining: &'a [u8]) -> Self {
        Self { remaining }
    }

    fn take(&mut self, length: usize) -> Result<&'a [u8], GithubTransactionStateError> {
        if self.remaining.len() < length {
            return Err(GithubTransactionStateError::InvalidState);
        }
        let (value, remaining) = self.remaining.split_at(length);
        self.remaining = remaining;
        Ok(value)
    }

    fn expect_header(&mut self, expected: &[u8]) -> Result<(), GithubTransactionStateError> {
        if self.take(expected.len())? != expected {
            return Err(GithubTransactionStateError::InvalidState);
        }
        Ok(())
    }

    fn read_secret_string(&mut self) -> Result<SecretString, GithubTransactionStateError> {
        let length = usize::from(u16::from_be_bytes(
            self.take(2)?
                .try_into()
                .map_err(|_| GithubTransactionStateError::InvalidState)?,
        ));
        let value = std::str::from_utf8(self.take(length)?)
            .map_err(|_| GithubTransactionStateError::InvalidState)?;
        if value.is_empty() {
            return Err(GithubTransactionStateError::InvalidState);
        }
        SecretString::new(value.to_owned()).map_err(|_| GithubTransactionStateError::InvalidState)
    }

    fn finish(self) -> Result<(), GithubTransactionStateError> {
        if self.remaining.is_empty() {
            Ok(())
        } else {
            Err(GithubTransactionStateError::InvalidState)
        }
    }
}

/// Sanitized current-format transaction-state failure.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum GithubTransactionStateError {
    /// Authenticated state is malformed, cross-kind, terminal, or unsupported.
    #[error("GitHub login transaction state is invalid")]
    InvalidState,
    /// Clear durable device metadata violates its closed bounds.
    #[error("GitHub login transaction metadata is invalid")]
    InvalidMetadata,
    /// The current binary transaction encoding exceeds its bounded length.
    #[error("GitHub login transaction state exceeds its bounded format")]
    TooLarge,
}
