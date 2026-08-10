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
};

const WEB_HEADER: &[u8; 8] = b"AUTWST01";
const DEVICE_HEADER: &[u8; 8] = b"AUTDST01";
const MAX_DEVICE_CODE_BYTES: usize = 4_096;
const MAX_DEVICE_POLL_INTERVAL_SECONDS: u64 = 300;

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
        let (state, verifier, created_at, expires_at) = transaction.into_parts().into_parts();
        let mut encoded = Vec::with_capacity(128);
        encoded.extend_from_slice(WEB_HEADER);
        push_string(&mut encoded, state.expose_secret())?;
        push_string(&mut encoded, verifier.expose_secret())?;
        push_timestamp(&mut encoded, created_at);
        push_timestamp(&mut encoded, expires_at);
        state_from_bytes(encoded)
    }

    /// Restores browser state and requires exact equality with clear durable times.
    ///
    /// # Errors
    ///
    /// Rejects old, cross-kind, malformed, oversized, or trailing-byte state and
    /// any authenticated/clear metadata disagreement.
    pub fn decode_web(
        state: LoginTransactionState,
        expected_created_at: UnixTimestamp,
        expected_expires_at: UnixTimestamp,
    ) -> Result<WebAuthorizationTransaction, GithubTransactionStateError> {
        let secret = state.into_secret();
        let mut decoder = Decoder::new(secret.expose_secret());
        decoder.expect_header(WEB_HEADER)?;
        let oauth_state = decoder.read_secret_string()?;
        let verifier = decoder.read_secret_string()?;
        let created_at = decoder.read_timestamp()?;
        let expires_at = decoder.read_timestamp()?;
        decoder.finish()?;
        if created_at != expected_created_at || expires_at != expected_expires_at {
            return Err(GithubTransactionStateError::MetadataMismatch);
        }
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
        let mut encoded = Vec::with_capacity(96);
        encoded.extend_from_slice(DEVICE_HEADER);
        push_string(&mut encoded, device_code.expose_secret())?;
        push_timestamp(&mut encoded, created_at);
        push_timestamp(&mut encoded, expires_at);
        push_timestamp(&mut encoded, next_poll_at);
        encoded.extend_from_slice(&poll_interval_seconds.to_be_bytes());
        encoded.push(device_status_byte(status));
        Ok((state_from_bytes(encoded)?, metadata))
    }

    /// Restores pending device state and authenticates every duplicated clear field.
    ///
    /// # Errors
    ///
    /// Rejects old, cross-kind, malformed, terminal, trailing-byte, or metadata-
    /// mismatched state and untrusted verification origins.
    pub fn decode_device(
        state: LoginTransactionState,
        metadata: GithubDeviceTransactionMetadata,
        trusted_endpoints: &GithubEndpoints,
    ) -> Result<DeviceAuthorization, GithubTransactionStateError> {
        let secret = state.into_secret();
        let mut decoder = Decoder::new(secret.expose_secret());
        decoder.expect_header(DEVICE_HEADER)?;
        let device_code = decoder.read_secret_string()?;
        let created_at = decoder.read_timestamp()?;
        let expires_at = decoder.read_timestamp()?;
        let next_poll_at = decoder.read_timestamp()?;
        let poll_interval_seconds = decoder.read_u64()?;
        let status = decode_device_status(decoder.read_u8()?)?;
        decoder.finish()?;
        if device_code.expose_secret().len() > MAX_DEVICE_CODE_BYTES
            || status != DeviceAuthorizationStatus::Pending
            || created_at != metadata.created_at
            || expires_at != metadata.expires_at
            || next_poll_at != metadata.next_poll_at
            || poll_interval_seconds
                .checked_mul(1_000)
                .is_none_or(|milliseconds| milliseconds != metadata.poll_interval_milliseconds)
        {
            return Err(GithubTransactionStateError::MetadataMismatch);
        }
        let verification_uri = Url::parse(&metadata.verification_uri)
            .map_err(|_| GithubTransactionStateError::InvalidMetadata)?;
        let parts = DeviceAuthorizationParts::new(
            device_code,
            metadata.user_code,
            verification_uri,
            created_at,
            expires_at,
            next_poll_at,
            poll_interval_seconds,
            status,
        );
        DeviceAuthorization::from_parts(parts, trusted_endpoints)
            .map_err(|_| GithubTransactionStateError::InvalidState)
    }
}

/// Device metadata duplicated between the encrypted payload and indexed durable fields.
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

fn device_status_byte(status: DeviceAuthorizationStatus) -> u8 {
    match status {
        DeviceAuthorizationStatus::Pending => 0,
        DeviceAuthorizationStatus::Complete => 1,
        DeviceAuthorizationStatus::Denied => 2,
        DeviceAuthorizationStatus::Expired => 3,
    }
}

fn decode_device_status(
    value: u8,
) -> Result<DeviceAuthorizationStatus, GithubTransactionStateError> {
    match value {
        0 => Ok(DeviceAuthorizationStatus::Pending),
        1 => Ok(DeviceAuthorizationStatus::Complete),
        2 => Ok(DeviceAuthorizationStatus::Denied),
        3 => Ok(DeviceAuthorizationStatus::Expired),
        _ => Err(GithubTransactionStateError::InvalidState),
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

fn push_timestamp(destination: &mut Vec<u8>, value: UnixTimestamp) {
    destination.extend_from_slice(&value.as_seconds().to_be_bytes());
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

    fn read_u64(&mut self) -> Result<u64, GithubTransactionStateError> {
        self.take(8)?
            .try_into()
            .map(u64::from_be_bytes)
            .map_err(|_| GithubTransactionStateError::InvalidState)
    }

    fn read_u8(&mut self) -> Result<u8, GithubTransactionStateError> {
        self.take(1)?
            .first()
            .copied()
            .ok_or(GithubTransactionStateError::InvalidState)
    }

    fn read_timestamp(&mut self) -> Result<UnixTimestamp, GithubTransactionStateError> {
        self.read_u64().map(UnixTimestamp::from_seconds)
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
    /// Authenticated metadata disagrees with its indexed durable copy.
    #[error("GitHub login transaction authenticated metadata does not match durable metadata")]
    MetadataMismatch,
    /// The current binary transaction encoding exceeds its bounded length.
    #[error("GitHub login transaction state exceeds its bounded format")]
    TooLarge,
}
