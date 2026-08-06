use std::{collections::BTreeSet, fmt, future::Future, pin::Pin};

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{
    human::{ProviderId, ProviderSubject, TenantId},
    secret::{SecretBytes, SecretString},
    time::UnixTimestamp,
};

const MAX_TOKEN_TYPE_LENGTH: usize = 255;
const MAX_SCOPE_LENGTH: usize = 255;
const MAX_KEY_ENCRYPTION_PURPOSE_LENGTH: usize = 128;

pub struct ProviderAccessToken(SecretString);

impl ProviderAccessToken {
    pub fn new(secret: SecretString) -> Self {
        Self(secret)
    }

    pub fn expose_secret(&self) -> &str {
        self.0.expose_secret()
    }
}

impl fmt::Debug for ProviderAccessToken {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ProviderAccessToken([REDACTED])")
    }
}

pub struct ProviderRefreshToken(SecretString);

impl ProviderRefreshToken {
    pub fn new(secret: SecretString) -> Self {
        Self(secret)
    }

    pub fn expose_secret(&self) -> &str {
        self.0.expose_secret()
    }
}

impl fmt::Debug for ProviderRefreshToken {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ProviderRefreshToken([REDACTED])")
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderGrantKind {
    BrowserAuthorizationCode,
    DeviceAuthorization,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(try_from = "ProviderTokenMetadataData")]
pub struct ProviderTokenMetadata {
    provider_id: ProviderId,
    provider_subject: Option<ProviderSubject>,
    grant_kind: ProviderGrantKind,
    token_type: String,
    scopes: BTreeSet<String>,
    issued_at: UnixTimestamp,
    access_expires_at: Option<UnixTimestamp>,
    refresh_expires_at: Option<UnixTimestamp>,
}

#[derive(Deserialize)]
struct ProviderTokenMetadataData {
    provider_id: ProviderId,
    provider_subject: Option<ProviderSubject>,
    grant_kind: ProviderGrantKind,
    token_type: String,
    scopes: BTreeSet<String>,
    issued_at: UnixTimestamp,
    access_expires_at: Option<UnixTimestamp>,
    refresh_expires_at: Option<UnixTimestamp>,
}

impl ProviderTokenMetadata {
    /// Creates validated provider-token metadata.
    ///
    /// # Errors
    ///
    /// Returns an error for an invalid token type or scope, or when a recorded
    /// expiration is not strictly after issuance.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        provider_id: ProviderId,
        provider_subject: Option<ProviderSubject>,
        grant_kind: ProviderGrantKind,
        token_type: impl Into<String>,
        scopes: BTreeSet<String>,
        issued_at: UnixTimestamp,
        access_expires_at: Option<UnixTimestamp>,
        refresh_expires_at: Option<UnixTimestamp>,
    ) -> Result<Self, ProviderTokenMetadataError> {
        let token_type = token_type.into();
        if token_type.is_empty()
            || token_type.len() > MAX_TOKEN_TYPE_LENGTH
            || token_type
                .chars()
                .any(|character| character.is_control() || character.is_whitespace())
        {
            return Err(ProviderTokenMetadataError::InvalidTokenType);
        }
        if scopes.iter().any(|scope| {
            scope.is_empty()
                || scope.len() > MAX_SCOPE_LENGTH
                || scope
                    .chars()
                    .any(|character| character.is_control() || character.is_whitespace())
        }) {
            return Err(ProviderTokenMetadataError::InvalidScope);
        }
        if access_expires_at.is_some_and(|expiration| expiration <= issued_at) {
            return Err(ProviderTokenMetadataError::InvalidAccessLifetime);
        }
        if refresh_expires_at.is_some_and(|expiration| expiration <= issued_at) {
            return Err(ProviderTokenMetadataError::InvalidRefreshLifetime);
        }
        Ok(Self {
            provider_id,
            provider_subject,
            grant_kind,
            token_type,
            scopes,
            issued_at,
            access_expires_at,
            refresh_expires_at,
        })
    }

    pub const fn provider_id(&self) -> &ProviderId {
        &self.provider_id
    }

    pub const fn provider_subject(&self) -> Option<&ProviderSubject> {
        self.provider_subject.as_ref()
    }

    pub const fn grant_kind(&self) -> ProviderGrantKind {
        self.grant_kind
    }

    pub fn token_type(&self) -> &str {
        &self.token_type
    }

    pub const fn scopes(&self) -> &BTreeSet<String> {
        &self.scopes
    }

    pub const fn issued_at(&self) -> UnixTimestamp {
        self.issued_at
    }

    pub const fn access_expires_at(&self) -> Option<UnixTimestamp> {
        self.access_expires_at
    }

    pub const fn refresh_expires_at(&self) -> Option<UnixTimestamp> {
        self.refresh_expires_at
    }
}

impl TryFrom<ProviderTokenMetadataData> for ProviderTokenMetadata {
    type Error = ProviderTokenMetadataError;

    fn try_from(value: ProviderTokenMetadataData) -> Result<Self, Self::Error> {
        Self::new(
            value.provider_id,
            value.provider_subject,
            value.grant_kind,
            value.token_type,
            value.scopes,
            value.issued_at,
            value.access_expires_at,
            value.refresh_expires_at,
        )
    }
}

#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum ProviderTokenMetadataError {
    #[error("provider token type is invalid")]
    InvalidTokenType,
    #[error("provider token scope is invalid")]
    InvalidScope,
    #[error("provider access-token expiration must be after issuance")]
    InvalidAccessLifetime,
    #[error("provider refresh-token expiration must be after issuance")]
    InvalidRefreshLifetime,
}

/// Provider token material plus safe expiration and rotation metadata.
///
/// The structure intentionally implements neither `Serialize` nor `Clone`.
pub struct ProviderTokenSet {
    access_token: ProviderAccessToken,
    refresh_token: Option<ProviderRefreshToken>,
    metadata: ProviderTokenMetadata,
}

impl ProviderTokenSet {
    /// Combines provider credentials with self-consistent safe metadata.
    ///
    /// # Errors
    ///
    /// Returns an error when metadata records refresh-token expiration but no
    /// refresh token is present.
    pub fn new(
        access_token: ProviderAccessToken,
        refresh_token: Option<ProviderRefreshToken>,
        metadata: ProviderTokenMetadata,
    ) -> Result<Self, ProviderTokenSetError> {
        if refresh_token.is_none() && metadata.refresh_expires_at().is_some() {
            return Err(ProviderTokenSetError::RefreshMetadataWithoutToken);
        }
        Ok(Self {
            access_token,
            refresh_token,
            metadata,
        })
    }

    pub const fn access_token(&self) -> &ProviderAccessToken {
        &self.access_token
    }

    pub const fn refresh_token(&self) -> Option<&ProviderRefreshToken> {
        self.refresh_token.as_ref()
    }

    pub const fn metadata(&self) -> &ProviderTokenMetadata {
        &self.metadata
    }

    pub fn into_parts(
        self,
    ) -> (
        ProviderAccessToken,
        Option<ProviderRefreshToken>,
        ProviderTokenMetadata,
    ) {
        (self.access_token, self.refresh_token, self.metadata)
    }
}

impl fmt::Debug for ProviderTokenSet {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProviderTokenSet")
            .field("access_token", &"[REDACTED]")
            .field(
                "refresh_token",
                &self.refresh_token.as_ref().map(|_| "[REDACTED]"),
            )
            .field("metadata", &self.metadata)
            .finish()
    }
}

#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum ProviderTokenSetError {
    #[error("refresh-token expiration metadata requires a refresh token")]
    RefreshMetadataWithoutToken,
}

#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
pub struct ProviderTokenKey {
    tenant_id: TenantId,
    provider_id: ProviderId,
    provider_subject: ProviderSubject,
}

impl ProviderTokenKey {
    pub const fn new(
        tenant_id: TenantId,
        provider_id: ProviderId,
        provider_subject: ProviderSubject,
    ) -> Self {
        Self {
            tenant_id,
            provider_id,
            provider_subject,
        }
    }

    pub const fn tenant_id(&self) -> &TenantId {
        &self.tenant_id
    }

    pub const fn provider_id(&self) -> &ProviderId {
        &self.provider_id
    }

    pub const fn provider_subject(&self) -> &ProviderSubject {
        &self.provider_subject
    }

    pub fn into_parts(self) -> (TenantId, ProviderId, ProviderSubject) {
        (self.tenant_id, self.provider_id, self.provider_subject)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(transparent)]
pub struct TokenVersion(u64);

impl TokenVersion {
    pub const fn new(value: u64) -> Self {
        Self(value)
    }

    pub const fn value(self) -> u64 {
        self.0
    }
}

#[derive(Debug)]
pub struct VersionedProviderTokens {
    version: TokenVersion,
    tokens: ProviderTokenSet,
}

impl VersionedProviderTokens {
    pub const fn new(version: TokenVersion, tokens: ProviderTokenSet) -> Self {
        Self { version, tokens }
    }

    pub const fn version(&self) -> TokenVersion {
        self.version
    }

    pub const fn tokens(&self) -> &ProviderTokenSet {
        &self.tokens
    }

    pub fn into_parts(self) -> (TokenVersion, ProviderTokenSet) {
        (self.version, self.tokens)
    }
}

pub type VaultFuture<'a, T> =
    Pin<Box<dyn Future<Output = Result<T, ProviderTokenVaultError>> + Send + 'a>>;

/// Custody boundary for provider credentials.
///
/// Implementations must encrypt token material with authenticated encryption before
/// persistence. Compare-and-swap replacement prevents concurrent refresh operations
/// from reviving a rotated refresh token.
pub trait ProviderTokenVault: fmt::Debug + Send + Sync {
    fn load<'a>(&'a self, key: &'a ProviderTokenKey) -> VaultFuture<'a, VersionedProviderTokens>;

    fn insert_if_absent<'a>(
        &'a self,
        key: &'a ProviderTokenKey,
        tokens: ProviderTokenSet,
    ) -> VaultFuture<'a, TokenVersion>;

    fn replace_if_version<'a>(
        &'a self,
        key: &'a ProviderTokenKey,
        expected: TokenVersion,
        replacement: ProviderTokenSet,
    ) -> VaultFuture<'a, TokenVersion>;

    fn revoke<'a>(&'a self, key: &'a ProviderTokenKey) -> VaultFuture<'a, ()>;
}

#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum ProviderTokenVaultError {
    #[error("provider token was not found")]
    NotFound,
    #[error("provider token already exists")]
    AlreadyExists,
    #[error("provider token was concurrently rotated")]
    VersionConflict,
    #[error("provider token vault is unavailable")]
    Unavailable,
    #[error("provider token ciphertext failed authentication")]
    IntegrityFailure,
}

/// Stable separation label for one use of a data-encryption key.
#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(try_from = "String", into = "String")]
pub struct KeyEncryptionPurpose(String);

impl KeyEncryptionPurpose {
    /// Creates a portable, bounded key-encryption purpose.
    ///
    /// # Errors
    ///
    /// Returns an error for an empty, oversized, or non-portable purpose.
    pub fn new(value: impl Into<String>) -> Result<Self, KeyEncryptionContextError> {
        let value = value.into();
        if value.is_empty()
            || value.len() > MAX_KEY_ENCRYPTION_PURPOSE_LENGTH
            || !value.bytes().all(|character| {
                character.is_ascii_alphanumeric()
                    || matches!(character, b'-' | b'_' | b':' | b'.' | b'/')
            })
        {
            return Err(KeyEncryptionContextError::InvalidPurpose);
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for KeyEncryptionPurpose {
    type Error = KeyEncryptionContextError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl From<KeyEncryptionPurpose> for String {
    fn from(value: KeyEncryptionPurpose) -> Self {
        value.0
    }
}

/// Non-secret, authenticated context bound to a wrapped data-encryption key.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct KeyEncryptionContext {
    tenant_id: TenantId,
    purpose: KeyEncryptionPurpose,
}

impl KeyEncryptionContext {
    pub const fn new(tenant_id: TenantId, purpose: KeyEncryptionPurpose) -> Self {
        Self { tenant_id, purpose }
    }

    pub const fn tenant_id(&self) -> &TenantId {
        &self.tenant_id
    }

    pub const fn purpose(&self) -> &KeyEncryptionPurpose {
        &self.purpose
    }

    pub fn into_parts(self) -> (TenantId, KeyEncryptionPurpose) {
        (self.tenant_id, self.purpose)
    }
}

/// Opaque KMS/HSM output. It is ciphertext, but debug output still omits its bytes.
pub struct WrappedDataKey(Vec<u8>);

impl WrappedDataKey {
    /// Creates an opaque wrapped data key from non-empty ciphertext.
    ///
    /// # Errors
    ///
    /// Returns an error for empty ciphertext.
    pub fn new(bytes: Vec<u8>) -> Result<Self, KeyEncryptionError> {
        if bytes.is_empty() {
            return Err(KeyEncryptionError::InvalidCiphertext);
        }
        Ok(Self(bytes))
    }

    pub fn ciphertext(&self) -> &[u8] {
        &self.0
    }

    pub fn into_ciphertext(self) -> Vec<u8> {
        self.0
    }
}

impl fmt::Debug for WrappedDataKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("WrappedDataKey")
            .field("ciphertext_length", &self.0.len())
            .finish()
    }
}

pub type KeyEncryptionFuture<'a, T> =
    Pin<Box<dyn Future<Output = Result<T, KeyEncryptionError>> + Send + 'a>>;

/// Port implemented by a KMS, HSM, Vault transit engine, or equivalent KEK service.
/// Token-vault adapters use it to wrap data-encryption keys; this is not itself an
/// encryption implementation.
pub trait KeyEncryptionProvider: fmt::Debug + Send + Sync {
    fn wrap_data_key<'a>(
        &'a self,
        plaintext_key: &'a SecretBytes,
        context: &'a KeyEncryptionContext,
    ) -> KeyEncryptionFuture<'a, WrappedDataKey>;

    fn unwrap_data_key<'a>(
        &'a self,
        wrapped_key: &'a WrappedDataKey,
        context: &'a KeyEncryptionContext,
    ) -> KeyEncryptionFuture<'a, SecretBytes>;
}

#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum KeyEncryptionError {
    #[error("wrapped data key is invalid")]
    InvalidCiphertext,
    #[error("key-encryption provider rejected the authenticated context")]
    ContextMismatch,
    #[error("key-encryption provider is unavailable")]
    Unavailable,
}

#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum KeyEncryptionContextError {
    #[error("key-encryption purpose is invalid")]
    InvalidPurpose,
}
