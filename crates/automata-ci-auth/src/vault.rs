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

/// A redacted provider access token with explicit plaintext exposure.
pub struct ProviderAccessToken(SecretString);

impl ProviderAccessToken {
    /// Wraps secret access-token material for provider-only custody.
    pub fn new(secret: SecretString) -> Self {
        Self(secret)
    }

    /// Exposes plaintext only at the provider request boundary.
    pub fn expose_secret(&self) -> &str {
        self.0.expose_secret()
    }
}

impl fmt::Debug for ProviderAccessToken {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ProviderAccessToken([REDACTED])")
    }
}

/// A redacted provider refresh token with explicit plaintext exposure.
pub struct ProviderRefreshToken(SecretString);

impl ProviderRefreshToken {
    /// Wraps secret refresh-token material for provider-only custody.
    pub fn new(secret: SecretString) -> Self {
        Self(secret)
    }

    /// Exposes plaintext only at the provider refresh boundary.
    pub fn expose_secret(&self) -> &str {
        self.0.expose_secret()
    }
}

impl fmt::Debug for ProviderRefreshToken {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ProviderRefreshToken([REDACTED])")
    }
}

/// OAuth grant flow that produced a provider token set.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderGrantKind {
    /// An interactive browser authorization-code exchange.
    BrowserAuthorizationCode,
    /// A device authorization flow polled by a CLI or installer.
    DeviceAuthorization,
}

/// Non-secret provenance and lifecycle metadata for provider credentials.
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

/// Builder for validated [`ProviderTokenMetadata`].
#[derive(Clone, Debug, Eq, PartialEq)]
#[must_use]
pub struct ProviderTokenMetadataBuilder {
    provider_id: ProviderId,
    provider_subject: Option<ProviderSubject>,
    grant_kind: ProviderGrantKind,
    token_type: String,
    scopes: BTreeSet<String>,
    issued_at: UnixTimestamp,
    access_expires_at: Option<UnixTimestamp>,
    refresh_expires_at: Option<UnixTimestamp>,
}

impl ProviderTokenMetadataBuilder {
    /// Records the stable provider subject when it is already known.
    pub fn provider_subject(mut self, provider_subject: Option<ProviderSubject>) -> Self {
        self.provider_subject = provider_subject;
        self
    }

    /// Replaces the granted provider scopes.
    pub fn scopes(mut self, scopes: BTreeSet<String>) -> Self {
        self.scopes = scopes;
        self
    }

    /// Records the access-token expiration, when the provider supplies one.
    pub const fn access_expires_at(mut self, expiration: Option<UnixTimestamp>) -> Self {
        self.access_expires_at = expiration;
        self
    }

    /// Records the refresh-token expiration, when the provider supplies one.
    pub const fn refresh_expires_at(mut self, expiration: Option<UnixTimestamp>) -> Self {
        self.refresh_expires_at = expiration;
        self
    }

    /// Validates and creates provider-token metadata.
    ///
    /// # Errors
    ///
    /// Returns an error for an invalid token type or scope, or when a recorded
    /// expiration is not strictly after issuance.
    pub fn build(self) -> Result<ProviderTokenMetadata, ProviderTokenMetadataError> {
        if self.token_type.is_empty()
            || self.token_type.len() > MAX_TOKEN_TYPE_LENGTH
            || !self
                .token_type
                .bytes()
                .all(|byte| (0x21..=0x7e).contains(&byte))
        {
            return Err(ProviderTokenMetadataError::InvalidTokenType);
        }
        if self.scopes.iter().any(|scope| {
            scope.is_empty()
                || scope.len() > MAX_SCOPE_LENGTH
                || !scope.bytes().all(|byte| {
                    byte.is_ascii_alphanumeric() || matches!(byte, b':' | b'.' | b'_' | b'/' | b'-')
                })
        }) {
            return Err(ProviderTokenMetadataError::InvalidScope);
        }
        if self
            .access_expires_at
            .is_some_and(|expiration| expiration <= self.issued_at)
        {
            return Err(ProviderTokenMetadataError::InvalidAccessLifetime);
        }
        if self
            .refresh_expires_at
            .is_some_and(|expiration| expiration <= self.issued_at)
        {
            return Err(ProviderTokenMetadataError::InvalidRefreshLifetime);
        }
        Ok(ProviderTokenMetadata {
            provider_id: self.provider_id,
            provider_subject: self.provider_subject,
            grant_kind: self.grant_kind,
            token_type: self.token_type,
            scopes: self.scopes,
            issued_at: self.issued_at,
            access_expires_at: self.access_expires_at,
            refresh_expires_at: self.refresh_expires_at,
        })
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
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
    /// Starts building validated provider-token metadata.
    pub fn builder(
        provider_id: ProviderId,
        grant_kind: ProviderGrantKind,
        token_type: impl Into<String>,
        issued_at: UnixTimestamp,
    ) -> ProviderTokenMetadataBuilder {
        ProviderTokenMetadataBuilder {
            provider_id,
            provider_subject: None,
            grant_kind,
            token_type: token_type.into(),
            scopes: BTreeSet::new(),
            issued_at,
            access_expires_at: None,
            refresh_expires_at: None,
        }
    }

    /// Returns the provider that issued the credentials.
    pub const fn provider_id(&self) -> &ProviderId {
        &self.provider_id
    }

    /// Returns the stable subject once identity discovery has bound it.
    pub const fn provider_subject(&self) -> Option<&ProviderSubject> {
        self.provider_subject.as_ref()
    }

    /// Returns the grant flow that issued the credentials.
    pub const fn grant_kind(&self) -> ProviderGrantKind {
        self.grant_kind
    }

    /// Returns the provider-declared authorization token type.
    pub fn token_type(&self) -> &str {
        &self.token_type
    }

    /// Returns the validated scopes granted by the provider.
    pub const fn scopes(&self) -> &BTreeSet<String> {
        &self.scopes
    }

    /// Returns when the provider credentials were issued.
    pub const fn issued_at(&self) -> UnixTimestamp {
        self.issued_at
    }

    /// Returns the access-token deadline when supplied by the provider.
    pub const fn access_expires_at(&self) -> Option<UnixTimestamp> {
        self.access_expires_at
    }

    /// Returns the refresh-token deadline when supplied by the provider.
    pub const fn refresh_expires_at(&self) -> Option<UnixTimestamp> {
        self.refresh_expires_at
    }
}

impl TryFrom<ProviderTokenMetadataData> for ProviderTokenMetadata {
    type Error = ProviderTokenMetadataError;

    fn try_from(value: ProviderTokenMetadataData) -> Result<Self, Self::Error> {
        Self::builder(
            value.provider_id,
            value.grant_kind,
            value.token_type,
            value.issued_at,
        )
        .provider_subject(value.provider_subject)
        .scopes(value.scopes)
        .access_expires_at(value.access_expires_at)
        .refresh_expires_at(value.refresh_expires_at)
        .build()
    }
}

/// Validation failures for non-secret provider-token metadata.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum ProviderTokenMetadataError {
    /// The token type was empty, oversized, or not visible ASCII.
    #[error("provider token type is invalid")]
    InvalidTokenType,
    #[error("provider token scope is invalid")]
    /// A scope was empty, oversized, or outside the portable alphabet.
    InvalidScope,
    /// Access-token expiry did not follow issuance.
    #[error("provider access-token expiration must be after issuance")]
    InvalidAccessLifetime,
    #[error("provider refresh-token expiration must be after issuance")]
    /// Refresh-token expiry did not follow issuance.
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

    /// Borrows the access token without exposing its plaintext.
    pub const fn access_token(&self) -> &ProviderAccessToken {
        &self.access_token
    }

    /// Borrows the optional refresh token without exposing its plaintext.
    pub const fn refresh_token(&self) -> Option<&ProviderRefreshToken> {
        self.refresh_token.as_ref()
    }

    /// Returns the non-secret provenance and lifecycle metadata.
    pub const fn metadata(&self) -> &ProviderTokenMetadata {
        &self.metadata
    }

    /// Binds credentials obtained before identity discovery to the stable
    /// provider subject returned by the provider's authenticated user API.
    ///
    /// # Errors
    ///
    /// Rejects a token set that was already bound to a different subject.
    pub fn bind_provider_subject(
        mut self,
        provider_subject: ProviderSubject,
    ) -> Result<Self, ProviderTokenSetError> {
        if self
            .metadata
            .provider_subject
            .as_ref()
            .is_some_and(|existing| existing != &provider_subject)
        {
            return Err(ProviderTokenSetError::ProviderSubjectMismatch);
        }
        self.metadata.provider_subject = Some(provider_subject);
        Ok(self)
    }

    /// Consumes the set into secret credentials and non-secret metadata.
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

/// Validation failures for a provider token set and its metadata.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum ProviderTokenSetError {
    /// Refresh expiry metadata exists without corresponding secret material.
    #[error("refresh-token expiration metadata requires a refresh token")]
    RefreshMetadataWithoutToken,
    #[error("provider token subject conflicts with the authenticated identity")]
    /// Existing token provenance names a different stable provider subject.
    ProviderSubjectMismatch,
}

/// Exact tenant/provider/subject key used for provider-token custody.
#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
pub struct ProviderTokenKey {
    tenant_id: TenantId,
    provider_id: ProviderId,
    provider_subject: ProviderSubject,
}

impl ProviderTokenKey {
    /// Creates an exact provider-token custody key.
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

    /// Returns the tenant that owns the credentials.
    pub const fn tenant_id(&self) -> &TenantId {
        &self.tenant_id
    }

    /// Returns the credential issuer.
    pub const fn provider_id(&self) -> &ProviderId {
        &self.provider_id
    }

    /// Returns the stable subject authorized by the credentials.
    pub const fn provider_subject(&self) -> &ProviderSubject {
        &self.provider_subject
    }

    /// Consumes the key into its exact identity tuple.
    pub fn into_parts(self) -> (TenantId, ProviderId, ProviderSubject) {
        (self.tenant_id, self.provider_id, self.provider_subject)
    }
}

/// Positive compare-and-swap version for provider credentials.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(transparent)]
pub struct TokenVersion(u64);

impl TokenVersion {
    /// Creates a positive version representable by `PostgreSQL` `BIGINT`.
    ///
    /// # Errors
    ///
    /// Rejects zero and values larger than `i64::MAX`.
    pub fn new(value: u64) -> Result<Self, TokenVersionError> {
        if value == 0 || value > i64::MAX as u64 {
            return Err(TokenVersionError);
        }
        Ok(Self(value))
    }

    /// Returns the positive version value.
    pub const fn value(self) -> u64 {
        self.0
    }
}

/// Validation failure for a provider-token compare-and-swap version.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
#[error("provider token version must be a positive PostgreSQL BIGINT")]
pub struct TokenVersionError;

/// Closed reason recorded when provider credentials are cryptographically erased.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderTokenRevocationReason {
    /// Explicit user or administrator revocation.
    Explicit,
    /// The upstream provider revoked authorization.
    ProviderAuthorizationRevoked,
    /// The provider definitively rejected refresh credentials.
    RefreshRejected,
    /// The owning Automata principal was disabled.
    PrincipalDisabled,
    /// The provider identity was unlinked from the principal.
    ProviderIdentityUnlinked,
}

impl ProviderTokenRevocationReason {
    /// Returns the stable, non-secret audit representation.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Explicit => "explicit",
            Self::ProviderAuthorizationRevoked => "provider_authorization_revoked",
            Self::RefreshRejected => "refresh_rejected",
            Self::PrincipalDisabled => "principal_disabled",
            Self::ProviderIdentityUnlinked => "provider_identity_unlinked",
        }
    }
}

/// One provider token set paired with its durable compare-and-swap version.
#[derive(Debug)]
pub struct VersionedProviderTokens {
    version: TokenVersion,
    tokens: ProviderTokenSet,
}

impl VersionedProviderTokens {
    /// Associates provider credentials with their durable version.
    pub const fn new(version: TokenVersion, tokens: ProviderTokenSet) -> Self {
        Self { version, tokens }
    }

    /// Returns the durable compare-and-swap version.
    pub const fn version(&self) -> TokenVersion {
        self.version
    }

    /// Borrows the redacted token set.
    pub const fn tokens(&self) -> &ProviderTokenSet {
        &self.tokens
    }

    /// Consumes the value into its version and credential set.
    pub fn into_parts(self) -> (TokenVersion, ProviderTokenSet) {
        (self.version, self.tokens)
    }
}

/// A provider-vault operation with sanitized storage outcomes.
pub type VaultFuture<'a, T> =
    Pin<Box<dyn Future<Output = Result<T, ProviderTokenVaultError>> + Send + 'a>>;

/// Custody boundary for provider credentials.
///
/// Implementations must encrypt token material with authenticated encryption before
/// persistence. Compare-and-swap replacement prevents concurrent refresh operations
/// from reviving a rotated refresh token.
pub trait ProviderTokenVault: fmt::Debug + Send + Sync {
    /// Loads current non-revoked credentials for an exact custody key.
    fn load<'a>(&'a self, key: &'a ProviderTokenKey) -> VaultFuture<'a, VersionedProviderTokens>;

    /// Inserts credentials only when the exact key has no durable value.
    fn insert_if_absent<'a>(
        &'a self,
        key: &'a ProviderTokenKey,
        tokens: ProviderTokenSet,
    ) -> VaultFuture<'a, TokenVersion>;

    /// Atomically rotates credentials only at the expected durable version.
    fn replace_if_version<'a>(
        &'a self,
        key: &'a ProviderTokenKey,
        expected: TokenVersion,
        replacement: ProviderTokenSet,
    ) -> VaultFuture<'a, TokenVersion>;

    /// Irreversibly revokes and cryptographically erases an exact credential set.
    fn revoke<'a>(
        &'a self,
        key: &'a ProviderTokenKey,
        reason: ProviderTokenRevocationReason,
    ) -> VaultFuture<'a, ()>;
}

/// Sanitized failures from encrypted provider-token custody.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum ProviderTokenVaultError {
    /// No credential set exists for the exact key.
    #[error("provider token was not found")]
    NotFound,
    #[error("provider token already exists")]
    /// An insert raced with an existing credential set.
    AlreadyExists,
    /// A rotation lost its compare-and-swap race.
    #[error("provider token was concurrently rotated")]
    VersionConflict,
    #[error("provider token is revoked")]
    /// The credential set was durably revoked.
    Revoked,
    /// The bounded vault request violates the custody contract.
    #[error("provider token request is invalid")]
    InvalidRequest,
    #[error("provider token vault is unavailable")]
    /// Encrypted credential storage is temporarily unavailable.
    Unavailable,
    /// Authenticated ciphertext or its bound context failed validation.
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

    /// Returns the stable domain-separation label.
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
    /// Binds a data-encryption key to one tenant and domain-separation purpose.
    pub const fn new(tenant_id: TenantId, purpose: KeyEncryptionPurpose) -> Self {
        Self { tenant_id, purpose }
    }

    /// Returns the tenant authenticated by key wrapping.
    pub const fn tenant_id(&self) -> &TenantId {
        &self.tenant_id
    }

    /// Returns the operation-specific domain-separation purpose.
    pub const fn purpose(&self) -> &KeyEncryptionPurpose {
        &self.purpose
    }

    /// Consumes the context into its authenticated components.
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

    /// Borrows the opaque wrapped-key ciphertext.
    pub fn ciphertext(&self) -> &[u8] {
        &self.0
    }

    /// Consumes the wrapper into its opaque ciphertext bytes.
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

/// A key-encryption operation whose failures never include key bytes.
pub type KeyEncryptionFuture<'a, T> =
    Pin<Box<dyn Future<Output = Result<T, KeyEncryptionError>> + Send + 'a>>;

/// Port implemented by a KMS, HSM, Vault transit engine, or equivalent KEK service.
/// Token-vault adapters use it to wrap data-encryption keys; this is not itself an
/// encryption implementation.
pub trait KeyEncryptionProvider: fmt::Debug + Send + Sync {
    /// Wraps a plaintext data-encryption key under authenticated context.
    fn wrap_data_key<'a>(
        &'a self,
        plaintext_key: &'a SecretBytes,
        context: &'a KeyEncryptionContext,
    ) -> KeyEncryptionFuture<'a, WrappedDataKey>;

    /// Unwraps a data-encryption key only under the identical context.
    fn unwrap_data_key<'a>(
        &'a self,
        wrapped_key: &'a WrappedDataKey,
        context: &'a KeyEncryptionContext,
    ) -> KeyEncryptionFuture<'a, SecretBytes>;
}

/// Sanitized failures from the key-encryption provider boundary.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum KeyEncryptionError {
    /// Wrapped-key ciphertext is empty, malformed, or unauthenticated.
    #[error("wrapped data key is invalid")]
    InvalidCiphertext,
    #[error("key-encryption provider rejected the authenticated context")]
    /// The ciphertext is not bound to the supplied tenant and purpose.
    ContextMismatch,
    /// The KMS, HSM, or equivalent provider is temporarily unavailable.
    #[error("key-encryption provider is unavailable")]
    Unavailable,
}

/// Validation failures for key-encryption domain separation.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum KeyEncryptionContextError {
    /// The purpose is empty, oversized, or outside the portable alphabet.
    #[error("key-encryption purpose is invalid")]
    InvalidPurpose,
}
