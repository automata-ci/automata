use std::{fmt, future::Future, pin::Pin};

use serde::{Deserialize, Serialize};
use subtle::ConstantTimeEq as _;
use thiserror::Error;
use url::Url;

use crate::{
    human::{ProviderId, TenantId},
    secret::{SecretBytes, SecretString},
    time::UnixTimestamp,
};

const MAX_BINDING_KEY_ID_LENGTH: usize = 128;
const MAX_LOGIN_TRANSACTION_LIFETIME_SECONDS: u64 = 3_600;
const MAX_RETURN_PATH_LENGTH: usize = 2_048;
const MAX_DEVICE_USER_CODE_LENGTH: usize = 64;
const MAX_VERIFICATION_URI_LENGTH: usize = 2_048;
const MIN_POLL_INTERVAL_MILLISECONDS: u64 = 1_000;
const MAX_POLL_INTERVAL_MILLISECONDS: u64 = 300_000;

/// Canonical, non-nil `PostgreSQL` UUID identity for one login transaction.
#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(try_from = "String", into = "String")]
pub struct LoginTransactionId(String);

impl LoginTransactionId {
    /// Creates a canonical, non-nil UUID transaction identifier.
    ///
    /// # Errors
    ///
    /// Rejects values that do not exactly match `PostgreSQL` UUID identity semantics.
    pub fn new(value: impl Into<String>) -> Result<Self, LoginTransactionValueError> {
        let value = value.into();
        let parsed =
            uuid::Uuid::parse_str(&value).map_err(|_| LoginTransactionValueError::InvalidId)?;
        if parsed.is_nil() || parsed.hyphenated().to_string() != value {
            return Err(LoginTransactionValueError::InvalidId);
        }
        Ok(Self(value))
    }

    #[must_use]
    /// Returns the canonical transaction UUID text.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for LoginTransactionId {
    type Error = LoginTransactionValueError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl From<LoginTransactionId> for String {
    fn from(value: LoginTransactionId) -> Self {
        value.0
    }
}

/// Why a provider login transaction exists.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case", tag = "purpose")]
pub enum LoginTransactionPurpose {
    /// Authenticate into one existing tenant.
    SignIn {
        /// Exact tenant to which the resulting session belongs.
        tenant_id: TenantId,
    },
    /// Authenticate the operator identity that completes first installation.
    InstallationSetup,
}

impl LoginTransactionPurpose {
    #[must_use]
    /// Returns the sign-in tenant, or `None` for installation setup.
    pub const fn tenant_id(&self) -> Option<&TenantId> {
        match self {
            Self::SignIn { tenant_id } => Some(tenant_id),
            Self::InstallationSetup => None,
        }
    }

    #[must_use]
    /// Returns the stable persistence representation of this purpose.
    pub const fn database_value(&self) -> &'static str {
        match self {
            Self::SignIn { .. } => "sign_in",
            Self::InstallationSetup => "installation_setup",
        }
    }
}

/// Browser authorization-code or CLI device login transaction.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LoginTransactionKind {
    /// Interactive browser authorization-code flow.
    Browser,
    /// CLI or installer device-authorization flow.
    Device,
}

impl LoginTransactionKind {
    #[must_use]
    /// Returns the stable persistence representation of this flow kind.
    pub const fn database_value(self) -> &'static str {
        match self {
            Self::Browser => "browser",
            Self::Device => "device",
        }
    }
}

/// Identifier for the keyed digest secret used for a pre-authentication proof.
#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(try_from = "String", into = "String")]
pub struct LoginBindingDigestKeyId(String);

impl LoginBindingDigestKeyId {
    /// Creates a bounded portable key identifier.
    ///
    /// # Errors
    ///
    /// Rejects empty, oversized, or non-portable identifiers.
    pub fn new(value: impl Into<String>) -> Result<Self, LoginTransactionValueError> {
        let value = value.into();
        if value.is_empty()
            || value.len() > MAX_BINDING_KEY_ID_LENGTH
            || !value.bytes().all(|character| {
                character.is_ascii_alphanumeric() || matches!(character, b'-' | b'_' | b':' | b'.')
            })
        {
            return Err(LoginTransactionValueError::InvalidBindingKeyId);
        }
        Ok(Self(value))
    }

    #[must_use]
    /// Returns the stable keyed-digest key identifier.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for LoginBindingDigestKeyId {
    type Error = LoginTransactionValueError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl From<LoginBindingDigestKeyId> for String {
    fn from(value: LoginBindingDigestKeyId) -> Self {
        value.0
    }
}

/// Fixed-size keyed digest. Raw browser state/cookies and CLI poll proofs never
/// cross the repository port.
#[derive(Clone, Serialize)]
#[serde(transparent)]
pub struct LoginBindingDigest([u8; 32]);

impl LoginBindingDigest {
    #[must_use]
    /// Wraps a fixed-size keyed digest of a raw login proof.
    pub const fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    #[must_use]
    /// Borrows the digest without exposing the raw proof.
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Debug for LoginBindingDigest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("LoginBindingDigest([REDACTED])")
    }
}

impl PartialEq for LoginBindingDigest {
    fn eq(&self, other: &Self) -> bool {
        bool::from(self.0.ct_eq(&other.0))
    }
}

impl Eq for LoginBindingDigest {}

impl<'de> Deserialize<'de> for LoginBindingDigest {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        <[u8; 32]>::deserialize(deserializer).map(Self)
    }
}

/// Key identity and constant-time digest for one pre-authentication proof.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LoginTransactionBinding {
    key_id: LoginBindingDigestKeyId,
    digest: LoginBindingDigest,
}

impl LoginTransactionBinding {
    #[must_use]
    /// Creates a proof binding from its digest-key identity and digest.
    pub const fn new(key_id: LoginBindingDigestKeyId, digest: LoginBindingDigest) -> Self {
        Self { key_id, digest }
    }

    #[must_use]
    /// Returns the key identity needed to verify this proof.
    pub const fn key_id(&self) -> &LoginBindingDigestKeyId {
        &self.key_id
    }

    #[must_use]
    /// Returns the constant-time comparable proof digest.
    pub const fn digest(&self) -> &LoginBindingDigest {
        &self.digest
    }
}

/// Validated local return path; absolute/external redirects are impossible.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(try_from = "String", into = "String")]
pub struct LoginReturnPath(String);

impl LoginReturnPath {
    /// Creates a bounded server-local redirect path.
    ///
    /// # Errors
    ///
    /// Rejects empty, external, oversized, or control-bearing paths.
    pub fn new(value: impl Into<String>) -> Result<Self, LoginTransactionValueError> {
        let value = value.into();
        if value.is_empty()
            || value.len() > MAX_RETURN_PATH_LENGTH
            || !value.starts_with('/')
            || value.starts_with("//")
            || value.chars().any(char::is_control)
        {
            return Err(LoginTransactionValueError::InvalidReturnPath);
        }
        Ok(Self(value))
    }

    #[must_use]
    /// Returns the validated server-local path.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for LoginReturnPath {
    type Error = LoginTransactionValueError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl From<LoginReturnPath> for String {
    fn from(value: LoginReturnPath) -> Self {
        value.0
    }
}

/// Provider-specific state under repository encryption custody.
///
/// This type intentionally implements neither `Serialize` nor `Clone`.
pub struct LoginTransactionState(SecretBytes);

impl LoginTransactionState {
    #[must_use]
    /// Wraps provider-specific state for encrypted repository custody.
    pub const fn new(state: SecretBytes) -> Self {
        Self(state)
    }

    #[must_use]
    /// Exposes plaintext state only at the provider protocol boundary.
    pub fn expose_secret(&self) -> &[u8] {
        self.0.expose_secret()
    }

    /// Consumes the wrapper into redacted, zeroizing secret bytes.
    pub fn into_secret(self) -> SecretBytes {
        self.0
    }
}

impl fmt::Debug for LoginTransactionState {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("LoginTransactionState([REDACTED])")
    }
}

/// Flow-specific durable metadata. Browser logins require two independent
/// proofs: provider OAuth state and a browser-client binding. Device logins use
/// a distinct poll proof.
pub enum LoginTransactionFlow {
    /// Browser flow protected by independent provider-state and client proofs.
    Browser {
        /// Keyed digest of the provider OAuth state.
        state: LoginTransactionBinding,
        /// Independent keyed digest bound to the initiating browser.
        client_binding: LoginTransactionBinding,
    },
    /// Device flow protected by a dedicated polling credential.
    Device {
        /// Keyed digest of the raw device-poll credential.
        poll_proof: LoginTransactionBinding,
        /// Provider-issued display code, retained as redacted secret material.
        user_code: SecretString,
        /// Bounded HTTPS provider verification URI.
        verification_uri: String,
        /// Current provider-directed minimum poll interval.
        poll_interval_milliseconds: u64,
        /// Earliest timestamp at which the next poll is allowed.
        next_poll_at: UnixTimestamp,
    },
}

impl LoginTransactionFlow {
    /// Creates a browser flow with independent OAuth-state and client proofs.
    ///
    /// # Errors
    ///
    /// Rejects identical state and client-binding proof material.
    pub fn browser(
        state: LoginTransactionBinding,
        client_binding: LoginTransactionBinding,
    ) -> Result<Self, LoginTransactionValueError> {
        if state == client_binding {
            return Err(LoginTransactionValueError::BrowserProofsNotIndependent);
        }
        Ok(Self::Browser {
            state,
            client_binding,
        })
    }

    /// Creates validated device-flow display and polling metadata.
    ///
    /// # Errors
    ///
    /// Rejects invalid codes, verification URIs, or poll intervals.
    pub fn device(
        poll_proof: LoginTransactionBinding,
        user_code: SecretString,
        verification_uri: impl Into<String>,
        poll_interval_milliseconds: u64,
        next_poll_at: UnixTimestamp,
    ) -> Result<Self, LoginTransactionValueError> {
        let verification_uri = verification_uri.into();
        if user_code.expose_secret().len() > MAX_DEVICE_USER_CODE_LENGTH
            || user_code.expose_secret().chars().any(char::is_whitespace)
        {
            return Err(LoginTransactionValueError::InvalidDeviceUserCode);
        }
        if verification_uri.len() > MAX_VERIFICATION_URI_LENGTH
            || !valid_verification_uri(&verification_uri)
        {
            return Err(LoginTransactionValueError::InvalidVerificationUri);
        }
        if !(MIN_POLL_INTERVAL_MILLISECONDS..=MAX_POLL_INTERVAL_MILLISECONDS)
            .contains(&poll_interval_milliseconds)
        {
            return Err(LoginTransactionValueError::InvalidPollInterval);
        }
        Ok(Self::Device {
            poll_proof,
            user_code,
            verification_uri,
            poll_interval_milliseconds,
            next_poll_at,
        })
    }

    #[must_use]
    /// Returns whether this is a browser or device transaction.
    pub const fn kind(&self) -> LoginTransactionKind {
        match self {
            Self::Browser { .. } => LoginTransactionKind::Browser,
            Self::Device { .. } => LoginTransactionKind::Device,
        }
    }

    #[must_use]
    /// Returns the two independent browser proofs when browser-based.
    pub const fn browser_proofs(
        &self,
    ) -> Option<(&LoginTransactionBinding, &LoginTransactionBinding)> {
        match self {
            Self::Browser {
                state,
                client_binding,
            } => Some((state, client_binding)),
            Self::Device { .. } => None,
        }
    }

    #[must_use]
    /// Returns redacted device display and polling metadata when device-based.
    pub fn device_parts(
        &self,
    ) -> Option<(
        &LoginTransactionBinding,
        &SecretString,
        &str,
        u64,
        UnixTimestamp,
    )> {
        match self {
            Self::Browser { .. } => None,
            Self::Device {
                poll_proof,
                user_code,
                verification_uri,
                poll_interval_milliseconds,
                next_poll_at,
            } => Some((
                poll_proof,
                user_code,
                verification_uri,
                *poll_interval_milliseconds,
                *next_poll_at,
            )),
        }
    }
}

fn valid_verification_uri(value: &str) -> bool {
    if value.contains('\\') || value.chars().any(char::is_control) {
        return false;
    }
    let Ok(uri) = Url::parse(value) else {
        return false;
    };
    uri.scheme() == "https"
        && uri.host_str().is_some()
        && uri.username().is_empty()
        && uri.password().is_none()
        && uri.fragment().is_none()
}

impl fmt::Debug for LoginTransactionFlow {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Browser {
                state,
                client_binding,
            } => formatter
                .debug_struct("Browser")
                .field("state", state)
                .field("client_binding", client_binding)
                .finish(),
            Self::Device {
                poll_proof,
                verification_uri,
                poll_interval_milliseconds,
                next_poll_at,
                ..
            } => formatter
                .debug_struct("Device")
                .field("poll_proof", poll_proof)
                .field("user_code", &"[REDACTED]")
                .field("verification_uri", verification_uri)
                .field("poll_interval_milliseconds", poll_interval_milliseconds)
                .field("next_poll_at", next_poll_at)
                .finish(),
        }
    }
}

/// Provider-neutral durable login transaction with encrypted-at-rest state.
pub struct LoginTransaction {
    id: LoginTransactionId,
    purpose: LoginTransactionPurpose,
    provider_id: ProviderId,
    flow: LoginTransactionFlow,
    return_path: Option<LoginReturnPath>,
    state: LoginTransactionState,
    created_at: UnixTimestamp,
    expires_at: UnixTimestamp,
}

impl LoginTransaction {
    /// Creates a bounded, provider-neutral login transaction.
    ///
    /// # Errors
    ///
    /// Rejects invalid lifetimes or device poll times outside the lifetime.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        id: LoginTransactionId,
        purpose: LoginTransactionPurpose,
        provider_id: ProviderId,
        flow: LoginTransactionFlow,
        return_path: Option<LoginReturnPath>,
        state: LoginTransactionState,
        created_at: UnixTimestamp,
        expires_at: UnixTimestamp,
    ) -> Result<Self, LoginTransactionValueError> {
        let lifetime = expires_at
            .as_seconds()
            .checked_sub(created_at.as_seconds())
            .ok_or(LoginTransactionValueError::InvalidLifetime)?;
        if lifetime == 0 || lifetime > MAX_LOGIN_TRANSACTION_LIFETIME_SECONDS {
            return Err(LoginTransactionValueError::InvalidLifetime);
        }
        if flow
            .device_parts()
            .is_some_and(|(_, _, _, _, next_poll_at)| {
                next_poll_at <= created_at || next_poll_at >= expires_at
            })
        {
            return Err(LoginTransactionValueError::InvalidNextPollAt);
        }
        Ok(Self {
            id,
            purpose,
            provider_id,
            flow,
            return_path,
            state,
            created_at,
            expires_at,
        })
    }

    #[must_use]
    /// Returns the canonical durable transaction identity.
    pub const fn id(&self) -> &LoginTransactionId {
        &self.id
    }

    #[must_use]
    /// Returns whether the transaction is tenant sign-in or installation setup.
    pub const fn purpose(&self) -> &LoginTransactionPurpose {
        &self.purpose
    }

    #[must_use]
    /// Returns the target tenant for normal sign-in.
    pub const fn tenant_id(&self) -> Option<&TenantId> {
        self.purpose.tenant_id()
    }

    #[must_use]
    /// Returns the only authentication provider allowed to consume the transaction.
    pub const fn provider_id(&self) -> &ProviderId {
        &self.provider_id
    }

    #[must_use]
    /// Returns whether this is a browser or device flow.
    pub const fn kind(&self) -> LoginTransactionKind {
        self.flow.kind()
    }

    #[must_use]
    /// Returns flow-specific keyed proofs and bounded public metadata.
    pub const fn flow(&self) -> &LoginTransactionFlow {
        &self.flow
    }

    #[must_use]
    /// Returns the validated local browser return path, when present.
    pub const fn return_path(&self) -> Option<&LoginReturnPath> {
        self.return_path.as_ref()
    }

    #[must_use]
    /// Borrows encrypted-custody provider state without exposing it.
    pub const fn state(&self) -> &LoginTransactionState {
        &self.state
    }

    #[must_use]
    /// Returns the immutable transaction creation time.
    pub const fn created_at(&self) -> UnixTimestamp {
        self.created_at
    }

    #[must_use]
    /// Returns the immutable transaction deadline.
    pub const fn expires_at(&self) -> UnixTimestamp {
        self.expires_at
    }

    #[allow(clippy::type_complexity)]
    /// Consumes the transaction into identity, flow, custody, and lifecycle parts.
    pub fn into_parts(
        self,
    ) -> (
        LoginTransactionId,
        LoginTransactionPurpose,
        ProviderId,
        LoginTransactionFlow,
        Option<LoginReturnPath>,
        LoginTransactionState,
        UnixTimestamp,
        UnixTimestamp,
    ) {
        (
            self.id,
            self.purpose,
            self.provider_id,
            self.flow,
            self.return_path,
            self.state,
            self.created_at,
            self.expires_at,
        )
    }
}

impl fmt::Debug for LoginTransaction {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LoginTransaction")
            .field("id", &self.id)
            .field("purpose", &self.purpose)
            .field("provider_id", &self.provider_id)
            .field("flow", &self.flow)
            .field("return_path", &self.return_path)
            .field("state", &"[REDACTED]")
            .field("created_at", &self.created_at)
            .field("expires_at", &self.expires_at)
            .finish()
    }
}

/// Raw-proof-free evidence presented to load or consume a login transaction.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum LoginTransactionProof {
    /// Two independent keyed browser proof digests.
    Browser {
        /// Digest of the provider OAuth state.
        state: LoginTransactionBinding,
        /// Digest bound independently to the initiating browser.
        client_binding: LoginTransactionBinding,
    },
    /// Keyed proof digest dedicated to device polling.
    Device {
        /// Digest of the raw device-poll credential.
        poll_proof: LoginTransactionBinding,
    },
}

impl LoginTransactionProof {
    #[must_use]
    /// Returns the flow kind proved by this evidence.
    pub const fn kind(&self) -> LoginTransactionKind {
        match self {
            Self::Browser { .. } => LoginTransactionKind::Browser,
            Self::Device { .. } => LoginTransactionKind::Device,
        }
    }

    #[must_use]
    /// Returns both independent browser proofs when browser-based.
    pub const fn browser_proofs(
        &self,
    ) -> Option<(&LoginTransactionBinding, &LoginTransactionBinding)> {
        match self {
            Self::Browser {
                state,
                client_binding,
            } => Some((state, client_binding)),
            Self::Device { .. } => None,
        }
    }
}

/// Exact non-secret identity, purpose, provider, and proof tuple for lookup.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LoginTransactionAccess {
    id: LoginTransactionId,
    purpose: LoginTransactionPurpose,
    provider_id: ProviderId,
    proof: LoginTransactionProof,
}

impl LoginTransactionAccess {
    /// Creates exact browser lookup evidence with two independent proofs.
    ///
    /// # Errors
    ///
    /// Rejects identical state and client-binding proof material.
    pub fn browser(
        id: LoginTransactionId,
        purpose: LoginTransactionPurpose,
        provider_id: ProviderId,
        state: LoginTransactionBinding,
        client_binding: LoginTransactionBinding,
    ) -> Result<Self, LoginTransactionValueError> {
        if state == client_binding {
            return Err(LoginTransactionValueError::BrowserProofsNotIndependent);
        }
        Ok(Self {
            id,
            purpose,
            provider_id,
            proof: LoginTransactionProof::Browser {
                state,
                client_binding,
            },
        })
    }

    #[must_use]
    /// Creates exact device-flow lookup evidence.
    pub const fn device(
        id: LoginTransactionId,
        purpose: LoginTransactionPurpose,
        provider_id: ProviderId,
        poll_proof: LoginTransactionBinding,
    ) -> Self {
        Self {
            id,
            purpose,
            provider_id,
            proof: LoginTransactionProof::Device { poll_proof },
        }
    }

    #[must_use]
    /// Returns the canonical transaction identity.
    pub const fn id(&self) -> &LoginTransactionId {
        &self.id
    }

    #[must_use]
    /// Returns the transaction purpose that is part of exact lookup authority.
    pub const fn purpose(&self) -> &LoginTransactionPurpose {
        &self.purpose
    }

    #[must_use]
    /// Returns the target tenant for normal sign-in.
    pub const fn tenant_id(&self) -> Option<&TenantId> {
        self.purpose.tenant_id()
    }

    #[must_use]
    /// Returns the exact provider included in lookup authority.
    pub const fn provider_id(&self) -> &ProviderId {
        &self.provider_id
    }

    #[must_use]
    /// Returns the proved browser or device flow kind.
    pub const fn kind(&self) -> LoginTransactionKind {
        self.proof.kind()
    }

    #[must_use]
    /// Returns the raw-proof-free keyed evidence.
    pub const fn proof(&self) -> &LoginTransactionProof {
        &self.proof
    }
}

/// Positive compare-and-swap version for a durable login transaction.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(into = "u64")]
pub struct LoginTransactionVersion(u64);

impl LoginTransactionVersion {
    /// Creates a positive version representable by a signed database integer.
    ///
    /// # Errors
    ///
    /// Rejects zero or values larger than `i64::MAX`.
    pub fn new(value: u64) -> Result<Self, LoginTransactionValueError> {
        if value == 0 || value > i64::MAX as u64 {
            return Err(LoginTransactionValueError::InvalidVersion);
        }
        Ok(Self(value))
    }

    #[must_use]
    /// Returns the positive durable version.
    pub const fn value(self) -> u64 {
        self.0
    }
}

impl TryFrom<u64> for LoginTransactionVersion {
    type Error = LoginTransactionValueError;
    fn try_from(value: u64) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl From<LoginTransactionVersion> for u64 {
    fn from(value: LoginTransactionVersion) -> Self {
        value.value()
    }
}

impl<'de> Deserialize<'de> for LoginTransactionVersion {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        u64::deserialize(deserializer)
            .and_then(|value| Self::new(value).map_err(serde::de::Error::custom))
    }
}

/// One login transaction paired with its durable compare-and-swap version.
#[derive(Debug)]
pub struct VersionedLoginTransaction {
    version: LoginTransactionVersion,
    transaction: LoginTransaction,
}

impl VersionedLoginTransaction {
    #[must_use]
    /// Associates a transaction with its current durable version.
    pub const fn new(version: LoginTransactionVersion, transaction: LoginTransaction) -> Self {
        Self {
            version,
            transaction,
        }
    }

    #[must_use]
    /// Returns the current durable version.
    pub const fn version(&self) -> LoginTransactionVersion {
        self.version
    }

    #[must_use]
    /// Borrows the encrypted-custody transaction.
    pub const fn transaction(&self) -> &LoginTransaction {
        &self.transaction
    }

    /// Consumes the value into its version and transaction.
    pub fn into_parts(self) -> (LoginTransactionVersion, LoginTransaction) {
        (self.version, self.transaction)
    }
}

/// Revision-guarded replacement of encrypted provider state and device timing.
#[derive(Debug)]
pub struct ReplaceLoginTransactionState {
    access: LoginTransactionAccess,
    expected_version: LoginTransactionVersion,
    replacement: LoginTransactionState,
    next_device_poll_at: Option<UnixTimestamp>,
    device_poll_interval_milliseconds: Option<u64>,
}

impl ReplaceLoginTransactionState {
    #[must_use]
    /// Creates a compare-and-swap replacement for one exact transaction.
    pub const fn new(
        access: LoginTransactionAccess,
        expected_version: LoginTransactionVersion,
        replacement: LoginTransactionState,
    ) -> Self {
        Self {
            access,
            expected_version,
            replacement,
            next_device_poll_at: None,
            device_poll_interval_milliseconds: None,
        }
    }

    #[must_use]
    /// Includes the next allowed device poll time in the same state replacement.
    pub const fn next_device_poll_at(mut self, next_poll_at: UnixTimestamp) -> Self {
        self.next_device_poll_at = Some(next_poll_at);
        self
    }

    /// Includes the exact current device polling interval in the same state CAS.
    ///
    /// Repository implementations reject this field for browser transactions and
    /// reject values outside the current device-flow bounds.
    #[must_use]
    pub const fn device_poll_interval_milliseconds(
        mut self,
        poll_interval_milliseconds: u64,
    ) -> Self {
        self.device_poll_interval_milliseconds = Some(poll_interval_milliseconds);
        self
    }

    #[must_use]
    /// Returns exact identity, purpose, provider, and proof lookup authority.
    pub const fn access(&self) -> &LoginTransactionAccess {
        &self.access
    }

    #[must_use]
    /// Returns the durable version required by the replacement.
    pub const fn expected_version(&self) -> LoginTransactionVersion {
        self.expected_version
    }

    #[must_use]
    /// Borrows the replacement provider state without exposing plaintext.
    pub const fn replacement(&self) -> &LoginTransactionState {
        &self.replacement
    }

    #[must_use]
    /// Returns the replacement next-poll timestamp, when supplied.
    pub const fn next_poll_at(&self) -> Option<UnixTimestamp> {
        self.next_device_poll_at
    }

    #[must_use]
    /// Returns the replacement provider poll interval, when supplied.
    pub const fn poll_interval_milliseconds(&self) -> Option<u64> {
        self.device_poll_interval_milliseconds
    }

    /// Validates flow-specific replacement fields that do not depend on repository
    /// time or the persisted transaction lifetime.
    ///
    /// # Errors
    ///
    /// Rejects device polling metadata on browser transactions and polling
    /// intervals outside the same bounds as [`LoginTransactionFlow::device`].
    pub fn validate(&self) -> Result<(), LoginTransactionValueError> {
        if self.access.kind() == LoginTransactionKind::Browser
            && (self.next_device_poll_at.is_some()
                || self.device_poll_interval_milliseconds.is_some())
        {
            return Err(LoginTransactionValueError::UnexpectedDevicePollMetadata);
        }
        if self
            .device_poll_interval_milliseconds
            .is_some_and(|interval| {
                !(MIN_POLL_INTERVAL_MILLISECONDS..=MAX_POLL_INTERVAL_MILLISECONDS)
                    .contains(&interval)
            })
        {
            return Err(LoginTransactionValueError::InvalidPollInterval);
        }
        Ok(())
    }

    #[allow(clippy::type_complexity)]
    /// Consumes the request into exact access, version, state, and device timing.
    pub fn into_parts(
        self,
    ) -> (
        LoginTransactionAccess,
        LoginTransactionVersion,
        LoginTransactionState,
        Option<UnixTimestamp>,
        Option<u64>,
    ) {
        (
            self.access,
            self.expected_version,
            self.replacement,
            self.next_device_poll_at,
            self.device_poll_interval_milliseconds,
        )
    }
}

/// Single-use request to consume an exact login transaction.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConsumeLoginTransaction {
    access: LoginTransactionAccess,
    expected_version: Option<LoginTransactionVersion>,
    now: UnixTimestamp,
}

impl ConsumeLoginTransaction {
    #[must_use]
    /// Creates a consume request using exact proof and current time.
    pub const fn new(access: LoginTransactionAccess, now: UnixTimestamp) -> Self {
        Self {
            access,
            expected_version: None,
            now,
        }
    }

    #[must_use]
    /// Requires one exact durable transaction version.
    pub const fn if_version(mut self, expected_version: LoginTransactionVersion) -> Self {
        self.expected_version = Some(expected_version);
        self
    }

    #[must_use]
    /// Returns exact identity, purpose, provider, and proof lookup authority.
    pub const fn access(&self) -> &LoginTransactionAccess {
        &self.access
    }

    #[must_use]
    /// Returns the optional compare-and-swap version requirement.
    pub const fn expected_version(&self) -> Option<LoginTransactionVersion> {
        self.expected_version
    }

    #[must_use]
    /// Returns the timestamp used to reject expired transactions.
    pub const fn now(&self) -> UnixTimestamp {
        self.now
    }
}

/// Closed result of creating a login transaction.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CreateLoginTransactionOutcome {
    /// The new transaction committed at the returned initial version.
    Created(LoginTransactionVersion),
    /// The requested transaction identity already exists.
    AlreadyExists,
}

/// Non-enumerating result of loading a login transaction with exact proofs.
#[derive(Debug)]
pub enum LoadLoginTransactionOutcome {
    /// The active transaction and current durable version.
    Active(Box<VersionedLoginTransaction>),
    /// Identity, purpose, provider, proof, or row did not match.
    NotFound,
    /// The exact transaction passed its immutable deadline.
    Expired,
    /// The exact transaction was already irreversibly consumed.
    Consumed,
}

/// Closed result of revision-guarded encrypted-state replacement.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReplaceLoginTransactionOutcome {
    /// State committed at the returned incremented version.
    Replaced(LoginTransactionVersion),
    /// Identity, purpose, provider, proof, or row did not match.
    NotFound,
    /// The exact transaction passed its immutable deadline.
    Expired,
    /// The exact transaction was already irreversibly consumed.
    Consumed,
    /// The durable state changed from the expected version.
    VersionConflict,
}

/// Closed result of consuming a single-use login transaction.
#[derive(Debug)]
pub enum ConsumeLoginTransactionOutcome {
    /// The transaction was tombstoned and its encrypted state returned once.
    Consumed(Box<LoginTransaction>),
    /// Identity, purpose, provider, proof, or row did not match.
    NotFound,
    /// The exact transaction passed its immutable deadline.
    Expired,
    /// The exact transaction was already irreversibly consumed.
    AlreadyConsumed,
    /// The durable state changed from the optional expected version.
    VersionConflict,
}

/// A login-transaction repository operation with sanitized outcomes.
pub type LoginTransactionRepositoryFuture<'a, T> =
    Pin<Box<dyn Future<Output = Result<T, LoginTransactionRepositoryError>> + Send + 'a>>;

/// Durable, encrypted, single-use human-login transaction boundary.
///
/// Any identity, purpose, provider, or proof mismatch must produce `NotFound`.
pub trait LoginTransactionRepository: fmt::Debug + Send + Sync {
    /// Persists encrypted provider state for a new bounded transaction.
    fn create(
        &self,
        transaction: LoginTransaction,
    ) -> LoginTransactionRepositoryFuture<'_, CreateLoginTransactionOutcome>;

    /// Loads one active transaction only when every exact proof dimension matches.
    fn load<'a>(
        &'a self,
        access: &'a LoginTransactionAccess,
        now: UnixTimestamp,
    ) -> LoginTransactionRepositoryFuture<'a, LoadLoginTransactionOutcome>;

    /// Atomically replaces encrypted state and optional device polling metadata.
    fn replace_state(
        &self,
        request: ReplaceLoginTransactionState,
        now: UnixTimestamp,
    ) -> LoginTransactionRepositoryFuture<'_, ReplaceLoginTransactionOutcome>;

    /// Irreversibly consumes one exact transaction at most once.
    fn consume(
        &self,
        request: ConsumeLoginTransaction,
    ) -> LoginTransactionRepositoryFuture<'_, ConsumeLoginTransactionOutcome>;
}

/// Validation failures for login identities, proofs, flow metadata, and lifecycle.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum LoginTransactionValueError {
    /// Transaction identity was nil, malformed, or noncanonical.
    #[error("login transaction ID must be a canonical non-nil UUID")]
    InvalidId,
    #[error("login binding digest key ID is invalid")]
    /// A proof-digest key identifier was empty, oversized, or non-portable.
    InvalidBindingKeyId,
    /// Provider state and browser-client proofs used identical keyed material.
    #[error("browser state and client-binding proofs must be independent")]
    BrowserProofsNotIndependent,
    #[error("login return path is invalid")]
    /// A return path was external, empty, oversized, or control-bearing.
    InvalidReturnPath,
    /// A provider device user code was oversized or whitespace-bearing.
    #[error("device user code is invalid")]
    InvalidDeviceUserCode,
    #[error("device verification URI must be a bounded HTTPS URI")]
    /// The device verification URI was not bounded HTTPS metadata.
    InvalidVerificationUri,
    /// The provider polling interval was outside the public bounds.
    #[error("device poll interval is outside the supported range")]
    InvalidPollInterval,
    #[error("device polling metadata is invalid for a browser transaction")]
    /// Device-only poll metadata was attached to a browser transaction.
    UnexpectedDevicePollMetadata,
    /// The next poll timestamp was outside the transaction lifetime.
    #[error("next device poll time is outside the transaction lifetime")]
    InvalidNextPollAt,
    #[error("login transaction lifetime must be between 1 and 3600 seconds")]
    /// The transaction lifetime was empty, expired, or above one hour.
    InvalidLifetime,
    /// The compare-and-swap version was zero or outside signed storage range.
    #[error("login transaction version must be a positive signed 64-bit value")]
    InvalidVersion,
}

/// Sanitized failures at the encrypted login-transaction repository boundary.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum LoginTransactionRepositoryError {
    /// Durable login storage is temporarily unavailable.
    #[error("login transaction storage is unavailable")]
    Unavailable,
    #[error("login transaction ciphertext failed authentication")]
    /// Authenticated encrypted provider state failed validation.
    IntegrityFailure,
    /// Durable transaction identity, flow, or lifecycle data is inconsistent.
    #[error("durable login transaction data violates an invariant")]
    CorruptData,
    #[error("login transaction request violates a persistence invariant")]
    /// The bounded request violates the persistence contract.
    InvalidRequest,
}
