//! Replica-safe orchestration for operational GitHub browser and device sign-in.
//!
//! This module deliberately stops at typed HTTP adapter seams. Provider tokens,
//! OAuth state, client bindings, poll proofs, and Automata session credentials
//! remain linearly owned secret values and are never serializable.

use std::{collections::BTreeMap, fmt, sync::Arc, time::Duration};

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use ring::hmac;
use thiserror::Error;
use url::Url;
use zeroize::Zeroizing;

use crate::{
    human::{
        AuthenticatedHuman, AuthenticationProvider, AuthenticationProviderError,
        ProviderCredential, ProviderId, ProviderIdentityAssertion, TenantId,
    },
    login::{
        ConsumeLoginTransaction, ConsumeLoginTransactionOutcome, CreateLoginTransactionOutcome,
        LoadLoginTransactionOutcome, LoginBindingDigest, LoginBindingDigestKeyId, LoginReturnPath,
        LoginTransaction, LoginTransactionAccess, LoginTransactionBinding, LoginTransactionFlow,
        LoginTransactionId, LoginTransactionPurpose, LoginTransactionRepository,
        LoginTransactionRepositoryError, LoginTransactionVersion, ReplaceLoginTransactionOutcome,
        ReplaceLoginTransactionState,
    },
    secret::{SecretBytes, SecretString, SecureRandom},
    session::{DurableSession, SessionKind},
    session_credential::{
        SessionCredential, SessionCredentialService, SessionCredentialServiceError,
    },
    sign_in::{
        FinalizeSignIn, FinalizeSignInOutcome, HumanSignInFinalizer, SignInFinalizerError,
        SignInValueError,
    },
    time::{Clock, UnixTimestamp},
    vault::{ProviderTokenSet, ProviderTokenSetError},
};

use super::{
    DeviceAuthorization, DevicePollOutcome, GithubAppProtocol, GithubCurrentUserRequest,
    GithubDeviceTransactionMetadata, GithubEndpoint, GithubEndpointError, GithubFlowError,
    GithubMembershipObservation, GithubMembershipSnapshotId, GithubTransactionStateCodec,
    GithubTransactionStateError, GithubWebCallback,
};

/// Exact HMAC key size for login proofs.
pub const GITHUB_LOGIN_PROOF_KEY_BYTES: usize = 32;
/// Maximum active plus verify-only login-proof keys.
pub const MAX_GITHUB_LOGIN_PROOF_KEYS: usize = 32;
/// Fixed retry budget for transaction or session-digest collisions.
pub const MAX_GITHUB_LOGIN_COLLISION_ATTEMPTS: usize = 8;
/// Lifetime of a freshly fetched GitHub numeric membership observation.
pub const GITHUB_MEMBERSHIP_OBSERVATION_TTL_SECONDS: u64 = 900;

const GENERATED_PROOF_BYTES: usize = 32;
const GENERATED_PROOF_LENGTH: usize = 43;
const PROOF_SEPARATOR: char = '~';
const BROWSER_PROOF_VERSION: &str = "bw1";
const DEVICE_PROOF_VERSION: &str = "dp1";
const MAX_PROOF_KEY_ID_LENGTH: usize = 128;
const MAX_PROOF_CREDENTIAL_LENGTH: usize =
    3 + 3 + MAX_PROOF_KEY_ID_LENGTH + 36 + GENERATED_PROOF_LENGTH;
const OAUTH_STATE_HMAC_DOMAIN: &[u8] = b"automata-ci/github-login/oauth-state/v1\0";
const BROWSER_BINDING_HMAC_DOMAIN: &[u8] = b"automata-ci/github-login/browser-binding/v1\0";
const DEVICE_POLL_HMAC_DOMAIN: &[u8] = b"automata-ci/github-login/device-poll/v1\0";

/// Consumed configuration for one login-proof HMAC key.
pub struct GithubLoginProofKey {
    id: LoginBindingDigestKeyId,
    material: SecretBytes,
}

impl GithubLoginProofKey {
    /// Creates one exact 256-bit proof key with a cookie-safe public ID.
    ///
    /// # Errors
    ///
    /// Rejects unsafe key IDs or material that is not exactly 32 bytes.
    pub fn new(
        id: LoginBindingDigestKeyId,
        material: SecretBytes,
    ) -> Result<Self, GithubLoginProofKeyringError> {
        if !valid_proof_key_id(id.as_str()) {
            return Err(GithubLoginProofKeyringError::InvalidKeyId);
        }
        if material.expose_secret().len() != GITHUB_LOGIN_PROOF_KEY_BYTES {
            return Err(GithubLoginProofKeyringError::InvalidKeyLength);
        }
        Ok(Self { id, material })
    }

    /// Returns the public key-version ID.
    #[must_use]
    pub const fn id(&self) -> &LoginBindingDigestKeyId {
        &self.id
    }

    fn into_parts(self) -> (LoginBindingDigestKeyId, SecretBytes) {
        (self.id, self.material)
    }
}

impl fmt::Debug for GithubLoginProofKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GithubLoginProofKey")
            .field("id", &self.id)
            .field("material", &"[REDACTED]")
            .finish()
    }
}

struct StoredProofKey(Zeroizing<[u8; GITHUB_LOGIN_PROOF_KEY_BYTES]>);

impl StoredProofKey {
    fn consume(material: SecretBytes) -> Self {
        let mut bytes = Zeroizing::new([0_u8; GITHUB_LOGIN_PROOF_KEY_BYTES]);
        bytes.copy_from_slice(material.expose_secret());
        drop(material);
        Self(bytes)
    }

    fn as_bytes(&self) -> &[u8] {
        self.0.as_ref()
    }
}

/// Rotation-aware login-proof keyring with one issuing key and verify-only keys.
pub struct GithubLoginProofKeyring {
    active_id: LoginBindingDigestKeyId,
    keys: BTreeMap<LoginBindingDigestKeyId, StoredProofKey>,
}

impl GithubLoginProofKeyring {
    /// Builds a bounded keyring.
    ///
    /// # Errors
    ///
    /// Rejects duplicate IDs or more than 32 total configured keys.
    pub fn new(
        active: GithubLoginProofKey,
        verify_only: Vec<GithubLoginProofKey>,
    ) -> Result<Self, GithubLoginProofKeyringError> {
        if verify_only.len() >= MAX_GITHUB_LOGIN_PROOF_KEYS {
            return Err(GithubLoginProofKeyringError::TooManyKeys);
        }
        let active_id = active.id().clone();
        let mut keys = BTreeMap::new();
        for configured in std::iter::once(active).chain(verify_only) {
            let (id, material) = configured.into_parts();
            if keys.insert(id, StoredProofKey::consume(material)).is_some() {
                return Err(GithubLoginProofKeyringError::DuplicateKeyId);
            }
        }
        Ok(Self { active_id, keys })
    }

    /// Returns the key version used for new proofs.
    #[must_use]
    pub const fn active_key_id(&self) -> &LoginBindingDigestKeyId {
        &self.active_id
    }

    fn active_key(&self) -> Result<&StoredProofKey, GithubLoginError> {
        self.keys
            .get(&self.active_id)
            .ok_or(GithubLoginError::IntegrityFailure)
    }

    fn verifying_key(
        &self,
        id: &LoginBindingDigestKeyId,
    ) -> Result<&StoredProofKey, GithubLoginError> {
        self.keys.get(id).ok_or(GithubLoginError::Invalid)
    }

    fn issue_binding(
        &self,
        domain: &[u8],
        transaction_id: &LoginTransactionId,
        purpose: &LoginTransactionPurpose,
        provider_id: &ProviderId,
        proof: &str,
    ) -> Result<LoginTransactionBinding, GithubLoginError> {
        let digest = derive_login_proof(
            self.active_key()?,
            domain,
            transaction_id,
            purpose,
            provider_id,
            proof,
        );
        Ok(LoginTransactionBinding::new(
            self.active_id.clone(),
            LoginBindingDigest::new(digest),
        ))
    }

    fn verify_binding(
        &self,
        key_id: &LoginBindingDigestKeyId,
        domain: &[u8],
        transaction_id: &LoginTransactionId,
        purpose: &LoginTransactionPurpose,
        provider_id: &ProviderId,
        proof: &str,
    ) -> Result<LoginTransactionBinding, GithubLoginError> {
        let digest = derive_login_proof(
            self.verifying_key(key_id)?,
            domain,
            transaction_id,
            purpose,
            provider_id,
            proof,
        );
        Ok(LoginTransactionBinding::new(
            key_id.clone(),
            LoginBindingDigest::new(digest),
        ))
    }
}

impl fmt::Debug for GithubLoginProofKeyring {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let verify_only_ids: Vec<_> = self
            .keys
            .keys()
            .filter(|id| *id != &self.active_id)
            .collect();
        formatter
            .debug_struct("GithubLoginProofKeyring")
            .field("active_id", &self.active_id)
            .field("verify_only_ids", &verify_only_ids)
            .field("key_material", &"[REDACTED]")
            .finish()
    }
}

/// Invalid login-proof keyring configuration.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum GithubLoginProofKeyringError {
    /// A public key ID is empty, oversized, or not cookie-safe ASCII.
    #[error("GitHub login-proof key ID is invalid")]
    InvalidKeyId,
    /// HMAC key material is not exactly 256 bits.
    #[error("GitHub login-proof key material must be exactly 32 bytes")]
    InvalidKeyLength,
    /// Active and verify-only key sets repeat one public key ID.
    #[error("GitHub login-proof key IDs must be unique")]
    DuplicateKeyId,
    /// The bounded active plus verify-only key count is exceeded.
    #[error("too many GitHub login-proof keys are configured")]
    TooManyKeys,
}

fn valid_proof_key_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_PROOF_KEY_ID_LENGTH
        && value
            .as_bytes()
            .first()
            .is_some_and(u8::is_ascii_alphanumeric)
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
}

fn derive_login_proof(
    key: &StoredProofKey,
    domain: &[u8],
    transaction_id: &LoginTransactionId,
    purpose: &LoginTransactionPurpose,
    provider_id: &ProviderId,
    proof: &str,
) -> [u8; 32] {
    let hmac_key = hmac::Key::new(hmac::HMAC_SHA256, key.as_bytes());
    let mut context = hmac::Context::with_key(&hmac_key);
    context.update(domain);
    update_framed(&mut context, transaction_id.as_str().as_bytes());
    update_framed(&mut context, provider_id.as_str().as_bytes());
    match purpose {
        LoginTransactionPurpose::SignIn { tenant_id } => {
            context.update(&[1]);
            update_framed(&mut context, tenant_id.as_str().as_bytes());
        }
        LoginTransactionPurpose::InstallationSetup => context.update(&[2]),
    }
    update_framed(&mut context, proof.as_bytes());
    let tag = context.sign();
    let mut digest = [0_u8; 32];
    digest.copy_from_slice(tag.as_ref());
    digest
}

fn update_framed(context: &mut hmac::Context, value: &[u8]) {
    context.update(&(value.len() as u64).to_be_bytes());
    context.update(value);
}

struct ParsedLoginProof {
    key_id: LoginBindingDigestKeyId,
    transaction_id: LoginTransactionId,
    encoded: SecretString,
}

impl ParsedLoginProof {
    fn generate(
        version: &str,
        key_id: LoginBindingDigestKeyId,
        transaction_id: LoginTransactionId,
        random: &dyn SecureRandom,
    ) -> Result<Self, GithubLoginError> {
        let mut bytes = Zeroizing::new([0_u8; GENERATED_PROOF_BYTES]);
        random
            .fill(bytes.as_mut())
            .map_err(|_| GithubLoginError::RandomnessUnavailable)?;
        let proof = Zeroizing::new(URL_SAFE_NO_PAD.encode(bytes.as_ref()));
        let encoded = SecretString::new(format!(
            "{version}{PROOF_SEPARATOR}{}{PROOF_SEPARATOR}{}{PROOF_SEPARATOR}{}",
            key_id.as_str(),
            transaction_id.as_str(),
            proof.as_str()
        ))
        .map_err(|_| GithubLoginError::IntegrityFailure)?;
        Ok(Self {
            key_id,
            transaction_id,
            encoded,
        })
    }

    fn parse(version: &str, raw: &str) -> Result<Self, InvalidGithubLoginProof> {
        if raw.len() > MAX_PROOF_CREDENTIAL_LENGTH || !raw.is_ascii() {
            return Err(InvalidGithubLoginProof);
        }
        let mut components = raw.split(PROOF_SEPARATOR);
        let parsed_version = components.next().ok_or(InvalidGithubLoginProof)?;
        let key_id = components.next().ok_or(InvalidGithubLoginProof)?;
        let transaction_id = components.next().ok_or(InvalidGithubLoginProof)?;
        let proof = components.next().ok_or(InvalidGithubLoginProof)?;
        if components.next().is_some()
            || parsed_version != version
            || !valid_proof_key_id(key_id)
            || proof.len() != GENERATED_PROOF_LENGTH
            || !proof
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
        {
            return Err(InvalidGithubLoginProof);
        }
        let mut decoded = Zeroizing::new(
            URL_SAFE_NO_PAD
                .decode(proof)
                .map_err(|_| InvalidGithubLoginProof)?,
        );
        if decoded.len() != GENERATED_PROOF_BYTES
            || URL_SAFE_NO_PAD.encode(decoded.as_slice()) != proof
        {
            return Err(InvalidGithubLoginProof);
        }
        decoded.fill(0);
        Ok(Self {
            key_id: LoginBindingDigestKeyId::new(key_id).map_err(|_| InvalidGithubLoginProof)?,
            transaction_id: LoginTransactionId::new(transaction_id)
                .map_err(|_| InvalidGithubLoginProof)?,
            encoded: SecretString::new(raw.to_owned()).map_err(|_| InvalidGithubLoginProof)?,
        })
    }

    fn proof(&self) -> Result<&str, GithubLoginError> {
        self.encoded
            .expose_secret()
            .rsplit_once(PROOF_SEPARATOR)
            .map(|(_, proof)| proof)
            .ok_or(GithubLoginError::IntegrityFailure)
    }
}

/// Secret browser client-binding cookie payload.
///
/// The HTTP adapter must place this value in a host-only, `HttpOnly`, `Secure`,
/// `SameSite=Lax`, path `/` cookie and clear it on every callback response.
pub struct GithubBrowserBindingCookie(ParsedLoginProof);

impl GithubBrowserBindingCookie {
    /// Strictly parses a complete cookie value.
    ///
    /// # Errors
    ///
    /// Returns one sanitized error for every malformed value.
    pub fn from_raw(raw: &str) -> Result<Self, InvalidGithubLoginProof> {
        ParsedLoginProof::parse(BROWSER_PROOF_VERSION, raw).map(Self)
    }

    /// Explicitly exposes the cookie payload at the HTTP response boundary.
    #[must_use]
    pub fn expose_secret(&self) -> &str {
        self.0.encoded.expose_secret()
    }

    /// Returns the non-secret transaction identity carried by the cookie.
    #[must_use]
    pub const fn transaction_id(&self) -> &LoginTransactionId {
        &self.0.transaction_id
    }

    /// Returns the public proof-key version.
    #[must_use]
    pub const fn key_id(&self) -> &LoginBindingDigestKeyId {
        &self.0.key_id
    }
}

impl fmt::Debug for GithubBrowserBindingCookie {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GithubBrowserBindingCookie")
            .field("transaction_id", self.transaction_id())
            .field("key_id", self.key_id())
            .field("encoded", &"[REDACTED]")
            .finish()
    }
}

/// Integrity-bound purpose of one active GitHub browser callback.
///
/// This value is derived from the durable transaction and keyed state/client
/// bindings. HTTP paths, query flags, and untrusted caller input never select it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GithubWebCallbackPurpose {
    /// Authenticate an existing principal into the configured tenant.
    SignIn,
    /// Complete the one-use installation setup transaction.
    InstallationSetup,
}

/// Secret, transaction-bound CLI polling credential.
pub struct GithubDevicePollCredential(ParsedLoginProof);

impl GithubDevicePollCredential {
    /// Strictly parses a complete poll credential.
    ///
    /// # Errors
    ///
    /// Returns one sanitized error for every malformed value.
    pub fn from_raw(raw: &str) -> Result<Self, InvalidGithubLoginProof> {
        ParsedLoginProof::parse(DEVICE_PROOF_VERSION, raw).map(Self)
    }

    /// Explicitly exposes the credential at the CLI response boundary.
    #[must_use]
    pub fn expose_secret(&self) -> &str {
        self.0.encoded.expose_secret()
    }

    /// Returns its non-secret transaction identity.
    #[must_use]
    pub const fn transaction_id(&self) -> &LoginTransactionId {
        &self.0.transaction_id
    }

    /// Returns the public proof-key version.
    #[must_use]
    pub const fn key_id(&self) -> &LoginBindingDigestKeyId {
        &self.0.key_id
    }
}

impl fmt::Debug for GithubDevicePollCredential {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GithubDevicePollCredential")
            .field("transaction_id", self.transaction_id())
            .field("key_id", self.key_id())
            .field("encoded", &"[REDACTED]")
            .finish()
    }
}

/// Sanitized strict-parser failure for browser and device login proofs.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
#[error("GitHub login proof is invalid")]
pub struct InvalidGithubLoginProof;

/// Browser and CLI session lifetimes used after provider authentication.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GithubLoginSessionLifetimes {
    browser_idle: Duration,
    browser_absolute: Duration,
    cli_idle: Duration,
    cli_absolute: Duration,
}

impl GithubLoginSessionLifetimes {
    /// Creates exact whole-second session lifetimes.
    ///
    /// # Errors
    ///
    /// Rejects zero, fractional, or idle-longer-than-absolute lifetimes.
    pub fn new(
        browser_idle: Duration,
        browser_absolute: Duration,
        cli_idle: Duration,
        cli_absolute: Duration,
    ) -> Result<Self, GithubLoginConfigurationError> {
        validate_session_lifetime(browser_idle, browser_absolute)?;
        validate_session_lifetime(cli_idle, cli_absolute)?;
        Ok(Self {
            browser_idle,
            browser_absolute,
            cli_idle,
            cli_absolute,
        })
    }

    const fn for_kind(self, kind: SessionKind) -> (Duration, Duration) {
        match kind {
            SessionKind::Browser => (self.browser_idle, self.browser_absolute),
            SessionKind::Cli => (self.cli_idle, self.cli_absolute),
        }
    }
}

fn validate_session_lifetime(
    idle: Duration,
    absolute: Duration,
) -> Result<(), GithubLoginConfigurationError> {
    if idle.is_zero()
        || absolute.is_zero()
        || idle.subsec_nanos() != 0
        || absolute.subsec_nanos() != 0
        || idle > absolute
    {
        return Err(GithubLoginConfigurationError::InvalidSessionLifetime);
    }
    Ok(())
}

/// Invalid service composition.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum GithubLoginConfigurationError {
    /// The authentication adapter and protocol use different provider IDs.
    #[error("GitHub authentication provider does not match protocol provider")]
    WrongAuthenticationProvider,
    /// An idle/absolute lifetime is zero, fractional, or inverted.
    #[error("GitHub login session lifetime is invalid")]
    InvalidSessionLifetime,
}

/// One browser authorization redirect and its independently generated binding.
pub struct GithubWebLoginStart {
    authorization_url: Url,
    binding_cookie: GithubBrowserBindingCookie,
    expires_at: UnixTimestamp,
}

impl GithubWebLoginStart {
    /// Returns the trusted provider authorization URL, including secret OAuth state.
    #[must_use]
    pub const fn authorization_url(&self) -> &Url {
        &self.authorization_url
    }

    /// Returns the secret binding value for the `HttpOnly` browser cookie.
    #[must_use]
    pub const fn binding_cookie(&self) -> &GithubBrowserBindingCookie {
        &self.binding_cookie
    }

    /// Returns the durable callback deadline.
    #[must_use]
    pub const fn expires_at(&self) -> UnixTimestamp {
        self.expires_at
    }

    /// Consumes the start response into HTTP adapter values.
    #[must_use]
    pub fn into_parts(self) -> (Url, GithubBrowserBindingCookie, UnixTimestamp) {
        (self.authorization_url, self.binding_cookie, self.expires_at)
    }
}

impl fmt::Debug for GithubWebLoginStart {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GithubWebLoginStart")
            .field("authorization_origin", &self.authorization_url.origin())
            .field("authorization_path", &self.authorization_url.path())
            .field("authorization_query", &"[REDACTED]")
            .field("binding_cookie", &self.binding_cookie)
            .field("expires_at", &self.expires_at)
            .finish()
    }
}

/// Device authorization details safe for the initiating CLI alone.
pub struct GithubDeviceLoginStart {
    poll_credential: GithubDevicePollCredential,
    user_code: SecretString,
    verification_uri: Url,
    expires_at: UnixTimestamp,
    poll_interval: Duration,
}

impl GithubDeviceLoginStart {
    /// Returns the only credential accepted by the poll endpoint.
    #[must_use]
    pub const fn poll_credential(&self) -> &GithubDevicePollCredential {
        &self.poll_credential
    }

    /// Explicitly exposes GitHub's short-lived user code for CLI display.
    #[must_use]
    pub fn user_code(&self) -> &str {
        self.user_code.expose_secret()
    }

    /// Returns GitHub's validated verification URL.
    #[must_use]
    pub const fn verification_uri(&self) -> &Url {
        &self.verification_uri
    }

    /// Returns the device authorization deadline.
    #[must_use]
    pub const fn expires_at(&self) -> UnixTimestamp {
        self.expires_at
    }

    /// Returns the initial minimum polling interval.
    #[must_use]
    pub const fn poll_interval(&self) -> Duration {
        self.poll_interval
    }
}

impl fmt::Debug for GithubDeviceLoginStart {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GithubDeviceLoginStart")
            .field("poll_credential", &self.poll_credential)
            .field("user_code", &"[REDACTED]")
            .field("verification_uri", &self.verification_uri)
            .field("expires_at", &self.expires_at)
            .field("poll_interval", &self.poll_interval)
            .finish()
    }
}

/// Successful sign-in and the only Automata bearer returned to the client.
pub struct GithubLoginCompletion {
    credential: SessionCredential,
    human: AuthenticatedHuman,
    session: Box<DurableSession>,
    current_authorization_revision: u64,
    return_path: Option<LoginReturnPath>,
}

impl GithubLoginCompletion {
    /// Returns the raw Automata credential owner; explicit exposure is still required.
    #[must_use]
    pub const fn credential(&self) -> &SessionCredential {
        &self.credential
    }

    /// Returns the admitted Automata human identity.
    #[must_use]
    pub const fn human(&self) -> &AuthenticatedHuman {
        &self.human
    }

    /// Returns the exact durable session created by the finalizer.
    #[must_use]
    pub const fn session(&self) -> &DurableSession {
        &self.session
    }

    /// Returns the current tenant authorization revision at admission.
    #[must_use]
    pub const fn current_authorization_revision(&self) -> u64 {
        self.current_authorization_revision
    }

    /// Returns the validated server-local redirect path, if one was requested.
    #[must_use]
    pub const fn return_path(&self) -> Option<&LoginReturnPath> {
        self.return_path.as_ref()
    }

    /// Consumes the completion into its HTTP/CLI adapter values.
    #[allow(clippy::type_complexity)]
    #[must_use]
    pub fn into_parts(
        self,
    ) -> (
        SessionCredential,
        AuthenticatedHuman,
        Box<DurableSession>,
        u64,
        Option<LoginReturnPath>,
    ) {
        (
            self.credential,
            self.human,
            self.session,
            self.current_authorization_revision,
            self.return_path,
        )
    }
}

impl fmt::Debug for GithubLoginCompletion {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GithubLoginCompletion")
            .field("credential", &"[REDACTED]")
            .field("human", &self.human)
            .field("session", &self.session)
            .field(
                "current_authorization_revision",
                &self.current_authorization_revision,
            )
            .field("return_path", &self.return_path)
            .finish()
    }
}

/// Result of one authorized device-flow poll.
pub enum GithubDeviceLoginPollOutcome {
    /// Authorization is incomplete at the existing provider interval.
    Pending {
        /// Earliest trusted-clock instant for the next poll.
        next_poll_at: UnixTimestamp,
    },
    /// GitHub increased the minimum provider polling interval.
    SlowDown {
        /// Earliest trusted-clock instant for the next poll.
        next_poll_at: UnixTimestamp,
    },
    /// Provider authentication and Automata session finalization succeeded.
    Complete(Box<GithubLoginCompletion>),
    /// The user or provider denied authorization.
    Denied,
    /// The device authorization expired before completion.
    Expired,
}

/// Result of one installation device-flow poll.
pub enum GithubInstallationDevicePollOutcome {
    /// Installation authorization is incomplete at the existing interval.
    Pending {
        /// Earliest trusted-clock instant for the next poll.
        next_poll_at: UnixTimestamp,
    },
    /// GitHub increased the minimum provider polling interval.
    SlowDown {
        /// Earliest trusted-clock instant for the next poll.
        next_poll_at: UnixTimestamp,
    },
    /// Provider authentication succeeded without issuing an Automata session.
    Complete(Box<GithubInstallationAuthentication>),
    /// The user or provider denied authorization.
    Denied,
    /// The device authorization expired before completion.
    Expired,
}

impl fmt::Debug for GithubInstallationDevicePollOutcome {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Pending { next_poll_at } => formatter
                .debug_struct("Pending")
                .field("next_poll_at", next_poll_at)
                .finish(),
            Self::SlowDown { next_poll_at } => formatter
                .debug_struct("SlowDown")
                .field("next_poll_at", next_poll_at)
                .finish(),
            Self::Complete(completion) => {
                formatter.debug_tuple("Complete").field(completion).finish()
            }
            Self::Denied => formatter.write_str("Denied"),
            Self::Expired => formatter.write_str("Expired"),
        }
    }
}

impl fmt::Debug for GithubDeviceLoginPollOutcome {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Pending { next_poll_at } => formatter
                .debug_struct("Pending")
                .field("next_poll_at", next_poll_at)
                .finish(),
            Self::SlowDown { next_poll_at } => formatter
                .debug_struct("SlowDown")
                .field("next_poll_at", next_poll_at)
                .finish(),
            Self::Complete(completion) => {
                formatter.debug_tuple("Complete").field(completion).finish()
            }
            Self::Denied => formatter.write_str("Denied"),
            Self::Expired => formatter.write_str("Expired"),
        }
    }
}

/// Provider-authenticated material from one consumed installation transaction.
///
/// The provider tokens remain linearly owned and redacted. Callers must pass
/// this value directly into the installation repository; it is not a session
/// and must never cross an HTTP response boundary.
pub struct GithubInstallationAuthentication {
    transaction_id: LoginTransactionId,
    identity: ProviderIdentityAssertion,
    provider_tokens: ProviderTokenSet,
    membership: GithubMembershipObservation,
    return_path: Option<LoginReturnPath>,
}

impl GithubInstallationAuthentication {
    /// Returns the consumed durable login transaction identity.
    #[must_use]
    pub const fn transaction_id(&self) -> &LoginTransactionId {
        &self.transaction_id
    }

    /// Returns the freshly re-fetched stable provider identity assertion.
    #[must_use]
    pub const fn identity(&self) -> &ProviderIdentityAssertion {
        &self.identity
    }

    /// Returns the validated server-local continuation path, if requested.
    #[must_use]
    pub const fn return_path(&self) -> Option<&LoginReturnPath> {
        self.return_path.as_ref()
    }

    /// Consumes the result into the installation repository's linearly owned inputs.
    #[must_use]
    pub fn into_parts(
        self,
    ) -> (
        LoginTransactionId,
        ProviderIdentityAssertion,
        ProviderTokenSet,
        GithubMembershipObservation,
        Option<LoginReturnPath>,
    ) {
        (
            self.transaction_id,
            self.identity,
            self.provider_tokens,
            self.membership,
            self.return_path,
        )
    }
}

impl fmt::Debug for GithubInstallationAuthentication {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GithubInstallationAuthentication")
            .field("transaction_id", &self.transaction_id)
            .field("identity", &self.identity)
            .field("provider_tokens", &"[REDACTED]")
            .field("membership", &self.membership)
            .field("return_path", &self.return_path)
            .finish()
    }
}

/// Sanitized operational login failure.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum GithubLoginError {
    /// Input, proof, callback, or provider data is invalid.
    #[error("GitHub login request is invalid")]
    Invalid,
    /// The durable transaction was consumed or concurrently changed.
    #[error("GitHub login transaction was already used or concurrently changed")]
    Replay,
    /// The bounded login transaction lifetime elapsed.
    #[error("GitHub login transaction expired")]
    Expired,
    /// The user or provider denied authorization.
    #[error("GitHub authorization was denied")]
    Denied,
    /// A device poll arrived before the durable provider deadline.
    #[error("GitHub device authorization was polled too early")]
    PollTooEarly {
        /// Earliest trusted-clock instant at which polling is permitted.
        next_poll_at: UnixTimestamp,
    },
    /// GitHub requested a bounded rate-limit retry.
    #[error("GitHub rate limit was exceeded")]
    RateLimited {
        /// Provider-supplied retry delay, when present and valid.
        retry_after_seconds: Option<u64>,
    },
    /// Provider authentication is temporarily unavailable.
    #[error("GitHub authentication is temporarily unavailable")]
    ProviderUnavailable,
    /// Login transaction, token, membership, or session storage is unavailable.
    #[error("GitHub login storage is temporarily unavailable")]
    StorageUnavailable,
    /// Secure state, verifier, proof, or session randomness is unavailable.
    #[error("secure randomness is temporarily unavailable")]
    RandomnessUnavailable,
    /// The authenticated numeric identity has no current tenant authority.
    #[error("the authenticated GitHub identity is not permitted for this tenant")]
    NotAuthorized,
    /// Repeated durable identifier/digest collisions exhausted the fixed budget.
    #[error("GitHub login collision budget was exhausted")]
    CollisionLimitExceeded,
    /// Authenticated or durable login state violates a security invariant.
    #[error("GitHub login state failed an integrity check")]
    IntegrityFailure,
}

/// Provider-neutral operational GitHub sign-in coordinator.
pub struct GithubLoginService {
    protocol: GithubAppProtocol,
    endpoint: Arc<dyn GithubEndpoint>,
    authentication_provider: Arc<dyn AuthenticationProvider>,
    transactions: Arc<dyn LoginTransactionRepository>,
    sessions: Arc<SessionCredentialService>,
    finalizer: Arc<dyn HumanSignInFinalizer>,
    proof_keys: GithubLoginProofKeyring,
    random: Arc<dyn SecureRandom>,
    clock: Arc<dyn Clock>,
    session_lifetimes: GithubLoginSessionLifetimes,
}

enum LoadedDevicePoll {
    Active {
        version: LoginTransactionVersion,
        authorization: DeviceAuthorization,
    },
    Expired,
}

struct ConsumedGithubAuthentication {
    access: LoginTransactionAccess,
    expected_version: LoginTransactionVersion,
    identity: ProviderIdentityAssertion,
    provider_tokens: ProviderTokenSet,
    membership: GithubMembershipObservation,
    return_path: Option<LoginReturnPath>,
}

enum ConsumedDevicePollOutcome {
    Pending { next_poll_at: UnixTimestamp },
    SlowDown { next_poll_at: UnixTimestamp },
    Complete(Box<ConsumedGithubAuthentication>),
    Denied,
    Expired,
}

impl GithubLoginService {
    /// Composes the protocol over durable provider-neutral boundaries.
    ///
    /// # Errors
    ///
    /// Rejects an authentication adapter configured for another provider.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        protocol: GithubAppProtocol,
        endpoint: Arc<dyn GithubEndpoint>,
        authentication_provider: Arc<dyn AuthenticationProvider>,
        transactions: Arc<dyn LoginTransactionRepository>,
        sessions: Arc<SessionCredentialService>,
        finalizer: Arc<dyn HumanSignInFinalizer>,
        proof_keys: GithubLoginProofKeyring,
        random: Arc<dyn SecureRandom>,
        clock: Arc<dyn Clock>,
        session_lifetimes: GithubLoginSessionLifetimes,
    ) -> Result<Self, GithubLoginConfigurationError> {
        if protocol.config().provider_id() != authentication_provider.provider_id() {
            return Err(GithubLoginConfigurationError::WrongAuthenticationProvider);
        }
        Ok(Self {
            protocol,
            endpoint,
            authentication_provider,
            transactions,
            sessions,
            finalizer,
            proof_keys,
            random,
            clock,
            session_lifetimes,
        })
    }

    /// Begins a browser sign-in with independent OAuth state and client binding.
    ///
    /// # Errors
    ///
    /// Fails closed on randomness, persistence, encoding, or bounded collision failure.
    pub async fn begin_web(
        &self,
        tenant_id: TenantId,
        return_path: LoginReturnPath,
    ) -> Result<GithubWebLoginStart, GithubLoginError> {
        self.begin_web_for_purpose(LoginTransactionPurpose::SignIn { tenant_id }, return_path)
            .await
    }

    /// Begins a browser authorization for the pre-armed installation identity.
    ///
    /// The caller must bind the returned transaction ID to the installation
    /// repository with the independently supplied bootstrap proof before
    /// returning the provider redirect to an anonymous client.
    ///
    /// # Errors
    ///
    /// Returns the same sanitized randomness, storage, integrity, and collision
    /// failures as ordinary browser sign-in initiation.
    pub async fn begin_installation_web(
        &self,
        return_path: LoginReturnPath,
    ) -> Result<GithubWebLoginStart, GithubLoginError> {
        self.begin_web_for_purpose(LoginTransactionPurpose::InstallationSetup, return_path)
            .await
    }

    async fn begin_web_for_purpose(
        &self,
        purpose: LoginTransactionPurpose,
        return_path: LoginReturnPath,
    ) -> Result<GithubWebLoginStart, GithubLoginError> {
        let provider_id = self.protocol.config().provider_id().clone();
        for _ in 0..MAX_GITHUB_LOGIN_COLLISION_ATTEMPTS {
            let transaction_id = generate_transaction_id(self.random.as_ref())?;
            let authorization = self
                .protocol
                .begin_web(self.random.as_ref(), self.clock.now())
                .map_err(|error| map_flow_error(&error))?;
            let authorization_url = authorization.authorization_url().clone();
            let protocol_transaction = authorization.into_transaction();
            let created_at = protocol_transaction.created_at();
            let expires_at = protocol_transaction.expires_at();
            let state_binding = self.proof_keys.issue_binding(
                OAUTH_STATE_HMAC_DOMAIN,
                &transaction_id,
                &purpose,
                &provider_id,
                protocol_transaction.state_secret(),
            )?;
            let browser_proof = ParsedLoginProof::generate(
                BROWSER_PROOF_VERSION,
                self.proof_keys.active_key_id().clone(),
                transaction_id.clone(),
                self.random.as_ref(),
            )?;
            let client_binding = self.proof_keys.issue_binding(
                BROWSER_BINDING_HMAC_DOMAIN,
                &transaction_id,
                &purpose,
                &provider_id,
                browser_proof.proof()?,
            )?;
            let flow = LoginTransactionFlow::browser(state_binding, client_binding)
                .map_err(|_| GithubLoginError::IntegrityFailure)?;
            let state = GithubTransactionStateCodec::encode_web(protocol_transaction)
                .map_err(map_codec_error)?;
            let transaction = LoginTransaction::new(
                transaction_id,
                purpose.clone(),
                provider_id.clone(),
                flow,
                Some(return_path.clone()),
                state,
                created_at,
                expires_at,
            )
            .map_err(|_| GithubLoginError::IntegrityFailure)?;
            match self
                .transactions
                .create(transaction)
                .await
                .map_err(map_repository_error)?
            {
                CreateLoginTransactionOutcome::Created(_) => {
                    return Ok(GithubWebLoginStart {
                        authorization_url,
                        binding_cookie: GithubBrowserBindingCookie(browser_proof),
                        expires_at,
                    });
                }
                CreateLoginTransactionOutcome::AlreadyExists => {}
            }
        }
        Err(GithubLoginError::CollisionLimitExceeded)
    }

    /// Classifies one active callback using its exact durable HMAC-bound purpose.
    ///
    /// This read-only operation exists for HTTP deployments that use one provider
    /// callback URL for ordinary sign-in and installation setup. It does not
    /// consume or advance the transaction; the matching completion method still
    /// owns the atomic consume and replay fence.
    ///
    /// # Errors
    ///
    /// Returns the same sanitized invalid, replay, expiry, storage, and integrity
    /// failures as an exact callback lookup. A binding for another tenant or
    /// purpose is never accepted as ordinary sign-in.
    pub async fn classify_web_callback_purpose(
        &self,
        tenant_id: &TenantId,
        binding_cookie: &GithubBrowserBindingCookie,
        callback: &GithubWebCallback,
    ) -> Result<GithubWebCallbackPurpose, GithubLoginError> {
        let sign_in = self.browser_access(
            LoginTransactionPurpose::SignIn {
                tenant_id: tenant_id.clone(),
            },
            binding_cookie,
            callback,
        )?;
        let installation = self.browser_access(
            LoginTransactionPurpose::InstallationSetup,
            binding_cookie,
            callback,
        )?;
        let now = self.clock.now();
        match self.load_active_version(&sign_in, now).await {
            Ok(_) => return Ok(GithubWebCallbackPurpose::SignIn),
            Err(GithubLoginError::Invalid) => {}
            Err(error) => return Err(error),
        }
        self.load_active_version(&installation, now).await?;
        Ok(GithubWebCallbackPurpose::InstallationSetup)
    }

    /// Completes a browser callback after durably consuming its exact state and binding.
    ///
    /// The durable transaction is consumed before any provider code exchange. A
    /// replay therefore cannot call GitHub or create a second Automata session.
    ///
    /// # Errors
    ///
    /// Returns sanitized invalid, replay, expiry, denial, provider, storage, or
    /// admission failures.
    pub async fn complete_web(
        &self,
        tenant_id: TenantId,
        binding_cookie: GithubBrowserBindingCookie,
        callback: &GithubWebCallback,
    ) -> Result<GithubLoginCompletion, GithubLoginError> {
        let authenticated = self
            .consume_and_authenticate_web(
                LoginTransactionPurpose::SignIn { tenant_id },
                binding_cookie,
                callback,
            )
            .await?;
        self.finalize_with_collision_retry(
            authenticated.access,
            authenticated.expected_version,
            authenticated.identity,
            authenticated.provider_tokens,
            authenticated.membership,
            SessionKind::Browser,
        )
        .await
    }

    /// Consumes and authenticates a browser callback for installation setup.
    ///
    /// The installation login must already have been proof-bound by the caller.
    /// This method deliberately does not create an Automata principal or session;
    /// it returns redacted linear material for `InstallationRepository::complete`.
    ///
    /// # Errors
    ///
    /// Returns sanitized invalid, replay, expiry, denial, provider, storage, or
    /// identity failures.
    pub async fn complete_installation_web(
        &self,
        binding_cookie: GithubBrowserBindingCookie,
        callback: &GithubWebCallback,
    ) -> Result<GithubInstallationAuthentication, GithubLoginError> {
        let authenticated = self
            .consume_and_authenticate_web(
                LoginTransactionPurpose::InstallationSetup,
                binding_cookie,
                callback,
            )
            .await?;
        Ok(GithubInstallationAuthentication {
            transaction_id: authenticated.access.id().clone(),
            identity: authenticated.identity,
            provider_tokens: authenticated.provider_tokens,
            membership: authenticated.membership,
            return_path: authenticated.return_path,
        })
    }

    async fn consume_and_authenticate_web(
        &self,
        purpose: LoginTransactionPurpose,
        binding_cookie: GithubBrowserBindingCookie,
        callback: &GithubWebCallback,
    ) -> Result<ConsumedGithubAuthentication, GithubLoginError> {
        let access = self.browser_access(purpose, &binding_cookie, callback)?;
        drop(binding_cookie);
        let now = self.clock.now();
        let version = self.load_active_version(&access, now).await?;
        let post_consume_version = next_version(version)?;
        let consumed = self.consume_exact(access.clone(), version, now).await?;
        let (_, _, _, flow, return_path, state, created_at, expires_at) = consumed.into_parts();
        if !matches!(flow, LoginTransactionFlow::Browser { .. }) {
            return Err(GithubLoginError::IntegrityFailure);
        }
        let protocol_transaction =
            GithubTransactionStateCodec::decode_web(state, created_at, expires_at)
                .map_err(map_codec_error)?;
        let tokens = self
            .protocol
            .complete_web(
                self.endpoint.as_ref(),
                protocol_transaction,
                callback,
                self.clock.now(),
            )
            .await
            .map_err(|error| map_flow_error(&error))?;
        let (identity, provider_tokens, membership) =
            self.authenticate_tokens(tokens, access.id()).await?;
        Ok(ConsumedGithubAuthentication {
            access,
            expected_version: post_consume_version,
            identity,
            provider_tokens,
            membership,
            return_path,
        })
    }

    fn browser_access(
        &self,
        purpose: LoginTransactionPurpose,
        binding_cookie: &GithubBrowserBindingCookie,
        callback: &GithubWebCallback,
    ) -> Result<LoginTransactionAccess, GithubLoginError> {
        let provider_id = self.protocol.config().provider_id().clone();
        let state_binding = self.proof_keys.verify_binding(
            binding_cookie.key_id(),
            OAUTH_STATE_HMAC_DOMAIN,
            binding_cookie.transaction_id(),
            &purpose,
            &provider_id,
            callback.state().expose_secret(),
        )?;
        let client_binding = self.proof_keys.verify_binding(
            binding_cookie.key_id(),
            BROWSER_BINDING_HMAC_DOMAIN,
            binding_cookie.transaction_id(),
            &purpose,
            &provider_id,
            binding_cookie.0.proof()?,
        )?;
        LoginTransactionAccess::browser(
            binding_cookie.transaction_id().clone(),
            purpose,
            provider_id,
            state_binding,
            client_binding,
        )
        .map_err(|_| GithubLoginError::Invalid)
    }

    /// Begins one CLI device authorization and persists its encrypted device code.
    ///
    /// # Errors
    ///
    /// Fails closed on provider, randomness, persistence, encoding, or collision failure.
    pub async fn begin_device(
        &self,
        tenant_id: TenantId,
        return_path: Option<LoginReturnPath>,
    ) -> Result<GithubDeviceLoginStart, GithubLoginError> {
        self.begin_device_for_purpose(LoginTransactionPurpose::SignIn { tenant_id }, return_path)
            .await
    }

    /// Begins a CLI device authorization for the pre-armed installation identity.
    ///
    /// The caller must proof-bind the returned transaction before exposing the
    /// device code and poll credential to an anonymous client.
    ///
    /// # Errors
    ///
    /// Returns the same sanitized provider, randomness, storage, integrity, and
    /// collision failures as ordinary device-flow initiation.
    pub async fn begin_installation_device(
        &self,
        return_path: Option<LoginReturnPath>,
    ) -> Result<GithubDeviceLoginStart, GithubLoginError> {
        self.begin_device_for_purpose(LoginTransactionPurpose::InstallationSetup, return_path)
            .await
    }

    async fn begin_device_for_purpose(
        &self,
        purpose: LoginTransactionPurpose,
        return_path: Option<LoginReturnPath>,
    ) -> Result<GithubDeviceLoginStart, GithubLoginError> {
        let provider_id = self.protocol.config().provider_id().clone();
        for _ in 0..MAX_GITHUB_LOGIN_COLLISION_ATTEMPTS {
            let transaction_id = generate_transaction_id(self.random.as_ref())?;
            let authorization = self
                .protocol
                .begin_device(self.endpoint.as_ref(), self.clock.now())
                .await
                .map_err(|error| map_flow_error(&error))?;
            let response_user_code = SecretString::new(authorization.user_code().to_owned())
                .map_err(|_| GithubLoginError::IntegrityFailure)?;
            let response_verification_uri = authorization.verification_uri().clone();
            let response_expires_at = authorization.expires_at();
            let (state, metadata) = GithubTransactionStateCodec::encode_device(authorization)
                .map_err(map_codec_error)?;
            let (
                durable_user_code,
                verification_uri,
                created_at,
                expires_at,
                next_poll_at,
                poll_interval_milliseconds,
            ) = metadata.into_parts();
            let poll_proof = ParsedLoginProof::generate(
                DEVICE_PROOF_VERSION,
                self.proof_keys.active_key_id().clone(),
                transaction_id.clone(),
                self.random.as_ref(),
            )?;
            let poll_binding = self.proof_keys.issue_binding(
                DEVICE_POLL_HMAC_DOMAIN,
                &transaction_id,
                &purpose,
                &provider_id,
                poll_proof.proof()?,
            )?;
            let flow = LoginTransactionFlow::device(
                poll_binding,
                durable_user_code,
                verification_uri,
                poll_interval_milliseconds,
                next_poll_at,
            )
            .map_err(|_| GithubLoginError::IntegrityFailure)?;
            let transaction = LoginTransaction::new(
                transaction_id,
                purpose.clone(),
                provider_id.clone(),
                flow,
                return_path.clone(),
                state,
                created_at,
                expires_at,
            )
            .map_err(|_| GithubLoginError::IntegrityFailure)?;
            match self
                .transactions
                .create(transaction)
                .await
                .map_err(map_repository_error)?
            {
                CreateLoginTransactionOutcome::Created(_) => {
                    return Ok(GithubDeviceLoginStart {
                        poll_credential: GithubDevicePollCredential(poll_proof),
                        user_code: response_user_code,
                        verification_uri: response_verification_uri,
                        expires_at: response_expires_at,
                        poll_interval: Duration::from_millis(poll_interval_milliseconds),
                    });
                }
                CreateLoginTransactionOutcome::AlreadyExists => {}
            }
        }
        Err(GithubLoginError::CollisionLimitExceeded)
    }

    /// Polls a device flow through an exact transaction-bound proof.
    ///
    /// Every provider-side advancement, including transient endpoint failures and
    /// `slow_down`, is CAS-persisted before this method returns. A completed token
    /// result is durably consumed before stable identity re-fetch and finalization.
    ///
    /// # Errors
    ///
    /// Returns sanitized invalid, replay, timing, provider, storage, or admission failures.
    pub async fn poll_device(
        &self,
        tenant_id: TenantId,
        poll_credential: GithubDevicePollCredential,
    ) -> Result<GithubDeviceLoginPollOutcome, GithubLoginError> {
        match self
            .poll_device_for_purpose(
                LoginTransactionPurpose::SignIn { tenant_id },
                poll_credential,
            )
            .await?
        {
            ConsumedDevicePollOutcome::Pending { next_poll_at } => {
                Ok(GithubDeviceLoginPollOutcome::Pending { next_poll_at })
            }
            ConsumedDevicePollOutcome::SlowDown { next_poll_at } => {
                Ok(GithubDeviceLoginPollOutcome::SlowDown { next_poll_at })
            }
            ConsumedDevicePollOutcome::Complete(authenticated) => {
                let authenticated = *authenticated;
                let completion = self
                    .finalize_with_collision_retry(
                        authenticated.access,
                        authenticated.expected_version,
                        authenticated.identity,
                        authenticated.provider_tokens,
                        authenticated.membership,
                        SessionKind::Cli,
                    )
                    .await?;
                Ok(GithubDeviceLoginPollOutcome::Complete(Box::new(completion)))
            }
            ConsumedDevicePollOutcome::Denied => Ok(GithubDeviceLoginPollOutcome::Denied),
            ConsumedDevicePollOutcome::Expired => Ok(GithubDeviceLoginPollOutcome::Expired),
        }
    }

    /// Polls a proof-bound installation device flow without creating a session.
    ///
    /// # Errors
    ///
    /// Returns sanitized invalid, replay, timing, provider, storage, or identity
    /// failures.
    pub async fn poll_installation_device(
        &self,
        poll_credential: GithubDevicePollCredential,
    ) -> Result<GithubInstallationDevicePollOutcome, GithubLoginError> {
        match self
            .poll_device_for_purpose(LoginTransactionPurpose::InstallationSetup, poll_credential)
            .await?
        {
            ConsumedDevicePollOutcome::Pending { next_poll_at } => {
                Ok(GithubInstallationDevicePollOutcome::Pending { next_poll_at })
            }
            ConsumedDevicePollOutcome::SlowDown { next_poll_at } => {
                Ok(GithubInstallationDevicePollOutcome::SlowDown { next_poll_at })
            }
            ConsumedDevicePollOutcome::Complete(authenticated) => {
                let authenticated = *authenticated;
                Ok(GithubInstallationDevicePollOutcome::Complete(Box::new(
                    GithubInstallationAuthentication {
                        transaction_id: authenticated.access.id().clone(),
                        identity: authenticated.identity,
                        provider_tokens: authenticated.provider_tokens,
                        membership: authenticated.membership,
                        return_path: authenticated.return_path,
                    },
                )))
            }
            ConsumedDevicePollOutcome::Denied => Ok(GithubInstallationDevicePollOutcome::Denied),
            ConsumedDevicePollOutcome::Expired => Ok(GithubInstallationDevicePollOutcome::Expired),
        }
    }

    async fn poll_device_for_purpose(
        &self,
        purpose: LoginTransactionPurpose,
        poll_credential: GithubDevicePollCredential,
    ) -> Result<ConsumedDevicePollOutcome, GithubLoginError> {
        let provider_id = self.protocol.config().provider_id().clone();
        let poll_binding = self.proof_keys.verify_binding(
            poll_credential.key_id(),
            DEVICE_POLL_HMAC_DOMAIN,
            poll_credential.transaction_id(),
            &purpose,
            &provider_id,
            poll_credential.0.proof()?,
        )?;
        let access = LoginTransactionAccess::device(
            poll_credential.transaction_id().clone(),
            purpose,
            provider_id,
            poll_binding,
        );
        let now = self.clock.now();
        let (version, mut authorization) = match self.load_device_poll(&access, now).await? {
            LoadedDevicePoll::Active {
                version,
                authorization,
            } => (version, authorization),
            LoadedDevicePoll::Expired => return Ok(ConsumedDevicePollOutcome::Expired),
        };
        let previous_poll_interval = authorization.poll_interval_seconds();
        let polled = self
            .protocol
            .poll_device(self.endpoint.as_ref(), &mut authorization, now)
            .await;
        match polled {
            Ok(DevicePollOutcome::Pending { next_poll_at }) => {
                let slowed_down = authorization.poll_interval_seconds() > previous_poll_interval;
                self.persist_device_advance(access, version, authorization, now)
                    .await?;
                if slowed_down {
                    Ok(ConsumedDevicePollOutcome::SlowDown { next_poll_at })
                } else {
                    Ok(ConsumedDevicePollOutcome::Pending { next_poll_at })
                }
            }
            Ok(DevicePollOutcome::Denied) | Err(GithubFlowError::InvalidDeviceCode) => {
                self.consume_terminal(access, version, now).await?;
                Ok(ConsumedDevicePollOutcome::Denied)
            }
            Ok(DevicePollOutcome::Expired) => {
                self.consume_terminal_or_expired(access, version, now)
                    .await?;
                Ok(ConsumedDevicePollOutcome::Expired)
            }
            Ok(DevicePollOutcome::Complete(tokens)) => {
                let post_consume_version = next_version(version)?;
                let consumed = self.consume_exact(access.clone(), version, now).await?;
                let return_path = consumed.return_path().cloned();
                drop(consumed);
                let (identity, provider_tokens, membership) =
                    self.authenticate_tokens(tokens, access.id()).await?;
                Ok(ConsumedDevicePollOutcome::Complete(Box::new(
                    ConsumedGithubAuthentication {
                        access,
                        expected_version: post_consume_version,
                        identity,
                        provider_tokens,
                        membership,
                        return_path,
                    },
                )))
            }
            Err(GithubFlowError::PollTooEarly { next_poll_at }) => {
                Err(GithubLoginError::PollTooEarly { next_poll_at })
            }
            Err(error @ GithubFlowError::Endpoint(_)) => {
                self.persist_device_advance(access, version, authorization, now)
                    .await?;
                Err(map_flow_error(&error))
            }
            Err(error) => Err(map_flow_error(&error)),
        }
    }

    async fn load_device_poll(
        &self,
        access: &LoginTransactionAccess,
        now: UnixTimestamp,
    ) -> Result<LoadedDevicePoll, GithubLoginError> {
        let loaded = self
            .transactions
            .load(access, now)
            .await
            .map_err(map_repository_error)?;
        let versioned = match loaded {
            LoadLoginTransactionOutcome::Active(transaction) => transaction,
            LoadLoginTransactionOutcome::NotFound => return Err(GithubLoginError::Invalid),
            LoadLoginTransactionOutcome::Expired => return Ok(LoadedDevicePoll::Expired),
            LoadLoginTransactionOutcome::Consumed => return Err(GithubLoginError::Replay),
        };
        let (version, transaction) = versioned.into_parts();
        let (_, _, _, flow, _, state, created_at, expires_at) = transaction.into_parts();
        let (user_code, verification_uri, poll_interval_milliseconds, next_poll_at) = match flow {
            LoginTransactionFlow::Device {
                user_code,
                verification_uri,
                poll_interval_milliseconds,
                next_poll_at,
                ..
            } => (
                user_code,
                verification_uri,
                poll_interval_milliseconds,
                next_poll_at,
            ),
            LoginTransactionFlow::Browser { .. } => {
                return Err(GithubLoginError::IntegrityFailure);
            }
        };
        let metadata = GithubDeviceTransactionMetadata::new(
            user_code,
            verification_uri,
            created_at,
            expires_at,
            next_poll_at,
            poll_interval_milliseconds,
        )
        .map_err(map_codec_error)?;
        let authorization = GithubTransactionStateCodec::decode_device(
            state,
            metadata,
            self.protocol.config().endpoints(),
        )
        .map_err(map_codec_error)?;
        Ok(LoadedDevicePoll::Active {
            version,
            authorization,
        })
    }

    async fn load_active_version(
        &self,
        access: &LoginTransactionAccess,
        now: UnixTimestamp,
    ) -> Result<LoginTransactionVersion, GithubLoginError> {
        match self
            .transactions
            .load(access, now)
            .await
            .map_err(map_repository_error)?
        {
            LoadLoginTransactionOutcome::Active(transaction) => Ok(transaction.version()),
            LoadLoginTransactionOutcome::NotFound => Err(GithubLoginError::Invalid),
            LoadLoginTransactionOutcome::Expired => Err(GithubLoginError::Expired),
            LoadLoginTransactionOutcome::Consumed => Err(GithubLoginError::Replay),
        }
    }

    async fn consume_exact(
        &self,
        access: LoginTransactionAccess,
        version: LoginTransactionVersion,
        now: UnixTimestamp,
    ) -> Result<LoginTransaction, GithubLoginError> {
        let request = ConsumeLoginTransaction::new(access, now).if_version(version);
        match self
            .transactions
            .consume(request)
            .await
            .map_err(map_repository_error)?
        {
            ConsumeLoginTransactionOutcome::Consumed(transaction) => Ok(*transaction),
            ConsumeLoginTransactionOutcome::Expired => Err(GithubLoginError::Expired),
            ConsumeLoginTransactionOutcome::NotFound
            | ConsumeLoginTransactionOutcome::AlreadyConsumed
            | ConsumeLoginTransactionOutcome::VersionConflict => Err(GithubLoginError::Replay),
        }
    }

    async fn consume_terminal(
        &self,
        access: LoginTransactionAccess,
        version: LoginTransactionVersion,
        now: UnixTimestamp,
    ) -> Result<(), GithubLoginError> {
        self.consume_exact(access, version, now).await.map(drop)
    }

    async fn consume_terminal_or_expired(
        &self,
        access: LoginTransactionAccess,
        version: LoginTransactionVersion,
        now: UnixTimestamp,
    ) -> Result<(), GithubLoginError> {
        match self.consume_exact(access, version, now).await {
            Ok(_) | Err(GithubLoginError::Expired) => Ok(()),
            Err(error) => Err(error),
        }
    }

    async fn persist_device_advance(
        &self,
        access: LoginTransactionAccess,
        version: LoginTransactionVersion,
        authorization: DeviceAuthorization,
        now: UnixTimestamp,
    ) -> Result<(), GithubLoginError> {
        let (state, metadata) =
            GithubTransactionStateCodec::encode_device(authorization).map_err(map_codec_error)?;
        let (_, _, _, _, next_poll_at, poll_interval_milliseconds) = metadata.into_parts();
        let replacement = ReplaceLoginTransactionState::new(access, version, state)
            .next_device_poll_at(next_poll_at)
            .device_poll_interval_milliseconds(poll_interval_milliseconds);
        match self
            .transactions
            .replace_state(replacement, now)
            .await
            .map_err(map_repository_error)?
        {
            ReplaceLoginTransactionOutcome::Replaced(_) => Ok(()),
            ReplaceLoginTransactionOutcome::Expired => Err(GithubLoginError::Expired),
            ReplaceLoginTransactionOutcome::NotFound
            | ReplaceLoginTransactionOutcome::Consumed
            | ReplaceLoginTransactionOutcome::VersionConflict => Err(GithubLoginError::Replay),
        }
    }

    async fn authenticate_tokens(
        &self,
        tokens: ProviderTokenSet,
        transaction_id: &LoginTransactionId,
    ) -> Result<
        (
            ProviderIdentityAssertion,
            ProviderTokenSet,
            GithubMembershipObservation,
        ),
        GithubLoginError,
    > {
        let credential = ProviderCredential::new(
            self.protocol.config().provider_id().clone(),
            SecretString::new(tokens.access_token().expose_secret().to_owned())
                .map_err(|_| GithubLoginError::IntegrityFailure)?,
        );
        let identity = self
            .authentication_provider
            .authenticate(&credential)
            .await
            .map_err(map_authentication_error)?;
        let memberships = self
            .endpoint
            .memberships(GithubCurrentUserRequest {
                access_token: credential.access_token(),
            })
            .await
            .map_err(map_endpoint_error)?;
        let observed_at = self.clock.now();
        let policy_valid_until = observed_at
            .checked_add(GITHUB_MEMBERSHIP_OBSERVATION_TTL_SECONDS)
            .map_err(|_| GithubLoginError::IntegrityFailure)?;
        let access_expires_at = tokens
            .metadata()
            .access_expires_at()
            .ok_or(GithubLoginError::Expired)?;
        let valid_until = std::cmp::min(policy_valid_until, access_expires_at);
        if valid_until <= observed_at {
            return Err(GithubLoginError::Expired);
        }
        let snapshot_id = GithubMembershipSnapshotId::new(transaction_id.as_str())
            .map_err(|_| GithubLoginError::IntegrityFailure)?;
        let membership =
            GithubMembershipObservation::new(snapshot_id, memberships, observed_at, valid_until)
                .map_err(|_| GithubLoginError::Invalid)?;
        drop(credential);
        let tokens = tokens
            .bind_provider_subject(identity.provider_subject().clone())
            .map_err(map_token_binding_error)?;
        Ok((identity, tokens, membership))
    }

    async fn finalize_with_collision_retry(
        &self,
        access: LoginTransactionAccess,
        expected_version: LoginTransactionVersion,
        identity: ProviderIdentityAssertion,
        tokens: ProviderTokenSet,
        membership: GithubMembershipObservation,
        kind: SessionKind,
    ) -> Result<GithubLoginCompletion, GithubLoginError> {
        let (idle_lifetime, absolute_lifetime) = self.session_lifetimes.for_kind(kind);
        let prepared = self
            .sessions
            .prepare(kind, idle_lifetime, absolute_lifetime)
            .map_err(map_session_error)?;
        let (mut credential, candidate) = prepared.into_parts();
        let mut request = FinalizeSignIn::new(
            access,
            expected_version,
            identity,
            tokens,
            membership,
            candidate,
            self.clock.now(),
        )
        .map_err(map_sign_in_value_error)?;

        for attempt in 0..MAX_GITHUB_LOGIN_COLLISION_ATTEMPTS {
            let outcome = self
                .finalizer
                .finalize(request)
                .await
                .map_err(map_finalizer_error)?;
            match outcome {
                FinalizeSignInOutcome::Admitted {
                    human,
                    session,
                    current_authorization_revision,
                    return_path,
                } => {
                    return Ok(GithubLoginCompletion {
                        credential,
                        human,
                        session,
                        current_authorization_revision,
                        return_path,
                    });
                }
                FinalizeSignInOutcome::SessionConflict { retry, .. }
                    if attempt + 1 < MAX_GITHUB_LOGIN_COLLISION_ATTEMPTS =>
                {
                    drop(credential);
                    let prepared = self
                        .sessions
                        .prepare(kind, idle_lifetime, absolute_lifetime)
                        .map_err(map_session_error)?;
                    let (replacement_credential, candidate) = prepared.into_parts();
                    request = retry
                        .with_session(candidate, self.clock.now())
                        .map_err(map_sign_in_value_error)?;
                    credential = replacement_credential;
                }
                FinalizeSignInOutcome::SessionConflict { .. } => {
                    return Err(GithubLoginError::CollisionLimitExceeded);
                }
                FinalizeSignInOutcome::Unmapped
                | FinalizeSignInOutcome::PrincipalDisabled
                | FinalizeSignInOutcome::MembershipSuspended
                | FinalizeSignInOutcome::IdentityConflict => {
                    return Err(GithubLoginError::NotAuthorized);
                }
                FinalizeSignInOutcome::Expired => return Err(GithubLoginError::Expired),
                FinalizeSignInOutcome::NotFound
                | FinalizeSignInOutcome::AlreadyConsumed
                | FinalizeSignInOutcome::VersionConflict => {
                    return Err(GithubLoginError::Replay);
                }
            }
        }
        Err(GithubLoginError::CollisionLimitExceeded)
    }
}

impl fmt::Debug for GithubLoginService {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GithubLoginService")
            .field("protocol", &self.protocol)
            .field("authentication_provider", &self.authentication_provider)
            .field("transactions", &self.transactions)
            .field("sessions", &"SessionCredentialService(..)")
            .field("finalizer", &self.finalizer)
            .field("proof_keys", &self.proof_keys)
            .field("session_lifetimes", &self.session_lifetimes)
            .finish_non_exhaustive()
    }
}

fn generate_transaction_id(
    random: &dyn SecureRandom,
) -> Result<LoginTransactionId, GithubLoginError> {
    for _ in 0..MAX_GITHUB_LOGIN_COLLISION_ATTEMPTS {
        let mut bytes = Zeroizing::new([0_u8; 16]);
        random
            .fill(bytes.as_mut())
            .map_err(|_| GithubLoginError::RandomnessUnavailable)?;
        let uuid = uuid::Uuid::from_bytes(*bytes);
        if !uuid.is_nil() {
            return LoginTransactionId::new(uuid.hyphenated().to_string())
                .map_err(|_| GithubLoginError::IntegrityFailure);
        }
    }
    Err(GithubLoginError::CollisionLimitExceeded)
}

fn next_version(
    version: LoginTransactionVersion,
) -> Result<LoginTransactionVersion, GithubLoginError> {
    let value = version
        .value()
        .checked_add(1)
        .ok_or(GithubLoginError::IntegrityFailure)?;
    LoginTransactionVersion::new(value).map_err(|_| GithubLoginError::IntegrityFailure)
}

fn map_repository_error(error: LoginTransactionRepositoryError) -> GithubLoginError {
    match error {
        LoginTransactionRepositoryError::Unavailable => GithubLoginError::StorageUnavailable,
        LoginTransactionRepositoryError::IntegrityFailure
        | LoginTransactionRepositoryError::CorruptData
        | LoginTransactionRepositoryError::InvalidRequest => GithubLoginError::IntegrityFailure,
    }
}

fn map_codec_error(_error: GithubTransactionStateError) -> GithubLoginError {
    GithubLoginError::IntegrityFailure
}

fn map_endpoint_error(error: GithubEndpointError) -> GithubLoginError {
    match error {
        GithubEndpointError::RateLimited {
            retry_after_seconds,
        } => GithubLoginError::RateLimited {
            retry_after_seconds,
        },
        GithubEndpointError::Unavailable => GithubLoginError::ProviderUnavailable,
        GithubEndpointError::Unauthorized
        | GithubEndpointError::Forbidden
        | GithubEndpointError::InvalidResponse => GithubLoginError::Invalid,
    }
}

fn map_flow_error(error: &GithubFlowError) -> GithubLoginError {
    match error {
        GithubFlowError::Randomness(_) => GithubLoginError::RandomnessUnavailable,
        GithubFlowError::Endpoint(error) => map_endpoint_error(*error),
        GithubFlowError::WebTransactionExpired
        | GithubFlowError::RefreshExpired
        | GithubFlowError::DeviceFlowTerminal => GithubLoginError::Expired,
        GithubFlowError::AuthorizationDenied => GithubLoginError::Denied,
        GithubFlowError::PollTooEarly { next_poll_at } => GithubLoginError::PollTooEarly {
            next_poll_at: *next_poll_at,
        },
        GithubFlowError::StateMismatch
        | GithubFlowError::InvalidProviderResponse
        | GithubFlowError::InvalidDeviceCode => GithubLoginError::Invalid,
        GithubFlowError::Time(_)
        | GithubFlowError::InvalidPersistedTransaction
        | GithubFlowError::WrongProvider
        | GithubFlowError::RefreshUnavailable => GithubLoginError::IntegrityFailure,
    }
}

fn map_authentication_error(error: AuthenticationProviderError) -> GithubLoginError {
    match error {
        AuthenticationProviderError::Unavailable => GithubLoginError::ProviderUnavailable,
        AuthenticationProviderError::Rejected | AuthenticationProviderError::InvalidResponse => {
            GithubLoginError::Invalid
        }
        AuthenticationProviderError::WrongProvider => GithubLoginError::IntegrityFailure,
    }
}

fn map_token_binding_error(_error: ProviderTokenSetError) -> GithubLoginError {
    GithubLoginError::IntegrityFailure
}

fn map_session_error(error: SessionCredentialServiceError) -> GithubLoginError {
    match error {
        SessionCredentialServiceError::RandomnessUnavailable => {
            GithubLoginError::RandomnessUnavailable
        }
        SessionCredentialServiceError::RepositoryUnavailable => {
            GithubLoginError::StorageUnavailable
        }
        SessionCredentialServiceError::InvalidCredential
        | SessionCredentialServiceError::InvalidLifetime
        | SessionCredentialServiceError::LifetimeOverflow
        | SessionCredentialServiceError::InternalFailure => GithubLoginError::IntegrityFailure,
    }
}

fn map_sign_in_value_error(error: SignInValueError) -> GithubLoginError {
    match error {
        SignInValueError::ExpiredMembershipObservation
        | SignInValueError::InvalidProviderTokenLifetime
        | SignInValueError::InvalidSessionLifetime => GithubLoginError::Expired,
        SignInValueError::InvalidPurpose
        | SignInValueError::InvalidSessionId
        | SignInValueError::WrongSessionKind
        | SignInValueError::WrongProviderGrantKind
        | SignInValueError::IdentityCredentialMismatch
        | SignInValueError::InvalidTimeOrder
        | SignInValueError::InvalidVersion => GithubLoginError::IntegrityFailure,
    }
}

fn map_finalizer_error(error: SignInFinalizerError) -> GithubLoginError {
    match error {
        SignInFinalizerError::Unavailable => GithubLoginError::StorageUnavailable,
        SignInFinalizerError::InvalidRequest | SignInFinalizerError::IntegrityFailure => {
            GithubLoginError::IntegrityFailure
        }
    }
}
