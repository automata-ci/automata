//! Opaque browser and CLI session-credential issuance and derivation.
//!
//! Raw credentials live only in redacted, non-serializable values. Durable
//! repositories receive a domain-separated keyed digest and never receive the
//! bearer value itself.

use std::{collections::BTreeMap, fmt, sync::Arc, time::Duration};

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use ring::hmac;
use thiserror::Error;
use zeroize::{Zeroize as _, Zeroizing};

use crate::{
    human::{AuthenticatedHuman, TenantId},
    secret::{CsrfToken, SecretBytes, SecretString, SecureRandom},
    session::{
        ActivateCliSession, ActivateCliSessionOutcome, CreateSession, CreateSessionOutcome,
        DurableSession, DurableSessionIdentity, HumanSessionRepository, ResolveSession,
        ResolveSessionOutcome, RevokeOwnSession, RevokeOwnSessionOutcome, SessionId, SessionKind,
        SessionRepositoryError, SessionTokenDigest, SessionTokenDigestKeyId, SessionTokenLookup,
        TouchSession, TouchSessionOutcome,
    },
    sign_in::PendingSessionCandidate,
    time::{Clock, UnixTimestamp},
};

/// Exact secret and HMAC key size used by session credentials.
pub const SESSION_CREDENTIAL_SECRET_BYTES: usize = 32;
/// Maximum number of active plus verify-only HMAC keys retained in one keyring.
pub const MAX_SESSION_CREDENTIAL_KEYS: usize = 32;
/// Maximum repository collision attempts made by one issuance request.
pub const MAX_SESSION_CREDENTIAL_ISSUE_ATTEMPTS: usize = 8;

const SESSION_CREDENTIAL_VERSION: &str = "v1";
const SESSION_CREDENTIAL_SEPARATOR: char = '~';
const GENERATED_SECRET_LENGTH: usize = 43;
const MAX_KEY_ID_LENGTH: usize = 128;
const MIN_CREDENTIAL_LENGTH: usize =
    SESSION_CREDENTIAL_VERSION.len() + 2 + 1 + GENERATED_SECRET_LENGTH;
const MAX_CREDENTIAL_LENGTH: usize =
    SESSION_CREDENTIAL_VERSION.len() + 2 + MAX_KEY_ID_LENGTH + GENERATED_SECRET_LENGTH;
// foundation-governance: derived-contract owner=auth-security kind=cryptographic-context
const LOOKUP_HMAC_DOMAIN: &[u8] = b"automata-ci/session-credential/lookup/v1\0";
// foundation-governance: derived-contract owner=auth-security kind=cryptographic-context
const CSRF_HMAC_DOMAIN: &[u8] = b"automata-ci/session-credential/csrf/v1\0";

/// One parsed opaque browser or CLI bearer credential.
///
/// The version and key ID prefix are public. The complete value remains a
/// secret and is deliberately non-cloneable and non-serializable.
pub struct SessionCredential {
    key_id: SessionTokenDigestKeyId,
    encoded: SecretString,
}

impl SessionCredential {
    /// Parses an owned credential with strict canonical bounds.
    ///
    /// # Errors
    ///
    /// Rejects an unknown version, malformed key ID, noncanonical secret, or
    /// any credential outside the exact format bounds.
    pub fn parse(encoded: SecretString) -> Result<Self, InvalidSessionCredential> {
        let key_id = validate_encoded_credential(encoded.expose_secret())?;
        Ok(Self { key_id, encoded })
    }

    /// Copies and parses a raw bearer after checking its bounds.
    ///
    /// # Errors
    ///
    /// Returns a single sanitized error for every malformed credential.
    pub fn from_raw(raw: &str) -> Result<Self, InvalidSessionCredential> {
        if !(MIN_CREDENTIAL_LENGTH..=MAX_CREDENTIAL_LENGTH).contains(&raw.len()) {
            return Err(InvalidSessionCredential);
        }
        let encoded = SecretString::new(raw.to_owned()).map_err(|_| InvalidSessionCredential)?;
        Self::parse(encoded)
    }

    /// Returns the public HMAC key version selected by this credential.
    #[must_use]
    pub const fn key_id(&self) -> &SessionTokenDigestKeyId {
        &self.key_id
    }

    /// Explicitly exposes the complete bearer at an external credential boundary.
    #[must_use]
    pub fn expose_secret(&self) -> &str {
        self.encoded.expose_secret()
    }
}

impl fmt::Debug for SessionCredential {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SessionCredential")
            .field("version", &SESSION_CREDENTIAL_VERSION)
            .field("key_id", &self.key_id)
            .field("encoded", &"[REDACTED]")
            .finish()
    }
}

fn validate_encoded_credential(
    value: &str,
) -> Result<SessionTokenDigestKeyId, InvalidSessionCredential> {
    if !(MIN_CREDENTIAL_LENGTH..=MAX_CREDENTIAL_LENGTH).contains(&value.len()) || !value.is_ascii()
    {
        return Err(InvalidSessionCredential);
    }

    let mut components = value.split(SESSION_CREDENTIAL_SEPARATOR);
    let version = components.next().ok_or(InvalidSessionCredential)?;
    let key_id = components.next().ok_or(InvalidSessionCredential)?;
    let secret = components.next().ok_or(InvalidSessionCredential)?;
    if components.next().is_some()
        || version != SESSION_CREDENTIAL_VERSION
        || !valid_key_id(key_id)
        || secret.len() != GENERATED_SECRET_LENGTH
        || !secret
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    {
        return Err(InvalidSessionCredential);
    }

    let mut decoded = URL_SAFE_NO_PAD
        .decode(secret)
        .map_err(|_| InvalidSessionCredential)?;
    let canonical = decoded.len() == SESSION_CREDENTIAL_SECRET_BYTES
        && URL_SAFE_NO_PAD.encode(&decoded) == secret;
    decoded.zeroize();
    if !canonical {
        return Err(InvalidSessionCredential);
    }

    SessionTokenDigestKeyId::new(key_id).map_err(|_| InvalidSessionCredential)
}

fn valid_key_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_KEY_ID_LENGTH
        && value
            .as_bytes()
            .first()
            .is_some_and(u8::is_ascii_alphanumeric)
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
}

/// Sanitized failure returned for every malformed or unknown bearer shape.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
#[error("session credential is invalid")]
pub struct InvalidSessionCredential;

/// Consumed configuration for one exact 256-bit session HMAC key.
pub struct SessionCredentialKey {
    id: SessionTokenDigestKeyId,
    material: SecretBytes,
}

impl SessionCredentialKey {
    /// Creates one session-credential HMAC key.
    ///
    /// # Errors
    ///
    /// Rejects a key ID that cannot appear in the public credential prefix or
    /// key material that is not exactly 32 bytes. Rejected material is consumed.
    pub fn new(
        id: SessionTokenDigestKeyId,
        material: SecretBytes,
    ) -> Result<Self, SessionCredentialKeyringError> {
        if !valid_key_id(id.as_str()) {
            return Err(SessionCredentialKeyringError::InvalidKeyId);
        }
        if material.expose_secret().len() != SESSION_CREDENTIAL_SECRET_BYTES {
            return Err(SessionCredentialKeyringError::InvalidKeyLength);
        }
        Ok(Self { id, material })
    }

    /// Returns the non-secret public key version ID.
    #[must_use]
    pub const fn id(&self) -> &SessionTokenDigestKeyId {
        &self.id
    }

    fn into_parts(self) -> (SessionTokenDigestKeyId, SecretBytes) {
        (self.id, self.material)
    }
}

impl fmt::Debug for SessionCredentialKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SessionCredentialKey")
            .field("id", &self.id)
            .field("material", &"[REDACTED]")
            .finish()
    }
}

struct StoredHmacKey(Zeroizing<[u8; SESSION_CREDENTIAL_SECRET_BYTES]>);

impl StoredHmacKey {
    fn consume(material: SecretBytes) -> Self {
        let mut bytes = Zeroizing::new([0_u8; SESSION_CREDENTIAL_SECRET_BYTES]);
        bytes.copy_from_slice(material.expose_secret());
        drop(material);
        Self(bytes)
    }

    fn as_bytes(&self) -> &[u8] {
        self.0.as_ref()
    }
}

/// Rotation-aware HMAC keyring with one issuing key and verify-only old keys.
pub struct SessionCredentialKeyring {
    active_id: SessionTokenDigestKeyId,
    keys: BTreeMap<SessionTokenDigestKeyId, StoredHmacKey>,
}

impl SessionCredentialKeyring {
    /// Builds a bounded active and verify-only keyring.
    ///
    /// # Errors
    ///
    /// Rejects duplicate key IDs or more than 32 total configured keys.
    pub fn new(
        active: SessionCredentialKey,
        verify_only: Vec<SessionCredentialKey>,
    ) -> Result<Self, SessionCredentialKeyringError> {
        if verify_only.len() >= MAX_SESSION_CREDENTIAL_KEYS {
            return Err(SessionCredentialKeyringError::TooManyKeys);
        }

        let active_id = active.id().clone();
        let mut keys = BTreeMap::new();
        for configured in std::iter::once(active).chain(verify_only) {
            let (id, material) = configured.into_parts();
            if keys.insert(id, StoredHmacKey::consume(material)).is_some() {
                return Err(SessionCredentialKeyringError::DuplicateKeyId);
            }
        }
        Ok(Self { active_id, keys })
    }

    /// Returns the only key version permitted to issue new credentials.
    #[must_use]
    pub const fn active_key_id(&self) -> &SessionTokenDigestKeyId {
        &self.active_id
    }

    fn active_key(&self) -> Result<&StoredHmacKey, SessionCredentialServiceError> {
        self.keys
            .get(&self.active_id)
            .ok_or(SessionCredentialServiceError::InternalFailure)
    }

    fn verifying_key(
        &self,
        credential: &SessionCredential,
    ) -> Result<&StoredHmacKey, SessionCredentialServiceError> {
        self.keys
            .get(credential.key_id())
            .ok_or(SessionCredentialServiceError::InvalidCredential)
    }

    fn lookup_with_key(
        credential: &SessionCredential,
        kind: SessionKind,
        key: &StoredHmacKey,
    ) -> SessionTokenLookup {
        let digest = derive_hmac(key, LOOKUP_HMAC_DOMAIN, kind, credential);
        SessionTokenLookup::new(credential.key_id().clone(), SessionTokenDigest::new(digest))
    }

    fn lookup_for_issuance(
        &self,
        credential: &SessionCredential,
        kind: SessionKind,
    ) -> Result<SessionTokenLookup, SessionCredentialServiceError> {
        if credential.key_id() != &self.active_id {
            return Err(SessionCredentialServiceError::InternalFailure);
        }
        Ok(Self::lookup_with_key(credential, kind, self.active_key()?))
    }

    fn lookup_for_verification(
        &self,
        credential: &SessionCredential,
        kind: SessionKind,
    ) -> Result<SessionTokenLookup, SessionCredentialServiceError> {
        let key = self.verifying_key(credential)?;
        Ok(Self::lookup_with_key(credential, kind, key))
    }

    fn csrf_for_verification(
        &self,
        credential: &SessionCredential,
        kind: SessionKind,
    ) -> Result<CsrfToken, SessionCredentialServiceError> {
        let key = self.verifying_key(credential)?;
        let derived = Zeroizing::new(derive_hmac(key, CSRF_HMAC_DOMAIN, kind, credential));
        let encoded = URL_SAFE_NO_PAD.encode(derived.as_ref());
        CsrfToken::from_generated_secret(
            SecretString::new(encoded)
                .map_err(|_| SessionCredentialServiceError::InternalFailure)?,
        )
        .map_err(|_| SessionCredentialServiceError::InternalFailure)
    }
}

impl fmt::Debug for SessionCredentialKeyring {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let verify_only_ids: Vec<_> = self
            .keys
            .keys()
            .filter(|id| *id != &self.active_id)
            .collect();
        formatter
            .debug_struct("SessionCredentialKeyring")
            .field("active_id", &self.active_id)
            .field("verify_only_ids", &verify_only_ids)
            .field("key_material", &"[REDACTED]")
            .finish()
    }
}

/// One linearly owned raw credential and its exact safe sign-in candidate.
///
/// Preparing these values together prevents accidental independent generation.
/// The bundle is non-cloneable and non-serializable. Consuming it is the only
/// way to separate the raw credential retained by orchestration from the safe
/// candidate moved into an atomic sign-in finalizer.
pub struct PreparedSessionCredential {
    credential: SessionCredential,
    candidate: PendingSessionCandidate,
}

impl PreparedSessionCredential {
    /// Returns the raw credential for the eventual client response boundary.
    #[must_use]
    pub const fn credential(&self) -> &SessionCredential {
        &self.credential
    }

    /// Returns the generated canonical session ID without exposing the bearer.
    #[must_use]
    pub const fn session_id(&self) -> &SessionId {
        self.candidate.session_id()
    }

    /// Returns the fixed browser or CLI session kind.
    #[must_use]
    pub const fn kind(&self) -> SessionKind {
        self.candidate.kind()
    }

    /// Returns the single clock observation used for session issuance.
    #[must_use]
    pub const fn issued_at(&self) -> UnixTimestamp {
        self.candidate.issued_at()
    }

    /// Returns the absolute idle deadline prepared for persistence.
    #[must_use]
    pub const fn idle_expires_at(&self) -> UnixTimestamp {
        self.candidate.idle_expires_at()
    }

    /// Returns the absolute maximum session deadline prepared for persistence.
    #[must_use]
    pub const fn expires_at(&self) -> UnixTimestamp {
        self.candidate.expires_at()
    }

    /// Separates the raw response credential from the safe finalizer candidate.
    ///
    /// The consuming operation preserves the exact pair and leaves no reusable
    /// preparation bundle behind.
    #[must_use]
    pub fn into_parts(self) -> (SessionCredential, PendingSessionCandidate) {
        (self.credential, self.candidate)
    }
}

impl fmt::Debug for PreparedSessionCredential {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PreparedSessionCredential")
            .field("credential", &"[REDACTED]")
            .field("candidate", &self.candidate)
            .finish()
    }
}

fn derive_hmac(
    key: &StoredHmacKey,
    domain: &[u8],
    kind: SessionKind,
    credential: &SessionCredential,
) -> [u8; 32] {
    let hmac_key = hmac::Key::new(hmac::HMAC_SHA256, key.as_bytes());
    let mut context = hmac::Context::with_key(&hmac_key);
    context.update(domain);
    context.update(kind.audience().as_bytes());
    context.update(&[0]);
    context.update(credential.expose_secret().as_bytes());
    let tag = context.sign();
    let mut digest = [0_u8; 32];
    digest.copy_from_slice(tag.as_ref());
    digest
}

/// Invalid session-credential HMAC keyring configuration.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum SessionCredentialKeyringError {
    /// A configured key ID is not portable in both cookie and bearer syntax.
    #[error("session credential key ID is invalid")]
    InvalidKeyId,
    /// HMAC keys must be exactly 256 bits.
    #[error("session credential key material must be exactly 32 bytes")]
    InvalidKeyLength,
    /// Active and verify-only key IDs must be globally unique.
    #[error("session credential key IDs must be unique")]
    DuplicateKeyId,
    /// Configuration is deliberately bounded to prevent unbounded key lookup state.
    #[error("too many session credential keys are configured")]
    TooManyKeys,
}

/// Validated identity, audience, revision, and lifetimes for one new session.
#[derive(Debug)]
pub struct SessionCredentialIssuance<'a> {
    tenant_id: &'a TenantId,
    human: &'a AuthenticatedHuman,
    kind: SessionKind,
    authorization_revision: u64,
    idle_lifetime_seconds: u64,
    absolute_lifetime_seconds: u64,
}

impl<'a> SessionCredentialIssuance<'a> {
    /// Creates a validated issuance request.
    ///
    /// # Errors
    ///
    /// Rejects a zero authorization revision, fractional or zero lifetimes,
    /// or an idle lifetime longer than the absolute lifetime.
    pub fn new(
        tenant_id: &'a TenantId,
        human: &'a AuthenticatedHuman,
        kind: SessionKind,
        authorization_revision: u64,
        idle_lifetime: Duration,
        absolute_lifetime: Duration,
    ) -> Result<Self, SessionCredentialRequestError> {
        let idle_lifetime_seconds = exact_positive_seconds(idle_lifetime)?;
        let absolute_lifetime_seconds = exact_positive_seconds(absolute_lifetime)?;
        if authorization_revision == 0 {
            return Err(SessionCredentialRequestError::InvalidAuthorizationRevision);
        }
        if idle_lifetime_seconds > absolute_lifetime_seconds {
            return Err(SessionCredentialRequestError::InvalidLifetime);
        }
        Ok(Self {
            tenant_id,
            human,
            kind,
            authorization_revision,
            idle_lifetime_seconds,
            absolute_lifetime_seconds,
        })
    }

    /// Returns the fixed browser or CLI audience kind.
    #[must_use]
    pub const fn kind(&self) -> SessionKind {
        self.kind
    }

    /// Returns the current durable authorization revision captured at issuance.
    #[must_use]
    pub const fn authorization_revision(&self) -> u64 {
        self.authorization_revision
    }
}

fn exact_positive_seconds(duration: Duration) -> Result<u64, SessionCredentialRequestError> {
    if duration.is_zero() || duration.subsec_nanos() != 0 {
        return Err(SessionCredentialRequestError::InvalidLifetime);
    }
    Ok(duration.as_secs())
}

/// Sanitized validation failure for an issuance or touch lifetime request.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum SessionCredentialRequestError {
    /// The current authorization revision is always positive.
    #[error("session authorization revision is invalid")]
    InvalidAuthorizationRevision,
    /// Durable session timestamps use positive whole-second lifetimes.
    #[error("session credential lifetime is invalid")]
    InvalidLifetime,
}

/// A newly persisted session and its one-time returned raw bearer credential.
pub struct IssuedSessionCredential {
    credential: SessionCredential,
    session: DurableSession,
}

impl IssuedSessionCredential {
    /// Returns the raw credential owner. Explicit exposure is still required.
    #[must_use]
    pub const fn credential(&self) -> &SessionCredential {
        &self.credential
    }

    /// Returns the safe durable session metadata persisted for this bearer.
    #[must_use]
    pub const fn session(&self) -> &DurableSession {
        &self.session
    }

    /// Consumes the result into its secret credential and safe metadata.
    #[must_use]
    pub fn into_parts(self) -> (SessionCredential, DurableSession) {
        (self.credential, self.session)
    }
}

impl fmt::Debug for IssuedSessionCredential {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("IssuedSessionCredential")
            .field("credential", &"[REDACTED]")
            .field("session", &self.session)
            .finish()
    }
}

/// Repository-backed opaque session-credential service.
pub struct SessionCredentialService {
    keyring: SessionCredentialKeyring,
    repository: Arc<dyn HumanSessionRepository>,
    random: Arc<dyn SecureRandom>,
    clock: Arc<dyn Clock>,
}

impl SessionCredentialService {
    /// Creates a service over established repository, randomness, and clock ports.
    #[must_use]
    pub fn new(
        keyring: SessionCredentialKeyring,
        repository: Arc<dyn HumanSessionRepository>,
        random: Arc<dyn SecureRandom>,
        clock: Arc<dyn Clock>,
    ) -> Self {
        Self {
            keyring,
            repository,
            random,
            clock,
        }
    }

    /// Prepares a raw credential and its exact safe atomic-sign-in candidate.
    ///
    /// This operation performs no repository I/O and intentionally has no
    /// principal or authorization revision. The finalizer supplies those values
    /// from its atomic durable identity-admission transaction.
    ///
    /// # Errors
    ///
    /// Rejects zero, fractional, or inconsistent lifetimes and fails on clock
    /// overflow, unavailable randomness, or an internal invariant violation.
    pub fn prepare(
        &self,
        kind: SessionKind,
        idle_lifetime: Duration,
        absolute_lifetime: Duration,
    ) -> Result<PreparedSessionCredential, SessionCredentialServiceError> {
        let idle_lifetime_seconds = exact_positive_seconds(idle_lifetime)
            .map_err(|_| SessionCredentialServiceError::InvalidLifetime)?;
        let absolute_lifetime_seconds = exact_positive_seconds(absolute_lifetime)
            .map_err(|_| SessionCredentialServiceError::InvalidLifetime)?;
        if idle_lifetime_seconds > absolute_lifetime_seconds {
            return Err(SessionCredentialServiceError::InvalidLifetime);
        }
        self.prepare_seconds(kind, idle_lifetime_seconds, absolute_lifetime_seconds)
    }

    /// Issues and durably creates a fresh opaque browser or CLI session.
    ///
    /// Session-ID and token-digest conflicts cause a complete fresh retry. The
    /// retry count is fixed and bounded.
    ///
    /// # Errors
    ///
    /// Fails on timestamp overflow, unavailable randomness or storage, corrupt
    /// repository behavior, or exhaustion of the collision budget.
    pub async fn issue(
        &self,
        request: SessionCredentialIssuance<'_>,
    ) -> Result<IssuedSessionCredential, SessionCredentialServiceError> {
        for _ in 0..MAX_SESSION_CREDENTIAL_ISSUE_ATTEMPTS {
            let prepared = self.prepare_seconds(
                request.kind,
                request.idle_lifetime_seconds,
                request.absolute_lifetime_seconds,
            )?;
            let (credential, candidate) = prepared.into_parts();
            let session = Self::build_session(&request, &candidate)?;
            let create = CreateSession::new(candidate.lookup().clone(), session.clone());
            match self
                .repository
                .create(create)
                .await
                .map_err(map_repository_error)?
            {
                CreateSessionOutcome::Created => {
                    return Ok(IssuedSessionCredential {
                        credential,
                        session,
                    });
                }
                CreateSessionOutcome::SessionIdConflict
                | CreateSessionOutcome::TokenDigestConflict => {}
            }
        }
        Err(SessionCredentialServiceError::CollisionLimitExceeded)
    }

    /// Resolves one raw bearer without passing it across the repository port.
    ///
    /// # Errors
    ///
    /// Rejects malformed and unknown-key credentials and sanitizes repository
    /// failures. Active records inconsistent with the expected audience fail closed.
    pub async fn resolve_raw(
        &self,
        raw: &str,
        expected_kind: SessionKind,
    ) -> Result<ResolveSessionOutcome, SessionCredentialServiceError> {
        let lookup = self.derive_lookup_raw(raw, expected_kind)?;
        let now = self.clock.now();
        let resolve = ResolveSession::new(lookup, expected_kind, now);
        let outcome = self
            .repository
            .resolve(&resolve)
            .await
            .map_err(map_repository_error)?;
        if let ResolveSessionOutcome::Active(session) = &outcome
            && !is_active_for(session, expected_kind, now)
        {
            return Err(SessionCredentialServiceError::InternalFailure);
        }
        Ok(outcome)
    }

    /// Activates one exact CLI bearer after the client has durably stored it.
    ///
    /// Only the CLI-domain-separated lookup digest crosses the repository
    /// boundary. A valid already-active replay succeeds idempotently, while all
    /// closed repository outcomes remain distinguishable to the HTTP adapter.
    ///
    /// # Errors
    ///
    /// Rejects malformed and unknown-key credentials and sanitizes repository
    /// failures. Successful outcomes with inconsistent metadata fail closed.
    pub async fn activate_cli_raw(
        &self,
        raw: &str,
    ) -> Result<ActivateCliSessionOutcome, SessionCredentialServiceError> {
        let lookup = self.derive_lookup_raw(raw, SessionKind::Cli)?;
        let now = self.clock.now();
        let request = ActivateCliSession::new(lookup, now);
        let outcome = self
            .repository
            .activate_cli(&request)
            .await
            .map_err(map_repository_error)?;
        match &outcome {
            ActivateCliSessionOutcome::Activated(session)
            | ActivateCliSessionOutcome::AlreadyActive(session)
                if !is_active_for(session, SessionKind::Cli, now) =>
            {
                Err(SessionCredentialServiceError::InternalFailure)
            }
            _ => Ok(outcome),
        }
    }

    /// Extends one raw bearer's idle deadline through the durable repository.
    ///
    /// # Errors
    ///
    /// Rejects malformed credentials and non-whole-second lifetimes, timestamp
    /// overflow, or sanitized repository failures.
    pub async fn touch_raw(
        &self,
        raw: &str,
        expected_kind: SessionKind,
        idle_lifetime: Duration,
    ) -> Result<TouchSessionOutcome, SessionCredentialServiceError> {
        let idle_seconds = exact_positive_seconds(idle_lifetime)
            .map_err(|_| SessionCredentialServiceError::InvalidLifetime)?;
        let lookup = self.derive_lookup_raw(raw, expected_kind)?;
        let now = self.clock.now();
        let idle_expires_at = now
            .checked_add(idle_seconds)
            .map_err(|_| SessionCredentialServiceError::LifetimeOverflow)?;
        let touch = TouchSession::new(lookup, expected_kind, now, idle_expires_at)
            .map_err(|_| SessionCredentialServiceError::InvalidLifetime)?;
        let outcome = self
            .repository
            .touch(&touch)
            .await
            .map_err(map_repository_error)?;
        match &outcome {
            TouchSessionOutcome::Touched(session) | TouchSessionOutcome::Unchanged(session)
                if !is_active_for(session, expected_kind, now) =>
            {
                Err(SessionCredentialServiceError::InternalFailure)
            }
            _ => Ok(outcome),
        }
    }

    /// Resolves and revokes the exact session owned by one raw bearer.
    ///
    /// Non-active credentials collapse to an idempotent `NotFound` or
    /// `AlreadyRevoked` outcome. Only safe identity metadata crosses into the
    /// revocation request.
    ///
    /// # Errors
    ///
    /// Rejects malformed credentials and sanitizes repository failures.
    pub async fn revoke_raw(
        &self,
        raw: &str,
        expected_kind: SessionKind,
    ) -> Result<RevokeOwnSessionOutcome, SessionCredentialServiceError> {
        let lookup = self.derive_lookup_raw(raw, expected_kind)?;
        let now = self.clock.now();
        let resolve = ResolveSession::new(lookup, expected_kind, now);
        let resolved = self
            .repository
            .resolve(&resolve)
            .await
            .map_err(map_repository_error)?;
        let session = match resolved {
            ResolveSessionOutcome::Active(session)
                if is_active_for(&session, expected_kind, now) =>
            {
                session
            }
            ResolveSessionOutcome::Active(_) => {
                return Err(SessionCredentialServiceError::InternalFailure);
            }
            ResolveSessionOutcome::Revoked => {
                return Ok(RevokeOwnSessionOutcome::AlreadyRevoked);
            }
            ResolveSessionOutcome::NotFound
            | ResolveSessionOutcome::WrongKindOrAudience
            | ResolveSessionOutcome::Expired
            | ResolveSessionOutcome::NotYetValid
            | ResolveSessionOutcome::PrincipalDisabled
            | ResolveSessionOutcome::MembershipSuspended
            | ResolveSessionOutcome::AuthorizationRevisionChanged { .. } => {
                return Ok(RevokeOwnSessionOutcome::NotFound);
            }
        };
        let identity = session.identity();
        let revoke = RevokeOwnSession::new(
            identity.tenant_id().clone(),
            identity.principal_id().clone(),
            identity.session_id().clone(),
            now,
        );
        self.repository
            .revoke_own(&revoke)
            .await
            .map_err(map_repository_error)
    }

    /// Derives the browser double-submit CSRF token for one raw credential.
    ///
    /// The CSRF HMAC domain is independent from durable lookup derivation.
    ///
    /// # Errors
    ///
    /// Rejects malformed credentials and credentials naming an unknown key.
    pub fn derive_csrf_raw(
        &self,
        raw: &str,
        expected_kind: SessionKind,
    ) -> Result<CsrfToken, SessionCredentialServiceError> {
        let credential = parse_raw(raw)?;
        self.keyring
            .csrf_for_verification(&credential, expected_kind)
    }

    /// Converts a raw bearer into the only safe value accepted by session storage.
    ///
    /// Parsing selects the public key ID directly, and the fixed browser or CLI
    /// audience is authenticated into the lookup HMAC. No clock or repository
    /// operation occurs at this boundary.
    ///
    /// # Errors
    ///
    /// Rejects malformed credentials and credentials naming an unknown key.
    pub fn derive_lookup_raw(
        &self,
        raw: &str,
        expected_kind: SessionKind,
    ) -> Result<SessionTokenLookup, SessionCredentialServiceError> {
        let credential = parse_raw(raw)?;
        self.keyring
            .lookup_for_verification(&credential, expected_kind)
    }

    fn generate_credential(&self) -> Result<SessionCredential, SessionCredentialServiceError> {
        let mut secret = Zeroizing::new([0_u8; SESSION_CREDENTIAL_SECRET_BYTES]);
        self.random
            .fill(secret.as_mut())
            .map_err(|_| SessionCredentialServiceError::RandomnessUnavailable)?;
        let encoded_secret = Zeroizing::new(URL_SAFE_NO_PAD.encode(secret.as_ref()));
        let encoded = format!(
            "{SESSION_CREDENTIAL_VERSION}{SESSION_CREDENTIAL_SEPARATOR}{}{SESSION_CREDENTIAL_SEPARATOR}{}",
            self.keyring.active_key_id().as_str(),
            encoded_secret.as_str()
        );
        SessionCredential::parse(
            SecretString::new(encoded)
                .map_err(|_| SessionCredentialServiceError::InternalFailure)?,
        )
        .map_err(|_| SessionCredentialServiceError::InternalFailure)
    }

    fn prepare_seconds(
        &self,
        kind: SessionKind,
        idle_lifetime_seconds: u64,
        absolute_lifetime_seconds: u64,
    ) -> Result<PreparedSessionCredential, SessionCredentialServiceError> {
        let issued_at = self.clock.now();
        let idle_expires_at = issued_at
            .checked_add(idle_lifetime_seconds)
            .map_err(|_| SessionCredentialServiceError::LifetimeOverflow)?;
        let expires_at = issued_at
            .checked_add(absolute_lifetime_seconds)
            .map_err(|_| SessionCredentialServiceError::LifetimeOverflow)?;
        let credential = self.generate_credential()?;
        let session_id = generate_session_id(self.random.as_ref())?;
        let lookup = self.keyring.lookup_for_issuance(&credential, kind)?;
        let candidate = PendingSessionCandidate::new(
            session_id,
            lookup,
            kind,
            issued_at,
            idle_expires_at,
            expires_at,
        )
        .map_err(|_| SessionCredentialServiceError::InternalFailure)?;
        Ok(PreparedSessionCredential {
            credential,
            candidate,
        })
    }

    fn build_session(
        request: &SessionCredentialIssuance<'_>,
        candidate: &PendingSessionCandidate,
    ) -> Result<DurableSession, SessionCredentialServiceError> {
        let identity = DurableSessionIdentity::new(
            candidate.session_id().clone(),
            request.tenant_id.clone(),
            request.human.principal_id().clone(),
            request.human.provider_id().clone(),
            request.human.provider_subject().clone(),
            candidate.kind(),
        )
        .map_err(|_| SessionCredentialServiceError::InternalFailure)?;
        DurableSession::new(
            identity,
            request.authorization_revision,
            candidate.issued_at(),
            candidate.issued_at(),
            candidate.idle_expires_at(),
            candidate.expires_at(),
            None,
        )
        .map_err(|_| SessionCredentialServiceError::InternalFailure)
    }
}

impl fmt::Debug for SessionCredentialService {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SessionCredentialService")
            .field("keyring", &self.keyring)
            .field("repository", &self.repository)
            .field("random", &"[REDACTED]")
            .field("clock", &self.clock)
            .finish()
    }
}

fn parse_raw(raw: &str) -> Result<SessionCredential, SessionCredentialServiceError> {
    SessionCredential::from_raw(raw).map_err(|_| SessionCredentialServiceError::InvalidCredential)
}

fn generate_session_id(
    random: &dyn SecureRandom,
) -> Result<SessionId, SessionCredentialServiceError> {
    let mut bytes = Zeroizing::new([0_u8; 16]);
    random
        .fill(bytes.as_mut())
        .map_err(|_| SessionCredentialServiceError::RandomnessUnavailable)?;
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    let id = uuid::Uuid::from_bytes(*bytes).hyphenated().to_string();
    SessionId::new(id).map_err(|_| SessionCredentialServiceError::InternalFailure)
}

fn is_active_for(session: &DurableSession, expected_kind: SessionKind, now: UnixTimestamp) -> bool {
    session.identity().kind() == expected_kind
        && session.identity().audience() == expected_kind.audience()
        && session.revoked_at().is_none()
        && session.issued_at() <= now
        && session.idle_expires_at() > now
        && session.expires_at() > now
}

fn map_repository_error(error: SessionRepositoryError) -> SessionCredentialServiceError {
    match error {
        SessionRepositoryError::Unavailable => SessionCredentialServiceError::RepositoryUnavailable,
        SessionRepositoryError::InvalidRequest | SessionRepositoryError::CorruptData => {
            SessionCredentialServiceError::InternalFailure
        }
    }
}

/// Sanitized runtime failure from session-credential operations.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum SessionCredentialServiceError {
    /// The raw bearer is malformed or names no configured verification key.
    #[error("session credential is invalid")]
    InvalidCredential,
    /// A preparation or touch lifetime is zero, fractional, or inconsistent.
    #[error("session credential lifetime is invalid")]
    InvalidLifetime,
    /// Absolute or idle expiry exceeded the timestamp domain.
    #[error("session credential lifetime is outside the supported range")]
    LifetimeOverflow,
    /// Secure random generation failed.
    #[error("session credential service is temporarily unavailable")]
    RandomnessUnavailable,
    /// All bounded session-ID or token-digest collision retries were consumed.
    #[error("session credential service could not allocate a unique session")]
    CollisionLimitExceeded,
    /// Durable storage is transiently unavailable.
    #[error("session credential storage is temporarily unavailable")]
    RepositoryUnavailable,
    /// An internal domain or repository invariant failed closed.
    #[error("session credential operation could not be completed")]
    InternalFailure,
}
