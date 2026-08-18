//! Instance-scoped authorization, identity, and membership provider ports.

use std::{collections::BTreeMap, fmt, future::Future, pin::Pin};

use automata_ci_secret::SecretValue;
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use sha2::{Digest as _, Sha256};
use thiserror::Error;
use url::{Host, Url};

use crate::{ExternalSubjectIdentity, ExternalSubjectKind, ProviderInstanceId};
use automata_ci_core::UnixMillis;

/// Maximum provider login bytes retained as display metadata.
pub const MAX_PROVIDER_LOGIN_BYTES: usize = 255;
/// Maximum provider display-name bytes.
pub const MAX_PROVIDER_DISPLAY_NAME_BYTES: usize = 1_024;
/// Maximum membership role bytes.
pub const MAX_PROVIDER_MEMBERSHIP_ROLE_BYTES: usize = 128;
/// Maximum memberships in one complete snapshot.
pub const MAX_PROVIDER_MEMBERSHIPS: usize = 4_096;
/// Maximum device poll interval.
pub const MAX_PROVIDER_DEVICE_POLL_MILLIS: u64 = 5 * 60 * 1_000;

/// Validated exact OAuth callback selected by the common login service.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ProviderCallbackUri {
    /// Exact credential-free HTTPS web callback.
    Web(Url),
    /// HTTP callback on a literal loopback address and explicit ephemeral port.
    Loopback(Url),
}

impl ProviderCallbackUri {
    /// Creates an exact web callback.
    ///
    /// # Errors
    ///
    /// Rejects non-HTTPS, credential-bearing, query-bearing, or fragment-bearing URLs.
    pub fn web(value: Url) -> Result<Self, ProviderHumanModelError> {
        if value.scheme() != "https" || !safe_callback(&value) {
            return Err(ProviderHumanModelError::InvalidCallbackUri);
        }
        Ok(Self::Web(value))
    }

    /// Creates an RFC 8252-style literal loopback callback.
    ///
    /// # Errors
    ///
    /// Rejects hostnames, non-loopback addresses, absent ports, or unsafe URL parts.
    pub fn loopback(value: Url) -> Result<Self, ProviderHumanModelError> {
        let loopback = value.host().is_some_and(|host| match host {
            Host::Ipv4(address) => address.is_loopback(),
            Host::Ipv6(address) => address.is_loopback(),
            Host::Domain(_) => false,
        });
        if value.scheme() != "http" || value.port().is_none() || !loopback || !safe_callback(&value)
        {
            return Err(ProviderHumanModelError::InvalidCallbackUri);
        }
        Ok(Self::Loopback(value))
    }

    /// Returns the exact callback URL.
    #[must_use]
    pub const fn as_url(&self) -> &Url {
        match self {
            Self::Web(value) | Self::Loopback(value) => value,
        }
    }

    /// Returns whether the callback is a CLI loopback callback.
    #[must_use]
    pub const fn is_loopback(&self) -> bool {
        matches!(self, Self::Loopback(_))
    }
}

/// RFC 7636 verifier retained as zeroizing secret material.
pub struct ProviderPkceVerifier(SecretValue);

impl ProviderPkceVerifier {
    /// Creates a verifier using the RFC 7636 unreserved grammar and bounds.
    ///
    /// # Errors
    ///
    /// Rejects values outside 43..=128 ASCII bytes or the unreserved grammar.
    pub fn new(value: String) -> Result<Self, ProviderHumanModelError> {
        if !(43..=128).contains(&value.len())
            || !value.bytes().all(|byte| {
                byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~')
            })
        {
            return Err(ProviderHumanModelError::InvalidPkceVerifier);
        }
        SecretValue::from_utf8(value)
            .map(Self)
            .map_err(|_| ProviderHumanModelError::InvalidPkceVerifier)
    }

    /// Derives the mandatory URL-safe, unpadded S256 challenge.
    #[must_use]
    pub fn s256_challenge(&self) -> String {
        URL_SAFE_NO_PAD.encode(Sha256::digest(self.0.expose_secret()))
    }

    /// Exposes the verifier only for the token exchange request.
    #[must_use]
    pub fn expose_secret(&self) -> &[u8] {
        self.0.expose_secret()
    }
}

impl fmt::Debug for ProviderPkceVerifier {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ProviderPkceVerifier([REDACTED])")
    }
}

/// Immutable authorization-code transaction input retained by the common service.
pub struct AuthorizationCodeRequest {
    instance_id: ProviderInstanceId,
    callback: ProviderCallbackUri,
    state: SecretValue,
    nonce: SecretValue,
    verifier: ProviderPkceVerifier,
    created_at: UnixMillis,
    expires_at: UnixMillis,
}

impl AuthorizationCodeRequest {
    /// Creates a bounded state-, nonce-, callback-, and PKCE-bound request.
    ///
    /// # Errors
    ///
    /// Rejects invalid or excessive transaction lifetimes.
    pub fn new(
        instance_id: ProviderInstanceId,
        callback: ProviderCallbackUri,
        state: SecretValue,
        nonce: SecretValue,
        verifier: ProviderPkceVerifier,
        created_at: UnixMillis,
        expires_at: UnixMillis,
    ) -> Result<Self, ProviderHumanModelError> {
        let lifetime = expires_at.get().checked_sub(created_at.get());
        if created_at.get() < 0
            || lifetime.is_none_or(|value| !(60_000..=30 * 60 * 1_000).contains(&value))
        {
            return Err(ProviderHumanModelError::InvalidTransactionLifetime);
        }
        if state.expose_secret() == nonce.expose_secret() {
            return Err(ProviderHumanModelError::NonIndependentProofs);
        }
        Ok(Self {
            instance_id,
            callback,
            state,
            nonce,
            verifier,
            created_at,
            expires_at,
        })
    }
    /// Returns the provider instance.
    #[must_use]
    pub const fn instance_id(&self) -> ProviderInstanceId {
        self.instance_id
    }
    /// Returns the exact callback.
    #[must_use]
    pub const fn callback(&self) -> &ProviderCallbackUri {
        &self.callback
    }
    /// Exposes OAuth state only while constructing or verifying the provider request.
    #[must_use]
    pub fn expose_state(&self) -> &[u8] {
        self.state.expose_secret()
    }
    /// Exposes OIDC nonce only at the provider protocol boundary.
    #[must_use]
    pub fn expose_nonce(&self) -> &[u8] {
        self.nonce.expose_secret()
    }
    /// Returns the PKCE verifier.
    #[must_use]
    pub const fn verifier(&self) -> &ProviderPkceVerifier {
        &self.verifier
    }
    /// Returns transaction creation time.
    #[must_use]
    pub const fn created_at(&self) -> UnixMillis {
        self.created_at
    }
    /// Returns the exclusive transaction deadline.
    #[must_use]
    pub const fn expires_at(&self) -> UnixMillis {
        self.expires_at
    }
}

impl fmt::Debug for AuthorizationCodeRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AuthorizationCodeRequest")
            .field("instance_id", &self.instance_id)
            .field("callback", &self.callback)
            .field("state", &"[REDACTED]")
            .field("nonce", &"[REDACTED]")
            .field("verifier", &"[REDACTED]")
            .field("created_at", &self.created_at)
            .field("expires_at", &self.expires_at)
            .finish()
    }
}

/// Provider authorization URL with its secret-bearing query redacted from diagnostics.
#[derive(Eq, PartialEq)]
pub struct ProviderAuthorizationUrl(Url);

impl ProviderAuthorizationUrl {
    /// Wraps a credential-free HTTPS authorization URL.
    ///
    /// # Errors
    ///
    /// Rejects non-HTTPS, credential-bearing, or fragment-bearing URLs.
    pub fn new(value: Url) -> Result<Self, ProviderHumanModelError> {
        if value.scheme() != "https"
            || value.host().is_none()
            || !value.username().is_empty()
            || value.password().is_some()
            || value.fragment().is_some()
        {
            return Err(ProviderHumanModelError::InvalidAuthorizationUrl);
        }
        Ok(Self(value))
    }
    /// Returns the authorization URL only to the redirect response boundary.
    #[must_use]
    pub const fn as_url(&self) -> &Url {
        &self.0
    }
}

impl fmt::Debug for ProviderAuthorizationUrl {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ProviderAuthorizationUrl([REDACTED])")
    }
}

/// Authorization code exchange bound to its original transaction.
pub struct AuthorizationCodeExchange {
    request: AuthorizationCodeRequest,
    code: SecretValue,
    received_at: UnixMillis,
}

impl AuthorizationCodeExchange {
    /// Creates a single-use code exchange before the transaction deadline.
    ///
    /// # Errors
    ///
    /// Rejects callbacks outside the transaction interval.
    pub fn new(
        request: AuthorizationCodeRequest,
        code: SecretValue,
        received_at: UnixMillis,
    ) -> Result<Self, ProviderHumanModelError> {
        if received_at < request.created_at || received_at >= request.expires_at {
            return Err(ProviderHumanModelError::ExpiredTransaction);
        }
        Ok(Self {
            request,
            code,
            received_at,
        })
    }
    /// Returns the original request.
    #[must_use]
    pub const fn request(&self) -> &AuthorizationCodeRequest {
        &self.request
    }
    /// Exposes the single-use provider code only at token exchange.
    #[must_use]
    pub fn expose_code(&self) -> &[u8] {
        self.code.expose_secret()
    }
    /// Returns callback receipt time.
    #[must_use]
    pub const fn received_at(&self) -> UnixMillis {
        self.received_at
    }
}

impl fmt::Debug for AuthorizationCodeExchange {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AuthorizationCodeExchange")
            .field("request", &self.request)
            .field("code", &"[REDACTED]")
            .field("received_at", &self.received_at)
            .finish()
    }
}

/// Security authority represented by one human OAuth token.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProviderHumanCredentialAuthority {
    /// Provider scopes constrain the token to identity and membership reads.
    Scoped,
    /// Provider scopes do not constrain API authority; use remains human-identity-only.
    Unrestricted,
}

/// Secret-bearing human provider credential; never an Automata session token.
pub struct ProviderHumanCredential {
    instance_id: ProviderInstanceId,
    access_token: SecretValue,
    refresh_token: Option<SecretValue>,
    authority: ProviderHumanCredentialAuthority,
    issued_at: UnixMillis,
    expires_at: Option<UnixMillis>,
}

impl ProviderHumanCredential {
    /// Creates a human-only credential with coherent optional expiry.
    ///
    /// # Errors
    ///
    /// Rejects invalid timestamps or non-future expiry.
    pub fn new(
        instance_id: ProviderInstanceId,
        access_token: SecretValue,
        refresh_token: Option<SecretValue>,
        authority: ProviderHumanCredentialAuthority,
        issued_at: UnixMillis,
        expires_at: Option<UnixMillis>,
    ) -> Result<Self, ProviderHumanModelError> {
        if issued_at.get() < 0 || expires_at.is_some_and(|value| value <= issued_at) {
            return Err(ProviderHumanModelError::InvalidCredentialLifetime);
        }
        Ok(Self {
            instance_id,
            access_token,
            refresh_token,
            authority,
            issued_at,
            expires_at,
        })
    }
    /// Returns the provider instance namespace.
    #[must_use]
    pub const fn instance_id(&self) -> ProviderInstanceId {
        self.instance_id
    }
    /// Exposes the access token only to human identity/membership provider calls.
    #[must_use]
    pub fn expose_access_token(&self) -> &[u8] {
        self.access_token.expose_secret()
    }
    /// Exposes the refresh token only to the authorization provider.
    #[must_use]
    pub fn expose_refresh_token(&self) -> Option<&[u8]> {
        self.refresh_token.as_ref().map(SecretValue::expose_secret)
    }
    /// Returns the declared provider token authority risk.
    #[must_use]
    pub const fn authority(&self) -> ProviderHumanCredentialAuthority {
        self.authority
    }
    /// Returns provider issuance time.
    #[must_use]
    pub const fn issued_at(&self) -> UnixMillis {
        self.issued_at
    }
    /// Returns provider expiry when supplied.
    #[must_use]
    pub const fn expires_at(&self) -> Option<UnixMillis> {
        self.expires_at
    }
    /// Consumes the credential into provider instance, zeroizing tokens, authority, and lifetime evidence.
    #[must_use]
    pub fn into_parts(
        self,
    ) -> (
        ProviderInstanceId,
        SecretValue,
        Option<SecretValue>,
        ProviderHumanCredentialAuthority,
        UnixMillis,
        Option<UnixMillis>,
    ) {
        (
            self.instance_id,
            self.access_token,
            self.refresh_token,
            self.authority,
            self.issued_at,
            self.expires_at,
        )
    }
}

impl fmt::Debug for ProviderHumanCredential {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProviderHumanCredential")
            .field("instance_id", &self.instance_id)
            .field("access_token", &"[REDACTED]")
            .field(
                "refresh_token",
                &self.refresh_token.as_ref().map(|_| "[REDACTED]"),
            )
            .field("authority", &self.authority)
            .field("issued_at", &self.issued_at)
            .field("expires_at", &self.expires_at)
            .finish()
    }
}

/// Future returned by authorization-code provider operations.
pub type AuthorizationCodeFuture<'a> = Pin<
    Box<
        dyn Future<Output = Result<ProviderHumanCredential, ProviderHumanProviderError>>
            + Send
            + 'a,
    >,
>;

/// Provider authorization-code adapter. S256 PKCE is mandatory in the common request.
pub trait AuthorizationCodeProvider: fmt::Debug + Send + Sync {
    /// Builds an instance-configured authorization URL for one exact request.
    ///
    /// # Errors
    ///
    /// Returns a sanitized provider error when configuration cannot safely
    /// represent the requested callback or flow.
    fn authorization_url(
        &self,
        request: &AuthorizationCodeRequest,
    ) -> Result<ProviderAuthorizationUrl, ProviderHumanProviderError>;
    /// Exchanges one single-use callback code.
    fn exchange<'a>(
        &'a self,
        request: &'a AuthorizationCodeExchange,
    ) -> AuthorizationCodeFuture<'a>;
    /// Refreshes a human credential when refresh material is available.
    fn refresh<'a>(
        &'a self,
        credential: &'a ProviderHumanCredential,
        observed_at: UnixMillis,
    ) -> AuthorizationCodeFuture<'a>;
}

/// Secret-bearing provider device authorization under bounded polling policy.
pub struct DeviceAuthorization {
    instance_id: ProviderInstanceId,
    device_code: SecretValue,
    user_code: SecretValue,
    verification_url: ProviderAuthorizationUrl,
    created_at: UnixMillis,
    expires_at: UnixMillis,
    next_poll_at: UnixMillis,
    poll_interval_millis: u64,
}

impl DeviceAuthorization {
    /// Creates validated device authorization state.
    ///
    /// # Errors
    ///
    /// Rejects invalid deadlines or poll intervals.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        instance_id: ProviderInstanceId,
        device_code: SecretValue,
        user_code: SecretValue,
        verification_url: ProviderAuthorizationUrl,
        created_at: UnixMillis,
        expires_at: UnixMillis,
        next_poll_at: UnixMillis,
        poll_interval_millis: u64,
    ) -> Result<Self, ProviderHumanModelError> {
        if created_at.get() < 0
            || created_at >= next_poll_at
            || next_poll_at >= expires_at
            || poll_interval_millis == 0
            || poll_interval_millis > MAX_PROVIDER_DEVICE_POLL_MILLIS
        {
            return Err(ProviderHumanModelError::InvalidDeviceAuthorization);
        }
        Ok(Self {
            instance_id,
            device_code,
            user_code,
            verification_url,
            created_at,
            expires_at,
            next_poll_at,
            poll_interval_millis,
        })
    }
    /// Returns the provider instance.
    #[must_use]
    pub const fn instance_id(&self) -> ProviderInstanceId {
        self.instance_id
    }
    /// Exposes the device code only to the provider poll request.
    #[must_use]
    pub fn expose_device_code(&self) -> &[u8] {
        self.device_code.expose_secret()
    }
    /// Exposes the display code only to the initiating CLI.
    #[must_use]
    pub fn expose_user_code(&self) -> &[u8] {
        self.user_code.expose_secret()
    }
    /// Returns the trusted verification URL.
    #[must_use]
    pub const fn verification_url(&self) -> &ProviderAuthorizationUrl {
        &self.verification_url
    }
    /// Returns creation time.
    #[must_use]
    pub const fn created_at(&self) -> UnixMillis {
        self.created_at
    }
    /// Returns expiry.
    #[must_use]
    pub const fn expires_at(&self) -> UnixMillis {
        self.expires_at
    }
    /// Returns earliest next poll.
    #[must_use]
    pub const fn next_poll_at(&self) -> UnixMillis {
        self.next_poll_at
    }
    /// Returns current minimum poll interval.
    #[must_use]
    pub const fn poll_interval_millis(&self) -> u64 {
        self.poll_interval_millis
    }
}

impl fmt::Debug for DeviceAuthorization {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DeviceAuthorization")
            .field("instance_id", &self.instance_id)
            .field("device_code", &"[REDACTED]")
            .field("user_code", &"[REDACTED]")
            .field("verification_url", &self.verification_url)
            .field("created_at", &self.created_at)
            .field("expires_at", &self.expires_at)
            .field("next_poll_at", &self.next_poll_at)
            .field("poll_interval_millis", &self.poll_interval_millis)
            .finish()
    }
}

/// Closed result of one permitted device poll.
#[derive(Debug)]
pub enum DeviceAuthorizationPoll {
    /// Authorization remains pending with provider-directed next poll time.
    Pending {
        /// Earliest next poll.
        next_poll_at: UnixMillis,
    },
    /// The human denied the authorization request.
    Denied,
    /// Authorization completed with a human-only provider credential.
    Complete(ProviderHumanCredential),
}

/// Future returned by optional device authorization operations.
pub type DeviceAuthorizationFuture<'a, T> =
    Pin<Box<dyn Future<Output = Result<T, ProviderHumanProviderError>> + Send + 'a>>;

/// Optional provider device authorization adapter.
pub trait DeviceAuthorizationProvider: fmt::Debug + Send + Sync {
    /// Starts device authorization for one exact provider instance.
    fn begin(
        &self,
        instance_id: ProviderInstanceId,
        requested_at: UnixMillis,
    ) -> DeviceAuthorizationFuture<'_, DeviceAuthorization>;
    /// Polls no earlier than the durable provider-directed deadline.
    fn poll<'a>(
        &'a self,
        authorization: &'a DeviceAuthorization,
        observed_at: UnixMillis,
    ) -> DeviceAuthorizationFuture<'a, DeviceAuthorizationPoll>;
}

/// Stable provider human identity with bounded mutable display metadata.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProviderHumanIdentity {
    subject: ExternalSubjectIdentity,
    login: String,
    display_name: Option<String>,
    observed_at: UnixMillis,
}

impl ProviderHumanIdentity {
    /// Creates an instance-scoped user identity.
    ///
    /// # Errors
    ///
    /// Rejects non-user subjects or unsafe display metadata.
    pub fn new(
        subject: ExternalSubjectIdentity,
        login: impl Into<String>,
        display_name: Option<String>,
        observed_at: UnixMillis,
    ) -> Result<Self, ProviderHumanModelError> {
        let login = login.into();
        if subject.kind() != ExternalSubjectKind::User
            || observed_at.get() < 0
            || !valid_display(&login, MAX_PROVIDER_LOGIN_BYTES, false)
            || display_name
                .as_ref()
                .is_some_and(|value| !valid_display(value, MAX_PROVIDER_DISPLAY_NAME_BYTES, true))
        {
            return Err(ProviderHumanModelError::InvalidIdentity);
        }
        Ok(Self {
            subject,
            login,
            display_name,
            observed_at,
        })
    }
    /// Returns the stable instance-scoped user subject.
    #[must_use]
    pub const fn subject(&self) -> &ExternalSubjectIdentity {
        &self.subject
    }
    /// Returns mutable provider login metadata.
    #[must_use]
    pub fn login(&self) -> &str {
        &self.login
    }
    /// Returns optional display metadata.
    #[must_use]
    pub fn display_name(&self) -> Option<&str> {
        self.display_name.as_deref()
    }
    /// Returns trusted observation time.
    #[must_use]
    pub const fn observed_at(&self) -> UnixMillis {
        self.observed_at
    }
}

/// Future returned by identity reads.
pub type IdentityReaderFuture<'a> = Pin<
    Box<dyn Future<Output = Result<ProviderHumanIdentity, ProviderHumanProviderError>> + Send + 'a>,
>;

/// Narrow adapter port for re-reading the authenticated stable human identity.
pub trait IdentityReader: fmt::Debug + Send + Sync {
    /// Reads the current identity and verifies the credential's exact instance.
    fn identity<'a>(
        &'a self,
        credential: &'a ProviderHumanCredential,
        observed_at: UnixMillis,
    ) -> IdentityReaderFuture<'a>;
}

/// Provider membership role retained as non-authoritative bounded evidence.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProviderMembershipRole(String);

impl ProviderMembershipRole {
    /// Creates a canonical lowercase provider role.
    ///
    /// # Errors
    ///
    /// Rejects empty, oversized, or noncanonical roles.
    pub fn new(value: impl Into<String>) -> Result<Self, ProviderHumanModelError> {
        let value = value.into();
        if value.is_empty()
            || value.len() > MAX_PROVIDER_MEMBERSHIP_ROLE_BYTES
            || !value
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
        {
            return Err(ProviderHumanModelError::InvalidMembership);
        }
        Ok(Self(value))
    }
    /// Returns canonical role evidence.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// One organization or team membership keyed only by stable identities.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProviderMembership {
    group: ExternalSubjectIdentity,
    parent: Option<ExternalSubjectIdentity>,
    role: Option<ProviderMembershipRole>,
}

impl ProviderMembership {
    /// Creates structurally valid organization or nested-team membership evidence.
    ///
    /// # Errors
    ///
    /// Rejects wrong kinds, cross-instance parents, or malformed hierarchy.
    pub fn new(
        group: ExternalSubjectIdentity,
        parent: Option<ExternalSubjectIdentity>,
        role: Option<ProviderMembershipRole>,
    ) -> Result<Self, ProviderHumanModelError> {
        let valid = match group.kind() {
            ExternalSubjectKind::Organization => parent.is_none(),
            ExternalSubjectKind::Team => parent.as_ref().is_some_and(|parent| {
                parent.kind() == ExternalSubjectKind::Organization
                    && parent.instance_id() == group.instance_id()
            }),
            ExternalSubjectKind::User | ExternalSubjectKind::ServiceAccount => false,
        };
        if !valid {
            return Err(ProviderHumanModelError::InvalidMembership);
        }
        Ok(Self {
            group,
            parent,
            role,
        })
    }
    /// Returns the stable organization or team.
    #[must_use]
    pub const fn group(&self) -> &ExternalSubjectIdentity {
        &self.group
    }
    /// Returns a team's stable parent organization.
    #[must_use]
    pub const fn parent(&self) -> Option<&ExternalSubjectIdentity> {
        self.parent.as_ref()
    }
    /// Returns provider role evidence when available.
    #[must_use]
    pub const fn role(&self) -> Option<&ProviderMembershipRole> {
        self.role.as_ref()
    }
}

/// Complete bounded membership observation for one exact user and instance.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProviderMembershipSnapshot {
    identity: ProviderHumanIdentity,
    memberships: BTreeMap<ExternalSubjectIdentity, ProviderMembership>,
    observed_at: UnixMillis,
}

impl ProviderMembershipSnapshot {
    /// Creates a complete canonical snapshot.
    ///
    /// # Errors
    ///
    /// Rejects duplicates, cross-instance evidence, missing parents, or excessive entries.
    pub fn new(
        identity: ProviderHumanIdentity,
        memberships: impl IntoIterator<Item = ProviderMembership>,
        observed_at: UnixMillis,
    ) -> Result<Self, ProviderHumanModelError> {
        if observed_at < identity.observed_at {
            return Err(ProviderHumanModelError::InvalidMembership);
        }
        let instance_id = identity.subject.instance_id();
        let mut values = BTreeMap::new();
        for membership in memberships {
            if values.len() >= MAX_PROVIDER_MEMBERSHIPS
                || membership.group.instance_id() != instance_id
                || values
                    .insert(membership.group.clone(), membership)
                    .is_some()
            {
                return Err(ProviderHumanModelError::InvalidMembership);
            }
        }
        for membership in values.values() {
            if let Some(parent) = &membership.parent
                && !values.contains_key(parent)
            {
                return Err(ProviderHumanModelError::InvalidMembership);
            }
        }
        Ok(Self {
            identity,
            memberships: values,
            observed_at,
        })
    }
    /// Returns the exact authenticated identity.
    #[must_use]
    pub const fn identity(&self) -> &ProviderHumanIdentity {
        &self.identity
    }
    /// Iterates in stable group identity order.
    pub fn memberships(&self) -> impl ExactSizeIterator<Item = &ProviderMembership> {
        self.memberships.values()
    }
    /// Returns trusted complete-snapshot time.
    #[must_use]
    pub const fn observed_at(&self) -> UnixMillis {
        self.observed_at
    }
}

/// Future returned by membership reads.
pub type MembershipReaderFuture<'a> = Pin<
    Box<
        dyn Future<Output = Result<ProviderMembershipSnapshot, ProviderHumanProviderError>>
            + Send
            + 'a,
    >,
>;

/// Narrow adapter port for complete bounded group membership evidence.
pub trait MembershipReader: fmt::Debug + Send + Sync {
    /// Reads a complete snapshot for the exact credential and identity.
    fn memberships<'a>(
        &'a self,
        credential: &'a ProviderHumanCredential,
        identity: &'a ProviderHumanIdentity,
        observed_at: UnixMillis,
    ) -> MembershipReaderFuture<'a>;
}

/// Sanitized external human-provider failure.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum ProviderHumanProviderError {
    /// Credential or authorization code was rejected.
    #[error("human provider authentication failed")]
    Unauthorized,
    /// Credential lacks authority for the read.
    #[error("human provider authorization failed")]
    Forbidden,
    /// Provider quota is temporarily exhausted.
    #[error("human provider is rate limited")]
    RateLimited,
    /// Provider endpoint is temporarily unavailable.
    #[error("human provider is unavailable")]
    Unavailable,
    /// Provider response violates the common contract.
    #[error("human provider response is invalid")]
    InvalidResponse,
    /// The configured provider does not implement this optional port.
    #[error("human provider operation is unsupported")]
    Unsupported,
}

/// Invalid common human-provider model.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum ProviderHumanModelError {
    /// Callback URI violates web or literal-loopback policy.
    #[error("provider callback URI is invalid")]
    InvalidCallbackUri,
    /// Authorization URL violates origin safety policy.
    #[error("provider authorization URL is invalid")]
    InvalidAuthorizationUrl,
    /// PKCE verifier violates RFC 7636 bounds or grammar.
    #[error("provider PKCE verifier is invalid")]
    InvalidPkceVerifier,
    /// Transaction lifetime is invalid.
    #[error("provider login transaction lifetime is invalid")]
    InvalidTransactionLifetime,
    /// State and nonce proofs are not independent.
    #[error("provider login proofs are not independent")]
    NonIndependentProofs,
    /// Authorization callback is outside its transaction interval.
    #[error("provider login transaction is expired")]
    ExpiredTransaction,
    /// Human credential lifetime is invalid.
    #[error("provider human credential lifetime is invalid")]
    InvalidCredentialLifetime,
    /// Device authorization metadata is invalid.
    #[error("provider device authorization is invalid")]
    InvalidDeviceAuthorization,
    /// Stable identity or display metadata is invalid.
    #[error("provider human identity is invalid")]
    InvalidIdentity,
    /// Membership evidence is invalid, incomplete, or excessive.
    #[error("provider membership evidence is invalid")]
    InvalidMembership,
}

fn safe_callback(value: &Url) -> bool {
    value.host().is_some()
        && value.username().is_empty()
        && value.password().is_none()
        && value.query().is_none()
        && value.fragment().is_none()
}
fn valid_display(value: &str, maximum: usize, allow_empty: bool) -> bool {
    (allow_empty || !value.is_empty())
        && value.len() <= maximum
        && value.trim() == value
        && !value.chars().any(char::is_control)
}
