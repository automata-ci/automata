use std::{fmt, future::Future, pin::Pin};

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{secret::SecretString, time::UnixTimestamp};

const MAX_IDENTIFIER_LENGTH: usize = 255;
const MAX_LOGIN_LENGTH: usize = 255;
const MAX_DISPLAY_NAME_LENGTH: usize = 1_024;

macro_rules! string_identifier {
    ($name:ident, $label:literal) => {
        #[doc = concat!("A bounded, provider-safe ", $label, ".")]
        #[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
        #[serde(try_from = "String", into = "String")]
        pub struct $name(String);

        impl $name {
            /// Creates a validated identity identifier.
            ///
            /// # Errors
            ///
            /// Returns an error when the identifier is empty, oversized, or contains
            /// control characters.
            pub fn new(value: impl Into<String>) -> Result<Self, IdentityError> {
                let value = value.into();
                validate_identifier(&value, $label)?;
                Ok(Self(value))
            }

            /// Returns the validated identifier text.
            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl TryFrom<String> for $name {
            type Error = IdentityError;

            fn try_from(value: String) -> Result<Self, Self::Error> {
                Self::new(value)
            }
        }

        impl From<$name> for String {
            fn from(value: $name) -> Self {
                value.0
            }
        }
    };
}

string_identifier!(ProviderId, "provider ID");
string_identifier!(ProviderSubject, "provider subject");
string_identifier!(PrincipalId, "principal ID");
string_identifier!(TenantId, "tenant ID");

fn validate_identifier(value: &str, label: &'static str) -> Result<(), IdentityError> {
    if value.is_empty() {
        return Err(IdentityError::Empty { label });
    }
    if value.len() > MAX_IDENTIFIER_LENGTH {
        return Err(IdentityError::TooLong {
            label,
            maximum: MAX_IDENTIFIER_LENGTH,
        });
    }
    if value.chars().any(char::is_control) {
        return Err(IdentityError::ControlCharacter { label });
    }
    Ok(())
}

/// Validation failures for identity identifiers and display metadata.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum IdentityError {
    /// A required identity value was empty.
    #[error("{label} must not be empty")]
    Empty {
        /// Sanitized name of the invalid identity field.
        label: &'static str,
    },
    /// An identity value exceeded its bounded byte length.
    #[error("{label} must not exceed {maximum} bytes")]
    TooLong {
        /// Sanitized name of the invalid identity field.
        label: &'static str,
        /// Maximum accepted UTF-8 byte length.
        maximum: usize,
    },
    /// An identity value contained a terminal control character.
    #[error("{label} must not contain control characters")]
    ControlCharacter {
        /// Sanitized name of the invalid identity field.
        label: &'static str,
    },
}

/// A human identity proven by one external authentication provider.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(try_from = "AuthenticatedHumanData")]
pub struct AuthenticatedHuman {
    principal_id: PrincipalId,
    provider_id: ProviderId,
    provider_subject: ProviderSubject,
    login: String,
    display_name: Option<String>,
    authenticated_at: UnixTimestamp,
}

#[derive(Deserialize)]
struct AuthenticatedHumanData {
    principal_id: PrincipalId,
    provider_id: ProviderId,
    provider_subject: ProviderSubject,
    login: String,
    display_name: Option<String>,
    authenticated_at: UnixTimestamp,
}

impl AuthenticatedHuman {
    /// Creates a validated human identity assertion.
    ///
    /// # Errors
    ///
    /// Returns an error when the provider login or optional display name is
    /// empty where required, oversized, or contains control characters.
    pub fn new(
        principal_id: PrincipalId,
        provider_id: ProviderId,
        provider_subject: ProviderSubject,
        login: impl Into<String>,
        display_name: Option<String>,
        authenticated_at: UnixTimestamp,
    ) -> Result<Self, IdentityError> {
        let login = login.into();
        validate_identity_text(&login, "provider login", MAX_LOGIN_LENGTH, false)?;
        if let Some(display_name) = &display_name {
            validate_identity_text(display_name, "display name", MAX_DISPLAY_NAME_LENGTH, true)?;
        }
        Ok(Self {
            principal_id,
            provider_id,
            provider_subject,
            login,
            display_name,
            authenticated_at,
        })
    }

    /// Returns the stable Automata-owned principal identity.
    pub const fn principal_id(&self) -> &PrincipalId {
        &self.principal_id
    }

    /// Returns the authentication provider that established this identity.
    pub const fn provider_id(&self) -> &ProviderId {
        &self.provider_id
    }

    /// Returns the provider's stable, non-display subject identity.
    pub const fn provider_subject(&self) -> &ProviderSubject {
        &self.provider_subject
    }

    /// Returns the provider login as mutable display metadata.
    pub fn login(&self) -> &str {
        &self.login
    }

    /// Returns the optional provider display name.
    pub fn display_name(&self) -> Option<&str> {
        self.display_name.as_deref()
    }

    /// Returns when the provider most recently established this identity.
    pub const fn authenticated_at(&self) -> UnixTimestamp {
        self.authenticated_at
    }
}

impl TryFrom<AuthenticatedHumanData> for AuthenticatedHuman {
    type Error = IdentityError;

    fn try_from(value: AuthenticatedHumanData) -> Result<Self, Self::Error> {
        Self::new(
            value.principal_id,
            value.provider_id,
            value.provider_subject,
            value.login,
            value.display_name,
            value.authenticated_at,
        )
    }
}

/// A provider-authenticated identity that has not yet been mapped to an
/// Automata-owned principal UUID.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(try_from = "ProviderIdentityAssertionData")]
pub struct ProviderIdentityAssertion {
    provider_id: ProviderId,
    provider_subject: ProviderSubject,
    login: String,
    display_name: Option<String>,
    authenticated_at: UnixTimestamp,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ProviderIdentityAssertionData {
    provider_id: ProviderId,
    provider_subject: ProviderSubject,
    login: String,
    display_name: Option<String>,
    authenticated_at: UnixTimestamp,
}

impl ProviderIdentityAssertion {
    /// Creates a validated stable provider identity assertion.
    ///
    /// # Errors
    ///
    /// Rejects an invalid login or display name. The provider subject is the
    /// stable authority; the mutable login is display metadata only.
    pub fn new(
        provider_id: ProviderId,
        provider_subject: ProviderSubject,
        login: impl Into<String>,
        display_name: Option<String>,
        authenticated_at: UnixTimestamp,
    ) -> Result<Self, IdentityError> {
        let login = login.into();
        validate_identity_text(&login, "provider login", MAX_LOGIN_LENGTH, false)?;
        if let Some(display_name) = &display_name {
            validate_identity_text(display_name, "display name", MAX_DISPLAY_NAME_LENGTH, true)?;
        }
        Ok(Self {
            provider_id,
            provider_subject,
            login,
            display_name,
            authenticated_at,
        })
    }

    /// Returns the provider that issued this unmapped assertion.
    pub const fn provider_id(&self) -> &ProviderId {
        &self.provider_id
    }

    /// Returns the provider's stable authorization subject.
    pub const fn provider_subject(&self) -> &ProviderSubject {
        &self.provider_subject
    }

    /// Returns the provider login as non-authoritative display metadata.
    pub fn login(&self) -> &str {
        &self.login
    }

    /// Returns optional non-authoritative display metadata.
    pub fn display_name(&self) -> Option<&str> {
        self.display_name.as_deref()
    }

    /// Returns when the provider established this assertion.
    pub const fn authenticated_at(&self) -> UnixTimestamp {
        self.authenticated_at
    }

    /// Binds the stable provider assertion to an Automata-owned principal.
    pub fn into_authenticated_human(self, principal_id: PrincipalId) -> AuthenticatedHuman {
        AuthenticatedHuman {
            principal_id,
            provider_id: self.provider_id,
            provider_subject: self.provider_subject,
            login: self.login,
            display_name: self.display_name,
            authenticated_at: self.authenticated_at,
        }
    }
}

impl TryFrom<ProviderIdentityAssertionData> for ProviderIdentityAssertion {
    type Error = IdentityError;

    fn try_from(value: ProviderIdentityAssertionData) -> Result<Self, Self::Error> {
        Self::new(
            value.provider_id,
            value.provider_subject,
            value.login,
            value.display_name,
            value.authenticated_at,
        )
    }
}

fn validate_identity_text(
    value: &str,
    label: &'static str,
    maximum: usize,
    allow_empty: bool,
) -> Result<(), IdentityError> {
    if !allow_empty && value.is_empty() {
        return Err(IdentityError::Empty { label });
    }
    if value.len() > maximum {
        return Err(IdentityError::TooLong { label, maximum });
    }
    if value.chars().any(char::is_control) {
        return Err(IdentityError::ControlCharacter { label });
    }
    Ok(())
}

/// An internal-only provider credential used to revalidate the user's identity.
///
/// This is deliberately not an Automata session token and must never be accepted
/// as an Automata API bearer credential.
pub struct ProviderCredential {
    provider_id: ProviderId,
    access_token: SecretString,
}

impl ProviderCredential {
    /// Creates an internal provider credential for one exact provider.
    pub const fn new(provider_id: ProviderId, access_token: SecretString) -> Self {
        Self {
            provider_id,
            access_token,
        }
    }

    /// Returns the only provider allowed to consume this credential.
    pub const fn provider_id(&self) -> &ProviderId {
        &self.provider_id
    }

    /// Borrows the raw provider token at the authentication adapter boundary.
    pub const fn access_token(&self) -> &SecretString {
        &self.access_token
    }

    /// Consumes the credential into its provider identity and secret token.
    pub fn into_parts(self) -> (ProviderId, SecretString) {
        (self.provider_id, self.access_token)
    }
}

impl fmt::Debug for ProviderCredential {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProviderCredential")
            .field("provider_id", &self.provider_id)
            .field("access_token", &"[REDACTED]")
            .finish()
    }
}

/// A provider authentication operation with sanitized failure outcomes.
pub type AuthenticationFuture<'a> = Pin<
    Box<
        dyn Future<Output = Result<ProviderIdentityAssertion, AuthenticationProviderError>>
            + Send
            + 'a,
    >,
>;

/// Runtime-pluggable boundary for authenticating human identities.
///
/// Implementations must re-fetch the provider subject for every login. Membership
/// assertions and authorization are intentionally outside this interface.
pub trait AuthenticationProvider: fmt::Debug + Send + Sync {
    /// Returns the provider identity accepted by this adapter.
    fn provider_id(&self) -> &ProviderId;

    /// Revalidates a provider credential into a stable identity assertion.
    fn authenticate<'a>(&'a self, credential: &'a ProviderCredential) -> AuthenticationFuture<'a>;
}

/// Sanitized failures from an external human-authentication provider.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum AuthenticationProviderError {
    /// The provider definitively rejected the credential.
    #[error("the provider rejected the credential")]
    Rejected,
    #[error("the authentication provider is unavailable")]
    /// The provider could not be reached or completed transiently.
    Unavailable,
    /// The provider returned identity data that violates the local contract.
    #[error("the provider returned an invalid identity response")]
    InvalidResponse,
    #[error("the credential was sent to the wrong authentication provider")]
    /// The credential was presented to an adapter for a different provider.
    WrongProvider,
}
