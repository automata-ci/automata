use std::{fmt, future::Future, pin::Pin};

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{secret::SecretString, time::UnixTimestamp};

const MAX_IDENTIFIER_LENGTH: usize = 255;
const MAX_LOGIN_LENGTH: usize = 255;
const MAX_DISPLAY_NAME_LENGTH: usize = 1_024;

macro_rules! string_identifier {
    ($name:ident, $label:literal) => {
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

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum IdentityError {
    #[error("{label} must not be empty")]
    Empty { label: &'static str },
    #[error("{label} must not exceed {maximum} bytes")]
    TooLong { label: &'static str, maximum: usize },
    #[error("{label} must not contain control characters")]
    ControlCharacter { label: &'static str },
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

    pub const fn principal_id(&self) -> &PrincipalId {
        &self.principal_id
    }

    pub const fn provider_id(&self) -> &ProviderId {
        &self.provider_id
    }

    pub const fn provider_subject(&self) -> &ProviderSubject {
        &self.provider_subject
    }

    pub fn login(&self) -> &str {
        &self.login
    }

    pub fn display_name(&self) -> Option<&str> {
        self.display_name.as_deref()
    }

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
    pub const fn new(provider_id: ProviderId, access_token: SecretString) -> Self {
        Self {
            provider_id,
            access_token,
        }
    }

    pub const fn provider_id(&self) -> &ProviderId {
        &self.provider_id
    }

    pub const fn access_token(&self) -> &SecretString {
        &self.access_token
    }

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

pub type AuthenticationFuture<'a> = Pin<
    Box<dyn Future<Output = Result<AuthenticatedHuman, AuthenticationProviderError>> + Send + 'a>,
>;

/// Runtime-pluggable boundary for authenticating human identities.
///
/// Implementations must re-fetch the provider subject for every login. Membership
/// assertions and authorization are intentionally outside this interface.
pub trait AuthenticationProvider: fmt::Debug + Send + Sync {
    fn provider_id(&self) -> &ProviderId;

    fn authenticate<'a>(&'a self, credential: &'a ProviderCredential) -> AuthenticationFuture<'a>;
}

#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum AuthenticationProviderError {
    #[error("the provider rejected the credential")]
    Rejected,
    #[error("the authentication provider is unavailable")]
    Unavailable,
    #[error("the provider returned an invalid identity response")]
    InvalidResponse,
    #[error("the credential was sent to the wrong authentication provider")]
    WrongProvider,
}
