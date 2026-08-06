use thiserror::Error;

const MAX_TENANT_ID_BYTES: usize = 255;

/// Store-side scope copied from an already authenticated tenant identity.
///
/// This type deliberately does not depend on `automata-auth`: authentication
/// adapters validate credentials, then copy their tenant ID through this
/// narrow persistence boundary. Construction validates the same durable shape
/// as `automata_auth::TenantId`; it does not itself authenticate a caller.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct TenantScope(String);

impl TenantScope {
    /// Creates a persistence-safe tenant scope from an authenticated tenant ID.
    ///
    /// # Errors
    ///
    /// Returns an error for an empty value, more than 255 UTF-8 bytes, or a
    /// value containing control characters.
    pub fn from_authenticated_tenant_id(
        value: impl Into<String>,
    ) -> Result<Self, TenantScopeError> {
        let value = value.into();
        if value.is_empty() {
            return Err(TenantScopeError::Empty);
        }
        if value.len() > MAX_TENANT_ID_BYTES {
            return Err(TenantScopeError::TooLong {
                maximum: MAX_TENANT_ID_BYTES,
            });
        }
        if value.chars().any(char::is_control) {
            return Err(TenantScopeError::ControlCharacter);
        }
        Ok(Self(value))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum TenantScopeError {
    #[error("tenant ID must not be empty")]
    Empty,
    #[error("tenant ID must not exceed {maximum} bytes")]
    TooLong { maximum: usize },
    #[error("tenant ID must not contain control characters")]
    ControlCharacter,
}
