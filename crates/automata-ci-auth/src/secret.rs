use std::{fmt, sync::Arc};

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::Deserialize;
use sha2::{Digest as _, Sha256};
use subtle::{Choice, ConstantTimeEq as _};
use thiserror::Error;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

const GENERATED_SECRET_BYTES: usize = 32;
const MAX_SECRET_LENGTH: usize = 65_536;

/// An owned UTF-8 secret that is redacted from debug output and zeroized on drop.
///
/// This type intentionally does not implement `Display` or `Serialize`. Calling
/// [`SecretString::expose_secret`] is an explicit boundary crossing.
#[derive(Deserialize, Zeroize, ZeroizeOnDrop)]
#[serde(try_from = "String")]
pub struct SecretString(String);

impl SecretString {
    /// Creates a bounded, non-empty secret.
    /// Rejected owned strings are zeroized before returning.
    ///
    /// # Errors
    ///
    /// Returns an error when the value is empty or exceeds the maximum size.
    pub fn new(value: impl Into<String>) -> Result<Self, SecretError> {
        let mut value = value.into();
        validate_secret_string(&mut value)?;
        Ok(Self(value))
    }

    /// Exposes the plaintext at an explicit, auditable custody boundary.
    pub fn expose_secret(&self) -> &str {
        &self.0
    }

    /// Compares this secret with a candidate without data-dependent early exit.
    pub fn constant_time_eq(&self, candidate: &str) -> bool {
        constant_time_string_eq(self.expose_secret(), candidate)
    }
}

impl TryFrom<String> for SecretString {
    type Error = SecretError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl fmt::Debug for SecretString {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SecretString([REDACTED])")
    }
}

fn validate_secret_string(value: &mut String) -> Result<(), SecretError> {
    if value.is_empty() {
        value.zeroize();
        return Err(SecretError::Empty);
    }
    if value.len() > MAX_SECRET_LENGTH {
        value.zeroize();
        return Err(SecretError::TooLong {
            maximum: MAX_SECRET_LENGTH,
        });
    }
    Ok(())
}

/// A shallow-cloneable string whose plaintext remains explicitly exposed.
///
/// Existing [`SecretString`] allocations can be shared without copying their
/// plaintext. Newly owned values, including empty strings, remain inside a
/// [`Zeroizing<String>`] until the final shared owner is dropped. This type
/// intentionally does not implement `Display`, `Serialize`, or `Deserialize`.
pub struct SharedSensitiveString(SharedSensitiveStringBacking);

enum SharedSensitiveStringBacking {
    Existing(Arc<SecretString>),
    Owned(Arc<Zeroizing<String>>),
}

impl SharedSensitiveString {
    /// Shares an existing secret without copying its plaintext allocation.
    #[must_use]
    pub fn from_secret(secret: Arc<SecretString>) -> Self {
        Self(SharedSensitiveStringBacking::Existing(secret))
    }

    /// Moves an owned string into shared zeroizing custody without copying its
    /// plaintext allocation.
    ///
    /// Empty strings are accepted because sensitivity and non-emptiness are
    /// independent properties at expression and environment boundaries.
    #[must_use]
    pub fn from_string(secret: String) -> Self {
        Self::from_owned(Zeroizing::new(secret))
    }

    /// Takes custody of an owned, zeroizing string without copying plaintext.
    ///
    /// Unlike [`SecretString`], an owned shared sensitive string may be empty.
    #[must_use]
    pub fn from_owned(secret: Zeroizing<String>) -> Self {
        Self(SharedSensitiveStringBacking::Owned(Arc::new(secret)))
    }

    /// Returns the plaintext UTF-8 byte length without exposing an owned value.
    #[must_use]
    pub fn len(&self) -> usize {
        self.expose_secret().len()
    }

    /// Reports whether the sensitive string is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.expose_secret().is_empty()
    }

    /// Exposes a borrowed plaintext view at an explicit custody boundary.
    #[must_use]
    pub fn expose_secret(&self) -> &str {
        match &self.0 {
            SharedSensitiveStringBacking::Existing(secret) => secret.expose_secret(),
            SharedSensitiveStringBacking::Owned(secret) => secret.as_str(),
        }
    }

    /// Compares this value with a borrowed candidate without content-dependent
    /// early exit, including when their lengths differ or either value is empty.
    #[must_use]
    pub fn constant_time_eq(&self, candidate: &str) -> bool {
        constant_time_string_eq(self.expose_secret(), candidate)
    }
}

impl Clone for SharedSensitiveString {
    fn clone(&self) -> Self {
        match &self.0 {
            SharedSensitiveStringBacking::Existing(secret) => {
                Self(SharedSensitiveStringBacking::Existing(Arc::clone(secret)))
            }
            SharedSensitiveStringBacking::Owned(secret) => {
                Self(SharedSensitiveStringBacking::Owned(Arc::clone(secret)))
            }
        }
    }
}

impl fmt::Debug for SharedSensitiveString {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SharedSensitiveString([REDACTED])")
    }
}

fn constant_time_string_eq(left: &str, right: &str) -> bool {
    let left = left.as_bytes();
    let right = right.as_bytes();
    let mut equal = Choice::from(u8::from(left.len() == right.len()));

    for index in 0..left.len().max(right.len()) {
        let left_byte = left.get(index).copied().unwrap_or_default();
        let right_byte = right.get(index).copied().unwrap_or_default();
        equal &= left_byte.ct_eq(&right_byte);
    }

    bool::from(equal)
}

/// Secret binary material, such as session-credential HMAC key material.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct SecretBytes(Vec<u8>);

impl SecretBytes {
    /// Creates non-empty secret binary material.
    ///
    /// # Errors
    ///
    /// Returns an error when the value is empty.
    pub fn new(value: Vec<u8>) -> Result<Self, SecretError> {
        if value.is_empty() {
            return Err(SecretError::Empty);
        }
        Ok(Self(value))
    }

    /// Exposes the plaintext bytes at an explicit custody boundary.
    pub fn expose_secret(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Debug for SecretBytes {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SecretBytes([REDACTED])")
    }
}

/// Validation failures for bounded secret values.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum SecretError {
    /// The supplied secret was empty.
    #[error("a secret must not be empty")]
    Empty,
    /// The supplied secret exceeded the bounded custody size.
    #[error("a secret exceeds the maximum length of {maximum} bytes")]
    TooLong {
        /// Maximum accepted UTF-8 byte length.
        maximum: usize,
    },
}

/// Failure to obtain cryptographically secure random bytes from the host.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
#[error("the operating system did not provide secure random bytes")]
pub struct RandomnessError;

/// Injectable cryptographically-secure randomness boundary.
pub trait SecureRandom: Send + Sync {
    /// Fills the entire destination with cryptographically secure random bytes.
    ///
    /// # Errors
    ///
    /// Returns an error when the underlying secure random source is unavailable.
    fn fill(&self, destination: &mut [u8]) -> Result<(), RandomnessError>;
}

/// The host operating system's cryptographically-secure random source.
#[derive(Clone, Copy, Debug, Default)]
pub struct SystemSecureRandom;

impl SecureRandom for SystemSecureRandom {
    fn fill(&self, destination: &mut [u8]) -> Result<(), RandomnessError> {
        getrandom::fill(destination).map_err(|_| RandomnessError)
    }
}

fn random_secret(random: &dyn SecureRandom) -> Result<SecretString, RandomnessError> {
    let mut bytes = Zeroizing::new([0_u8; GENERATED_SECRET_BYTES]);
    random.fill(bytes.as_mut())?;
    let encoded = URL_SAFE_NO_PAD.encode(bytes.as_ref());
    SecretString::new(encoded).map_err(|_| RandomnessError)
}

fn has_generated_secret_shape(value: &str) -> bool {
    let Ok(mut decoded) = URL_SAFE_NO_PAD.decode(value) else {
        return false;
    };
    let valid = value.len() == 43 && decoded.len() == GENERATED_SECRET_BYTES;
    decoded.zeroize();
    valid
}

macro_rules! opaque_token {
    ($name:ident) => {
        #[doc = concat!("A redacted opaque credential represented by [`", stringify!($name), "`].")]
        pub struct $name(SecretString);

        impl $name {
            /// Generates a new 256-bit opaque token.
            ///
            /// # Errors
            ///
            /// Returns an error when secure randomness is unavailable.
            pub fn generate(random: &dyn SecureRandom) -> Result<Self, RandomnessError> {
                random_secret(random).map(Self)
            }

            /// Wraps an existing secret without asserting generated-token shape.
            pub fn from_secret(secret: SecretString) -> Self {
                Self(secret)
            }

            /// Restores a token previously produced by [`Self::generate`].
            ///
            /// # Errors
            ///
            /// Rejects values that are not the canonical 43-character base64url
            /// encoding of exactly 256 bits.
            pub fn from_generated_secret(secret: SecretString) -> Result<Self, OpaqueTokenError> {
                let value = secret.expose_secret();
                if !has_generated_secret_shape(value) {
                    return Err(OpaqueTokenError::InvalidGeneratedToken);
                }
                Ok(Self(secret))
            }

            /// Reports whether this token has the exact shape emitted by
            /// [`Self::generate`].
            #[must_use]
            pub fn has_generated_shape(&self) -> bool {
                has_generated_secret_shape(self.expose_secret())
            }

            /// Exposes the raw credential at an explicit custody boundary.
            pub fn expose_secret(&self) -> &str {
                self.0.expose_secret()
            }

            /// Compares the credential with a candidate in constant time.
            pub fn matches(&self, candidate: &str) -> bool {
                self.0.constant_time_eq(candidate)
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str(concat!(stringify!($name), "([REDACTED])"))
            }
        }
    };
}

opaque_token!(CsrfToken);
opaque_token!(OAuthState);

/// Validation failures for persisted opaque credentials.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum OpaqueTokenError {
    /// The value is not the canonical generated 256-bit token encoding.
    #[error("opaque token is not a canonical generated 256-bit value")]
    InvalidGeneratedToken,
}

/// RFC 7636 PKCE verifier. Generated verifiers are 43 base64url characters.
pub struct PkceVerifier(SecretString);

impl PkceVerifier {
    /// Generates a 256-bit RFC 7636 verifier.
    ///
    /// # Errors
    ///
    /// Returns an error when secure randomness is unavailable.
    pub fn generate(random: &dyn SecureRandom) -> Result<Self, RandomnessError> {
        random_secret(random).map(Self)
    }

    /// Validates an existing RFC 7636 verifier.
    ///
    /// # Errors
    ///
    /// Returns an error unless the verifier has 43 to 128 unreserved characters.
    pub fn from_secret(secret: SecretString) -> Result<Self, PkceError> {
        let value = secret.expose_secret();
        if !(43..=128).contains(&value.len()) || !value.bytes().all(is_pkce_character) {
            return Err(PkceError::InvalidVerifier);
        }
        Ok(Self(secret))
    }

    /// Exposes the verifier at the provider protocol boundary.
    pub fn expose_secret(&self) -> &str {
        self.0.expose_secret()
    }

    /// Derives the RFC 7636 S256 challenge for this verifier.
    pub fn challenge_s256(&self) -> PkceChallenge {
        let digest = Sha256::digest(self.0.expose_secret().as_bytes());
        PkceChallenge(URL_SAFE_NO_PAD.encode(digest))
    }
}

impl fmt::Debug for PkceVerifier {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("PkceVerifier([REDACTED])")
    }
}

fn is_pkce_character(value: u8) -> bool {
    value.is_ascii_alphanumeric() || matches!(value, b'-' | b'.' | b'_' | b'~')
}

/// A non-secret RFC 7636 S256 challenge derived from a verifier.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PkceChallenge(String);

impl PkceChallenge {
    /// Returns the base64url-encoded challenge value.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Validation failures for RFC 7636 verifier values.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum PkceError {
    /// The verifier does not satisfy RFC 7636 length or character constraints.
    #[error("PKCE verifier must contain 43 to 128 RFC 7636 unreserved characters")]
    InvalidVerifier,
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::{
        MAX_SECRET_LENGTH, SecretError, SharedSensitiveString, SharedSensitiveStringBacking,
        validate_secret_string,
    };

    #[test]
    fn oversized_rejection_zeroizes_the_owned_input_buffer() {
        let mut rejected = "s".repeat(MAX_SECRET_LENGTH + 1);

        assert_eq!(
            validate_secret_string(&mut rejected),
            Err(SecretError::TooLong {
                maximum: MAX_SECRET_LENGTH,
            })
        );
        assert!(rejected.as_bytes().iter().all(|byte| *byte == 0));
    }

    #[test]
    fn owned_backing_is_released_only_after_the_final_shared_owner() {
        let sensitive = SharedSensitiveString::from_string(String::from("drop-sentinel"));
        let SharedSensitiveStringBacking::Owned(backing) = &sensitive.0 else {
            panic!("expected owned backing");
        };
        let weak = Arc::downgrade(backing);
        let clone = sensitive.clone();

        drop(sensitive);
        assert!(weak.upgrade().is_some());

        drop(clone);
        assert!(weak.upgrade().is_none());
    }
}
