use std::fmt;

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::Deserialize;
use sha2::{Digest as _, Sha256};
use subtle::ConstantTimeEq as _;
use thiserror::Error;
use zeroize::{Zeroize, ZeroizeOnDrop};

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
    ///
    /// # Errors
    ///
    /// Returns an error when the value is empty or exceeds the maximum size.
    pub fn new(value: impl Into<String>) -> Result<Self, SecretError> {
        let value = value.into();
        if value.is_empty() {
            return Err(SecretError::Empty);
        }
        if value.len() > MAX_SECRET_LENGTH {
            return Err(SecretError::TooLong {
                maximum: MAX_SECRET_LENGTH,
            });
        }
        Ok(Self(value))
    }

    pub fn expose_secret(&self) -> &str {
        &self.0
    }

    pub fn constant_time_eq(&self, candidate: &str) -> bool {
        bool::from(self.0.as_bytes().ct_eq(candidate.as_bytes()))
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

/// Secret binary material, such as an unwrapped data-encryption key.
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

    pub fn expose_secret(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Debug for SecretBytes {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SecretBytes([REDACTED])")
    }
}

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum SecretError {
    #[error("a secret must not be empty")]
    Empty,
    #[error("a secret exceeds the maximum length of {maximum} bytes")]
    TooLong { maximum: usize },
}

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
    let mut bytes = [0_u8; GENERATED_SECRET_BYTES];
    random.fill(&mut bytes)?;
    let encoded = URL_SAFE_NO_PAD.encode(bytes);
    bytes.zeroize();
    SecretString::new(encoded).map_err(|_| RandomnessError)
}

macro_rules! opaque_token {
    ($name:ident) => {
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

            pub fn from_secret(secret: SecretString) -> Self {
                Self(secret)
            }

            pub fn expose_secret(&self) -> &str {
                self.0.expose_secret()
            }

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
opaque_token!(SessionToken);

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

    pub fn expose_secret(&self) -> &str {
        self.0.expose_secret()
    }

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

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PkceChallenge(String);

impl PkceChallenge {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum PkceError {
    #[error("PKCE verifier must contain 43 to 128 RFC 7636 unreserved characters")]
    InvalidVerifier,
}
