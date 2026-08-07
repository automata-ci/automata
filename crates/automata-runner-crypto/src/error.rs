use thiserror::Error;

/// Invalid trusted at-rest protection configuration.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum ContentProtectorConfigurationError {
    /// Protection ID is not a portable bounded identifier.
    #[error("content protection identifier is invalid")]
    InvalidProtectionId,
    /// AES-256-GCM key material is not exactly 32 bytes.
    #[error("AES-256-GCM content protection key has an invalid length")]
    InvalidKeyLength,
    /// Key material was rejected by the cryptographic provider.
    #[error("AES-256-GCM content protection key is invalid")]
    InvalidKey,
}
