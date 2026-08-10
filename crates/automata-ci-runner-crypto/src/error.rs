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
    /// Active and decrypt-only protection IDs must be globally unique.
    #[error("content protection keyring contains a duplicate identifier")]
    DuplicateProtectionId,
    /// A local keyring retains only a small bounded number of old keys.
    #[error("content protection keyring contains too many decrypt-only keys")]
    TooManyDecryptOnlyKeys,
}
