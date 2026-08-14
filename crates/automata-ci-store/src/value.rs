use std::num::{NonZeroU16, NonZeroU64};

use serde_json::Value;
use sha2::{Digest as _, Sha256};
use thiserror::Error;

/// Maximum encoded size accepted for one immutable `JobIR` object.
pub const MAX_JOB_IR_BYTES: u64 = 16 * 1024 * 1024;
/// Maximum encoded size accepted for one terminal-result object.
pub const MAX_TERMINAL_RESULT_BYTES: u64 = 16 * 1024 * 1024;
/// Maximum compressed size described by one immutable log segment.
pub const MAX_LOG_SEGMENT_BYTES: u64 = 64 * 1024 * 1024;
/// Maximum JSON size stored in a runner routing/session snapshot.
pub const MAX_ROUTING_DOCUMENT_BYTES: usize = 1024 * 1024;

const MAX_OBJECT_KEY_BYTES: usize = 1024;
const MAX_LABEL_BYTES: usize = 255;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum TerminalResultLimitRejection {
    EncodedBytes,
}

pub(crate) const fn terminal_result_bytes_rejection(
    observed: u64,
) -> Option<TerminalResultLimitRejection> {
    if observed > MAX_TERMINAL_RESULT_BYTES {
        return Some(TerminalResultLimitRejection::EncodedBytes);
    }
    None
}

/// A positive schema number persisted with an immutable document.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct DocumentSchema(NonZeroU16);

impl DocumentSchema {
    /// Creates a positive durable schema number.
    ///
    /// # Errors
    ///
    /// Returns [`DurabilityValueError::ZeroSchema`] for zero.
    pub fn new(value: u16) -> Result<Self, DurabilityValueError> {
        NonZeroU16::new(value)
            .map(Self)
            .ok_or(DurabilityValueError::ZeroSchema)
    }

    #[must_use]
    pub const fn get(self) -> u16 {
        self.0.get()
    }
}

/// A positive runner protocol version selected for one session.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct RunnerProtocolVersion(NonZeroU16);

impl RunnerProtocolVersion {
    /// Creates a positive selected protocol version.
    ///
    /// # Errors
    ///
    /// Returns [`DurabilityValueError::ZeroProtocolVersion`] for zero.
    pub fn new(value: u16) -> Result<Self, DurabilityValueError> {
        NonZeroU16::new(value)
            .map(Self)
            .ok_or(DurabilityValueError::ZeroProtocolVersion)
    }

    #[must_use]
    pub const fn get(self) -> u16 {
        self.0.get()
    }
}

/// Monotonic registered-runner configuration/certificate generation.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct RunnerGeneration(NonZeroU64);

impl RunnerGeneration {
    /// Creates a positive generation representable by `PostgreSQL` `BIGINT`.
    ///
    /// # Errors
    ///
    /// Returns an error for zero or a value larger than `i64::MAX`.
    pub fn new(value: u64) -> Result<Self, DurabilityValueError> {
        positive_bigint(value, DurabilityValueError::InvalidRunnerGeneration).map(Self)
    }

    #[must_use]
    pub const fn get(self) -> u64 {
        self.0.get()
    }
}

/// Monotonic connection epoch allocated by the trusted control plane.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct SessionEpoch(NonZeroU64);

impl SessionEpoch {
    /// Creates a positive epoch representable by `PostgreSQL` `BIGINT`.
    ///
    /// # Errors
    ///
    /// Returns an error for zero or a value larger than `i64::MAX`.
    pub fn new(value: u64) -> Result<Self, DurabilityValueError> {
        positive_bigint(value, DurabilityValueError::InvalidSessionEpoch).map(Self)
    }

    #[must_use]
    pub const fn get(self) -> u64 {
        self.0.get()
    }
}

/// One-based, stable execution slot ordinal within one runner session.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct StableRunnerSlot(NonZeroU16);

impl StableRunnerSlot {
    /// Creates a one-based stable slot ordinal.
    ///
    /// # Errors
    ///
    /// Returns [`DurabilityValueError::ZeroRunnerSlot`] for zero.
    pub fn new(ordinal: u16) -> Result<Self, DurabilityValueError> {
        NonZeroU16::new(ordinal)
            .map(Self)
            .ok_or(DurabilityValueError::ZeroRunnerSlot)
    }

    #[must_use]
    pub const fn ordinal(self) -> u16 {
        self.0.get()
    }

    #[must_use]
    pub const fn get(self) -> u16 {
        self.ordinal()
    }
}

/// Positive registered slot capacity for server-owned routing.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct RunnerSlotCount(NonZeroU16);

impl RunnerSlotCount {
    /// Creates a positive registered slot count.
    ///
    /// # Errors
    ///
    /// Returns [`DurabilityValueError::ZeroRunnerSlots`] for zero.
    pub fn new(value: u16) -> Result<Self, DurabilityValueError> {
        NonZeroU16::new(value)
            .map(Self)
            .ok_or(DurabilityValueError::ZeroRunnerSlots)
    }

    #[must_use]
    pub const fn get(self) -> u16 {
        self.0.get()
    }

    #[must_use]
    pub const fn contains(self, slot: StableRunnerSlot) -> bool {
        slot.ordinal() <= self.get()
    }
}

/// Credential-free S3-compatible object key.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ObjectKey(String);

impl ObjectKey {
    /// Creates a bounded object key safe to retain in diagnostics.
    ///
    /// # Errors
    ///
    /// Rejects empty keys, keys over 1024 UTF-8 bytes, control characters,
    /// absolute paths, and path traversal components.
    pub fn new(value: impl Into<String>) -> Result<Self, DurabilityValueError> {
        let value = value.into();
        validate_text(&value, MAX_OBJECT_KEY_BYTES, "object key")?;
        if value.starts_with('/') {
            return Err(DurabilityValueError::AbsoluteObjectKey);
        }
        if value.split('/').any(|component| component == "..") {
            return Err(DurabilityValueError::TraversingObjectKey);
        }
        Ok(Self(value))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Canonical, bounded JSON object retained as durable routing evidence.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RoutingDocument(String);

impl RoutingDocument {
    /// Parses and canonicalizes a bounded JSON object.
    ///
    /// # Errors
    ///
    /// Rejects oversized, malformed, or non-object JSON.
    pub fn new(value: impl AsRef<str>) -> Result<Self, DurabilityValueError> {
        let value = value.as_ref();
        if value.len() > MAX_ROUTING_DOCUMENT_BYTES {
            return Err(DurabilityValueError::RoutingDocumentTooLarge {
                size: value.len(),
                maximum: MAX_ROUTING_DOCUMENT_BYTES,
            });
        }
        let parsed: Value = serde_json::from_str(value)
            .map_err(|_| DurabilityValueError::InvalidRoutingDocument)?;
        if !parsed.is_object() {
            return Err(DurabilityValueError::RoutingDocumentNotObject);
        }
        let canonical = serde_json::to_string(&parsed)
            .map_err(|_| DurabilityValueError::InvalidRoutingDocument)?;
        Ok(Self(canonical))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Canonical, case-insensitive label stored and evaluated by server routing.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct RoutingLabel(String);

impl RoutingLabel {
    /// Creates a bounded, non-blank routing label.
    ///
    /// # Errors
    ///
    /// Rejects blank, oversized, or control-bearing labels.
    pub fn new(value: impl Into<String>) -> Result<Self, DurabilityValueError> {
        let value = value.into();
        validate_text(&value, MAX_LABEL_BYTES, "routing label")?;
        if value.trim() != value {
            return Err(DurabilityValueError::SurroundingWhitespace {
                field: "routing label",
            });
        }
        let canonical = value.to_lowercase();
        validate_text(&canonical, MAX_LABEL_BYTES, "routing label")?;
        Ok(Self(canonical))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

fn positive_bigint(
    value: u64,
    error: DurabilityValueError,
) -> Result<NonZeroU64, DurabilityValueError> {
    if value > 9_223_372_036_854_775_807 {
        return Err(error);
    }
    NonZeroU64::new(value).ok_or(error)
}

pub(crate) fn validate_text(
    value: &str,
    maximum: usize,
    field: &'static str,
) -> Result<(), DurabilityValueError> {
    if value.is_empty() {
        return Err(DurabilityValueError::EmptyText { field });
    }
    if value.len() > maximum {
        return Err(DurabilityValueError::TextTooLong { field, maximum });
    }
    if value.chars().any(char::is_control) {
        return Err(DurabilityValueError::ControlCharacter { field });
    }
    Ok(())
}

pub(crate) fn decode_sha256_digest(
    bytes: Vec<u8>,
) -> Result<automata_ci_core::Sha256Digest, DurabilityValueError> {
    let length = bytes.len();
    let bytes = bytes
        .try_into()
        .map_err(|_| DurabilityValueError::InvalidDigestLength { length })?;
    Ok(automata_ci_core::Sha256Digest::from_bytes(bytes))
}

pub(crate) fn sha256_digest(bytes: &[u8]) -> automata_ci_core::Sha256Digest {
    automata_ci_core::Sha256Digest::from_bytes(Sha256::digest(bytes).into())
}

/// Invalid values rejected before they reach a storage adapter.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum DurabilityValueError {
    #[error("SHA-256 digest has {length} bytes; expected 32")]
    InvalidDigestLength { length: usize },
    #[error("document schema must be positive")]
    ZeroSchema,
    #[error("runner protocol version must be positive")]
    ZeroProtocolVersion,
    #[error("runner generation must be in 1..=i64::MAX")]
    InvalidRunnerGeneration,
    #[error("runner session epoch must be in 1..=i64::MAX")]
    InvalidSessionEpoch,
    #[error("runner slot count must be positive")]
    ZeroRunnerSlots,
    #[error("stable runner slot ordinal must be positive")]
    ZeroRunnerSlot,
    #[error("{field} must not be empty")]
    EmptyText { field: &'static str },
    #[error("{field} must not exceed {maximum} UTF-8 bytes")]
    TextTooLong { field: &'static str, maximum: usize },
    #[error("{field} must not contain control characters")]
    ControlCharacter { field: &'static str },
    #[error("{field} must not have surrounding whitespace")]
    SurroundingWhitespace { field: &'static str },
    #[error("object key must be relative")]
    AbsoluteObjectKey,
    #[error("object key must not contain a parent traversal component")]
    TraversingObjectKey,
    #[error("routing document has {size} bytes; maximum is {maximum}")]
    RoutingDocumentTooLarge { size: usize, maximum: usize },
    #[error("routing document is not valid JSON")]
    InvalidRoutingDocument,
    #[error("routing document must be a JSON object")]
    RoutingDocumentNotObject,
}

#[cfg(test)]
mod tests {
    use super::{
        MAX_TERMINAL_RESULT_BYTES, TerminalResultLimitRejection, terminal_result_bytes_rejection,
    };

    #[test]
    fn terminal_result_bytes_has_exact_boundaries() {
        assert_eq!(
            terminal_result_bytes_rejection(MAX_TERMINAL_RESULT_BYTES - 1),
            None
        );
        assert_eq!(
            terminal_result_bytes_rejection(MAX_TERMINAL_RESULT_BYTES),
            None
        );
        assert_eq!(
            terminal_result_bytes_rejection(MAX_TERMINAL_RESULT_BYTES + 1),
            Some(TerminalResultLimitRejection::EncodedBytes)
        );
    }
}
