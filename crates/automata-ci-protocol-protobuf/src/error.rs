//! Sanitized errors at the protobuf trust boundary.

use automata_ci_protocol::MessageValidationError;
use thiserror::Error;

/// Failure while decoding an untrusted protobuf frame.
///
/// Error messages identify structural fields, never their possibly sensitive
/// contents. Detailed domain validation remains available through the source
/// error of [`Self::InvalidMessage`].
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum DecodeError {
    /// The transport delivered no protobuf message bytes.
    #[error("protobuf protocol frame is empty")]
    EmptyFrame,
    /// The frame exceeded the trusted allocation ceiling.
    #[error("protobuf protocol frame has {size} bytes; maximum is {maximum}")]
    FrameTooLarge {
        /// Actual frame length.
        size: usize,
        /// Configured maximum frame length.
        maximum: usize,
    },
    /// A nested repeated field exceeded its trusted item budget before domain
    /// collection allocation.
    #[error("protobuf collection `{field}` has {length} items; maximum is {maximum}")]
    CollectionTooLarge {
        /// Stable schema field name, never untrusted input.
        field: &'static str,
        /// Received item count.
        length: usize,
        /// Configured item maximum.
        maximum: usize,
    },
    /// A log batch exceeded its trusted aggregate byte budget.
    #[error("protobuf log batch has {size} payload bytes; maximum is {maximum}")]
    LogPayloadTooLarge {
        /// Aggregate decoded payload length.
        size: usize,
        /// Configured aggregate maximum.
        maximum: usize,
    },
    /// The bytes were not a structurally valid protobuf message.
    #[error("protocol frame is not valid protobuf")]
    MalformedProtobuf(#[source] prost::DecodeError),
    /// A required protobuf message or scalar wrapper was absent.
    #[error("required protobuf field `{field}` is missing")]
    MissingField {
        /// Stable schema field name, never untrusted input.
        field: &'static str,
    },
    /// A required oneof had no recognized variant.
    #[error("required protobuf variant `{field}` is missing or unknown")]
    MissingVariant {
        /// Stable schema field name, never untrusted input.
        field: &'static str,
    },
    /// A UUID byte field was not exactly 16 bytes.
    #[error("protobuf UUID field `{field}` has {received} bytes; expected 16")]
    InvalidUuidLength {
        /// Stable schema field name, never untrusted input.
        field: &'static str,
        /// Received byte count.
        received: usize,
    },
    /// A protobuf integer did not fit the narrower domain representation.
    #[error("protobuf integer field `{field}` is outside its supported range")]
    IntegerOutOfRange {
        /// Stable schema field name, never untrusted input.
        field: &'static str,
    },
    /// An enum carried zero or a value unknown to this schema.
    #[error("protobuf enum field `{field}` contains unsupported value {value}")]
    UnknownEnum {
        /// Stable schema field name, never untrusted input.
        field: &'static str,
        /// Unknown numeric value, which contains no user text.
        value: i32,
    },
    /// A canonical repeated set or map was not strictly ascending.
    #[error("protobuf collection `{field}` is not in canonical order")]
    NonCanonicalOrder {
        /// Stable schema field name, never untrusted input.
        field: &'static str,
    },
    /// A canonical repeated set or map contained a duplicate key/value.
    #[error("protobuf collection `{field}` contains a duplicate")]
    DuplicateEntry {
        /// Stable schema field name, never untrusted input.
        field: &'static str,
    },
    /// Text was valid in a domain type only after normalization, so the wire
    /// representation was not canonical.
    #[error("protobuf field `{field}` is not canonically represented")]
    NonCanonicalValue {
        /// Stable schema field name, never untrusted input.
        field: &'static str,
    },
    /// A domain constructor rejected a malformed scalar value.
    #[error("protobuf field `{field}` is not a valid domain value")]
    InvalidValue {
        /// Stable schema field name, never untrusted input.
        field: &'static str,
    },
    /// An independently versioned embedded schema cannot be consumed by this
    /// build.
    #[error("protobuf field `{field}` uses schema {received}; supported schema is {supported}")]
    UnsupportedSchema {
        /// Stable schema field name, never untrusted input.
        field: &'static str,
        /// Received numeric schema version.
        received: u32,
        /// Supported numeric schema version.
        supported: u32,
    },
    /// A standalone immutable job runtime-context object was structurally
    /// canonical but failed its domain invariants.
    #[error("decoded job runtime context failed validation")]
    InvalidRuntimeContext(#[source] automata_ci_core::RuntimeContextError),
    /// A retained execution-time value template failed canonical validation.
    #[error("decoded value template failed validation")]
    InvalidValueTemplate(#[source] automata_ci_core::ValueTemplateError),
    /// The fully converted domain message failed its normal protocol checks.
    #[error("decoded protobuf message failed protocol validation")]
    InvalidMessage(#[source] MessageValidationError),
}

/// Failure while validating or encoding a local domain message.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum EncodeError {
    /// A standalone immutable job runtime-context object was invalid.
    #[error("job runtime context failed validation")]
    InvalidRuntimeContext(#[source] automata_ci_core::RuntimeContextError),
    /// The domain message failed its normal protocol checks.
    #[error("protobuf message failed protocol validation")]
    InvalidMessage(#[source] MessageValidationError),
    /// The canonical encoded frame exceeded the configured transport ceiling.
    #[error("encoded protobuf frame has {size} bytes; maximum is {maximum}")]
    FrameTooLarge {
        /// Actual canonical encoded length.
        size: usize,
        /// Configured maximum frame length.
        maximum: usize,
    },
}
