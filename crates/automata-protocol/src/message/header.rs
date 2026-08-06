//! Metadata shared by every post-handshake message.

use automata_core::OperationId;
use serde::{Deserialize, Serialize};

use super::validation::{MessageValidationError, validate_schema};
use crate::{MESSAGE_SCHEMA_VERSION, ProtocolVersion, SUPPORTED_PROTOCOL_RANGE};

/// Common metadata on every message after handshake negotiation.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct MessageHeader {
    message_schema_version: u16,
    protocol_version: ProtocolVersion,
    operation_id: OperationId,
}

impl MessageHeader {
    /// Creates a header for the negotiated protocol and idempotent operation.
    #[must_use]
    pub const fn new(protocol_version: ProtocolVersion, operation_id: OperationId) -> Self {
        Self {
            message_schema_version: MESSAGE_SCHEMA_VERSION,
            protocol_version,
            operation_id,
        }
    }

    #[must_use]
    pub const fn message_schema_version(self) -> u16 {
        self.message_schema_version
    }

    #[must_use]
    pub const fn protocol_version(self) -> ProtocolVersion {
        self.protocol_version
    }

    #[must_use]
    pub const fn operation_id(self) -> OperationId {
        self.operation_id
    }

    /// Validates message schema and locally supported protocol.
    ///
    /// # Errors
    ///
    /// Returns [`MessageValidationError`] for an unsupported message schema or
    /// a protocol version not spoken by this build.
    pub fn validate(self) -> Result<(), MessageValidationError> {
        validate_schema(self.message_schema_version)?;
        if !SUPPORTED_PROTOCOL_RANGE.contains(self.protocol_version) {
            return Err(MessageValidationError::UnsupportedProtocol {
                received: self.protocol_version,
                supported: SUPPORTED_PROTOCOL_RANGE,
            });
        }
        Ok(())
    }
}
