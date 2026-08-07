//! Metadata shared by every post-handshake message.

use automata_core::{OperationId, RunnerSessionId};
use serde::{Deserialize, Serialize};

use super::validation::{MessageValidationError, validate_schema};
use crate::{MESSAGE_SCHEMA_VERSION, ProtocolVersion, SUPPORTED_PROTOCOL_RANGE};

/// Common metadata on every message after handshake negotiation.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct MessageHeader {
    message_schema_version: u16,
    protocol_version: ProtocolVersion,
    session_id: RunnerSessionId,
    operation_id: OperationId,
    in_reply_to: Option<OperationId>,
}

impl MessageHeader {
    /// Creates a request header for an authenticated session and idempotent
    /// operation.
    #[must_use]
    pub const fn request(
        protocol_version: ProtocolVersion,
        session_id: RunnerSessionId,
        operation_id: OperationId,
    ) -> Self {
        Self {
            message_schema_version: MESSAGE_SCHEMA_VERSION,
            protocol_version,
            session_id,
            operation_id,
            in_reply_to: None,
        }
    }

    /// Creates a response header correlated to an idempotent request.
    #[must_use]
    pub const fn reply(
        protocol_version: ProtocolVersion,
        session_id: RunnerSessionId,
        operation_id: OperationId,
        in_reply_to: OperationId,
    ) -> Self {
        Self {
            message_schema_version: MESSAGE_SCHEMA_VERSION,
            protocol_version,
            session_id,
            operation_id,
            in_reply_to: Some(in_reply_to),
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
    pub const fn session_id(self) -> RunnerSessionId {
        self.session_id
    }

    #[must_use]
    pub const fn operation_id(self) -> OperationId {
        self.operation_id
    }

    #[must_use]
    pub const fn in_reply_to(self) -> Option<OperationId> {
        self.in_reply_to
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

    /// Validates a runner request header.
    ///
    /// # Errors
    ///
    /// Returns [`MessageValidationError`] when the header is not locally
    /// supported or incorrectly carries response correlation.
    pub fn validate_request(self) -> Result<(), MessageValidationError> {
        self.validate()?;
        if self.in_reply_to.is_some() {
            return Err(MessageValidationError::UnexpectedResponseCorrelation);
        }
        Ok(())
    }

    /// Validates a server response header.
    ///
    /// # Errors
    ///
    /// Returns [`MessageValidationError`] when the header is not locally
    /// supported or lacks request correlation.
    pub fn validate_reply(self) -> Result<(), MessageValidationError> {
        self.validate()?;
        if self.in_reply_to.is_none() {
            return Err(MessageValidationError::MissingResponseCorrelation);
        }
        Ok(())
    }

    /// Validates a response against its initiating request.
    ///
    /// # Errors
    ///
    /// Returns [`MessageValidationError`] for direction, protocol, session, or
    /// operation-correlation mismatches.
    pub fn validate_reply_for(self, request: Self) -> Result<(), MessageValidationError> {
        request.validate_request()?;
        self.validate_reply()?;
        if self.protocol_version != request.protocol_version {
            return Err(MessageValidationError::ResponseProtocolMismatch {
                expected: request.protocol_version,
                received: self.protocol_version,
            });
        }
        if self.session_id != request.session_id {
            return Err(MessageValidationError::ResponseSessionMismatch {
                expected: request.session_id,
                received: self.session_id,
            });
        }
        let received = self
            .in_reply_to
            .ok_or(MessageValidationError::MissingResponseCorrelation)?;
        if received != request.operation_id {
            return Err(MessageValidationError::ResponseOperationMismatch {
                expected: request.operation_id,
                received,
            });
        }
        Ok(())
    }
}
