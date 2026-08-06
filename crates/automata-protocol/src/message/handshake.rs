//! Pre-negotiation hello and rejection messages.

use automata_core::{
    CORE_SCHEMA_VERSION, OperationId, RunnerCapabilities, RunnerSessionId, UnixMillis,
};
use serde::{Deserialize, Serialize};

use super::validation::{MessageValidationError, validate_schema};
use crate::{MESSAGE_SCHEMA_VERSION, ProtocolRange, ProtocolVersion, SUPPORTED_PROTOCOL_RANGE};

/// First runner-to-server handshake message, sent before version selection.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RunnerHello {
    message_schema_version: u16,
    operation_id: OperationId,
    supported_protocol: ProtocolRange,
    runner: RunnerCapabilities,
    sent_at: UnixMillis,
}

impl RunnerHello {
    /// Creates a hello advertisement for the supplied supported range.
    #[must_use]
    pub const fn new(
        operation_id: OperationId,
        supported_protocol: ProtocolRange,
        runner: RunnerCapabilities,
        sent_at: UnixMillis,
    ) -> Self {
        Self {
            message_schema_version: MESSAGE_SCHEMA_VERSION,
            operation_id,
            supported_protocol,
            runner,
            sent_at,
        }
    }

    #[must_use]
    pub const fn message_schema_version(&self) -> u16 {
        self.message_schema_version
    }

    #[must_use]
    pub const fn operation_id(&self) -> OperationId {
        self.operation_id
    }

    #[must_use]
    pub const fn supported_protocol(&self) -> ProtocolRange {
        self.supported_protocol
    }

    #[must_use]
    pub const fn runner(&self) -> &RunnerCapabilities {
        &self.runner
    }

    #[must_use]
    pub const fn sent_at(&self) -> UnixMillis {
        self.sent_at
    }

    /// Validates handshake-local schemas and range ordering.
    ///
    /// # Errors
    ///
    /// Returns [`MessageValidationError`] for an invalid message, protocol, or
    /// core schema, or for a runner advertising no execution slots.
    pub fn validate(&self) -> Result<(), MessageValidationError> {
        validate_schema(self.message_schema_version)?;
        self.supported_protocol.validate()?;
        if self.runner.schema_version() != CORE_SCHEMA_VERSION {
            return Err(MessageValidationError::UnsupportedCoreSchema {
                received: self.runner.schema_version(),
                supported: CORE_SCHEMA_VERSION,
            });
        }
        if self.runner.max_parallel_jobs() == 0 {
            return Err(MessageValidationError::NoRunnerSlots);
        }
        Ok(())
    }
}

/// Successful server response selecting one protocol version.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ServerHello {
    message_schema_version: u16,
    /// Correlates this response to the runner hello operation.
    operation_id: OperationId,
    selected_protocol: ProtocolVersion,
    session_id: RunnerSessionId,
    server_time: UnixMillis,
    heartbeat_interval_millis: u32,
    lease_duration_millis: u32,
}

impl ServerHello {
    /// Creates a successful handshake response.
    #[must_use]
    pub const fn new(
        operation_id: OperationId,
        selected_protocol: ProtocolVersion,
        session_id: RunnerSessionId,
        server_time: UnixMillis,
        heartbeat_interval_millis: u32,
        lease_duration_millis: u32,
    ) -> Self {
        Self {
            message_schema_version: MESSAGE_SCHEMA_VERSION,
            operation_id,
            selected_protocol,
            session_id,
            server_time,
            heartbeat_interval_millis,
            lease_duration_millis,
        }
    }

    #[must_use]
    pub const fn message_schema_version(&self) -> u16 {
        self.message_schema_version
    }

    #[must_use]
    pub const fn operation_id(&self) -> OperationId {
        self.operation_id
    }

    #[must_use]
    pub const fn selected_protocol(&self) -> ProtocolVersion {
        self.selected_protocol
    }

    #[must_use]
    pub const fn session_id(&self) -> RunnerSessionId {
        self.session_id
    }

    #[must_use]
    pub const fn server_time(&self) -> UnixMillis {
        self.server_time
    }

    #[must_use]
    pub const fn heartbeat_interval_millis(&self) -> u32 {
        self.heartbeat_interval_millis
    }

    #[must_use]
    pub const fn lease_duration_millis(&self) -> u32 {
        self.lease_duration_millis
    }

    /// Validates the response independently of handshake correlation.
    ///
    /// # Errors
    ///
    /// Returns [`MessageValidationError`] when schemas, protocol selection, or
    /// timing values cannot be accepted by this build.
    pub fn validate(&self) -> Result<(), MessageValidationError> {
        validate_schema(self.message_schema_version)?;
        if !SUPPORTED_PROTOCOL_RANGE.contains(self.selected_protocol) {
            return Err(MessageValidationError::UnsupportedProtocol {
                received: self.selected_protocol,
                supported: SUPPORTED_PROTOCOL_RANGE,
            });
        }
        if self.heartbeat_interval_millis == 0 || self.lease_duration_millis == 0 {
            return Err(MessageValidationError::InvalidServerTiming);
        }
        Ok(())
    }

    /// Validates a successful response against the initiating hello.
    ///
    /// # Errors
    ///
    /// Returns [`MessageValidationError`] when schemas, correlation, selected
    /// protocol, or server timing values are invalid.
    pub fn validate_for(&self, hello: &RunnerHello) -> Result<(), MessageValidationError> {
        self.validate()?;
        if self.operation_id != hello.operation_id {
            return Err(MessageValidationError::HandshakeCorrelationMismatch {
                expected: hello.operation_id,
                received: self.operation_id,
            });
        }
        if !hello.supported_protocol.contains(self.selected_protocol) {
            return Err(MessageValidationError::SelectionOutsideRunnerRange {
                selected: self.selected_protocol,
                offered: hello.supported_protocol,
            });
        }
        Ok(())
    }
}

/// Typed pre-negotiation handshake rejection. It intentionally has no
/// [`super::MessageHeader`], because no protocol version was successfully selected.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct HandshakeRejected {
    message_schema_version: u16,
    operation_id: OperationId,
    code: HandshakeErrorCode,
    supported_protocol: ProtocolRange,
    message: String,
}

impl HandshakeRejected {
    #[must_use]
    pub fn new(
        operation_id: OperationId,
        code: HandshakeErrorCode,
        supported_protocol: ProtocolRange,
        message: impl Into<String>,
    ) -> Self {
        Self {
            message_schema_version: MESSAGE_SCHEMA_VERSION,
            operation_id,
            code,
            supported_protocol,
            message: message.into(),
        }
    }

    #[must_use]
    pub const fn message_schema_version(&self) -> u16 {
        self.message_schema_version
    }

    #[must_use]
    pub const fn operation_id(&self) -> OperationId {
        self.operation_id
    }

    #[must_use]
    pub const fn code(&self) -> HandshakeErrorCode {
        self.code
    }

    #[must_use]
    pub const fn supported_protocol(&self) -> ProtocolRange {
        self.supported_protocol
    }

    #[must_use]
    pub fn message(&self) -> &str {
        &self.message
    }
}

/// Stable reasons a server may reject the initial runner hello.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum HandshakeErrorCode {
    InvalidHello,
    UnsupportedProtocol,
    Unauthenticated,
    Unauthorized,
}
