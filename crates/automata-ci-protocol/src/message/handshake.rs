//! Pre-negotiation hello and rejection messages.

use automata_ci_core::{
    CORE_SCHEMA_VERSION, JobIrVersion, JobIrVersionRange, OperationId, RunnerCapabilities,
    RunnerSessionId, UnixMillis,
};
use serde::{Deserialize, Serialize};

use super::validation::{MessageValidationError, validate_schema};
use super::{CommandCursor, SessionDisposition, SessionResume};
use crate::{MESSAGE_SCHEMA_VERSION, ProtocolRange, ProtocolVersion, SUPPORTED_PROTOCOL_RANGE};

/// First runner-to-server handshake message, sent before version selection.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RunnerHello {
    message_schema_version: u16,
    operation_id: OperationId,
    supported_protocol: ProtocolRange,
    supported_job_ir: JobIrVersionRange,
    runner: RunnerCapabilities,
    resume: Option<SessionResume>,
    sent_at: UnixMillis,
}

impl RunnerHello {
    /// Creates a hello advertisement for the supplied supported range.
    #[must_use]
    pub const fn new(
        operation_id: OperationId,
        supported_protocol: ProtocolRange,
        supported_job_ir: JobIrVersionRange,
        runner: RunnerCapabilities,
        sent_at: UnixMillis,
    ) -> Self {
        Self {
            message_schema_version: MESSAGE_SCHEMA_VERSION,
            operation_id,
            supported_protocol,
            supported_job_ir,
            runner,
            resume: None,
            sent_at,
        }
    }

    #[must_use]
    /// Returns the message-structure schema understood by the runner.
    pub const fn message_schema_version(&self) -> u16 {
        self.message_schema_version
    }

    #[must_use]
    /// Returns the stable operation identity used to correlate the response.
    pub const fn operation_id(&self) -> OperationId {
        self.operation_id
    }

    #[must_use]
    /// Returns the inclusive wire-protocol range offered by the runner.
    pub const fn supported_protocol(&self) -> ProtocolRange {
        self.supported_protocol
    }

    #[must_use]
    /// Returns the inclusive `JobIR` schema range offered by the runner.
    pub const fn supported_job_ir(&self) -> JobIrVersionRange {
        self.supported_job_ir
    }

    /// Returns the runner's execution inventory advertisement.
    ///
    /// Advertised labels and groups are never authorization or routing truth;
    /// the server intersects capabilities with the authenticated,
    /// administrator-owned registration before scheduling.
    #[must_use]
    pub const fn runner(&self) -> &RunnerCapabilities {
        &self.runner
    }

    #[must_use]
    /// Returns the old-session claim and durable cursor, when resumption was requested.
    pub const fn resume(&self) -> Option<SessionResume> {
        self.resume
    }

    /// Adds a request to resume a locally journaled session. The server must
    /// still authenticate the runner and validate the durable session state.
    #[must_use]
    pub const fn with_resume(mut self, resume: SessionResume) -> Self {
        self.resume = Some(resume);
        self
    }

    #[must_use]
    /// Returns when the runner constructed the hello, in Unix milliseconds.
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
    operation_id: OperationId,
    in_reply_to: OperationId,
    session: NegotiatedSession,
    timing: ServerTiming,
}

/// Version selection and durable state established by a successful handshake.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct NegotiatedSession {
    selected_protocol: ProtocolVersion,
    selected_job_ir: JobIrVersion,
    session_id: RunnerSessionId,
    session_disposition: SessionDisposition,
    command_cursor: CommandCursor,
}

impl NegotiatedSession {
    /// Records the exact negotiated versions and resulting durable session state.
    #[must_use]
    pub const fn new(
        selected_protocol: ProtocolVersion,
        selected_job_ir: JobIrVersion,
        session_id: RunnerSessionId,
        session_disposition: SessionDisposition,
        command_cursor: CommandCursor,
    ) -> Self {
        Self {
            selected_protocol,
            selected_job_ir,
            session_id,
            session_disposition,
            command_cursor,
        }
    }

    #[must_use]
    /// Returns the highest mutually supported wire protocol selected by the server.
    pub const fn selected_protocol(self) -> ProtocolVersion {
        self.selected_protocol
    }

    #[must_use]
    /// Returns the highest mutually supported `JobIR` schema selected by the server.
    pub const fn selected_job_ir(self) -> JobIrVersion {
        self.selected_job_ir
    }

    #[must_use]
    /// Returns the authenticated session identity for post-handshake messages.
    pub const fn session_id(self) -> RunnerSessionId {
        self.session_id
    }

    #[must_use]
    /// Returns whether the server opened or resumed the session.
    pub const fn session_disposition(self) -> SessionDisposition {
        self.session_disposition
    }

    #[must_use]
    /// Returns the durable command prefix acknowledged at session establishment.
    pub const fn command_cursor(self) -> CommandCursor {
        self.command_cursor
    }
}

/// Server time and liveness policy selected for a runner session.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ServerTiming {
    server_time: UnixMillis,
    heartbeat_interval_millis: u32,
    lease_duration_millis: u32,
}

impl ServerTiming {
    /// Creates a server clock sample and nonzero liveness intervals.
    ///
    /// [`ServerHello::validate`] rejects zero heartbeat or lease durations.
    #[must_use]
    pub const fn new(
        server_time: UnixMillis,
        heartbeat_interval_millis: u32,
        lease_duration_millis: u32,
    ) -> Self {
        Self {
            server_time,
            heartbeat_interval_millis,
            lease_duration_millis,
        }
    }

    #[must_use]
    /// Returns the server clock sample in Unix milliseconds.
    pub const fn server_time(self) -> UnixMillis {
        self.server_time
    }

    #[must_use]
    /// Returns the requested interval between runner heartbeats.
    pub const fn heartbeat_interval_millis(self) -> u32 {
        self.heartbeat_interval_millis
    }

    #[must_use]
    /// Returns the server-selected lease lifetime in milliseconds.
    pub const fn lease_duration_millis(self) -> u32 {
        self.lease_duration_millis
    }
}

impl ServerHello {
    /// Creates a successful handshake response.
    #[must_use]
    pub const fn new(
        operation_id: OperationId,
        in_reply_to: OperationId,
        session: NegotiatedSession,
        timing: ServerTiming,
    ) -> Self {
        Self {
            message_schema_version: MESSAGE_SCHEMA_VERSION,
            operation_id,
            in_reply_to,
            session,
            timing,
        }
    }

    #[must_use]
    /// Returns the message-structure schema selected by this build.
    pub const fn message_schema_version(&self) -> u16 {
        self.message_schema_version
    }

    #[must_use]
    /// Returns this response's stable idempotency identity.
    pub const fn operation_id(&self) -> OperationId {
        self.operation_id
    }

    #[must_use]
    /// Returns the runner-hello operation answered by this response.
    pub const fn in_reply_to(&self) -> OperationId {
        self.in_reply_to
    }

    #[must_use]
    /// Returns the negotiated versions and resulting durable session state.
    pub const fn session(&self) -> NegotiatedSession {
        self.session
    }

    #[must_use]
    /// Returns the selected clock and liveness policy.
    pub const fn timing(&self) -> ServerTiming {
        self.timing
    }

    #[must_use]
    /// Returns the selected wire protocol version.
    pub const fn selected_protocol(&self) -> ProtocolVersion {
        self.session.selected_protocol
    }

    #[must_use]
    /// Returns the selected `JobIR` schema version.
    pub const fn selected_job_ir(&self) -> JobIrVersion {
        self.session.selected_job_ir
    }

    #[must_use]
    /// Returns the authenticated identity for post-handshake messages.
    pub const fn session_id(&self) -> RunnerSessionId {
        self.session.session_id
    }

    #[must_use]
    /// Returns whether this handshake opened or resumed the session.
    pub const fn session_disposition(&self) -> SessionDisposition {
        self.session.session_disposition
    }

    #[must_use]
    /// Returns the runner's accepted durable server-command prefix.
    pub const fn command_cursor(&self) -> CommandCursor {
        self.session.command_cursor
    }

    #[must_use]
    /// Returns the server clock sample in Unix milliseconds.
    pub const fn server_time(&self) -> UnixMillis {
        self.timing.server_time
    }

    #[must_use]
    /// Returns the requested interval between runner heartbeats.
    pub const fn heartbeat_interval_millis(&self) -> u32 {
        self.timing.heartbeat_interval_millis
    }

    #[must_use]
    /// Returns the selected lease lifetime in milliseconds.
    pub const fn lease_duration_millis(&self) -> u32 {
        self.timing.lease_duration_millis
    }

    /// Validates the response independently of handshake correlation.
    ///
    /// # Errors
    ///
    /// Returns [`MessageValidationError`] when schemas, protocol selection, or
    /// timing values cannot be accepted by this build.
    pub fn validate(&self) -> Result<(), MessageValidationError> {
        validate_schema(self.message_schema_version)?;
        if !SUPPORTED_PROTOCOL_RANGE.contains(self.session.selected_protocol) {
            return Err(MessageValidationError::UnsupportedProtocol {
                received: self.session.selected_protocol,
                supported: SUPPORTED_PROTOCOL_RANGE,
            });
        }
        if !JobIrVersionRange::current().supports(self.session.selected_job_ir) {
            return Err(MessageValidationError::UnsupportedJobIr {
                received: self.session.selected_job_ir,
                supported: JobIrVersionRange::current(),
            });
        }
        if self.timing.heartbeat_interval_millis == 0 || self.timing.lease_duration_millis == 0 {
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
        if self.in_reply_to != hello.operation_id {
            return Err(MessageValidationError::HandshakeCorrelationMismatch {
                expected: hello.operation_id,
                received: self.in_reply_to,
            });
        }
        if !hello
            .supported_protocol
            .contains(self.session.selected_protocol)
        {
            return Err(MessageValidationError::SelectionOutsideRunnerRange {
                selected: self.session.selected_protocol,
                offered: hello.supported_protocol,
            });
        }
        if !hello
            .supported_job_ir
            .supports(self.session.selected_job_ir)
        {
            return Err(MessageValidationError::JobIrSelectionOutsideRunnerRange {
                selected: self.session.selected_job_ir,
                offered: hello.supported_job_ir,
            });
        }
        match (self.session.session_disposition, hello.resume) {
            (SessionDisposition::Opened, _)
                if self.session.command_cursor != CommandCursor::initial() =>
            {
                return Err(MessageValidationError::NewSessionHasCommandCursor);
            }
            (SessionDisposition::Resumed, Some(resume))
                if resume.session_id() == self.session.session_id
                    && resume.command_cursor() == self.session.command_cursor => {}
            (SessionDisposition::Resumed, _) => {
                return Err(MessageValidationError::SessionResumeMismatch);
            }
            (SessionDisposition::Opened, _) => {}
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
    in_reply_to: OperationId,
    code: HandshakeErrorCode,
    supported_protocol: ProtocolRange,
    message: String,
    orphan_recovery: Option<SessionOrphanAuthorization>,
}

impl HandshakeRejected {
    /// Creates a pre-negotiation rejection without orphan-delivery authority.
    ///
    /// The message is human-readable and must be sanitized by the producer;
    /// peers use [`HandshakeErrorCode`] rather than parsing it for control flow.
    #[must_use]
    pub fn new(
        operation_id: OperationId,
        in_reply_to: OperationId,
        code: HandshakeErrorCode,
        supported_protocol: ProtocolRange,
        message: impl Into<String>,
    ) -> Self {
        Self {
            message_schema_version: MESSAGE_SCHEMA_VERSION,
            operation_id,
            in_reply_to,
            code,
            supported_protocol,
            message: message.into(),
            orphan_recovery: None,
        }
    }

    /// Creates a rejection that explicitly authorizes reconciliation of one
    /// definitively invalidated old session.
    ///
    /// The authorization is useful only after the response is correlated to
    /// an authenticated hello carrying the exact same resume claim.
    #[must_use]
    pub fn session_not_resumable(
        operation_id: OperationId,
        in_reply_to: OperationId,
        supported_protocol: ProtocolRange,
        orphan_recovery: SessionOrphanAuthorization,
        message: impl Into<String>,
    ) -> Self {
        Self {
            message_schema_version: MESSAGE_SCHEMA_VERSION,
            operation_id,
            in_reply_to,
            code: HandshakeErrorCode::SessionNotResumable,
            supported_protocol,
            message: message.into(),
            orphan_recovery: Some(orphan_recovery),
        }
    }

    /// Attaches recovery authority for decoding and protocol test adapters.
    ///
    /// The resulting value is accepted only when its code is
    /// [`HandshakeErrorCode::SessionNotResumable`]; normal producers should
    /// prefer [`Self::session_not_resumable`].
    #[must_use]
    pub fn with_orphan_recovery(mut self, orphan_recovery: SessionOrphanAuthorization) -> Self {
        self.orphan_recovery = Some(orphan_recovery);
        self
    }

    #[must_use]
    /// Returns the message-structure schema spoken by the rejecting server.
    pub const fn message_schema_version(&self) -> u16 {
        self.message_schema_version
    }

    #[must_use]
    /// Returns this rejection's stable operation identity.
    pub const fn operation_id(&self) -> OperationId {
        self.operation_id
    }

    #[must_use]
    /// Returns the runner-hello operation answered by this rejection.
    pub const fn in_reply_to(&self) -> OperationId {
        self.in_reply_to
    }

    #[must_use]
    /// Returns the stable machine-readable rejection reason.
    pub const fn code(&self) -> HandshakeErrorCode {
        self.code
    }

    #[must_use]
    /// Returns the wire-protocol range still supported by the server.
    pub const fn supported_protocol(&self) -> ProtocolRange {
        self.supported_protocol
    }

    #[must_use]
    /// Returns the sanitized human-readable rejection explanation.
    pub fn message(&self) -> &str {
        &self.message
    }

    /// Returns the exact old-session recovery authorization, when present.
    #[must_use]
    pub const fn orphan_recovery(&self) -> Option<SessionOrphanAuthorization> {
        self.orphan_recovery
    }

    /// Validates the rejection independently of request correlation.
    ///
    /// # Errors
    ///
    /// Rejects schema/range failures and any attempt to attach recovery
    /// authority to a code other than `SessionNotResumable`. A peer from an
    /// earlier deployment may omit the optional authority; callers must then
    /// treat the rejection as non-authorizing.
    pub fn validate(&self) -> Result<(), MessageValidationError> {
        validate_schema(self.message_schema_version)?;
        self.supported_protocol.validate()?;
        match (self.code, self.orphan_recovery) {
            (HandshakeErrorCode::SessionNotResumable, _) | (_, None) => Ok(()),
            (_, Some(_)) => Err(MessageValidationError::UnexpectedOrphanRecoveryAuthorization),
        }
    }

    /// Validates rejection correlation against the initiating runner hello.
    ///
    /// # Errors
    ///
    /// Returns [`MessageValidationError::HandshakeCorrelationMismatch`] when
    /// this response belongs to another handshake operation.
    pub fn validate_for(&self, hello: &RunnerHello) -> Result<(), MessageValidationError> {
        self.validate()?;
        if self.in_reply_to != hello.operation_id {
            return Err(MessageValidationError::HandshakeCorrelationMismatch {
                expected: hello.operation_id,
                received: self.in_reply_to,
            });
        }
        match (self.code, self.orphan_recovery, hello.resume) {
            (HandshakeErrorCode::SessionNotResumable, Some(authorization), Some(resume))
                if authorization.session_id() == resume.session_id() => {}
            (HandshakeErrorCode::SessionNotResumable, Some(_), None) => {
                return Err(MessageValidationError::OrphanRecoveryWithoutResume);
            }
            (HandshakeErrorCode::SessionNotResumable, Some(authorization), Some(resume)) => {
                return Err(MessageValidationError::OrphanRecoverySessionMismatch {
                    expected: resume.session_id(),
                    received: authorization.session_id(),
                });
            }
            (_, Some(_), _) => {
                return Err(MessageValidationError::UnexpectedOrphanRecoveryAuthorization);
            }
            (_, None, _) => {}
        }
        Ok(())
    }
}

/// Server-selected delivery dispositions for one invalidated runner session.
///
/// This value does not authorize recovery by itself. It becomes authoritative
/// only as part of a correlated [`HandshakeRejected`] received from the
/// authenticated control-plane peer.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SessionOrphanAuthorization {
    session_id: RunnerSessionId,
    permissions: OrphanDeliveryPermissions,
}

impl SessionOrphanAuthorization {
    /// Binds explicit abandonment permissions to one old session fence.
    #[must_use]
    pub const fn new(session_id: RunnerSessionId, permissions: OrphanDeliveryPermissions) -> Self {
        Self {
            session_id,
            permissions,
        }
    }

    /// Returns the exact invalidated session.
    #[must_use]
    pub const fn session_id(self) -> RunnerSessionId {
        self.session_id
    }

    /// Returns the delivery classes the server permits abandoning.
    #[must_use]
    pub const fn permissions(self) -> OrphanDeliveryPermissions {
        self.permissions
    }
}

/// Explicit old-session delivery classes which may be abandoned locally.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct OrphanDeliveryPermissions {
    terminal_result: bool,
    log_delivery: bool,
    lease_rejection: bool,
}

impl OrphanDeliveryPermissions {
    /// Creates an explicit delivery permission set.
    #[must_use]
    pub const fn new(terminal_result: bool, log_delivery: bool, lease_rejection: bool) -> Self {
        Self {
            terminal_result,
            log_delivery,
            lease_rejection,
        }
    }

    #[must_use]
    /// Returns whether an orphaned terminal result may be abandoned.
    pub const fn terminal_result(self) -> bool {
        self.terminal_result
    }

    #[must_use]
    /// Returns whether orphaned log delivery may be abandoned.
    pub const fn log_delivery(self) -> bool {
        self.log_delivery
    }

    #[must_use]
    /// Returns whether an orphaned lease rejection may be abandoned.
    pub const fn lease_rejection(self) -> bool {
        self.lease_rejection
    }
}

/// Stable reasons a server may reject the initial runner hello.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum HandshakeErrorCode {
    /// The hello violates its schema or local invariants.
    InvalidHello,
    /// The peers have no mutually supported wire protocol.
    UnsupportedProtocol,
    /// The peers have no mutually supported `JobIR` schema.
    UnsupportedJobIr,
    /// The runner's transport or credential identity could not be established.
    Unauthenticated,
    /// The authenticated runner is not allowed to open this session.
    Unauthorized,
    /// The authenticated runner's claimed durable session is no longer resumable.
    SessionNotResumable,
}
