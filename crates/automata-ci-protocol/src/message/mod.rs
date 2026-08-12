//! Versioned, owned handshake and execution messages.

mod authority;
mod codec;
mod control;
mod envelope;
mod error;
mod execution;
mod handshake;
mod header;
mod lease;
mod limits;
mod log;
mod managed_secret;
mod session;
mod validation;

pub use authority::*;
pub use codec::{ValidatedRunnerToServer, ValidatedServerToRunner};
pub use control::{CommandAck, OperationAck};
pub use envelope::{RunnerToServer, ServerToRunner};
pub use error::{ErrorMessage, NoWork, RemoteErrorCode};
pub use execution::{CancelJob, JobResultMessage, JobStateUpdate};
pub use handshake::{
    HandshakeErrorCode, HandshakeRejected, NegotiatedSession, OrphanDeliveryPermissions,
    RunnerHello, ServerHello, ServerTiming, SessionOrphanAuthorization,
};
pub use header::MessageHeader;
pub use lease::{
    LeaseDisposition, LeaseHeartbeat, LeaseOffer, LeaseRejectionReason, LeaseRenewal, LeaseRequest,
    LeaseResponse,
};
pub use limits::{MAX_CONFIGURABLE_FRAME_BYTES, ProtocolLimits, ProtocolLimitsError};
pub use log::{LogAckMessage, LogBatch};
pub use managed_secret::{
    MANAGED_SECRET_BINDING_OVERLAY_SCHEMA_VERSION, MAX_MANAGED_SECRET_BINDINGS,
    ManagedSecretBindingOverlay, ManagedSecretBindingOverlayEntry,
    ManagedSecretBindingOverlayError,
};
pub use session::{
    CommandCursor, CommandCursorError, CommandSequence, CommandSequenceError, RunnerSlotOrdinal,
    RunnerSlotOrdinalError, ServerCommandHeader, SessionDisposition, SessionResume,
};
pub use validation::{MessageValidationError, validate_job_ir_envelope};
