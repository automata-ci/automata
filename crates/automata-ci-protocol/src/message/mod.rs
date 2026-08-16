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
mod lease_authority;
mod limits;
mod log;
mod managed_secret;
mod session;
mod validation;

pub use authority::*;
pub use codec::{ValidatedRunnerToServer, ValidatedServerToRunner};
pub use control::{CommandAck, OperationAck};
pub use envelope::{RunnerToServer, ServerToRunner};
pub use error::{ErrorMessage, RemoteErrorCode};
pub use execution::{CancelJob, JobResultMessage, JobStateUpdate};
pub use handshake::{
    HandshakeErrorCode, HandshakeRejected, NegotiatedSession, OrphanDeliveryPermissions,
    RunnerHello, ServerHello, ServerTiming, SessionOrphanAuthorization,
};
pub use header::MessageHeader;
pub use lease::{
    LeaseDisposition, LeaseHeartbeat, LeaseOffer, LeasePollOutcome, LeasePollResponse,
    LeaseRejectionReason, LeaseRenewal, LeaseRequest, LeaseResponse,
};
pub use lease_authority::{
    LEASE_AUTHORITY_POLL_CONTRIBUTIONS_SCHEMA_VERSION, LeaseAuthorityName,
    LeaseAuthorityPollContribution, LeaseAuthorityPollContributionError,
    LeaseAuthorityPollContributions, LeaseAuthorityPollReceipt, MAX_LEASE_AUTHORITY_NAME_BYTES,
    MAX_LEASE_AUTHORITY_POLL_CONTRIBUTIONS, MAX_LEASE_AUTHORITY_POLL_PAYLOAD_BYTES,
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
