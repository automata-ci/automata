use automata_control_plane::{
    EffectiveRunnerError, RoutingRequirementsError, RunnerCapabilityIntersectionError,
    RunnerEvidenceError, SchedulingInputError,
};
use automata_core::{RunnerSessionId, SelectorError};
use automata_protocol::{MessageValidationError, ProtocolVersion};
use automata_store::{
    ClaimCommandError, DurabilityValueError, LeaseRequestKeyError, RunnableScanError, StoreError,
};
use thiserror::Error;

/// Which durable capability document failed decoding or validation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CapabilityDocument {
    /// Server-owned runner registration capabilities.
    Registered,
    /// Capabilities negotiated for the authenticated live session.
    Negotiated,
}

impl std::fmt::Display for CapabilityDocument {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Registered => formatter.write_str("registered"),
            Self::Negotiated => formatter.write_str("negotiated"),
        }
    }
}

/// Failed correlation between authenticated connection state and a validated
/// protocol lease request.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum RequestCorrelationError {
    /// The wire request names another session.
    #[error("lease request session {received} does not match authenticated session {expected}")]
    Session {
        expected: RunnerSessionId,
        received: RunnerSessionId,
    },
    /// The wire request does not use the protocol selected for this session.
    #[error("lease request protocol {received:?} does not match negotiated protocol {expected:?}")]
    Protocol {
        expected: ProtocolVersion,
        received: ProtocolVersion,
    },
}

/// Contradictions returned by a repository or an impure scheduling policy.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum LeasePollInvariant {
    #[error("routing snapshot belongs to another authenticated session")]
    RoutingFenceMismatch,
    #[error("routing snapshot selected a different JobIR version")]
    RoutingJobIrVersionMismatch,
    #[error("slot availability contradicts registered slot capacity")]
    SlotAvailabilityContradiction,
    #[error("scheduler selected an attempt absent from its immutable input")]
    UnknownPlacementAttempt,
    #[error("scheduler changed the selected attempt's job identity")]
    PlacementJobMismatch,
    #[error("scheduler selected another runner session")]
    PlacementSessionMismatch,
    #[error("scheduler selected a slot other than the exact polled slot")]
    PlacementSlotMismatch,
    #[error("scheduler selected a slot that durable state reported unavailable")]
    PlacementOnUnavailableSlot,
    #[error("claim receipt belongs to another lease request")]
    ReceiptRequestMismatch,
    #[error("claim receipt returned an assignment for another session or slot")]
    ReceiptAssignmentMismatch,
    #[error("claim receipt returned a lease for another attempt")]
    ReceiptAttemptMismatch,
    #[error("claim receipt contains a JobIR version other than the negotiated selection")]
    ReceiptJobIrVersionMismatch,
}

/// Typed, adapter-neutral failures from one lease poll.
#[derive(Debug, Error)]
pub enum LeasePollError {
    /// The lease request had not passed protocol-level validation.
    #[error("lease request failed protocol validation")]
    InvalidProtocolRequest(#[source] MessageValidationError),
    /// Authenticated and request identities did not correlate.
    #[error(transparent)]
    RequestCorrelation(#[from] RequestCorrelationError),
    /// A protocol slot could not be represented by the durable store type.
    #[error("validated protocol slot could not be represented durably")]
    InvalidDurableSlot(#[source] DurabilityValueError),
    /// A durable chain key contradicted protocol-v4 request invariants.
    #[error("validated lease-request chain could not be represented durably")]
    InvalidLeaseRequestChain(#[source] LeaseRequestKeyError),
    /// A durable capability document was not valid core-domain JSON.
    #[error("{document} runner capability document could not be decoded")]
    CapabilityDecode {
        document: CapabilityDocument,
        #[source]
        source: serde_json::Error,
    },
    /// A decoded capability advertisement violated the core schema.
    #[error("{document} runner capability document is invalid")]
    CapabilityValidation {
        document: CapabilityDocument,
        #[source]
        source: automata_core::CapabilityValidationError,
    },
    /// Durable administrative selectors were malformed.
    #[error("durable runner routing selector is invalid")]
    InvalidRoutingSelector(#[source] SelectorError),
    /// Negotiated evidence did not belong to the authenticated runner.
    #[error("negotiated runner evidence is invalid")]
    InvalidRunnerEvidence(#[source] RunnerEvidenceError),
    /// Registered and observed abilities could not form a least-authority set.
    #[error("runner capability intersection is invalid")]
    InvalidCapabilityIntersection(#[source] RunnerCapabilityIntersectionError),
    /// Intersected abilities could not be safely authorized against evidence.
    #[error("effective runner state is invalid")]
    InvalidEffectiveRunner(#[source] EffectiveRunnerError),
    /// A durable runnable row had invalid planner requirements.
    #[error("runnable routing requirements are invalid")]
    InvalidRoutingRequirements(#[source] RoutingRequirementsError),
    /// A scheduler snapshot contained contradictory durable identities.
    #[error("scheduler input is invalid")]
    InvalidSchedulingInput(#[source] SchedulingInputError),
    /// A scheduler selected outside the opaque durable scan page.
    #[error("scheduler selection does not match the durable scan page")]
    InvalidRunnableScan(#[source] RunnableScanError),
    /// Trusted-time lease expiry arithmetic exceeded `UnixMillis`.
    #[error("lease expiration overflows the trusted timestamp range")]
    LeaseExpiryOverflow,
    /// A claim command could not represent the configured lease interval.
    #[error("lease claim command is invalid")]
    InvalidClaim(#[source] ClaimCommandError),
    /// A durable read or mutation failed without exposing its database driver.
    #[error("lease-poll repository operation failed")]
    Store(#[source] StoreError),
    /// A repository or policy violated an application invariant.
    #[error(transparent)]
    Invariant(#[from] LeasePollInvariant),
}

impl From<StoreError> for LeasePollError {
    fn from(error: StoreError) -> Self {
        Self::Store(error)
    }
}
