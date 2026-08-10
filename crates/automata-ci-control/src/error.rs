use automata_ci_control_plane::{
    EffectiveRunnerError, RoutingRequirementsError, RunnerCapabilityIntersectionError,
    RunnerEvidenceError, SchedulingInputError,
};
use automata_ci_core::{RunnerSessionId, SelectorError};
use automata_ci_protocol::{MessageValidationError, ProtocolVersion};
use automata_ci_store::{
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
        /// Session established by the authenticated connection.
        expected: RunnerSessionId,
        /// Session asserted by the decoded wire request.
        received: RunnerSessionId,
    },
    /// The wire request does not use the protocol selected for this session.
    #[error("lease request protocol {received:?} does not match negotiated protocol {expected:?}")]
    Protocol {
        /// Version selected during the authenticated protocol handshake.
        expected: ProtocolVersion,
        /// Version asserted by the decoded wire request.
        received: ProtocolVersion,
    },
}

/// Contradictions returned by a repository or an impure scheduling policy.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum LeasePollInvariant {
    /// The routing snapshot is fenced to a different runner session.
    #[error("routing snapshot belongs to another authenticated session")]
    RoutingFenceMismatch,
    /// Durable routing selected a different `JobIR` version than the session.
    #[error("routing snapshot selected a different JobIR version")]
    RoutingJobIrVersionMismatch,
    /// Slot availability disagrees with the registered slot range.
    #[error("slot availability contradicts registered slot capacity")]
    SlotAvailabilityContradiction,
    /// The policy selected an attempt outside the immutable scanned page.
    #[error("scheduler selected an attempt absent from its immutable input")]
    UnknownPlacementAttempt,
    /// The policy changed the selected attempt's durable job identity.
    #[error("scheduler changed the selected attempt's job identity")]
    PlacementJobMismatch,
    /// The policy placed work on a session other than the authenticated one.
    #[error("scheduler selected another runner session")]
    PlacementSessionMismatch,
    /// The policy placed work on a slot other than the one being polled.
    #[error("scheduler selected a slot other than the exact polled slot")]
    PlacementSlotMismatch,
    /// The policy selected the polled slot after durable state made it unavailable.
    #[error("scheduler selected a slot that durable state reported unavailable")]
    PlacementOnUnavailableSlot,
    /// A durable receipt does not authenticate the exact request key and digest.
    #[error("claim receipt belongs to another lease request")]
    ReceiptRequestMismatch,
    /// A claimed receipt assigns work to another fenced session or slot.
    #[error("claim receipt returned an assignment for another session or slot")]
    ReceiptAssignmentMismatch,
    /// A newly returned receipt claims an attempt other than the policy selection.
    #[error("claim receipt returned a lease for another attempt")]
    ReceiptAttemptMismatch,
    /// A claimed receipt references a `JobIR` version not negotiated by the session.
    #[error("claim receipt contains a JobIR version other than the negotiated selection")]
    ReceiptJobIrVersionMismatch,
}

/// Typed, adapter-neutral failures from one lease poll.
///
/// Variants separate malformed or mis-correlated requests, invalid durable or
/// policy state, and repository failures so a transport can choose a bounded
/// response and retry policy without parsing text. Display strings are intended
/// for trusted diagnostics; callers must not expose this value or its source
/// chain directly to an untrusted runner.
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
        /// Durable capability document that failed JSON decoding.
        document: CapabilityDocument,
        /// Decoder failure retained for trusted diagnostics.
        #[source]
        source: serde_json::Error,
    },
    /// A decoded capability advertisement violated the core schema.
    #[error("{document} runner capability document is invalid")]
    CapabilityValidation {
        /// Decoded capability document that failed domain validation.
        document: CapabilityDocument,
        /// Domain validation failure retained for trusted diagnostics.
        #[source]
        source: automata_ci_core::CapabilityValidationError,
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
