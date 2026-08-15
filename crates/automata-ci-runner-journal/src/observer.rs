use std::time::Duration;

/// Finite semantic domain of a runner-journal mutation.
///
/// These values deliberately describe durable state classes, never a runner,
/// lease, operation, slot, path, or provider identity.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum JournalMutationDomain {
    /// Runner-session creation or resumption.
    Session,
    /// Per-slot lease-request checkpoint preparation or advancement.
    LeasePoll,
    /// Inbound command disposition and contiguous-cursor advancement.
    Command,
    /// Lease offer, acceptance, rejection, acknowledgement, or renewal state.
    Lease,
    /// Attempt lifecycle and cancellation state.
    Lifecycle,
    /// Terminal-result outbox state.
    Result,
    /// Provider mutation intent or recovery outcome.
    Provider,
    /// Execution-endpoint acceptance, invocation, result, or cancellation.
    Endpoint,
    /// Runner-to-control-plane operation cursor state.
    Outbound,
    /// Durable log stream, segment, seal, or acknowledgement state.
    Log,
    /// Server-authorized old-session reconciliation state.
    Orphan,
    /// Final slot release.
    Slot,
}

/// Finite terminal outcome of an attempted journal mutation.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum JournalMutationOutcome {
    /// A changed candidate was atomically committed and published in memory.
    Committed,
    /// The requested state was already durable, so no write was needed.
    Noop,
    /// The semantic mutation or bounded encoding was rejected before I/O.
    Rejected,
    /// The commit failed before rename and its lack of effect is known.
    IoError,
    /// Rename may have taken effect but directory durability is uncertain.
    Uncertain,
    /// The handle was already poisoned or its process-local mutex was poisoned.
    Poisoned,
}

/// One completed attempt at the journal's durable mutation boundary.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct JournalMutationObservation {
    domain: JournalMutationDomain,
    outcome: JournalMutationOutcome,
    duration: Duration,
    encoded_bytes: Option<u64>,
}

impl JournalMutationObservation {
    /// Describes one completed mutation without attaching runner, lease, path,
    /// operation, or provider identifiers.
    #[must_use]
    pub const fn new(
        domain: JournalMutationDomain,
        outcome: JournalMutationOutcome,
        duration: Duration,
        encoded_bytes: Option<u64>,
    ) -> Self {
        Self {
            domain,
            outcome,
            duration,
            encoded_bytes,
        }
    }

    /// Returns the closed semantic class of the attempted mutation.
    #[must_use]
    pub const fn domain(self) -> JournalMutationDomain {
        self.domain
    }

    /// Returns the result at the physical durability boundary.
    #[must_use]
    pub const fn outcome(self) -> JournalMutationOutcome {
        self.outcome
    }

    /// Returns the elapsed time through commit classification and observation.
    #[must_use]
    pub const fn duration(self) -> Duration {
        self.duration
    }

    /// Returns the canonical encoded journal size after a successful commit.
    #[must_use]
    pub const fn encoded_bytes(self) -> Option<u64> {
        self.encoded_bytes
    }
}

/// Infallible observation port for physical journal mutations.
///
/// Implementations must remain bounded and must not perform durable or remote
/// I/O. Observation is deliberately outside the journal's correctness model.
pub trait JournalObserver: Send + Sync {
    /// Publishes the canonical encoded size read or created during open.
    fn observe_opened(&self, _encoded_bytes: u64) {}

    /// Publishes one completed mutation attempt.
    fn observe_mutation(&self, _observation: JournalMutationObservation) {}
}

/// Observer used when journal telemetry is disabled.
#[derive(Clone, Copy, Debug, Default)]
pub struct NoopJournalObserver;

impl JournalObserver for NoopJournalObserver {}
