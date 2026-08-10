use std::{fmt, time::Duration};

/// Closed outcome of one physical lease-poll attempt.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LeasePollObservation {
    /// A new durable claim transition committed.
    Claimed,
    /// A prior durable claim receipt was replayed.
    ClaimedReplay,
    /// A new durable no-work receipt committed.
    NoWork,
    /// A prior durable no-work receipt was replayed.
    NoWorkReplay,
    /// A new durable negative claim receipt committed.
    Rejected(LeaseClaimRejection),
    /// A prior durable negative claim receipt was replayed.
    RejectedReplay(LeaseClaimRejection),
    /// The physical poll failed before returning a durable semantic outcome.
    Failed(LeasePollFailure),
}

/// Privacy-safe durable claim rejection categories.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LeaseClaimRejection {
    /// The selected attempt no longer exists at transactional recheck.
    AttemptNotFound,
    /// The selected attempt is no longer in the queued lifecycle state.
    AttemptNotQueued,
    /// A dependency or other durable condition made the attempt unrunnable.
    NoLongerRunnable,
    /// Current routing state no longer permits this runner to claim the attempt.
    NotRoutable,
    /// The polled stable slot is outside the runner's registered capacity.
    SlotOutOfRange,
    /// Another live assignment already occupies the polled stable slot.
    SlotOccupied,
    /// Another operation advanced the durable scan cursor before this claim.
    ScanSuperseded,
}

/// Privacy-safe physical lease-poll failure categories.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LeasePollFailure {
    /// The request was malformed or did not correlate with its authenticated session.
    InvalidRequest,
    /// Durable data, policy output, or trusted configuration violated an invariant.
    InvalidState,
    /// The durable repository failed before a semantic result was available.
    Unavailable,
}

/// Provider-neutral observation seam for the bounded lease-poll service.
///
/// Implementations must not retain request or durable identities. All inputs
/// are bounded scalar values or closed enums selected by this crate.
pub trait LeasePollObserver: fmt::Debug + Send + Sync {
    /// Records the final result of one physical poll attempt.
    fn observe_poll(&self, _outcome: LeasePollObservation, _duration: Duration) {}

    /// Records how many durable runnable candidates one fresh poll inspected.
    fn observe_candidates(&self, _count: usize) {}

    /// Records queue-to-claim latency for a newly committed claim only.
    fn observe_queue_wait(&self, _duration: Duration) {}
}

/// Allocation-free observer used when metrics are not composed.
#[derive(Clone, Copy, Debug, Default)]
pub struct NoopLeasePollObserver;

impl LeasePollObserver for NoopLeasePollObserver {}

pub(crate) static NOOP_LEASE_POLL_OBSERVER: NoopLeasePollObserver = NoopLeasePollObserver;
