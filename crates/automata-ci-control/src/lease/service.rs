use std::{
    collections::BTreeSet,
    time::{Duration, Instant},
};

use crate::lease::{
    ClaimRejection, LeaseRequestKey, NoWorkLeaseRequest, RunnableAttempt, RunnableScanPage,
    RunnableScanRequest, TryClaimAttempt, TryClaimOutcome, TryClaimReceipt,
};
use crate::scheduling::{
    AuthorizedRunnerRouting, EffectiveRunner, Placement, PlacementDecision, RoutingRequirements,
    RunnableCandidate, RunnerEvidence, RunnerSlot, SchedulerPolicy, SchedulingInput, SessionGuard,
    intersect_runner_capabilities,
};
use automata_ci_core::{
    JobIrVersion, Lease, RunnerCapabilities, RunnerGroup, RunnerLabel, UnixMillis,
};
use automata_ci_protocol::{LeaseRequest, ProtocolVersion, RunnerSlotOrdinal};
use automata_ci_store::{JobIrMetadata, RoutingDocument, RunnerSessionFence, StableRunnerSlot};

use super::{
    CapabilityDocument, LeaseClock, LeaseIdGenerator, LeasePollConfig, LeasePollError,
    LeasePollFailure, LeasePollInvariant, LeasePollObservation, LeasePollObserver,
    LeasePollRepository, RequestCorrelationError, RunnableAttemptGate,
    RunnableAttemptGateDisposition,
    observer::NOOP_LEASE_POLL_OBSERVER,
    routing::{RunnerRoutingSnapshot, RunnerSlotAvailability},
};

/// Exact authenticated connection context established before request dispatch.
///
/// This value contains no credential and does not authenticate a caller. A
/// transport-specific boundary constructs it only after authenticating the
/// connection and negotiating protocol and `JobIR` versions. The service then
/// uses its durable fence to prevent a request from crossing runner sessions.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AuthenticatedRunnerSession {
    fence: RunnerSessionFence,
    protocol_version: ProtocolVersion,
    job_ir_version: JobIrVersion,
}

impl AuthenticatedRunnerSession {
    /// Binds an authenticated durable fence to its negotiated wire protocol.
    #[must_use]
    pub const fn new(
        fence: RunnerSessionFence,
        protocol_version: ProtocolVersion,
        job_ir_version: JobIrVersion,
    ) -> Self {
        Self {
            fence,
            protocol_version,
            job_ir_version,
        }
    }

    /// Returns the exact durable session fence.
    #[must_use]
    pub const fn fence(self) -> RunnerSessionFence {
        self.fence
    }

    /// Returns the protocol selected during the authenticated handshake.
    #[must_use]
    pub const fn protocol_version(self) -> ProtocolVersion {
        self.protocol_version
    }

    /// Returns the exact `JobIR` version selected during the handshake.
    #[must_use]
    pub const fn job_ir_version(self) -> JobIrVersion {
        self.job_ir_version
    }
}

/// Successful provider-neutral lease result.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ClaimedLeasePoll {
    lease: Lease,
    slot: RunnerSlotOrdinal,
    job_ir: JobIrMetadata,
    replayed: bool,
}

impl ClaimedLeasePoll {
    /// Reconstitutes one exact claimed poll from a trusted scheduling adapter.
    #[must_use]
    pub const fn new(
        lease: Lease,
        slot: RunnerSlotOrdinal,
        job_ir: JobIrMetadata,
        replayed: bool,
    ) -> Self {
        Self {
            lease,
            slot,
            job_ir,
            replayed,
        }
    }

    /// Returns the exclusive core-domain lease and fencing token.
    #[must_use]
    pub const fn lease(&self) -> &Lease {
        &self.lease
    }

    /// Returns the exact stable protocol slot that initiated the poll.
    #[must_use]
    pub const fn slot(&self) -> RunnerSlotOrdinal {
        self.slot
    }

    /// Returns immutable object metadata; object bytes remain with a provider.
    #[must_use]
    pub const fn job_ir(&self) -> &JobIrMetadata {
        &self.job_ir
    }

    /// Reports whether a durable terminal receipt was replayed.
    #[must_use]
    pub const fn was_replayed(&self) -> bool {
        self.replayed
    }
}

/// Provider-neutral durable result of one authenticated outbound runner poll.
///
/// The `replayed` fields distinguish a receipt returned for an exact retry from
/// a result first committed by the current call. Both forms describe the same
/// durable semantic result and are safe for idempotent response reconstruction.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum LeasePollOutcome {
    /// One immutable `JobIR` object may be loaded and offered under this lease.
    Claimed(ClaimedLeasePoll),
    /// The scheduler found no compatible work/capacity and durably recorded it.
    NoWork {
        /// Whether this call replayed an already committed no-work receipt.
        replayed: bool,
    },
    /// The transactional claim recheck lost a race or rejected durable state.
    Rejected {
        /// Closed durable reason that prevented the claim.
        reason: ClaimRejection,
        /// Whether this call replayed an already committed rejection receipt.
        replayed: bool,
    },
}

/// Application service for one bounded, authenticated lease poll.
///
/// Authentication, wire decoding, SQL, and `JobIR` object loading remain the
/// responsibility of surrounding adapters. This service correlates the request
/// with the supplied session fence, derives least-authority scheduling input
/// from bounded durable snapshots, checks the policy's placement against that
/// input, and delegates the atomic claim or no-work receipt to the repository.
pub struct LeasePollService<'a> {
    repository: &'a dyn LeasePollRepository,
    scheduler: &'a dyn SchedulerPolicy,
    clock: &'a dyn LeaseClock,
    lease_ids: &'a dyn LeaseIdGenerator,
    attempt_gate: Option<&'a dyn RunnableAttemptGate>,
    observer: &'a dyn LeasePollObserver,
    config: LeasePollConfig,
}

impl std::fmt::Debug for LeasePollService<'_> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("LeasePollService")
            .field("scheduler", &self.scheduler)
            .field("clock", &self.clock)
            .field("lease_ids", &self.lease_ids)
            .field("attempt_gate", &self.attempt_gate)
            .field("observer", &self.observer)
            .field("config", &self.config)
            .finish_non_exhaustive()
    }
}

impl<'a> LeasePollService<'a> {
    /// Composes neutral ports and an immutable scheduler policy.
    ///
    /// The repository is responsible for transactional fencing and durable
    /// exact-request replay. The clock and identity source are invoked only by
    /// a fresh scheduling path; their values never override a stored receipt.
    #[must_use]
    pub const fn new(
        repository: &'a dyn LeasePollRepository,
        scheduler: &'a dyn SchedulerPolicy,
        clock: &'a dyn LeaseClock,
        lease_ids: &'a dyn LeaseIdGenerator,
        config: LeasePollConfig,
    ) -> Self {
        Self {
            repository,
            scheduler,
            clock,
            lease_ids,
            attempt_gate: None,
            observer: &NOOP_LEASE_POLL_OBSERVER,
            config,
        }
    }

    /// Installs a provider-neutral observer for physical and semantic poll outcomes.
    #[must_use]
    pub fn with_observer(mut self, observer: &'a dyn LeasePollObserver) -> Self {
        self.observer = observer;
        self
    }

    /// Installs a value-free pre-scheduling attempt gate.
    #[must_use]
    pub fn with_attempt_gate(mut self, gate: &'a dyn RunnableAttemptGate) -> Self {
        self.attempt_gate = Some(gate);
        self
    }

    /// Executes one authenticated outbound runner poll.
    ///
    /// Receipt lookup always precedes routing/capacity/queue reads. A found
    /// receipt is translated directly and never passed back to the scheduler.
    /// If concurrent callers race after lookup, the repository's atomic receipt
    /// contract remains authoritative and this method returns its replayed or
    /// rejected result. A successful return therefore always reflects durable
    /// state rather than a speculative policy decision.
    ///
    /// # Errors
    ///
    /// Returns [`LeasePollError`] for request correlation, corrupt durable
    /// documents, invalid scheduler output, time overflow, or repository
    /// failures. The error is for trusted application handling; a transport
    /// should map it to a sanitized bounded response and decide whether to retry
    /// from its variant, not its display text.
    pub async fn poll(
        &self,
        authenticated: AuthenticatedRunnerSession,
        request: &LeaseRequest,
    ) -> Result<LeasePollOutcome, LeasePollError> {
        let started = Instant::now();
        let result = self.poll_inner(authenticated, request).await;
        let observation = match &result {
            Ok(outcome) => observe_outcome(outcome),
            Err(error) => LeasePollObservation::Failed(observe_failure(error)),
        };
        self.observer.observe_poll(observation, started.elapsed());
        result
    }

    async fn poll_inner(
        &self,
        authenticated: AuthenticatedRunnerSession,
        request: &LeaseRequest,
    ) -> Result<LeasePollOutcome, LeasePollError> {
        let poll = ValidatedLeasePoll::new(authenticated, request)?;

        if let Some(receipt) = self
            .repository
            .lookup_lease_request(poll.request_key)
            .await?
        {
            return Self::receipt_outcome(poll, &receipt, None, true);
        }

        let observed_at = self.clock.now();
        let routing = self
            .repository
            .routing_for_session(poll.request_key.session())
            .await?;
        ensure_routing_context(&routing, poll)?;
        let registered = decode_capabilities(
            routing.registered_capabilities(),
            CapabilityDocument::Registered,
        )?;
        let negotiated = decode_capabilities(
            routing.negotiated_capabilities(),
            CapabilityDocument::Negotiated,
        )?;

        let availability = self
            .repository
            .slot_availability(
                poll.request_key.session(),
                poll.request_key.slot(),
                observed_at,
            )
            .await?;
        validate_availability(&routing, poll.request_key.slot(), availability)?;
        let effective = effective_runner(
            &routing,
            &registered,
            negotiated,
            poll.request_key.slot(),
            availability,
            observed_at,
        )?;
        let slot_is_effectively_available = !effective.available_slots().is_empty();

        let page = self
            .repository
            .scan_runnable(RunnableScanRequest::new(
                poll.request_key.session(),
                poll.request_key.slot(),
                self.config.scan_limit(),
                observed_at,
            ))
            .await?;
        let candidates = page
            .candidates()
            .iter()
            .map(candidate_from_durable)
            .collect::<Result<Vec<_>, _>>()?;
        self.observer.observe_candidates(candidates.len());
        let mut scheduler_candidates = Vec::with_capacity(candidates.len());
        for candidate in &candidates {
            let disposition = if let Some(gate) = self.attempt_gate {
                gate.evaluate(candidate.candidate.attempt_id(), observed_at)
                    .await?
            } else {
                RunnableAttemptGateDisposition::Ready
            };
            if disposition == RunnableAttemptGateDisposition::Ready {
                scheduler_candidates.push(candidate.candidate.clone());
            }
        }
        let runners = [effective];
        let input = SchedulingInput::new(&scheduler_candidates, &runners)
            .map_err(LeasePollError::InvalidSchedulingInput)?;

        match self.scheduler.decide(input) {
            PlacementDecision::Place(placement) => {
                self.claim(
                    poll,
                    availability == RunnerSlotAvailability::Available
                        && slot_is_effectively_available,
                    observed_at,
                    placement,
                    &candidates,
                    &page,
                )
                .await
            }
            PlacementDecision::Decline(_) => {
                let receipt = self
                    .repository
                    .record_no_work(
                        NoWorkLeaseRequest::new(
                            poll.request_key,
                            observed_at,
                            page.no_work_advance(),
                        )
                        .map_err(LeasePollError::InvalidClaim)?,
                    )
                    .await?;
                Self::receipt_outcome(poll, &receipt, None, false)
            }
        }
    }

    async fn claim(
        &self,
        poll: ValidatedLeasePoll,
        slot_is_available: bool,
        observed_at: UnixMillis,
        placement: Placement,
        candidates: &[ApplicationCandidate],
        page: &RunnableScanPage,
    ) -> Result<LeasePollOutcome, LeasePollError> {
        if !slot_is_available {
            return Err(LeasePollInvariant::PlacementOnUnavailableSlot.into());
        }
        let expected_session = SessionGuard::new(
            poll.request_key.session().runner_id(),
            poll.request_key.session().session_id(),
        );
        if placement.session() != expected_session {
            return Err(LeasePollInvariant::PlacementSessionMismatch.into());
        }
        if placement.slot().runner_id() != poll.request_key.session().runner_id()
            || placement.slot().ordinal() != poll.request_key.slot().ordinal()
        {
            return Err(LeasePollInvariant::PlacementSlotMismatch.into());
        }
        let selected = candidates
            .iter()
            .find(|candidate| candidate.candidate.attempt_id() == placement.attempt_id())
            .ok_or(LeasePollInvariant::UnknownPlacementAttempt)?;
        if selected.candidate.job_id() != placement.job_id() {
            return Err(LeasePollInvariant::PlacementJobMismatch.into());
        }

        let expires_at = observed_at
            .get()
            .checked_add(self.config.lease_time_to_live().as_millis())
            .map(UnixMillis::new)
            .ok_or(LeasePollError::LeaseExpiryOverflow)?;
        let claim = TryClaimAttempt::new(
            poll.request_key,
            placement.attempt_id(),
            self.lease_ids.next_lease_id(),
            observed_at,
            expires_at,
            page.claim_advance(placement.attempt_id())
                .map_err(LeasePollError::InvalidRunnableScan)?,
        )
        .map_err(LeasePollError::InvalidClaim)?;
        let receipt = self.repository.try_claim(claim).await?;
        let outcome = Self::receipt_outcome(
            poll,
            &receipt,
            Some((placement.attempt_id(), placement.job_id())),
            false,
        )?;
        if matches!(&outcome, LeasePollOutcome::Claimed(claimed) if !claimed.was_replayed())
            && let Some(milliseconds) = observed_at
                .get()
                .checked_sub(selected.candidate.queued_at().get())
                .and_then(|value| u64::try_from(value).ok())
        {
            self.observer
                .observe_queue_wait(Duration::from_millis(milliseconds));
        }
        Ok(outcome)
    }

    fn receipt_outcome(
        poll: ValidatedLeasePoll,
        receipt: &TryClaimReceipt,
        selected: Option<(automata_ci_core::AttemptId, automata_ci_core::JobId)>,
        found_before_scheduling: bool,
    ) -> Result<LeasePollOutcome, LeasePollError> {
        if receipt.request_key() != poll.request_key
            || receipt.request_digest() != poll.request_key.request_digest()
        {
            return Err(LeasePollInvariant::ReceiptRequestMismatch.into());
        }
        let replayed = found_before_scheduling || receipt.was_replayed();
        match receipt.outcome() {
            TryClaimOutcome::Claimed(claimed) => {
                let request_key = receipt.request_key();
                if claimed.assignment().session() != request_key.session()
                    || claimed.assignment().slot() != request_key.slot()
                {
                    return Err(LeasePollInvariant::ReceiptAssignmentMismatch.into());
                }
                let attempt_id = claimed.lease().attempt_id();
                if selected.is_some_and(|(selected_attempt, selected_job)| {
                    !replayed
                        && (selected_attempt != attempt_id
                            || selected_job != claimed.job_ir().job_id())
                }) {
                    return Err(LeasePollInvariant::ReceiptAttemptMismatch.into());
                }
                if claimed.job_ir().version() != poll.job_ir_version {
                    return Err(LeasePollInvariant::ReceiptJobIrVersionMismatch.into());
                }
                let slot = RunnerSlotOrdinal::new(request_key.slot().ordinal())
                    .map_err(|_| LeasePollInvariant::ReceiptAssignmentMismatch)?;
                Ok(LeasePollOutcome::Claimed(ClaimedLeasePoll::new(
                    claimed.lease().clone(),
                    slot,
                    claimed.job_ir().clone(),
                    replayed,
                )))
            }
            TryClaimOutcome::Rejected(reason) => Ok(LeasePollOutcome::Rejected {
                reason: *reason,
                replayed,
            }),
            TryClaimOutcome::NoWork => Ok(LeasePollOutcome::NoWork { replayed }),
        }
    }
}

const fn observe_outcome(outcome: &LeasePollOutcome) -> LeasePollObservation {
    match outcome {
        LeasePollOutcome::Claimed(claimed) if claimed.was_replayed() => {
            LeasePollObservation::ClaimedReplay
        }
        LeasePollOutcome::Claimed(_) => LeasePollObservation::Claimed,
        LeasePollOutcome::NoWork { replayed: true } => LeasePollObservation::NoWorkReplay,
        LeasePollOutcome::NoWork { replayed: false } => LeasePollObservation::NoWork,
        LeasePollOutcome::Rejected {
            reason,
            replayed: true,
        } => LeasePollObservation::RejectedReplay(observe_rejection(*reason)),
        LeasePollOutcome::Rejected {
            reason,
            replayed: false,
        } => LeasePollObservation::Rejected(observe_rejection(*reason)),
    }
}

const fn observe_rejection(reason: ClaimRejection) -> super::LeaseClaimRejection {
    match reason {
        ClaimRejection::ClaimExpired => super::LeaseClaimRejection::ClaimExpired,
        ClaimRejection::ClaimSuperseded => super::LeaseClaimRejection::ClaimSuperseded,
        ClaimRejection::AttemptNotFound => super::LeaseClaimRejection::AttemptNotFound,
        ClaimRejection::AttemptNotQueued(_) => super::LeaseClaimRejection::AttemptNotQueued,
        ClaimRejection::NoLongerRunnable => super::LeaseClaimRejection::NoLongerRunnable,
        ClaimRejection::NotRoutable => super::LeaseClaimRejection::NotRoutable,
        ClaimRejection::SlotOutOfRange => super::LeaseClaimRejection::SlotOutOfRange,
        ClaimRejection::SlotOccupied { .. } => super::LeaseClaimRejection::SlotOccupied,
        ClaimRejection::ScanSuperseded => super::LeaseClaimRejection::ScanSuperseded,
    }
}

const fn observe_failure(error: &LeasePollError) -> LeasePollFailure {
    match error {
        LeasePollError::InvalidProtocolRequest(_)
        | LeasePollError::RequestCorrelation(_)
        | LeasePollError::InvalidDurableSlot(_)
        | LeasePollError::InvalidLeaseRequestChain(_) => LeasePollFailure::InvalidRequest,
        LeasePollError::Store(_) => LeasePollFailure::Unavailable,
        LeasePollError::CapabilityDecode { .. }
        | LeasePollError::CapabilityValidation { .. }
        | LeasePollError::InvalidRoutingSelector(_)
        | LeasePollError::InvalidRunnerEvidence(_)
        | LeasePollError::InvalidCapabilityIntersection(_)
        | LeasePollError::InvalidEffectiveRunner(_)
        | LeasePollError::InvalidRoutingRequirements(_)
        | LeasePollError::InvalidSchedulingInput(_)
        | LeasePollError::InvalidRunnableScan(_)
        | LeasePollError::LeaseExpiryOverflow
        | LeasePollError::InvalidClaim(_)
        | LeasePollError::Invariant(_) => LeasePollFailure::InvalidState,
    }
}

#[derive(Clone, Copy, Debug)]
struct ValidatedLeasePoll {
    request_key: LeaseRequestKey,
    job_ir_version: JobIrVersion,
}

impl ValidatedLeasePoll {
    fn new(
        authenticated: AuthenticatedRunnerSession,
        request: &LeaseRequest,
    ) -> Result<Self, LeasePollError> {
        let header = request.header();
        request
            .validate()
            .map_err(LeasePollError::InvalidProtocolRequest)?;
        if header.session_id() != authenticated.fence.session_id() {
            return Err(RequestCorrelationError::Session {
                expected: authenticated.fence.session_id(),
                received: header.session_id(),
            }
            .into());
        }
        if header.protocol_version() != authenticated.protocol_version {
            return Err(RequestCorrelationError::Protocol {
                expected: authenticated.protocol_version,
                received: header.protocol_version(),
            }
            .into());
        }
        let slot = StableRunnerSlot::new(request.slot().get())
            .map_err(LeasePollError::InvalidDurableSlot)?;
        let request_key = match request.acknowledges_operation_id() {
            Some(predecessor) => LeaseRequestKey::successor(
                authenticated.fence,
                header.operation_id(),
                slot,
                predecessor,
            )
            .map_err(LeasePollError::InvalidLeaseRequestChain)?,
            None => LeaseRequestKey::first(authenticated.fence, header.operation_id(), slot),
        };
        Ok(Self {
            request_key,
            job_ir_version: authenticated.job_ir_version,
        })
    }
}

struct ApplicationCandidate {
    candidate: RunnableCandidate,
}

fn ensure_routing_context(
    routing: &RunnerRoutingSnapshot,
    expected: ValidatedLeasePoll,
) -> Result<(), LeasePollError> {
    if routing.fence() != expected.request_key.session() {
        return Err(LeasePollInvariant::RoutingFenceMismatch.into());
    }
    if routing.job_ir_version() != expected.job_ir_version {
        return Err(LeasePollInvariant::RoutingJobIrVersionMismatch.into());
    }
    Ok(())
}

fn decode_capabilities(
    document: &RoutingDocument,
    kind: CapabilityDocument,
) -> Result<RunnerCapabilities, LeasePollError> {
    let capabilities =
        serde_json::from_str::<RunnerCapabilities>(document.as_str()).map_err(|source| {
            LeasePollError::CapabilityDecode {
                document: kind,
                source,
            }
        })?;
    capabilities
        .validate()
        .map_err(|source| LeasePollError::CapabilityValidation {
            document: kind,
            source,
        })?;
    Ok(capabilities)
}

fn validate_availability(
    routing: &RunnerRoutingSnapshot,
    slot: StableRunnerSlot,
    availability: RunnerSlotAvailability,
) -> Result<(), LeasePollError> {
    let configured = routing.slots().contains(slot);
    match availability {
        RunnerSlotAvailability::OutOfRange if configured => {
            return Err(LeasePollInvariant::SlotAvailabilityContradiction.into());
        }
        RunnerSlotAvailability::Available | RunnerSlotAvailability::Occupied { .. }
            if !configured =>
        {
            return Err(LeasePollInvariant::SlotAvailabilityContradiction.into());
        }
        RunnerSlotAvailability::Available
        | RunnerSlotAvailability::Occupied { .. }
        | RunnerSlotAvailability::OutOfRange
        | RunnerSlotAvailability::RunnerUnavailable => {}
    }
    Ok(())
}

fn effective_runner(
    routing: &RunnerRoutingSnapshot,
    registered: &RunnerCapabilities,
    negotiated: RunnerCapabilities,
    requested_slot: StableRunnerSlot,
    availability: RunnerSlotAvailability,
    observed_at: UnixMillis,
) -> Result<EffectiveRunner, LeasePollError> {
    let session = SessionGuard::new(routing.fence().runner_id(), routing.fence().session_id());
    let machine_capabilities = intersect_runner_capabilities(registered, &negotiated)
        .map_err(LeasePollError::InvalidCapabilityIntersection)?;
    let evidence = RunnerEvidence::new(session, negotiated, observed_at)
        .map_err(LeasePollError::InvalidRunnerEvidence)?;
    let labels = routing
        .labels()
        .iter()
        .map(|label| RunnerLabel::new(label.as_str()))
        .collect::<Result<BTreeSet<_>, _>>()
        .map_err(LeasePollError::InvalidRoutingSelector)?;
    let groups = routing
        .group_name()
        .map(RunnerGroup::new)
        .transpose()
        .map_err(LeasePollError::InvalidRoutingSelector)?;
    let authorized = AuthorizedRunnerRouting::new(labels, groups);
    let available_slots = if availability == RunnerSlotAvailability::Available
        && requested_slot.ordinal() <= machine_capabilities.max_parallel_jobs()
    {
        vec![
            RunnerSlot::new(routing.fence().runner_id(), requested_slot.ordinal())
                .map_err(|_| LeasePollInvariant::SlotAvailabilityContradiction)?,
        ]
    } else {
        Vec::new()
    };
    EffectiveRunner::authorize(&evidence, authorized, machine_capabilities, available_slots)
        .map_err(LeasePollError::InvalidEffectiveRunner)
}

fn candidate_from_durable(
    durable: &RunnableAttempt,
) -> Result<ApplicationCandidate, LeasePollError> {
    let routing = RoutingRequirements::new(durable.requirements().clone())
        .map_err(LeasePollError::InvalidRoutingRequirements)?;
    Ok(ApplicationCandidate {
        candidate: RunnableCandidate::new(
            durable.attempt_id(),
            durable.job_id(),
            durable.queued_at(),
            routing,
        ),
    })
}
