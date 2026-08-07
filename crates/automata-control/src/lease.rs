use std::collections::BTreeSet;

use automata_control_plane::{
    AuthorizedRunnerRouting, EffectiveRunner, Placement, PlacementDecision, RoutingRequirements,
    RunnableCandidate, RunnerEvidence, RunnerSlot, SchedulerPolicy, SchedulingInput, SessionGuard,
    intersect_runner_capabilities,
};
use automata_core::{
    JobIrVersion, Lease, RunnerCapabilities, RunnerGroup, RunnerLabel, UnixMillis,
};
use automata_protocol::{LeaseRequest, ProtocolVersion, RunnerSlotOrdinal};
use automata_store::{
    ClaimRejection, JobIrMetadata, LeaseRequestKey, NoWorkLeaseRequest, RoutingDocument,
    RunnableAttempt, RunnableScanPage, RunnableScanRequest, RunnerRoutingSnapshot,
    RunnerSessionFence, RunnerSlotAvailability, StableRunnerSlot, TryClaimAttempt, TryClaimOutcome,
    TryClaimReceipt,
};

use crate::{
    CapabilityDocument, LeaseClock, LeaseIdGenerator, LeasePollConfig, LeasePollError,
    LeasePollInvariant, LeasePollRepository, RequestCorrelationError,
};

/// Exact authenticated connection context established before request dispatch.
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

/// Provider-neutral result of one authenticated outbound runner lease poll.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum LeasePollOutcome {
    /// One immutable `JobIR` object may be loaded and offered under this lease.
    Claimed(ClaimedLeasePoll),
    /// The scheduler found no compatible work/capacity and durably recorded it.
    NoWork { replayed: bool },
    /// The transactional claim recheck lost a race or rejected durable state.
    Rejected {
        reason: ClaimRejection,
        replayed: bool,
    },
}

/// G1 application service for one bounded lease poll.
pub struct LeasePollService<'a> {
    repository: &'a dyn LeasePollRepository,
    scheduler: &'a dyn SchedulerPolicy,
    clock: &'a dyn LeaseClock,
    lease_ids: &'a dyn LeaseIdGenerator,
    config: LeasePollConfig,
}

impl std::fmt::Debug for LeasePollService<'_> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("LeasePollService")
            .field("scheduler", &self.scheduler)
            .field("clock", &self.clock)
            .field("lease_ids", &self.lease_ids)
            .field("config", &self.config)
            .finish_non_exhaustive()
    }
}

impl<'a> LeasePollService<'a> {
    /// Composes neutral ports and an immutable scheduler policy.
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
            config,
        }
    }

    /// Executes one authenticated outbound runner poll.
    ///
    /// Receipt lookup always precedes routing/capacity/queue reads. A found
    /// receipt is translated directly and never passed back to the scheduler.
    ///
    /// # Errors
    ///
    /// Returns [`LeasePollError`] for request correlation, corrupt durable
    /// documents, invalid scheduler output, time overflow, or repository
    /// failures.
    pub async fn poll(
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
        let scheduler_candidates = candidates
            .iter()
            .map(|candidate| candidate.candidate.clone())
            .collect::<Vec<_>>();
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
        Self::receipt_outcome(
            poll,
            &receipt,
            Some((placement.attempt_id(), placement.job_id())),
            false,
        )
    }

    fn receipt_outcome(
        poll: ValidatedLeasePoll,
        receipt: &TryClaimReceipt,
        selected: Option<(automata_core::AttemptId, automata_core::JobId)>,
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
