use automata_ci_core::{
    JobLifecycle, LeaseGuard, LogStreamId, OperationId, RunnerSessionId, Sha256Digest, UnixMillis,
};
use automata_ci_protocol::{
    LeaseAuthorityPollReceipt, LeaseRejectionReason, RunnerSlotOrdinal, RuntimeAuthorityGeneration,
};

use crate::{
    CancellationRecord, CommandDisposition, DurableCommand, DurableContentRef, EndpointOperation,
    EndpointResultContentRef, JournalError, JournalSnapshot, LeaseOfferRecord, LeasePollCompletion,
    LogSegmentAcknowledgement, LogSegmentPublication, OrphanAbandonmentReason,
    OrphanAuthorityProof, OrphanAuthorityVerifier, OrphanDelivery, OutboundOperationSequence,
    ProviderFailureOutcome, ProviderOperation, RuntimeAuthorityDeliveryRecord, SandboxIdentity,
    SessionBinding, TerminalResultRecord,
};

/// Backend-neutral, object-safe port for crash-recoverable runner state.
///
/// Every successful mutation is durable before it returns. Callers must record
/// a lease offer before acknowledging its command or reporting acceptance, and
/// must record a provider intent before invoking the corresponding adapter.
pub trait RunnerJournal: Send + Sync {
    /// Returns a consistent point-in-time snapshot.
    ///
    /// # Errors
    ///
    /// Returns [`JournalError`] if the adapter was poisoned by an uncertain
    /// commit or cannot access its state.
    fn snapshot(&self) -> Result<JournalSnapshot, JournalError>;

    /// Opens or resumes a session. A different session can replace the current
    /// one only when no slot contains recoverable work.
    ///
    /// # Errors
    ///
    /// Returns [`JournalError`] for stale active work or a failed durable commit.
    fn begin_session(&self, binding: SessionBinding) -> Result<JournalSnapshot, JournalError>;

    /// Durably prepares the first exact lease request for `slot`, or returns
    /// the already prepared checkpoint unchanged.
    ///
    /// Callers may generate a disposable candidate operation identity on every
    /// recovery attempt: once a checkpoint exists, the candidate is ignored so
    /// the exact durable request can be reconstructed and retried.
    ///
    /// # Errors
    ///
    /// Returns [`JournalError`] for a stale session, an out-of-range slot, an
    /// operation-identity conflict, or failed commit.
    fn prepare_lease_poll(
        &self,
        session_id: RunnerSessionId,
        slot: RunnerSlotOrdinal,
        operation_id: OperationId,
    ) -> Result<JournalSnapshot, JournalError>;

    /// Atomically commits one complete lease-poll result.
    ///
    /// A nested command disposition and its application effect, when present,
    /// become durable in the same physical commit as the carrier poll's exact
    /// successor and pending authority receipts. Commands may target a slot
    /// other than the carrier. Exact replay after an uncertain commit is a
    /// no-op that returns the already durable state.
    ///
    /// # Errors
    ///
    /// Returns [`JournalError`] for a missing or unrelated checkpoint, stale
    /// or conflicting command, operation-identity conflict, or failed commit.
    fn complete_lease_poll(
        &self,
        session_id: RunnerSessionId,
        completion: LeasePollCompletion,
    ) -> Result<JournalSnapshot, JournalError>;

    /// Clears the exact accepted contribution receipts after every source has
    /// durably acknowledged them. Repeating an already completed clear is a no-op.
    ///
    /// # Errors
    ///
    /// Returns [`JournalError`] for a stale session, missing checkpoint,
    /// substituted receipt set, or failed commit.
    fn acknowledge_lease_authority_receipts(
        &self,
        session_id: RunnerSessionId,
        slot: RunnerSlotOrdinal,
        expected: &[LeaseAuthorityPollReceipt],
    ) -> Result<JournalSnapshot, JournalError>;

    /// Atomically records a generic command disposition and advances the
    /// contiguous cursor. Ignored stale/no-slot/unsupported commands therefore
    /// cannot wedge session progress.
    ///
    /// # Errors
    ///
    /// Returns [`JournalError`] for a gap, conflicting/out-of-window replay,
    /// stale session, or failed commit.
    fn record_command_disposition(
        &self,
        session_id: RunnerSessionId,
        command: DurableCommand,
        disposition: CommandDisposition,
    ) -> Result<JournalSnapshot, JournalError>;

    /// Durably records an offer and advances the contiguous command cursor in
    /// the same atomic commit. Its `JobIR` reference must come from a content
    /// adapter only after verified bytes and directory metadata are fsynced.
    ///
    /// # Errors
    ///
    /// Returns [`JournalError`] for a stale session, occupied slot, wrong
    /// runner identity, command gap, replay conflict, or failed commit.
    fn record_lease_offer(
        &self,
        session_id: RunnerSessionId,
        offer: LeaseOfferRecord,
    ) -> Result<JournalSnapshot, JournalError>;

    /// Records local acceptance after the offer and command cursor are durable.
    ///
    /// # Errors
    ///
    /// Returns [`JournalError`] for stale session/lease credentials or I/O.
    fn accept_lease(
        &self,
        session_id: RunnerSessionId,
        slot: RunnerSlotOrdinal,
        guard: LeaseGuard,
    ) -> Result<JournalSnapshot, JournalError>;

    /// Adopts protected authority bytes for an exact accepted offer.
    ///
    /// # Errors
    ///
    /// Returns [`JournalError`] unless the lease is accepted and every offer,
    /// generation, digest, operation, and content binding is exact.
    fn record_runtime_authority_delivery(
        &self,
        session_id: RunnerSessionId,
        slot: RunnerSlotOrdinal,
        guard: LeaseGuard,
        delivery: RuntimeAuthorityDeliveryRecord,
    ) -> Result<JournalSnapshot, JournalError>;

    /// Marks the exact protected authority generation acknowledged by control.
    ///
    /// # Errors
    ///
    /// Returns [`JournalError`] for missing, stale, or conflicting delivery state.
    fn acknowledge_runtime_authority_delivery(
        &self,
        session_id: RunnerSessionId,
        slot: RunnerSlotOrdinal,
        guard: LeaseGuard,
        generation: RuntimeAuthorityGeneration,
        bundle_digest: Sha256Digest,
        operation_id: OperationId,
    ) -> Result<JournalSnapshot, JournalError>;

    /// Persists the exact rejected-offer response and its caller-observed
    /// enqueue time before it is sent. The slot remains recoverable until its
    /// response operation is acknowledged. Exact replay retains the first
    /// committed timestamp.
    ///
    /// # Errors
    ///
    /// Returns [`JournalError`] for an accepted/conflicting offer, stale
    /// credentials, or I/O.
    fn reject_lease(
        &self,
        session_id: RunnerSessionId,
        slot: RunnerSlotOrdinal,
        guard: LeaseGuard,
        reason: LeaseRejectionReason,
        response_operation_id: OperationId,
        enqueued_at: UnixMillis,
    ) -> Result<JournalSnapshot, JournalError>;

    /// Marks the exact rejected response durably accepted by the control plane.
    ///
    /// # Errors
    ///
    /// Returns [`JournalError`] for a non-rejected offer, operation mismatch,
    /// stale credentials, or I/O.
    fn acknowledge_lease_rejection(
        &self,
        session_id: RunnerSessionId,
        slot: RunnerSlotOrdinal,
        guard: LeaseGuard,
        response_operation_id: OperationId,
    ) -> Result<JournalSnapshot, JournalError>;

    /// Removes a rejected offer only after its exact response operation has a
    /// durable control-plane acknowledgement.
    ///
    /// # Errors
    ///
    /// Returns [`JournalError`] while acknowledgement is absent, for a response
    /// identity mismatch, stale credentials, or I/O.
    fn release_rejected_lease(
        &self,
        session_id: RunnerSessionId,
        slot: RunnerSlotOrdinal,
        guard: LeaseGuard,
        response_operation_id: OperationId,
    ) -> Result<JournalSnapshot, JournalError>;

    /// Extends a lease expiration monotonically.
    ///
    /// # Errors
    ///
    /// Returns [`JournalError`] for stale credentials, expiration regression,
    /// or I/O.
    fn renew_lease(
        &self,
        session_id: RunnerSessionId,
        slot: RunnerSlotOrdinal,
        guard: LeaseGuard,
        expires_at: UnixMillis,
    ) -> Result<JournalSnapshot, JournalError>;

    /// Durably records a cancellation command, advances the command cursor,
    /// and atomically lets cancellation win any unresolved endpoint operation.
    ///
    /// # Errors
    ///
    /// Returns [`JournalError`] for stale credentials, a command gap/conflict,
    /// an invalid lifecycle edge, or I/O.
    fn record_cancellation(
        &self,
        session_id: RunnerSessionId,
        slot: RunnerSlotOrdinal,
        guard: LeaseGuard,
        cancellation: CancellationRecord,
    ) -> Result<JournalSnapshot, JournalError>;

    /// Advances the local attempt lifecycle using the shared core state machine.
    ///
    /// # Errors
    ///
    /// Returns [`JournalError`] unless the offer is accepted, the guard is
    /// current, and the lifecycle edge is valid.
    fn transition_lifecycle(
        &self,
        session_id: RunnerSessionId,
        slot: RunnerSlotOrdinal,
        guard: LeaseGuard,
        next: JobLifecycle,
    ) -> Result<JournalSnapshot, JournalError>;

    /// Atomically enters a terminal lifecycle and records the exact result
    /// outbox operation/content reference and caller-observed enqueue time.
    /// Result payload bytes must be committed and fsynced before this call.
    /// Exact replay retains the first committed timestamp.
    ///
    /// # Errors
    ///
    /// Returns [`JournalError`] for a non-terminal/invalid transition,
    /// conflicting replay, stale credentials, invalid content, or I/O.
    fn record_terminal_result(
        &self,
        session_id: RunnerSessionId,
        slot: RunnerSlotOrdinal,
        guard: LeaseGuard,
        terminal: JobLifecycle,
        result: TerminalResultRecord,
        enqueued_at: UnixMillis,
    ) -> Result<JournalSnapshot, JournalError>;

    /// Marks the exact terminal result accepted by a correlated `OperationAck`.
    ///
    /// # Errors
    ///
    /// Returns [`JournalError`] for a missing/mismatched result, stale
    /// credentials, or I/O.
    fn acknowledge_terminal_result(
        &self,
        session_id: RunnerSessionId,
        slot: RunnerSlotOrdinal,
        guard: LeaseGuard,
        operation_id: OperationId,
    ) -> Result<JournalSnapshot, JournalError>;

    /// Accepts one exact endpoint request after its protected commitment is durable.
    ///
    /// Capacity, ordering, request-reference, and result-byte reservations are
    /// checked before this operation can be committed for backend invocation.
    ///
    /// # Errors
    ///
    /// Returns [`JournalError`] for stale fences, conflicting replay, a pending
    /// predecessor, exhausted per-slot capacity, or a failed durable commit.
    fn accept_endpoint_operation(
        &self,
        session_id: RunnerSessionId,
        slot: RunnerSlotOrdinal,
        guard: LeaseGuard,
        operation: EndpointOperation,
    ) -> Result<JournalSnapshot, JournalError>;

    /// Commits permission to expose an accepted operation to the backend.
    ///
    /// # Errors
    ///
    /// Returns [`JournalError`] for a missing/cancelled operation, stale fence,
    /// or failed durable commit.
    fn commit_endpoint_invocation(
        &self,
        session_id: RunnerSessionId,
        slot: RunnerSlotOrdinal,
        guard: LeaseGuard,
        operation_id: OperationId,
    ) -> Result<JournalSnapshot, JournalError>;

    /// Lets cancellation win unless an exact result was already durable.
    ///
    /// Result-first cancellation is an idempotent no-op. A durable cancellation
    /// prevents backend invocation and later result adoption.
    ///
    /// # Errors
    ///
    /// Returns [`JournalError`] for a missing operation, stale fence, or failed
    /// commit.
    fn record_endpoint_cancellation(
        &self,
        session_id: RunnerSessionId,
        slot: RunnerSlotOrdinal,
        guard: LeaseGuard,
        operation_id: OperationId,
    ) -> Result<JournalSnapshot, JournalError>;

    /// Completes a cancellation only after exact sandbox absence is durable.
    ///
    /// # Errors
    ///
    /// Returns [`JournalError`] if cancellation did not previously win, the
    /// operation is missing, the fence is stale, or persistence fails.
    fn complete_endpoint_cancellation(
        &self,
        session_id: RunnerSessionId,
        slot: RunnerSlotOrdinal,
        guard: LeaseGuard,
        operation_id: OperationId,
    ) -> Result<JournalSnapshot, JournalError>;

    /// Resolves an uncertain invocation after exact sandbox absence is durable.
    ///
    /// # Errors
    ///
    /// Returns [`JournalError`] while the sandbox identity remains present, if
    /// the operation is not ambiguous, the fence is stale, or persistence fails.
    fn abandon_endpoint_operation(
        &self,
        session_id: RunnerSessionId,
        slot: RunnerSlotOrdinal,
        guard: LeaseGuard,
        operation_id: OperationId,
    ) -> Result<JournalSnapshot, JournalError>;

    /// Adopts a payload-first protected endpoint result after invocation.
    ///
    /// # Errors
    ///
    /// Returns [`JournalError`] when cancellation already won, invocation was
    /// not committed, the result exceeds its reservation, replay conflicts, or
    /// the durable commit fails.
    fn record_endpoint_result(
        &self,
        session_id: RunnerSessionId,
        slot: RunnerSlotOrdinal,
        guard: LeaseGuard,
        operation_id: OperationId,
        result: EndpointResultContentRef,
    ) -> Result<JournalSnapshot, JournalError>;

    /// Records an idempotent provider mutation intent before the mutation.
    ///
    /// # Errors
    ///
    /// Returns [`JournalError`] for stale credentials, invalid ordering,
    /// conflicting replay, or I/O.
    fn record_provider_intent(
        &self,
        session_id: RunnerSessionId,
        slot: RunnerSlotOrdinal,
        guard: LeaseGuard,
        intent: ProviderOperation,
    ) -> Result<JournalSnapshot, JournalError>;

    /// Records the bounded provider/handle identity immediately after sandbox
    /// creation and completes its matching intent atomically.
    ///
    /// # Errors
    ///
    /// Returns [`JournalError`] without a current create intent, on identity
    /// conflict, for stale credentials, or on I/O.
    fn record_sandbox_created(
        &self,
        session_id: RunnerSessionId,
        slot: RunnerSlotOrdinal,
        guard: LeaseGuard,
        operation_id: OperationId,
        sandbox: SandboxIdentity,
    ) -> Result<JournalSnapshot, JournalError>;

    /// Marks the latest non-create provider mutation applied. Completing a
    /// destroy intent also clears the sandbox handle.
    ///
    /// # Errors
    ///
    /// Returns [`JournalError`] for a missing/conflicting intent, stale
    /// credentials, or I/O.
    fn complete_provider_operation(
        &self,
        session_id: RunnerSessionId,
        slot: RunnerSlotOrdinal,
        guard: LeaseGuard,
        operation_id: OperationId,
    ) -> Result<JournalSnapshot, JournalError>;

    /// Durably classifies the latest provider call as failed. A known-no-effect
    /// outcome resolves the intent; an uncertain outcome remains pending and
    /// must be retried or reconciled with the same operation identity.
    ///
    /// Failure detail is intentionally a bounded enum so credentials and raw
    /// provider diagnostics cannot enter the journal.
    ///
    /// # Errors
    ///
    /// Returns [`JournalError`] for a missing, stale, or already resolved
    /// operation identity, stale lease credentials, or I/O.
    fn fail_provider_operation(
        &self,
        session_id: RunnerSessionId,
        slot: RunnerSlotOrdinal,
        guard: LeaseGuard,
        operation_id: OperationId,
        failure: ProviderFailureOutcome,
    ) -> Result<JournalSnapshot, JournalError>;

    /// Advances the contiguous local cursor for outbound idempotent operations.
    ///
    /// # Errors
    ///
    /// Returns [`JournalError`] for a cursor gap/regression, stale credentials,
    /// or I/O.
    fn advance_outbound_operation(
        &self,
        session_id: RunnerSessionId,
        slot: RunnerSlotOrdinal,
        guard: LeaseGuard,
        sequence: OutboundOperationSequence,
    ) -> Result<JournalSnapshot, JournalError>;

    /// Establishes the one durable log stream associated with a lease.
    ///
    /// # Errors
    ///
    /// Returns [`JournalError`] for a conflicting stream, stale credentials,
    /// or I/O.
    fn open_log_stream(
        &self,
        session_id: RunnerSessionId,
        slot: RunnerSlotOrdinal,
        guard: LeaseGuard,
        stream_id: LogStreamId,
    ) -> Result<JournalSnapshot, JournalError>;

    /// Creates or payload-first replaces the one open immutable log tail. The
    /// caller-observed enqueue time is retained when a new segment begins;
    /// tail replacement and exact replay preserve that original time.
    ///
    /// # Errors
    ///
    /// Returns [`JournalError`] for a gap/replay conflict, wrong stream, stale
    /// credentials, or I/O.
    fn record_log_segment(
        &self,
        session_id: RunnerSessionId,
        slot: RunnerSlotOrdinal,
        guard: LeaseGuard,
        publication: LogSegmentPublication,
        enqueued_at: UnixMillis,
    ) -> Result<JournalSnapshot, JournalError>;

    /// Seals the exact current tail before it can become a delivery head.
    ///
    /// # Errors
    ///
    /// Returns [`JournalError`] for a stale content identity, wrong stream,
    /// stale credentials, or I/O.
    fn seal_log_segment(
        &self,
        session_id: RunnerSessionId,
        slot: RunnerSlotOrdinal,
        guard: LeaseGuard,
        stream_id: LogStreamId,
        expected_content: DurableContentRef,
    ) -> Result<JournalSnapshot, JournalError>;

    /// Removes exactly one sealed durable head and retains one bounded replay
    /// witness. ACK never creates replacement payload bytes.
    ///
    /// # Errors
    ///
    /// Returns [`JournalError`] for a divergent replay, stale head identity,
    /// wrong stream, stale credentials, or I/O.
    fn acknowledge_log_segment(
        &self,
        session_id: RunnerSessionId,
        slot: RunnerSlotOrdinal,
        guard: LeaseGuard,
        acknowledgement: LogSegmentAcknowledgement,
    ) -> Result<JournalSnapshot, JournalError>;

    /// Verifies explicit control-plane authority before journaling an
    /// old-session lease as orphaned. The runner has no boolean or unverified
    /// self-authorization path.
    ///
    /// # Errors
    ///
    /// Returns [`JournalError`] when the authority adapter denies the proof,
    /// the grant does not match the exact fence, credentials are stale, or I/O
    /// fails.
    fn authorize_orphan(
        &self,
        session_id: RunnerSessionId,
        slot: RunnerSlotOrdinal,
        guard: LeaseGuard,
        verifier: &dyn OrphanAuthorityVerifier,
        proof: &OrphanAuthorityProof,
    ) -> Result<JournalSnapshot, JournalError>;

    /// Records a server-authorized bounded disposition for an undeliverable
    /// old-session result, log stream, or rejection.
    ///
    /// # Errors
    ///
    /// Returns [`JournalError`] without a matching orphan grant/permission,
    /// for conflicting replay, stale credentials, or I/O.
    fn abandon_orphan_delivery(
        &self,
        session_id: RunnerSessionId,
        slot: RunnerSlotOrdinal,
        guard: LeaseGuard,
        authority_operation_id: OperationId,
        delivery: OrphanDelivery,
        reason: OrphanAbandonmentReason,
    ) -> Result<JournalSnapshot, JournalError>;

    /// Removes a terminal slot only after all provider operations are complete,
    /// no sandbox remains to reconcile, and any log stream has a fully
    /// acknowledged terminal frame.
    ///
    /// # Errors
    ///
    /// Returns [`JournalError`] for active work, stale credentials, or I/O.
    fn release_slot(
        &self,
        session_id: RunnerSessionId,
        slot: RunnerSlotOrdinal,
        guard: LeaseGuard,
    ) -> Result<JournalSnapshot, JournalError>;
}
