use async_trait::async_trait;
use automata_ci_auth::{authorization::SecretExposureClass, human::TenantId};
use automata_ci_core::{
    AttemptId, JobConclusion, JobIrVersion, JobLifecycle, Lease, LeaseGuard, LogSequence,
    LogStreamId, RunnerId, RunnerSessionId, Sha256Digest, UnixMillis,
};
use automata_ci_store::{
    AcknowledgeRunnerCommands, CommandCursor, DocumentSchema, DurableRunnerCommand,
    EnqueueRunnerCommand, JobIrMetadata, LeaseOfferCommandIdentity, MAX_LOG_SEGMENT_BYTES,
    MAX_TERMINAL_RESULT_BYTES, ObjectKey, RenewLease, RunnerGeneration, RunnerOperationReceipt,
    RunnerOperationRequest, RunnerOperationResponse, RunnerProtocolVersion, RunnerSessionFence,
    StableRunnerSlot, StoreError,
};
use thiserror::Error;

const MAX_UNCOMPRESSED_RUNNER_LOG_BYTES: u64 = 256 * 1024 * 1024;
const MAX_DURABLE_LOG_SEQUENCE: u64 = 9_223_372_036_854_775_807;

/// Server-owned identity needed to resolve the one current live session epoch.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CurrentRunnerSession {
    runner_id: RunnerId,
    generation: RunnerGeneration,
    session_id: RunnerSessionId,
}

impl CurrentRunnerSession {
    /// Creates an exact registration generation and session claim.
    #[must_use]
    pub const fn new(
        runner_id: RunnerId,
        generation: RunnerGeneration,
        session_id: RunnerSessionId,
    ) -> Self {
        Self {
            runner_id,
            generation,
            session_id,
        }
    }

    /// Returns the administrator-owned runner ID.
    #[must_use]
    pub const fn runner_id(self) -> RunnerId {
        self.runner_id
    }

    /// Returns the exact current registration generation.
    #[must_use]
    pub const fn generation(self) -> RunnerGeneration {
        self.generation
    }

    /// Returns the runner-claimed session ID.
    #[must_use]
    pub const fn session_id(self) -> RunnerSessionId {
        self.session_id
    }
}

/// Durable resolver for a currently online registration and its exact live epoch.
#[async_trait]
pub trait CurrentRunnerSessionRepository: Send + Sync {
    /// Returns a fence only for an exact, observed-online session whose desired
    /// state is active or draining. Disabled, absent, stale, superseded, and
    /// mismatched identity claims return `None`. The lookup must not cache
    /// replica-local authority.
    async fn resolve_current_session(
        &self,
        request: CurrentRunnerSession,
    ) -> Result<Option<RunnerSessionFence>, StoreError>;
}

/// Exact claimed lease-poll coordinates used to recover or publish its durable offer.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LeaseOfferClaim {
    request: RunnerOperationRequest,
    protocol_version: RunnerProtocolVersion,
    slot: StableRunnerSlot,
    lease: Lease,
    job_ir: JobIrMetadata,
}

impl LeaseOfferClaim {
    /// Creates a claim whose request, lease, and immutable `JobIR` share one runner authority.
    ///
    /// # Errors
    /// Returns an error for a lease owned by another runner or unsupported `JobIR` metadata.
    pub fn new(
        request: RunnerOperationRequest,
        protocol_version: RunnerProtocolVersion,
        slot: StableRunnerSlot,
        lease: Lease,
        job_ir: JobIrMetadata,
    ) -> Result<Self, RunnerControlValueError> {
        if lease.runner_id() != request.session().runner_id() {
            return Err(RunnerControlValueError::LeaseRunnerMismatch);
        }
        if job_ir.version() != JobIrVersion::current() {
            return Err(RunnerControlValueError::UnsupportedJobIr);
        }
        Ok(Self {
            request,
            protocol_version,
            slot,
            lease,
            job_ir,
        })
    }

    /// Returns the runner poll identity and canonical wire-request digest.
    #[must_use]
    pub const fn request(&self) -> &RunnerOperationRequest {
        &self.request
    }

    /// Returns the exact negotiated protocol.
    #[must_use]
    pub const fn protocol_version(&self) -> RunnerProtocolVersion {
        self.protocol_version
    }

    /// Returns the stable runner slot.
    #[must_use]
    pub const fn slot(&self) -> StableRunnerSlot {
        self.slot
    }

    /// Returns the already-issued exclusive lease.
    #[must_use]
    pub const fn lease(&self) -> &Lease {
        &self.lease
    }

    /// Returns immutable `JobIR` object metadata from the durable claim receipt.
    #[must_use]
    pub const fn job_ir(&self) -> &JobIrMetadata {
        &self.job_ir
    }
}

/// Durable state of one exact claimed lease poll before authority issuance.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum LeaseOfferClaimStatus {
    /// The exact claim remains current and may proceed to authority issuance.
    Current,
    /// The offer was already atomically published and must be replayed byte-for-byte.
    Published(Box<PublishedLeaseOffer>),
    /// The exact claim's attempt fence has irreversibly advanced or disappeared.
    ClaimSuperseded,
}

/// Complete verified lease-offer command awaiting an atomic durable publication.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PublishLeaseOffer {
    claim: LeaseOfferClaim,
    offer_valid_until: UnixMillis,
    command: EnqueueRunnerCommand,
}

impl PublishLeaseOffer {
    /// Creates a publication whose request, command, and lease share one exact runner fence.
    ///
    /// # Errors
    /// Returns an error for a cross-session command or a lease owned by another runner.
    pub fn new(
        request: RunnerOperationRequest,
        protocol_version: RunnerProtocolVersion,
        slot: StableRunnerSlot,
        lease: Lease,
        job_ir: JobIrMetadata,
        offer_valid_until: UnixMillis,
        command: EnqueueRunnerCommand,
    ) -> Result<Self, RunnerControlValueError> {
        if request.session() != command.session() {
            return Err(RunnerControlValueError::SessionMismatch);
        }
        let claim = LeaseOfferClaim::new(request, protocol_version, slot, lease, job_ir)?;
        validate_offer_validity_horizon(claim.lease(), command.created_at(), offer_valid_until)?;
        Ok(Self {
            claim,
            offer_valid_until,
            command,
        })
    }

    /// Returns the exact durable claim coordinates being published.
    #[must_use]
    pub const fn claim(&self) -> &LeaseOfferClaim {
        &self.claim
    }

    /// Returns the runner poll identity and canonical request digest.
    #[must_use]
    pub const fn request(&self) -> &RunnerOperationRequest {
        self.claim.request()
    }

    /// Returns the exact negotiated protocol.
    #[must_use]
    pub const fn protocol_version(&self) -> RunnerProtocolVersion {
        self.claim.protocol_version()
    }

    /// Returns the stable runner slot.
    #[must_use]
    pub const fn slot(&self) -> StableRunnerSlot {
        self.claim.slot()
    }

    /// Returns the already-issued exclusive lease.
    #[must_use]
    pub const fn lease(&self) -> &Lease {
        self.claim.lease()
    }

    /// Returns immutable `JobIR` object metadata verified by the application.
    #[must_use]
    pub const fn job_ir(&self) -> &JobIrMetadata {
        self.claim.job_ir()
    }

    /// Returns the exclusive horizon shared by the lease and every delivered runtime authority.
    #[must_use]
    pub const fn offer_valid_until(&self) -> UnixMillis {
        self.offer_valid_until
    }

    /// Returns the proposed exact outbox command. On replay the repository returns the original
    /// command identity and bytes, ignoring a newly proposed server operation ID.
    #[must_use]
    pub const fn command(&self) -> &EnqueueRunnerCommand {
        &self.command
    }
}

/// Exact typed offer publication loaded from or committed to durable state.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PublishedLeaseOffer {
    request: RunnerOperationRequest,
    protocol_version: RunnerProtocolVersion,
    slot: StableRunnerSlot,
    lease: Lease,
    job_ir: JobIrMetadata,
    offer_valid_until: UnixMillis,
    command: DurableRunnerCommand,
}

impl PublishedLeaseOffer {
    /// Builds a decoded durable publication.
    /// # Errors
    /// Returns an error unless the horizon is after command creation and lease issuance and no
    /// later than the durable lease expiry.
    pub fn new(
        request: RunnerOperationRequest,
        protocol_version: RunnerProtocolVersion,
        slot: StableRunnerSlot,
        lease: Lease,
        job_ir: JobIrMetadata,
        offer_valid_until: UnixMillis,
        command: DurableRunnerCommand,
    ) -> Result<Self, RunnerControlValueError> {
        validate_offer_validity_horizon(&lease, command.request().created_at(), offer_valid_until)?;
        Ok(Self {
            request,
            protocol_version,
            slot,
            lease,
            job_ir,
            offer_valid_until,
            command,
        })
    }

    /// Returns the exact runner poll request identity.
    #[must_use]
    pub const fn request(&self) -> &RunnerOperationRequest {
        &self.request
    }

    /// Returns the negotiated protocol.
    #[must_use]
    pub const fn protocol_version(&self) -> RunnerProtocolVersion {
        self.protocol_version
    }

    /// Returns the stable runner slot.
    #[must_use]
    pub const fn slot(&self) -> StableRunnerSlot {
        self.slot
    }

    /// Returns the exact lease metadata.
    #[must_use]
    pub const fn lease(&self) -> &Lease {
        &self.lease
    }

    /// Returns immutable `JobIR` metadata.
    #[must_use]
    pub const fn job_ir(&self) -> &JobIrMetadata {
        &self.job_ir
    }

    /// Returns the exclusive horizon shared by the lease and every delivered runtime authority.
    #[must_use]
    pub const fn offer_valid_until(&self) -> UnixMillis {
        self.offer_valid_until
    }

    /// Returns the original durable outbox command and assigned sequence.
    #[must_use]
    pub const fn command(&self) -> &DurableRunnerCommand {
        &self.command
    }

    /// Reports whether this exact publication was loaded from a prior commit.
    #[must_use]
    pub const fn was_replayed(&self) -> bool {
        self.command.was_replayed()
    }
}

fn validate_offer_validity_horizon(
    lease: &Lease,
    command_created_at: UnixMillis,
    offer_valid_until: UnixMillis,
) -> Result<(), RunnerControlValueError> {
    if command_created_at < lease.issued_at()
        || offer_valid_until <= lease.issued_at()
        || offer_valid_until > lease.expires_at()
        || offer_valid_until <= command_created_at
    {
        return Err(RunnerControlValueError::InvalidOfferValidityHorizon);
    }
    Ok(())
}

/// Atomic typed lease-offer publication port.
#[async_trait]
pub trait RunnerLeaseOfferRepository: Send + Sync {
    /// Classifies one exact claimed poll under the same locks used by publication and reaping.
    async fn inspect_lease_offer_claim(
        &self,
        request: LeaseOfferClaim,
    ) -> Result<LeaseOfferClaimStatus, StoreError>;

    /// Resolves an outbox replay to its exact typed publication. `None` means no publication owns
    /// the identity; a known publication whose attempt fence or authority horizon is stale returns
    /// [`StoreError::AttemptFenceRejected`]. Callers must treat a typed offer with `None` as durable
    /// corruption, never as a generic command.
    async fn resolve_lease_offer_command(
        &self,
        identity: LeaseOfferCommandIdentity,
    ) -> Result<Option<PublishedLeaseOffer>, StoreError>;

    /// Atomically allocates a per-session sequence, inserts the exact outbox body, and records all
    /// offer metadata. A durable claim may precede this transaction, but no command is runner-
    /// visible unless this transaction commits.
    async fn publish_lease_offer(
        &self,
        request: PublishLeaseOffer,
    ) -> Result<PublishedLeaseOffer, StoreError>;
}

/// Lease heartbeat mutation and exact response proposed for one atomic commit.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CommitLeaseHeartbeat {
    request: RunnerOperationRequest,
    command_cursor: CommandCursor,
    renewal: RenewLease,
    reported_lifecycle: Option<JobLifecycle>,
    response: RunnerOperationResponse,
}

impl CommitLeaseHeartbeat {
    /// Creates a heartbeat transaction for one exact session.
    ///
    /// # Errors
    /// Returns an error if the receipt and lease mutation name different sessions.
    pub fn new(
        request: RunnerOperationRequest,
        command_cursor: CommandCursor,
        renewal: RenewLease,
        response: RunnerOperationResponse,
    ) -> Result<Self, RunnerControlValueError> {
        if request.session() != renewal.session() {
            return Err(RunnerControlValueError::SessionMismatch);
        }
        Ok(Self {
            request,
            command_cursor,
            renewal,
            reported_lifecycle: None,
            response,
        })
    }

    /// Returns the idempotency identity.
    #[must_use]
    pub const fn request(&self) -> &RunnerOperationRequest {
        &self.request
    }

    /// Returns the last command cursor retained while updating session liveness.
    #[must_use]
    pub const fn command_cursor(&self) -> CommandCursor {
        self.command_cursor
    }

    /// Returns the exact lease renewal.
    #[must_use]
    pub const fn renewal(&self) -> RenewLease {
        self.renewal
    }

    /// Adds the runner's current non-terminal lifecycle to the atomic heartbeat.
    ///
    /// # Errors
    /// Returns an error when a heartbeat attempts to report queued or terminal work.
    pub fn with_reported_lifecycle(
        mut self,
        lifecycle: JobLifecycle,
    ) -> Result<Self, RunnerControlValueError> {
        if lifecycle == JobLifecycle::Queued || lifecycle.is_terminal() {
            return Err(RunnerControlValueError::InvalidHeartbeatLifecycle);
        }
        self.reported_lifecycle = Some(lifecycle);
        Ok(self)
    }

    /// Returns the lifecycle that must be committed before renewing the lease.
    #[must_use]
    pub const fn reported_lifecycle(&self) -> Option<JobLifecycle> {
        self.reported_lifecycle
    }

    /// Returns canonical response bytes proposed for the first commit.
    #[must_use]
    pub const fn response(&self) -> &RunnerOperationResponse {
        &self.response
    }
}

/// Durable action taken for a runner's response to an offered lease.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LeaseResponseAction {
    /// Accept the exact offer and move it from leased to preparing.
    Accept,
    /// Decline transiently and return the attempt to the runnable queue.
    Requeue,
    /// Reject an invalid job permanently and conclude the attempt as failed.
    Fail,
}

/// Exact lease response and receipt proposed for one atomic commit.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CommitLeaseResponse {
    request: RunnerOperationRequest,
    command_cursor: CommandCursor,
    attempt_id: AttemptId,
    slot: StableRunnerSlot,
    guard: LeaseGuard,
    action: LeaseResponseAction,
    observed_at: UnixMillis,
    response: RunnerOperationResponse,
}

impl CommitLeaseResponse {
    /// Creates a response for one exact published offer.
    #[allow(clippy::too_many_arguments)]
    #[must_use]
    pub const fn new(
        request: RunnerOperationRequest,
        command_cursor: CommandCursor,
        attempt_id: AttemptId,
        slot: StableRunnerSlot,
        guard: LeaseGuard,
        action: LeaseResponseAction,
        observed_at: UnixMillis,
        response: RunnerOperationResponse,
    ) -> Self {
        Self {
            request,
            command_cursor,
            attempt_id,
            slot,
            guard,
            action,
            observed_at,
            response,
        }
    }

    /// Returns the idempotent runner operation.
    #[must_use]
    pub const fn request(&self) -> &RunnerOperationRequest {
        &self.request
    }
    /// Returns the acknowledged command cursor.
    #[must_use]
    pub const fn command_cursor(&self) -> CommandCursor {
        self.command_cursor
    }
    /// Returns the attempt responding to the offer.
    #[must_use]
    pub const fn attempt_id(&self) -> AttemptId {
        self.attempt_id
    }
    /// Returns the offered runner slot.
    #[must_use]
    pub const fn slot(&self) -> StableRunnerSlot {
        self.slot
    }
    /// Returns the exclusive lease guard.
    #[must_use]
    pub const fn guard(&self) -> LeaseGuard {
        self.guard
    }
    /// Returns the durable response action.
    #[must_use]
    pub const fn action(&self) -> LeaseResponseAction {
        self.action
    }
    /// Returns the trusted observation time.
    #[must_use]
    pub const fn observed_at(&self) -> UnixMillis {
        self.observed_at
    }
    /// Returns the canonical response bytes.
    #[must_use]
    pub const fn response(&self) -> &RunnerOperationResponse {
        &self.response
    }
}

/// Immutable terminal result plus the exact acknowledgement committed with it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CommitRunnerTerminalResult {
    request: RunnerOperationRequest,
    attempt_id: AttemptId,
    guard: LeaseGuard,
    schema: DocumentSchema,
    encoded_size: u64,
    digest: Sha256Digest,
    object_key: ObjectKey,
    conclusion: JobConclusion,
    completed_at: UnixMillis,
    committed_at: UnixMillis,
    response: RunnerOperationResponse,
}

impl CommitRunnerTerminalResult {
    /// Creates a bounded immutable terminal object commit.
    ///
    /// # Errors
    /// Rejects an empty/oversized object or a trusted commit before completion.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        request: RunnerOperationRequest,
        attempt_id: AttemptId,
        guard: LeaseGuard,
        schema: DocumentSchema,
        encoded_size: u64,
        digest: Sha256Digest,
        object_key: ObjectKey,
        conclusion: JobConclusion,
        completed_at: UnixMillis,
        committed_at: UnixMillis,
        response: RunnerOperationResponse,
    ) -> Result<Self, RunnerControlValueError> {
        if !(1..=MAX_TERMINAL_RESULT_BYTES).contains(&encoded_size) {
            return Err(RunnerControlValueError::InvalidObjectSize);
        }
        if committed_at < completed_at {
            return Err(RunnerControlValueError::CommitBeforeCompletion);
        }
        Ok(Self {
            request,
            attempt_id,
            guard,
            schema,
            encoded_size,
            digest,
            object_key,
            conclusion,
            completed_at,
            committed_at,
            response,
        })
    }

    /// Returns the idempotent runner operation.
    #[must_use]
    pub const fn request(&self) -> &RunnerOperationRequest {
        &self.request
    }
    /// Returns the completed attempt.
    #[must_use]
    pub const fn attempt_id(&self) -> AttemptId {
        self.attempt_id
    }
    /// Returns the exclusive lease guard.
    #[must_use]
    pub const fn guard(&self) -> LeaseGuard {
        self.guard
    }
    /// Returns the terminal-result schema.
    #[must_use]
    pub const fn schema(&self) -> DocumentSchema {
        self.schema
    }
    /// Returns the encoded object size.
    #[must_use]
    pub const fn encoded_size(&self) -> u64 {
        self.encoded_size
    }
    /// Returns the terminal-result digest.
    #[must_use]
    pub const fn digest(&self) -> Sha256Digest {
        self.digest
    }
    /// Returns the immutable object key.
    #[must_use]
    pub const fn object_key(&self) -> &ObjectKey {
        &self.object_key
    }
    /// Returns the job conclusion.
    #[must_use]
    pub const fn conclusion(&self) -> JobConclusion {
        self.conclusion
    }
    /// Returns the runner-reported completion time.
    #[must_use]
    pub const fn completed_at(&self) -> UnixMillis {
        self.completed_at
    }
    /// Returns the trusted commit time.
    #[must_use]
    pub const fn committed_at(&self) -> UnixMillis {
        self.committed_at
    }
    /// Returns the canonical response bytes.
    #[must_use]
    pub const fn response(&self) -> &RunnerOperationResponse {
        &self.response
    }
}

/// Whether raw user-controlled output may enter persistent log storage.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RawLogDisposition {
    /// Runner-redacted standard output and standard error may be persisted.
    Persist,
}

/// Exact runner log coordinates presented for authoritative durable admission.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RunnerLogAdmissionRequest {
    request: RunnerOperationRequest,
    attempt_id: AttemptId,
    guard: LeaseGuard,
    stream_id: LogStreamId,
    schema: DocumentSchema,
    first_sequence: LogSequence,
    last_sequence: LogSequence,
    observed_at: UnixMillis,
    end_of_stream: bool,
}

impl RunnerLogAdmissionRequest {
    /// Creates one operation-, attempt-, fence-, stream-, and sequence-bound admission request.
    ///
    /// # Errors
    /// Rejects inverted ranges and sequences outside the durable backend range.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        request: RunnerOperationRequest,
        attempt_id: AttemptId,
        guard: LeaseGuard,
        stream_id: LogStreamId,
        schema: DocumentSchema,
        first_sequence: LogSequence,
        last_sequence: LogSequence,
        observed_at: UnixMillis,
        end_of_stream: bool,
    ) -> Result<Self, RunnerControlValueError> {
        if first_sequence > last_sequence {
            return Err(RunnerControlValueError::InvertedLogSequence);
        }
        if last_sequence.get() > MAX_DURABLE_LOG_SEQUENCE {
            return Err(RunnerControlValueError::LogSequenceOutOfRange);
        }
        Ok(Self {
            request,
            attempt_id,
            guard,
            stream_id,
            schema,
            first_sequence,
            last_sequence,
            observed_at,
            end_of_stream,
        })
    }

    /// Returns the exact operation identity and request digest.
    #[must_use]
    pub const fn request(&self) -> &RunnerOperationRequest {
        &self.request
    }

    /// Returns the attempt receiving the log batch.
    #[must_use]
    pub const fn attempt_id(&self) -> AttemptId {
        self.attempt_id
    }

    /// Returns the exact active lease fence.
    #[must_use]
    pub const fn guard(&self) -> LeaseGuard {
        self.guard
    }

    /// Returns the immutable stream identity.
    #[must_use]
    pub const fn stream_id(&self) -> LogStreamId {
        self.stream_id
    }

    /// Returns the log document schema.
    #[must_use]
    pub const fn schema(&self) -> DocumentSchema {
        self.schema
    }

    /// Returns the first sequence in the contiguous batch.
    #[must_use]
    pub const fn first_sequence(&self) -> LogSequence {
        self.first_sequence
    }

    /// Returns the last sequence in the contiguous batch.
    #[must_use]
    pub const fn last_sequence(&self) -> LogSequence {
        self.last_sequence
    }

    /// Returns the trusted server observation time used for authority checks.
    #[must_use]
    pub const fn observed_at(&self) -> UnixMillis {
        self.observed_at
    }

    /// Reports whether the final frame closes the stream.
    #[must_use]
    pub const fn is_end_of_stream(&self) -> bool {
        self.end_of_stream
    }
}

/// Authoritative immutable attempt policy admitted for one exact log batch.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RunnerLogAdmission {
    request: RunnerLogAdmissionRequest,
    tenant_id: TenantId,
    slot: StableRunnerSlot,
    secret_exposure: SecretExposureClass,
    raw_log_disposition: RawLogDisposition,
}

impl RunnerLogAdmission {
    /// Creates an adapter-issued admission after durable authority verification.
    ///
    /// # Errors
    /// Rejects a raw-log disposition inconsistent with the immutable exposure ceiling.
    /// Every current attempt uses the masked-persistence policy.
    pub fn new(
        request: RunnerLogAdmissionRequest,
        tenant_id: TenantId,
        slot: StableRunnerSlot,
        secret_exposure: SecretExposureClass,
        raw_log_disposition: RawLogDisposition,
    ) -> Result<Self, RunnerControlValueError> {
        let consistent = raw_log_disposition == RawLogDisposition::Persist;
        if !consistent {
            return Err(RunnerControlValueError::InconsistentLogSafetyPolicy);
        }
        Ok(Self {
            request,
            tenant_id,
            slot,
            secret_exposure,
            raw_log_disposition,
        })
    }

    /// Returns the exact admitted log coordinates.
    #[must_use]
    pub const fn request(&self) -> &RunnerLogAdmissionRequest {
        &self.request
    }

    /// Returns the authoritative tenant owning both runner and attempt.
    #[must_use]
    pub const fn tenant_id(&self) -> &TenantId {
        &self.tenant_id
    }

    /// Returns the exact durable runner slot assigned to the attempt.
    #[must_use]
    pub const fn slot(&self) -> StableRunnerSlot {
        self.slot
    }

    /// Returns the immutable maximum secret exposure admitted for the attempt.
    #[must_use]
    pub const fn secret_exposure(&self) -> SecretExposureClass {
        self.secret_exposure
    }

    /// Returns the authoritative handling required for runner-filtered user output.
    #[must_use]
    pub const fn raw_log_disposition(&self) -> RawLogDisposition {
        self.raw_log_disposition
    }
}

/// Immutable ordered log segment plus the exact contiguous acknowledgement.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CommitRunnerLogSegment {
    admission: RunnerLogAdmission,
    object_key: ObjectKey,
    digest: Sha256Digest,
    encoded_size: u64,
    uncompressed_size: u64,
    response: RunnerOperationResponse,
}

impl CommitRunnerLogSegment {
    /// Creates a bounded ordered log segment commit.
    ///
    /// # Errors
    /// Rejects empty or oversized object representations.
    pub fn new(
        admission: RunnerLogAdmission,
        object_key: ObjectKey,
        digest: Sha256Digest,
        encoded_size: u64,
        uncompressed_size: u64,
        response: RunnerOperationResponse,
    ) -> Result<Self, RunnerControlValueError> {
        if encoded_size == 0
            || encoded_size > MAX_LOG_SEGMENT_BYTES
            || uncompressed_size == 0
            || uncompressed_size > MAX_UNCOMPRESSED_RUNNER_LOG_BYTES
        {
            return Err(RunnerControlValueError::InvalidObjectSize);
        }
        Ok(Self {
            admission,
            object_key,
            digest,
            encoded_size,
            uncompressed_size,
            response,
        })
    }

    /// Returns the authoritative admission that must be revalidated by the commit adapter.
    #[must_use]
    pub const fn admission(&self) -> &RunnerLogAdmission {
        &self.admission
    }

    /// Returns the idempotent runner operation.
    #[must_use]
    pub const fn request(&self) -> &RunnerOperationRequest {
        self.admission.request().request()
    }
    /// Returns the attempt receiving the segment.
    #[must_use]
    pub const fn attempt_id(&self) -> AttemptId {
        self.admission.request().attempt_id()
    }
    /// Returns the exclusive lease guard.
    #[must_use]
    pub const fn guard(&self) -> LeaseGuard {
        self.admission.request().guard()
    }
    /// Returns the immutable log stream.
    #[must_use]
    pub const fn stream_id(&self) -> LogStreamId {
        self.admission.request().stream_id()
    }
    /// Returns the log document schema.
    #[must_use]
    pub const fn schema(&self) -> DocumentSchema {
        self.admission.request().schema()
    }
    /// Returns the first sequence in the segment.
    #[must_use]
    pub const fn first_sequence(&self) -> LogSequence {
        self.admission.request().first_sequence()
    }
    /// Returns the last sequence in the segment.
    #[must_use]
    pub const fn last_sequence(&self) -> LogSequence {
        self.admission.request().last_sequence()
    }
    /// Returns the immutable object key.
    #[must_use]
    pub const fn object_key(&self) -> &ObjectKey {
        &self.object_key
    }
    /// Returns the encoded segment digest.
    #[must_use]
    pub const fn digest(&self) -> Sha256Digest {
        self.digest
    }
    /// Returns the encoded segment size.
    #[must_use]
    pub const fn encoded_size(&self) -> u64 {
        self.encoded_size
    }
    /// Returns the uncompressed segment size.
    #[must_use]
    pub const fn uncompressed_size(&self) -> u64 {
        self.uncompressed_size
    }
    /// Returns the trusted storage time.
    #[must_use]
    pub const fn stored_at(&self) -> UnixMillis {
        self.admission.request().observed_at()
    }
    /// Reports whether this segment closes the stream.
    #[must_use]
    pub const fn is_end_of_stream(&self) -> bool {
        self.admission.request().is_end_of_stream()
    }
    /// Returns the canonical response bytes.
    #[must_use]
    pub const fn response(&self) -> &RunnerOperationResponse {
        &self.response
    }
}

/// Command cursor acknowledgement and exact response proposed for one atomic commit.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CommitCommandAcknowledgement {
    request: RunnerOperationRequest,
    acknowledgement: AcknowledgeRunnerCommands,
    response: RunnerOperationResponse,
}

impl CommitCommandAcknowledgement {
    /// Creates an acknowledgement transaction for one exact session.
    ///
    /// # Errors
    /// Returns an error if the receipt and cursor mutation name different sessions.
    pub fn new(
        request: RunnerOperationRequest,
        acknowledgement: AcknowledgeRunnerCommands,
        response: RunnerOperationResponse,
    ) -> Result<Self, RunnerControlValueError> {
        if request.session() != acknowledgement.session() {
            return Err(RunnerControlValueError::SessionMismatch);
        }
        Ok(Self {
            request,
            acknowledgement,
            response,
        })
    }

    /// Returns the idempotency identity.
    #[must_use]
    pub const fn request(&self) -> &RunnerOperationRequest {
        &self.request
    }

    /// Returns the exact cursor and trusted observation time.
    #[must_use]
    pub const fn acknowledgement(&self) -> AcknowledgeRunnerCommands {
        self.acknowledgement
    }

    /// Returns canonical response bytes proposed for the first commit.
    #[must_use]
    pub const fn response(&self) -> &RunnerOperationResponse {
        &self.response
    }
}

/// Atomic runner mutation and response-receipt boundary.
#[async_trait]
pub trait RunnerControlTransactionRepository: Send + Sync {
    /// Resolves immutable tenant, attempt, fence, stream, and output-safety authority before any
    /// log bytes are serialized or written to blob storage. Implementations must not mutate
    /// durable log or receipt state during this read-only admission.
    async fn admit_runner_log_segment(
        &self,
        request: RunnerLogAdmissionRequest,
    ) -> Result<RunnerLogAdmission, StoreError>;

    /// Bounds a proposed renewal to the exact fenced attempt's current runtime authority.
    ///
    /// Implementations must return a request with identical attempt, session,
    /// and guard coordinates, rebased to the post-lock repository observation
    /// and expiry. A GitHub authority record that exists but is not current and
    /// Ready fails closed; absence means the attempt has no GitHub runtime-
    /// authority ceiling. The ceiling applies only while the reported
    /// lifecycle can expose repository credentials; `Finalizing` continues
    /// under ordinary lease authority after executor quiescence. The atomic
    /// commit revalidates this decision against concurrent authority
    /// transitions and the durable lifecycle.
    async fn authorize_lease_renewal(
        &self,
        request: RenewLease,
        reported_lifecycle: JobLifecycle,
    ) -> Result<RenewLease, StoreError>;

    /// Atomically accepts/rejects an exact published offer and records its acknowledgement.
    async fn commit_lease_response(
        &self,
        request: CommitLeaseResponse,
    ) -> Result<RunnerOperationReceipt, StoreError>;

    /// Atomically updates session liveness, renews the exact lease, and records the response.
    async fn commit_lease_heartbeat(
        &self,
        request: CommitLeaseHeartbeat,
    ) -> Result<RunnerOperationReceipt, StoreError>;

    /// Atomically advances the outbox cursor/session heartbeat and records the response.
    async fn commit_command_acknowledgement(
        &self,
        request: CommitCommandAcknowledgement,
    ) -> Result<RunnerOperationReceipt, StoreError>;

    /// Atomically commits fenced terminal metadata, terminal lifecycle, and acknowledgement.
    async fn commit_runner_terminal_result(
        &self,
        request: CommitRunnerTerminalResult,
    ) -> Result<RunnerOperationReceipt, StoreError>;

    /// Atomically appends fenced contiguous log metadata and records its exact acknowledgement.
    async fn commit_runner_log_segment(
        &self,
        request: CommitRunnerLogSegment,
    ) -> Result<RunnerOperationReceipt, StoreError>;
}

/// Invalid cross-object runner-control request composition.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum RunnerControlValueError {
    /// Receipt and mutation belong to different durable sessions.
    #[error("runner control request crosses durable sessions")]
    SessionMismatch,
    /// The proposed lease belongs to another runner.
    #[error("runner control lease belongs to another runner")]
    LeaseRunnerMismatch,
    /// The offer metadata is not the current executable `JobIR` schema.
    #[error("runner control offer uses an unsupported JobIR schema")]
    UnsupportedJobIr,
    /// The durable offer horizon is outside its lease/command interval.
    #[error("runner control offer validity horizon is invalid")]
    InvalidOfferValidityHorizon,
    /// A heartbeat reported a queued or terminal lifecycle.
    #[error("runner heartbeat lifecycle is not active")]
    InvalidHeartbeatLifecycle,
    /// Immutable object size is outside its durable bound.
    #[error("runner ingress object size is outside its durable bound")]
    InvalidObjectSize,
    /// A trusted terminal commit predates runner completion.
    #[error("runner terminal result commit predates completion")]
    CommitBeforeCompletion,
    /// Log segment sequence range is inverted.
    #[error("runner log sequence range is inverted")]
    InvertedLogSequence,
    /// Log sequence cannot be represented by the durable backend contract.
    #[error("runner log sequence exceeds the durable range")]
    LogSequenceOutOfRange,
    /// Raw-log handling disagrees with the immutable secret-exposure ceiling.
    #[error("runner log safety policy is inconsistent")]
    InconsistentLogSafetyPolicy,
}
