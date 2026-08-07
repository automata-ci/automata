use async_trait::async_trait;
use automata_core::{
    AttemptId, JobConclusion, JobIrVersion, JobLifecycle, Lease, LeaseGuard, LogSequence,
    LogStreamId, OperationId, RunnerId, RunnerSessionId, Sha256Digest, UnixMillis,
};
use thiserror::Error;

use crate::{
    AcknowledgeRunnerCommands, CommandCursor, CommandSequence, DocumentSchema,
    DurableRunnerCommand, EnqueueRunnerCommand, JobIrMetadata, MAX_LOG_SEGMENT_BYTES,
    MAX_TERMINAL_RESULT_BYTES, ObjectKey, RenewLease, RunnerGeneration, RunnerOperationReceipt,
    RunnerOperationRequest, RunnerOperationResponse, RunnerProtocolVersion, RunnerSessionFence,
    StableRunnerSlot, StoreError,
};

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
    slot: crate::StableRunnerSlot,
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
        slot: crate::StableRunnerSlot,
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
    pub const fn slot(&self) -> crate::StableRunnerSlot {
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

/// Exact server-command identity used to resolve a replay to one typed offer publication.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LeaseOfferCommandIdentity {
    session: RunnerSessionFence,
    operation_id: OperationId,
    sequence: CommandSequence,
}

impl LeaseOfferCommandIdentity {
    #[must_use]
    pub const fn new(
        session: RunnerSessionFence,
        operation_id: OperationId,
        sequence: CommandSequence,
    ) -> Self {
        Self {
            session,
            operation_id,
            sequence,
        }
    }

    #[must_use]
    pub const fn session(self) -> RunnerSessionFence {
        self.session
    }

    #[must_use]
    pub const fn operation_id(self) -> OperationId {
        self.operation_id
    }

    #[must_use]
    pub const fn sequence(self) -> CommandSequence {
        self.sequence
    }
}

/// Complete verified lease-offer command awaiting an atomic durable publication.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PublishLeaseOffer {
    claim: LeaseOfferClaim,
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
        slot: crate::StableRunnerSlot,
        lease: Lease,
        job_ir: JobIrMetadata,
        command: EnqueueRunnerCommand,
    ) -> Result<Self, RunnerControlValueError> {
        if request.session() != command.session() {
            return Err(RunnerControlValueError::SessionMismatch);
        }
        let claim = LeaseOfferClaim::new(request, protocol_version, slot, lease, job_ir)?;
        Ok(Self { claim, command })
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
    pub const fn slot(&self) -> crate::StableRunnerSlot {
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
    slot: crate::StableRunnerSlot,
    lease: Lease,
    job_ir: JobIrMetadata,
    command: DurableRunnerCommand,
}

impl PublishedLeaseOffer {
    /// Builds a decoded durable publication.
    #[must_use]
    pub const fn new(
        request: RunnerOperationRequest,
        protocol_version: RunnerProtocolVersion,
        slot: crate::StableRunnerSlot,
        lease: Lease,
        job_ir: JobIrMetadata,
        command: DurableRunnerCommand,
    ) -> Self {
        Self {
            request,
            protocol_version,
            slot,
            lease,
            job_ir,
            command,
        }
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
    pub const fn slot(&self) -> crate::StableRunnerSlot {
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

/// Atomic typed lease-offer publication port.
#[async_trait]
pub trait RunnerLeaseOfferRepository: Send + Sync {
    /// Classifies one exact claimed poll under the same locks used by publication and reaping.
    async fn inspect_lease_offer_claim(
        &self,
        request: LeaseOfferClaim,
    ) -> Result<LeaseOfferClaimStatus, StoreError>;

    /// Resolves an outbox replay to its exact typed publication. Missing, orphaned, or mismatched
    /// lease-offer commands are durable corruption, never generic commands.
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

    #[must_use]
    pub const fn request(&self) -> &RunnerOperationRequest {
        &self.request
    }
    #[must_use]
    pub const fn command_cursor(&self) -> CommandCursor {
        self.command_cursor
    }
    #[must_use]
    pub const fn attempt_id(&self) -> AttemptId {
        self.attempt_id
    }
    #[must_use]
    pub const fn slot(&self) -> StableRunnerSlot {
        self.slot
    }
    #[must_use]
    pub const fn guard(&self) -> LeaseGuard {
        self.guard
    }
    #[must_use]
    pub const fn action(&self) -> LeaseResponseAction {
        self.action
    }
    #[must_use]
    pub const fn observed_at(&self) -> UnixMillis {
        self.observed_at
    }
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
        if encoded_size == 0 || encoded_size > MAX_TERMINAL_RESULT_BYTES {
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

    #[must_use]
    pub const fn request(&self) -> &RunnerOperationRequest {
        &self.request
    }
    #[must_use]
    pub const fn attempt_id(&self) -> AttemptId {
        self.attempt_id
    }
    #[must_use]
    pub const fn guard(&self) -> LeaseGuard {
        self.guard
    }
    #[must_use]
    pub const fn schema(&self) -> DocumentSchema {
        self.schema
    }
    #[must_use]
    pub const fn encoded_size(&self) -> u64 {
        self.encoded_size
    }
    #[must_use]
    pub const fn digest(&self) -> Sha256Digest {
        self.digest
    }
    #[must_use]
    pub const fn object_key(&self) -> &ObjectKey {
        &self.object_key
    }
    #[must_use]
    pub const fn conclusion(&self) -> JobConclusion {
        self.conclusion
    }
    #[must_use]
    pub const fn completed_at(&self) -> UnixMillis {
        self.completed_at
    }
    #[must_use]
    pub const fn committed_at(&self) -> UnixMillis {
        self.committed_at
    }
    #[must_use]
    pub const fn response(&self) -> &RunnerOperationResponse {
        &self.response
    }
}

/// Immutable ordered log segment plus the exact contiguous acknowledgement.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CommitRunnerLogSegment {
    request: RunnerOperationRequest,
    attempt_id: AttemptId,
    guard: LeaseGuard,
    stream_id: LogStreamId,
    schema: DocumentSchema,
    first_sequence: LogSequence,
    last_sequence: LogSequence,
    object_key: ObjectKey,
    digest: Sha256Digest,
    encoded_size: u64,
    uncompressed_size: u64,
    stored_at: UnixMillis,
    end_of_stream: bool,
    response: RunnerOperationResponse,
}

impl CommitRunnerLogSegment {
    /// Creates a bounded ordered log segment commit.
    ///
    /// # Errors
    /// Rejects inverted ranges and empty/oversized object representations.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        request: RunnerOperationRequest,
        attempt_id: AttemptId,
        guard: LeaseGuard,
        stream_id: LogStreamId,
        schema: DocumentSchema,
        first_sequence: LogSequence,
        last_sequence: LogSequence,
        object_key: ObjectKey,
        digest: Sha256Digest,
        encoded_size: u64,
        uncompressed_size: u64,
        stored_at: UnixMillis,
        end_of_stream: bool,
        response: RunnerOperationResponse,
    ) -> Result<Self, RunnerControlValueError> {
        if first_sequence > last_sequence {
            return Err(RunnerControlValueError::InvertedLogSequence);
        }
        if last_sequence.get() > MAX_DURABLE_LOG_SEQUENCE {
            return Err(RunnerControlValueError::LogSequenceOutOfRange);
        }
        if encoded_size == 0
            || encoded_size > MAX_LOG_SEGMENT_BYTES
            || uncompressed_size == 0
            || uncompressed_size > MAX_UNCOMPRESSED_RUNNER_LOG_BYTES
        {
            return Err(RunnerControlValueError::InvalidObjectSize);
        }
        Ok(Self {
            request,
            attempt_id,
            guard,
            stream_id,
            schema,
            first_sequence,
            last_sequence,
            object_key,
            digest,
            encoded_size,
            uncompressed_size,
            stored_at,
            end_of_stream,
            response,
        })
    }

    #[must_use]
    pub const fn request(&self) -> &RunnerOperationRequest {
        &self.request
    }
    #[must_use]
    pub const fn attempt_id(&self) -> AttemptId {
        self.attempt_id
    }
    #[must_use]
    pub const fn guard(&self) -> LeaseGuard {
        self.guard
    }
    #[must_use]
    pub const fn stream_id(&self) -> LogStreamId {
        self.stream_id
    }
    #[must_use]
    pub const fn schema(&self) -> DocumentSchema {
        self.schema
    }
    #[must_use]
    pub const fn first_sequence(&self) -> LogSequence {
        self.first_sequence
    }
    #[must_use]
    pub const fn last_sequence(&self) -> LogSequence {
        self.last_sequence
    }
    #[must_use]
    pub const fn object_key(&self) -> &ObjectKey {
        &self.object_key
    }
    #[must_use]
    pub const fn digest(&self) -> Sha256Digest {
        self.digest
    }
    #[must_use]
    pub const fn encoded_size(&self) -> u64 {
        self.encoded_size
    }
    #[must_use]
    pub const fn uncompressed_size(&self) -> u64 {
        self.uncompressed_size
    }
    #[must_use]
    pub const fn stored_at(&self) -> UnixMillis {
        self.stored_at
    }
    #[must_use]
    pub const fn is_end_of_stream(&self) -> bool {
        self.end_of_stream
    }
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
}
