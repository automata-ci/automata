use std::{fmt, sync::Arc};

use async_trait::async_trait;
use automata_auth::machine::{AuthenticatedMachine, ExternalRunnerIdentity};
use automata_blob::{BlobDescriptor, BlobKey, BlobStoreErrorKind, ImmutableBlobStore, MediaType};
use automata_control::{
    AuthenticatedRunnerSession, LeaseClock, LeaseIdGenerator, LeasePollConfig, LeasePollError,
    LeasePollOutcome, LeasePollRepository, LeasePollService,
};
use automata_control_plane::SchedulerPolicy;
use automata_core::{
    JobIrEnvelope, Lease, OperationId, RunnerId, RunnerSessionId, Sha256Digest, UnixMillis,
};
use automata_protocol::{
    CancelJob, CommandSequence, JobRuntimeAuthorities, LeaseOffer, LeaseRequest,
    MAX_CONFIGURABLE_FRAME_BYTES, ProtocolLimits, ProtocolVersion, RunnerSlotOrdinal,
    ServerCommandHeader, ServerToRunner,
};
use automata_protocol_protobuf::encode_job_ir;
use automata_store::{
    CANCEL_JOB_COMMAND_KIND, CANCEL_JOB_COMMAND_SCHEMA, CancelJobCommandPayload,
    CommandSequence as StoreCommandSequence, CurrentRunnerSession, CurrentRunnerSessionRepository,
    DocumentSchema, DurableRunnerCommand, EnqueueRunnerCommand, JobIrMetadata,
    LeaseOfferClaim as StoreLeaseOfferClaim, LeaseOfferClaimStatus as StoreLeaseOfferClaimStatus,
    LeaseOfferCommandIdentity as StoreLeaseOfferCommandIdentity, PublishLeaseOffer,
    PublishedLeaseOffer, RunnerCommandPayload, RunnerGeneration, RunnerLeaseOfferRepository,
    RunnerOperationKind, RunnerOperationRequest, RunnerProtocolVersion, RunnerSessionFence,
    StableRunnerSlot,
};
use sha2::{Digest as _, Sha256};
use thiserror::Error;
use zeroize::Zeroizing;

/// Immutable media type used for standalone protobuf `JobIR` objects.
pub const JOB_IR_PROTOBUF_MEDIA_TYPE: &str = "application/vnd.automata.job-ir.protobuf";

const LEASE_REQUEST_KIND: &str = "automata.runner.lease-request.v1";
const LEASE_OFFER_COMMAND_KIND: &str = "automata.runner.lease-offer.v2";
const LEASE_OFFER_COMMAND_SCHEMA: u16 = 2;

#[derive(serde::Serialize)]
struct LeaseOfferCommandPayloadRef<'a> {
    job: &'a JobIrEnvelope,
    lease: &'a Lease,
    protocol_version: u16,
    runtime_authorities: &'a JobRuntimeAuthorities,
    schema: u16,
    slot: u16,
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct DurableLeaseOfferCommandPayload {
    job: JobIrEnvelope,
    lease: Lease,
    protocol_version: u16,
    runtime_authorities: JobRuntimeAuthorities,
    schema: u16,
    slot: u16,
}

/// Administrator-owned lifecycle state for one registered runner.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DesiredRunnerState {
    /// New sessions and work polling are allowed.
    Active,
    /// Existing sessions may finish, but new sessions are refused.
    Draining,
    /// The machine is not authorized to establish or use sessions.
    Disabled,
}

/// Exact server-owned registration authorized for one external machine.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthorizedRunnerRegistration {
    external_identity: ExternalRunnerIdentity,
    runner_id: RunnerId,
    generation: RunnerGeneration,
    certificate_sha256: [u8; 32],
    desired_state: DesiredRunnerState,
}

impl AuthorizedRunnerRegistration {
    /// Creates an exact registration assertion returned by a trusted adapter.
    #[must_use]
    pub const fn new(
        external_identity: ExternalRunnerIdentity,
        runner_id: RunnerId,
        generation: RunnerGeneration,
        certificate_sha256: [u8; 32],
        desired_state: DesiredRunnerState,
    ) -> Self {
        Self {
            external_identity,
            runner_id,
            generation,
            certificate_sha256,
            desired_state,
        }
    }

    /// Returns the provider identity stored by the administrator.
    #[must_use]
    pub const fn external_identity(&self) -> &ExternalRunnerIdentity {
        &self.external_identity
    }

    /// Returns the exact internal runner identity.
    #[must_use]
    pub const fn runner_id(&self) -> RunnerId {
        self.runner_id
    }

    /// Returns the current registered credential/configuration generation.
    #[must_use]
    pub const fn generation(&self) -> RunnerGeneration {
        self.generation
    }

    /// Returns the exact registered leaf-certificate digest.
    #[must_use]
    pub const fn certificate_sha256(&self) -> &[u8; 32] {
        &self.certificate_sha256
    }

    /// Returns the server-owned desired state.
    #[must_use]
    pub const fn desired_state(&self) -> DesiredRunnerState {
        self.desired_state
    }
}

/// Sanitized failure from a narrow control application port.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum ControlPortError {
    /// Shared durable state is temporarily unavailable.
    #[error("runner control state is unavailable")]
    Unavailable,
    /// Durable bytes or identity mappings violate an invariant.
    #[error("runner control state is corrupt")]
    Corrupt,
    /// A conflicting durable mutation was rejected.
    #[error("runner control operation conflicts with durable state")]
    Conflict,
}

/// Object-safe lookup from a freshly authenticated external machine to server-owned authority.
#[async_trait]
pub trait RunnerRegistrationAuthorizer: fmt::Debug + Send + Sync {
    /// Returns no registration for an unrecognized identity. Implementations must query shared
    /// state and must not derive groups, labels, generation, or desired state from a hello.
    async fn authorize(
        &self,
        machine: &AuthenticatedMachine,
    ) -> Result<Option<AuthorizedRunnerRegistration>, ControlPortError>;
}

/// Narrow durable lookup needed because a wire session ID does not contain its epoch.
#[async_trait]
pub trait RunnerSessionFenceResolver: fmt::Debug + Send + Sync {
    /// Resolves only a currently live fence for this exact runner, generation, and session ID.
    async fn resolve_current(
        &self,
        runner_id: RunnerId,
        generation: RunnerGeneration,
        session_id: RunnerSessionId,
    ) -> Result<Option<RunnerSessionFence>, ControlPortError>;
}

/// Immutable coordinates for issuing authority into one exact lease offer.
#[derive(Clone, Copy, Debug)]
pub struct RuntimeAuthorityIssueRequest<'a> {
    job: &'a JobIrEnvelope,
    lease: &'a Lease,
    issued_at: UnixMillis,
}

impl<'a> RuntimeAuthorityIssueRequest<'a> {
    /// Binds issuance to verified `JobIR` and a newly claimed exclusive lease.
    #[must_use]
    pub const fn new(job: &'a JobIrEnvelope, lease: &'a Lease, issued_at: UnixMillis) -> Self {
        Self {
            job,
            lease,
            issued_at,
        }
    }

    /// Returns the verified semantic job.
    #[must_use]
    pub const fn job(self) -> &'a JobIrEnvelope {
        self.job
    }

    /// Returns the exact runner-owned lease and fence.
    #[must_use]
    pub const fn lease(self) -> &'a Lease {
        self.lease
    }

    /// Returns the stable issuance anchor used for deterministic retries.
    #[must_use]
    pub const fn issued_at(self) -> UnixMillis {
        self.issued_at
    }
}

/// Pluggable server-side authority issuer invoked at lease-offer construction.
///
/// Implementations must derive credentials only from the exact request, keep
/// signing keys server-side, and return byte-identical authority for repeated
/// calls with identical coordinates.
#[async_trait]
pub trait RuntimeAuthorityIssuer: fmt::Debug + Send + Sync {
    /// Issues all job-scoped authorities required by this deployment.
    async fn issue(
        &self,
        request: RuntimeAuthorityIssueRequest<'_>,
    ) -> Result<JobRuntimeAuthorities, ControlPortError>;
}

/// Adapter from the durable current-session repository to the application resolver port.
pub struct StoreRunnerSessionFenceResolver {
    repository: Arc<dyn CurrentRunnerSessionRepository>,
}

impl fmt::Debug for StoreRunnerSessionFenceResolver {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("StoreRunnerSessionFenceResolver")
            .finish_non_exhaustive()
    }
}

impl StoreRunnerSessionFenceResolver {
    /// Wraps one replica-neutral durable resolver.
    #[must_use]
    pub const fn new(repository: Arc<dyn CurrentRunnerSessionRepository>) -> Self {
        Self { repository }
    }
}

#[async_trait]
impl RunnerSessionFenceResolver for StoreRunnerSessionFenceResolver {
    async fn resolve_current(
        &self,
        runner_id: RunnerId,
        generation: RunnerGeneration,
        session_id: RunnerSessionId,
    ) -> Result<Option<RunnerSessionFence>, ControlPortError> {
        self.repository
            .resolve_current_session(CurrentRunnerSession::new(runner_id, generation, session_id))
            .await
            .map_err(|error| store_port_error(&error))
    }
}

/// Bounded immutable object reader for planned standalone `JobIR` protobuf bytes.
#[async_trait]
pub trait JobIrObjectReader: fmt::Debug + Send + Sync {
    /// Reads and verifies the exact immutable metadata while enforcing `maximum_bytes` before
    /// returning an allocation.
    async fn read_job_ir(
        &self,
        metadata: &JobIrMetadata,
        maximum_bytes: u64,
    ) -> Result<Vec<u8>, ControlPortError>;
}

/// Provider-neutral verified reader over an [`ImmutableBlobStore`].
pub struct ImmutableBlobJobIrReader {
    store: Arc<dyn ImmutableBlobStore>,
}

impl fmt::Debug for ImmutableBlobJobIrReader {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ImmutableBlobJobIrReader")
            .finish_non_exhaustive()
    }
}

impl ImmutableBlobJobIrReader {
    /// Wraps a content-addressed immutable blob adapter.
    #[must_use]
    pub const fn new(store: Arc<dyn ImmutableBlobStore>) -> Self {
        Self { store }
    }
}

#[async_trait]
impl JobIrObjectReader for ImmutableBlobJobIrReader {
    async fn read_job_ir(
        &self,
        metadata: &JobIrMetadata,
        maximum_bytes: u64,
    ) -> Result<Vec<u8>, ControlPortError> {
        if metadata.encoded_size() > maximum_bytes {
            return Err(ControlPortError::Corrupt);
        }
        let key = BlobKey::new(metadata.object_key().as_str().to_owned())
            .map_err(|_| ControlPortError::Corrupt)?;
        let media_type =
            MediaType::new(JOB_IR_PROTOBUF_MEDIA_TYPE).map_err(|_| ControlPortError::Corrupt)?;
        let descriptor =
            BlobDescriptor::new(key, metadata.digest(), metadata.encoded_size(), media_type);
        self.store
            .get_verified(&descriptor, maximum_bytes)
            .await
            .map(|blob| blob.into_bytes().to_vec())
            .map_err(|error| match error.kind() {
                BlobStoreErrorKind::Unavailable | BlobStoreErrorKind::Unauthorized => {
                    ControlPortError::Unavailable
                }
                BlobStoreErrorKind::NotFound
                | BlobStoreErrorKind::Conflict
                | BlobStoreErrorKind::Integrity
                | BlobStoreErrorKind::TooLarge
                | BlobStoreErrorKind::InvalidResponse => ControlPortError::Corrupt,
            })
    }
}

/// Exact claimed lease-poll coordinates inspected before authority issuance.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LeaseOfferClaim {
    session: RunnerSessionFence,
    request_operation_id: OperationId,
    request_digest: Sha256Digest,
    protocol_version: ProtocolVersion,
    slot: RunnerSlotOrdinal,
    lease: automata_core::Lease,
    job_ir_metadata: JobIrMetadata,
}

impl LeaseOfferClaim {
    /// Creates a claim probe from a receipt-backed lease-poll outcome.
    #[allow(clippy::too_many_arguments)]
    #[must_use]
    pub const fn new(
        session: RunnerSessionFence,
        request_operation_id: OperationId,
        request_digest: Sha256Digest,
        protocol_version: ProtocolVersion,
        slot: RunnerSlotOrdinal,
        lease: automata_core::Lease,
        job_ir_metadata: JobIrMetadata,
    ) -> Self {
        Self {
            session,
            request_operation_id,
            request_digest,
            protocol_version,
            slot,
            lease,
            job_ir_metadata,
        }
    }

    /// Returns the exact fenced session.
    #[must_use]
    pub const fn session(&self) -> RunnerSessionFence {
        self.session
    }

    /// Returns the runner poll operation being recovered.
    #[must_use]
    pub const fn request_operation_id(&self) -> OperationId {
        self.request_operation_id
    }

    /// Returns the digest of canonical runner request bytes.
    #[must_use]
    pub const fn request_digest(&self) -> Sha256Digest {
        self.request_digest
    }

    /// Returns the negotiated protocol.
    #[must_use]
    pub const fn protocol_version(&self) -> ProtocolVersion {
        self.protocol_version
    }

    /// Returns the stable runner slot.
    #[must_use]
    pub const fn slot(&self) -> RunnerSlotOrdinal {
        self.slot
    }

    /// Returns the exclusive lease from the immutable claim receipt.
    #[must_use]
    pub const fn lease(&self) -> &automata_core::Lease {
        &self.lease
    }

    /// Returns immutable `JobIR` metadata from the claim receipt.
    #[must_use]
    pub const fn job_ir_metadata(&self) -> &JobIrMetadata {
        &self.job_ir_metadata
    }
}

/// Recovery state of one exact claimed lease poll.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum LeaseOfferClaimStatus {
    /// The claim is still the exact active attempt fence.
    Current,
    /// The exact durable command was already published and must be replayed.
    Published(Box<DurableRunnerCommand>),
    /// The claim's attempt fence has irreversibly advanced or disappeared.
    ClaimSuperseded,
}

/// Fully verified lease-offer body awaiting one durable command identity.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LeaseOfferCommand {
    session: RunnerSessionFence,
    request_operation_id: OperationId,
    request_digest: Sha256Digest,
    protocol_version: ProtocolVersion,
    slot: RunnerSlotOrdinal,
    lease: automata_core::Lease,
    job_ir_metadata: JobIrMetadata,
    job: JobIrEnvelope,
    runtime_authorities: JobRuntimeAuthorities,
    created_at: UnixMillis,
}

impl LeaseOfferCommand {
    /// Creates a command after the application has verified the immutable object.
    #[allow(clippy::too_many_arguments)]
    #[must_use]
    pub const fn new(
        session: RunnerSessionFence,
        request_operation_id: OperationId,
        request_digest: Sha256Digest,
        protocol_version: ProtocolVersion,
        slot: RunnerSlotOrdinal,
        lease: automata_core::Lease,
        job_ir_metadata: JobIrMetadata,
        job: JobIrEnvelope,
        runtime_authorities: JobRuntimeAuthorities,
        created_at: UnixMillis,
    ) -> Self {
        Self {
            session,
            request_operation_id,
            request_digest,
            protocol_version,
            slot,
            lease,
            job_ir_metadata,
            job,
            runtime_authorities,
            created_at,
        }
    }

    /// Returns the exact fenced session.
    #[must_use]
    pub const fn session(&self) -> RunnerSessionFence {
        self.session
    }
    /// Returns the runner poll operation being answered.
    #[must_use]
    pub const fn request_operation_id(&self) -> OperationId {
        self.request_operation_id
    }
    /// Returns the digest of canonical runner request bytes.
    #[must_use]
    pub const fn request_digest(&self) -> Sha256Digest {
        self.request_digest
    }
    /// Returns the negotiated protocol.
    #[must_use]
    pub const fn protocol_version(&self) -> ProtocolVersion {
        self.protocol_version
    }
    /// Returns the stable runner slot.
    #[must_use]
    pub const fn slot(&self) -> RunnerSlotOrdinal {
        self.slot
    }
    /// Returns the exclusive lease.
    #[must_use]
    pub const fn lease(&self) -> &automata_core::Lease {
        &self.lease
    }
    /// Returns the immutable storage metadata that was verified.
    #[must_use]
    pub const fn job_ir_metadata(&self) -> &JobIrMetadata {
        &self.job_ir_metadata
    }
    /// Returns the validated `JobIR` envelope.
    #[must_use]
    pub const fn job(&self) -> &JobIrEnvelope {
        &self.job
    }
    /// Returns exact job-scoped authority included in the durable offer.
    #[must_use]
    pub const fn runtime_authorities(&self) -> &JobRuntimeAuthorities {
        &self.runtime_authorities
    }
    /// Returns trusted command creation time.
    #[must_use]
    pub const fn created_at(&self) -> UnixMillis {
        self.created_at
    }
}

/// Identity allocated atomically with a durable typed lease-offer command.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PublishedCommand {
    operation_id: OperationId,
    sequence: CommandSequence,
}

impl PublishedCommand {
    /// Creates a published command identity.
    #[must_use]
    pub const fn new(operation_id: OperationId, sequence: CommandSequence) -> Self {
        Self {
            operation_id,
            sequence,
        }
    }
    /// Returns its stable operation identity.
    #[must_use]
    pub const fn operation_id(self) -> OperationId {
        self.operation_id
    }
    /// Returns its durable one-based sequence.
    #[must_use]
    pub const fn sequence(self) -> CommandSequence {
        self.sequence
    }
}

/// Result of atomically publishing a verified offer command.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LeaseOfferPublishOutcome {
    /// The exact durable command was published or loaded from its prior commit.
    Published(PublishedCommand),
    /// The claim was irreversibly superseded before publication could commit.
    ClaimSuperseded,
}

/// Atomic inspection and publication seam for typed lease offers.
#[async_trait]
pub trait LeaseOfferCommandPublisher: fmt::Debug + Send + Sync {
    /// Classifies an exact receipt-backed claim before external authority issuance.
    async fn inspect(
        &self,
        claim: LeaseOfferClaim,
    ) -> Result<LeaseOfferClaimStatus, ControlPortError>;

    /// Resolves a generic outbox or receipt replay to the exact command owned by one typed
    /// publication and validates its durable payload against that publication.
    async fn resolve_replay(
        &self,
        session: RunnerSessionFence,
        operation_id: OperationId,
        sequence: CommandSequence,
    ) -> Result<Option<DurableRunnerCommand>, ControlPortError>;

    /// Idempotently persists the complete typed command and allocates its stable identity.
    async fn publish(
        &self,
        command: LeaseOfferCommand,
    ) -> Result<LeaseOfferPublishOutcome, ControlPortError>;
}

/// Durable lease-offer publisher backed by the atomic store seam.
pub struct StoreLeaseOfferCommandPublisher {
    repository: Arc<dyn RunnerLeaseOfferRepository>,
    ids: Arc<dyn ControlIdGenerator>,
}

impl fmt::Debug for StoreLeaseOfferCommandPublisher {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("StoreLeaseOfferCommandPublisher")
            .finish_non_exhaustive()
    }
}

impl StoreLeaseOfferCommandPublisher {
    /// Composes typed offer publication over shared durable state and a fresh ID source.
    #[must_use]
    pub const fn new(
        repository: Arc<dyn RunnerLeaseOfferRepository>,
        ids: Arc<dyn ControlIdGenerator>,
    ) -> Self {
        Self { repository, ids }
    }
}

fn store_lease_offer_claim(
    claim: &LeaseOfferClaim,
) -> Result<(StoreLeaseOfferClaim, RunnerOperationKind), ControlPortError> {
    let request_kind =
        RunnerOperationKind::new(LEASE_REQUEST_KIND).map_err(|_| ControlPortError::Corrupt)?;
    let request = RunnerOperationRequest::new(
        claim.session(),
        claim.request_operation_id(),
        request_kind.clone(),
        claim.request_digest(),
    );
    let protocol = RunnerProtocolVersion::new(claim.protocol_version().get())
        .map_err(|_| ControlPortError::Corrupt)?;
    let slot = StableRunnerSlot::new(claim.slot().get()).map_err(|_| ControlPortError::Corrupt)?;
    let store_claim = StoreLeaseOfferClaim::new(
        request,
        protocol,
        slot,
        claim.lease().clone(),
        claim.job_ir_metadata().clone(),
    )
    .map_err(|_| ControlPortError::Corrupt)?;
    Ok((store_claim, request_kind))
}

fn published_claim_matches(
    published: &PublishedLeaseOffer,
    expected: &StoreLeaseOfferClaim,
    request_kind: &RunnerOperationKind,
) -> bool {
    published.protocol_version() == expected.protocol_version()
        && published.slot() == expected.slot()
        && published.lease() == expected.lease()
        && published.job_ir() == expected.job_ir()
        && published.request().session() == expected.request().session()
        && published.request().operation_id() == expected.request().operation_id()
        && published.request().kind() == request_kind
        && published.request().request_digest() == expected.request().request_digest()
        && durable_lease_offer_payload_matches(published)
}

fn durable_lease_offer_payload_matches(published: &PublishedLeaseOffer) -> bool {
    let command = published.command().request();
    if command.session() != published.request().session()
        || command.kind().as_str() != LEASE_OFFER_COMMAND_KIND
        || command.payload().schema().get() != LEASE_OFFER_COMMAND_SCHEMA
    {
        return false;
    }
    let Ok(payload) =
        serde_json::from_slice::<DurableLeaseOfferCommandPayload>(command.payload().bytes())
    else {
        return false;
    };
    let mut canonical_payload = Zeroizing::new(Vec::new());
    if serde_json::to_writer(
        &mut *canonical_payload,
        &LeaseOfferCommandPayloadRef {
            job: &payload.job,
            lease: &payload.lease,
            protocol_version: payload.protocol_version,
            runtime_authorities: &payload.runtime_authorities,
            schema: payload.schema,
            slot: payload.slot,
        },
    )
    .is_err()
        || canonical_payload.as_slice() != command.payload().bytes()
    {
        return false;
    }
    if payload.schema != LEASE_OFFER_COMMAND_SCHEMA
        || payload.protocol_version != published.protocol_version().get()
        || payload.slot != published.slot().get()
        || &payload.lease != published.lease()
        || payload
            .runtime_authorities
            .validate_for(&payload.job, &payload.lease)
            .is_err()
    {
        return false;
    }
    let Some(limits) = durable_job_ir_limits() else {
        return false;
    };
    let Ok(encoded_job) = encode_job_ir(&payload.job, &limits) else {
        return false;
    };
    let metadata = published.job_ir();
    payload.job.version() == metadata.version()
        && payload.job.job().job_id() == metadata.job_id()
        && payload.job.job().run_id() == metadata.run_id()
        && u64::try_from(encoded_job.len()).ok() == Some(metadata.encoded_size())
        && Sha256Digest::from_bytes(Sha256::digest(encoded_job).into()) == metadata.digest()
}

fn durable_job_ir_limits() -> Option<ProtocolLimits> {
    ProtocolLimits::new(
        MAX_CONFIGURABLE_FRAME_BYTES,
        MAX_CONFIGURABLE_FRAME_BYTES,
        MAX_CONFIGURABLE_FRAME_BYTES,
        MAX_CONFIGURABLE_FRAME_BYTES,
        MAX_CONFIGURABLE_FRAME_BYTES,
    )
    .ok()
}

#[async_trait]
impl LeaseOfferCommandPublisher for StoreLeaseOfferCommandPublisher {
    async fn inspect(
        &self,
        claim: LeaseOfferClaim,
    ) -> Result<LeaseOfferClaimStatus, ControlPortError> {
        let (store_claim, request_kind) = store_lease_offer_claim(&claim)?;
        match self
            .repository
            .inspect_lease_offer_claim(store_claim.clone())
            .await
            .map_err(|error| lease_offer_port_error(&error))?
        {
            StoreLeaseOfferClaimStatus::Current => Ok(LeaseOfferClaimStatus::Current),
            StoreLeaseOfferClaimStatus::ClaimSuperseded => {
                Ok(LeaseOfferClaimStatus::ClaimSuperseded)
            }
            StoreLeaseOfferClaimStatus::Published(publication) => {
                if !published_claim_matches(&publication, &store_claim, &request_kind) {
                    return Err(ControlPortError::Corrupt);
                }
                Ok(LeaseOfferClaimStatus::Published(Box::new(
                    publication.command().clone(),
                )))
            }
        }
    }

    async fn resolve_replay(
        &self,
        session: RunnerSessionFence,
        operation_id: OperationId,
        sequence: CommandSequence,
    ) -> Result<Option<DurableRunnerCommand>, ControlPortError> {
        let store_sequence =
            StoreCommandSequence::new(sequence.get()).map_err(|_| ControlPortError::Corrupt)?;
        let Some(published) = self
            .repository
            .resolve_lease_offer_command(StoreLeaseOfferCommandIdentity::new(
                session,
                operation_id,
                store_sequence,
            ))
            .await
            .map_err(|error| lease_offer_port_error(&error))?
        else {
            return Ok(None);
        };
        if published.request().kind().as_str() != LEASE_REQUEST_KIND
            || published.command().request().session() != session
            || published.command().request().operation_id() != operation_id
            || published.command().sequence() != store_sequence
            || !durable_lease_offer_payload_matches(&published)
        {
            return Err(ControlPortError::Corrupt);
        }
        Ok(Some(published.command().clone()))
    }

    async fn publish(
        &self,
        command: LeaseOfferCommand,
    ) -> Result<LeaseOfferPublishOutcome, ControlPortError> {
        let claim = LeaseOfferClaim::new(
            command.session(),
            command.request_operation_id(),
            command.request_digest(),
            command.protocol_version(),
            command.slot(),
            command.lease().clone(),
            command.job_ir_metadata().clone(),
        );
        let (store_claim, request_kind) = store_lease_offer_claim(&claim)?;
        let command_kind = RunnerOperationKind::new(LEASE_OFFER_COMMAND_KIND)
            .map_err(|_| ControlPortError::Corrupt)?;
        let schema = DocumentSchema::new(LEASE_OFFER_COMMAND_SCHEMA)
            .map_err(|_| ControlPortError::Corrupt)?;
        let mut payload = Zeroizing::new(Vec::new());
        serde_json::to_writer(
            &mut *payload,
            &LeaseOfferCommandPayloadRef {
                job: command.job(),
                lease: command.lease(),
                protocol_version: command.protocol_version().get(),
                runtime_authorities: command.runtime_authorities(),
                schema: LEASE_OFFER_COMMAND_SCHEMA,
                slot: command.slot().get(),
            },
        )
        .map_err(|_| ControlPortError::Corrupt)?;
        let payload = RunnerCommandPayload::new(schema, std::mem::take(&mut *payload))
            .map_err(|_| ControlPortError::Corrupt)?;
        let durable_command = EnqueueRunnerCommand::new(
            command.session(),
            self.ids.next_operation_id(),
            command_kind.clone(),
            payload.clone(),
            command.created_at(),
        );
        let publication = PublishLeaseOffer::new(
            store_claim.request().clone(),
            store_claim.protocol_version(),
            store_claim.slot(),
            store_claim.lease().clone(),
            store_claim.job_ir().clone(),
            durable_command,
        )
        .map_err(|_| ControlPortError::Corrupt)?;
        let published = match self.repository.publish_lease_offer(publication).await {
            Ok(published) => published,
            Err(automata_store::StoreError::AttemptFenceRejected(attempt_id))
                if attempt_id == command.lease().attempt_id() =>
            {
                return Ok(LeaseOfferPublishOutcome::ClaimSuperseded);
            }
            Err(error) => return Err(lease_offer_port_error(&error)),
        };
        if !published_claim_matches(&published, &store_claim, &request_kind)
            || published.command().request().session() != command.session()
            || published.command().request().kind() != &command_kind
            || published.command().request().payload() != &payload
        {
            return Err(ControlPortError::Corrupt);
        }
        let sequence = CommandSequence::new(published.command().sequence().get())
            .map_err(|_| ControlPortError::Corrupt)?;
        Ok(LeaseOfferPublishOutcome::Published(PublishedCommand::new(
            published.command().request().operation_id(),
            sequence,
        )))
    }
}

pub(crate) fn decode_durable_server_command(
    command: &DurableRunnerCommand,
    protocol_version: ProtocolVersion,
    limits: &ProtocolLimits,
) -> Result<ServerToRunner, ControlPortError> {
    let request = command.request();
    let sequence =
        CommandSequence::new(command.sequence().get()).map_err(|_| ControlPortError::Corrupt)?;
    let header = ServerCommandHeader::new(
        protocol_version,
        request.session().session_id(),
        request.operation_id(),
        sequence,
    );
    let message = match request.kind().as_str() {
        LEASE_OFFER_COMMAND_KIND => {
            if request.payload().schema().get() != LEASE_OFFER_COMMAND_SCHEMA {
                return Err(ControlPortError::Corrupt);
            }
            let payload: DurableLeaseOfferCommandPayload =
                serde_json::from_slice(request.payload().bytes())
                    .map_err(|_| ControlPortError::Corrupt)?;
            if payload.schema != LEASE_OFFER_COMMAND_SCHEMA
                || payload.protocol_version != protocol_version.get()
                || payload.lease.runner_id() != request.session().runner_id()
                || payload
                    .runtime_authorities
                    .validate_for(&payload.job, &payload.lease)
                    .is_err()
            {
                return Err(ControlPortError::Corrupt);
            }
            let slot =
                RunnerSlotOrdinal::new(payload.slot).map_err(|_| ControlPortError::Corrupt)?;
            ServerToRunner::LeaseOffer(Box::new(LeaseOffer::new(
                header,
                slot,
                payload.lease,
                payload.job,
                payload.runtime_authorities,
            )))
        }
        CANCEL_JOB_COMMAND_KIND => {
            if request.payload().schema().get() != CANCEL_JOB_COMMAND_SCHEMA {
                return Err(ControlPortError::Corrupt);
            }
            let payload = CancelJobCommandPayload::decode_json(request.payload().bytes())
                .map_err(|_| ControlPortError::Corrupt)?;
            if payload.protocol_version() != protocol_version.get() {
                return Err(ControlPortError::Corrupt);
            }
            ServerToRunner::CancelJob(CancelJob::new(
                header,
                payload.attempt_id(),
                payload.guard(),
                payload.reason(),
                payload.requested_at(),
            ))
        }
        _ => return Err(ControlPortError::Corrupt),
    };
    message
        .validate(limits)
        .map_err(|_| ControlPortError::Corrupt)?;
    Ok(message)
}

pub(crate) fn is_durable_lease_offer_command(command: &DurableRunnerCommand) -> bool {
    command.request().kind().as_str() == LEASE_OFFER_COMMAND_KIND
}

/// Object-safe lease-poll boundary used by the handler and test fakes.
#[async_trait]
pub trait LeasePoller: fmt::Debug + Send + Sync {
    /// Polls using the exact authenticated durable session.
    async fn poll(
        &self,
        authenticated: AuthenticatedRunnerSession,
        request: &LeaseRequest,
    ) -> Result<LeasePollOutcome, LeasePollError>;
}

/// Adapter that invokes the existing [`LeasePollService`] over its current ports.
pub struct LeasePollAdapter {
    repository: Arc<dyn LeasePollRepository>,
    scheduler: Arc<dyn SchedulerPolicy>,
    clock: Arc<dyn LeaseClock>,
    lease_ids: Arc<dyn LeaseIdGenerator>,
    config: LeasePollConfig,
}

impl fmt::Debug for LeasePollAdapter {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LeasePollAdapter")
            .field("config", &self.config)
            .finish_non_exhaustive()
    }
}

impl LeasePollAdapter {
    /// Composes the existing durable scheduler service behind an object-safe application port.
    #[must_use]
    pub fn new(
        repository: Arc<dyn LeasePollRepository>,
        scheduler: Arc<dyn SchedulerPolicy>,
        clock: Arc<dyn LeaseClock>,
        lease_ids: Arc<dyn LeaseIdGenerator>,
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
}

#[async_trait]
impl LeasePoller for LeasePollAdapter {
    async fn poll(
        &self,
        authenticated: AuthenticatedRunnerSession,
        request: &LeaseRequest,
    ) -> Result<LeasePollOutcome, LeasePollError> {
        LeasePollService::new(
            self.repository.as_ref(),
            self.scheduler.as_ref(),
            self.clock.as_ref(),
            self.lease_ids.as_ref(),
            self.config,
        )
        .poll(authenticated, request)
        .await
    }
}

/// Fresh control identity source.
pub trait ControlIdGenerator: fmt::Debug + Send + Sync {
    /// Returns a fresh server operation ID.
    fn next_operation_id(&self) -> OperationId;
    /// Returns a fresh durable session ID.
    fn next_session_id(&self) -> RunnerSessionId;
}

/// Random RFC 9562 version-4 control identities.
#[derive(Clone, Copy, Debug, Default)]
pub struct RandomControlIdGenerator;

impl ControlIdGenerator for RandomControlIdGenerator {
    fn next_operation_id(&self) -> OperationId {
        OperationId::new()
    }
    fn next_session_id(&self) -> RunnerSessionId {
        RunnerSessionId::new()
    }
}

fn store_port_error(error: &automata_store::StoreError) -> ControlPortError {
    match error {
        automata_store::StoreError::Operation(_) => ControlPortError::Unavailable,
        automata_store::StoreError::OperationConflict { .. }
        | automata_store::StoreError::AttemptFenceRejected(_)
        | automata_store::StoreError::CommandCursorAhead { .. }
        | automata_store::StoreError::ImmutableConflict(_)
        | automata_store::StoreError::RunnerNotFound(_)
        | automata_store::StoreError::RunnerDisabled(_)
        | automata_store::StoreError::RunnerNotAcceptingWork(_)
        | automata_store::StoreError::RunnerGenerationMismatch { .. }
        | automata_store::StoreError::SessionNotFound(_)
        | automata_store::StoreError::SessionClosed(_)
        | automata_store::StoreError::SessionFenceRejected(_) => ControlPortError::Conflict,
        _ => ControlPortError::Corrupt,
    }
}

fn lease_offer_port_error(error: &automata_store::StoreError) -> ControlPortError {
    if matches!(error, automata_store::StoreError::RunnerNotAcceptingWork(_)) {
        ControlPortError::Unavailable
    } else {
        store_port_error(error)
    }
}
