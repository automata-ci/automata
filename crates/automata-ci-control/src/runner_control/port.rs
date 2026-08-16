use std::{collections::BTreeMap, fmt, sync::Arc};

use crate::cancellation::{
    CANCEL_JOB_COMMAND_KIND, CANCEL_JOB_COMMAND_SCHEMA, CancelJobCommandPayload,
};
use crate::lease::{
    AuthenticatedRunnerSession, LeaseClock, LeaseIdGenerator, LeasePollConfig, LeasePollError,
    LeasePollObserver, LeasePollOutcome, LeasePollRepository, LeasePollService,
    NoopLeasePollObserver, RunnableAttemptGate,
};
use crate::scheduling::SchedulerPolicy;
use async_trait::async_trait;
use automata_ci_auth::machine::{AuthenticatedMachine, ExternalRunnerIdentity};
use automata_ci_blob::{
    BlobDescriptor, BlobKey, BlobStoreErrorKind, ImmutableBlobStore, MediaType,
};
use automata_ci_core::{
    EnvironmentProfile, JobIrEnvelope, JobIrVersion, Lease, OperationId, RunnerId, RunnerSessionId,
    Sha256Digest, UnixMillis, WindowsHyperVBrokerGrant, WindowsHyperVBrokerGrantClaims,
    windows_action_archive_policy_sha256,
};
use automata_ci_protocol::{
    CancelJob, CommandSequence, JobRuntimeAuthorities, LeaseOffer, LeaseRequest,
    MAX_CONFIGURABLE_FRAME_BYTES, ManagedSecretBindingOverlay, ProtocolLimits, ProtocolVersion,
    RunnerSlotOrdinal, ServerCommandHeader, ServerToRunner, VerifiedWindowsRunnerPlacementRenewal,
    WindowsRunnerPlacementRenewalEnvelope,
};
use automata_ci_protocol_protobuf::encode_job_ir;
use automata_ci_store::{
    CommandSequence as StoreCommandSequence, DocumentSchema, DurableRunnerCommand,
    EnqueueRunnerCommand, JobIrMetadata,
    LeaseOfferCommandIdentity as StoreLeaseOfferCommandIdentity, RunnerCommandPayload,
    RunnerGeneration, RunnerOperationKind, RunnerOperationRequest, RunnerProtocolVersion,
    RunnerSessionFence, StableRunnerSlot,
};
use ring::signature::{Ed25519KeyPair, KeyPair as _};
use sha2::{Digest as _, Sha256};
use thiserror::Error;
use zeroize::Zeroizing;

use super::durable::{
    AcceptedRuntimeAuthorityOffer, CommitRuntimeAuthorityDelivery, CurrentRunnerSession,
    CurrentRunnerSessionRepository, LeaseOfferClaim as StoreLeaseOfferClaim,
    LeaseOfferClaimStatus as StoreLeaseOfferClaimStatus, PublishLeaseOffer, PublishedLeaseOffer,
    RunnerLeaseOfferRepository, RuntimeAuthorityDeliveryAdmission,
    RuntimeAuthorityDeliveryDisposition,
};

/// Immutable media type used for standalone protobuf `JobIR` objects.
pub const JOB_IR_PROTOBUF_MEDIA_TYPE: &str = "application/vnd.automata.job-ir.protobuf";

const LEASE_REQUEST_KIND: &str = "automata.runner.lease-request.v1";
const LEASE_OFFER_COMMAND_KIND: &str = "automata.runner.lease-offer.v4";
const LEASE_OFFER_COMMAND_SCHEMA: u16 = 4;
const LEGACY_LEASE_OFFER_COMMAND_KIND: &str = "automata.runner.lease-offer.v2";
const LEGACY_LEASE_OFFER_COMMAND_SCHEMA: u16 = 2;

#[derive(serde::Serialize)]
struct LeaseOfferCommandPayloadRef<'a> {
    job: &'a JobIrEnvelope,
    lease: &'a Lease,
    managed_secret_bindings: &'a ManagedSecretBindingOverlay,
    windows_hyperv_placement: &'a Option<WindowsHyperVPlacementEvidence>,
    protocol_version: u16,
    schema: u16,
    slot: u16,
}

#[derive(serde::Serialize)]
struct LegacyLeaseOfferCommandPayloadRef<'a> {
    job: &'a JobIrEnvelope,
    lease: &'a Lease,
    managed_secret_bindings: &'a ManagedSecretBindingOverlay,
    protocol_version: u16,
    schema: u16,
    slot: u16,
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct DurableLeaseOfferCommandPayload {
    job: JobIrEnvelope,
    lease: Lease,
    managed_secret_bindings: ManagedSecretBindingOverlay,
    windows_hyperv_placement: Option<WindowsHyperVPlacementEvidence>,
    protocol_version: u16,
    schema: u16,
    slot: u16,
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct LegacyDurableLeaseOfferCommandPayload {
    job: JobIrEnvelope,
    lease: Lease,
    managed_secret_bindings: ManagedSecretBindingOverlay,
    protocol_version: u16,
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
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RuntimeAuthorityIssueRequest<'a> {
    job: &'a JobIrEnvelope,
    job_ir_metadata: &'a JobIrMetadata,
    lease: &'a Lease,
    issued_at: UnixMillis,
    session: RunnerSessionFence,
    slot: StableRunnerSlot,
}

impl<'a> RuntimeAuthorityIssueRequest<'a> {
    /// Binds issuance to verified current `JobIR` and an exact claimed runner lease.
    ///
    /// # Errors
    ///
    /// Rejects invalid or non-current `JobIR`, mismatched immutable metadata,
    /// an invalid lease, a different session runner, nil execution identities,
    /// or an issuance anchor other than the lease's durable issuance time.
    pub fn new(
        job: &'a JobIrEnvelope,
        job_ir_metadata: &'a JobIrMetadata,
        lease: &'a Lease,
        issued_at: UnixMillis,
        session: RunnerSessionFence,
        slot: StableRunnerSlot,
    ) -> Result<Self, RuntimeAuthorityIssueRequestError> {
        if job.version() != JobIrVersion::current()
            || job_ir_metadata.version() != JobIrVersion::current()
        {
            return Err(RuntimeAuthorityIssueRequestError::UnsupportedJobIr);
        }
        job.validate()
            .map_err(|_| RuntimeAuthorityIssueRequestError::InvalidJobIr)?;
        if job.job().trust_snapshot().is_construction_placeholder() {
            return Err(RuntimeAuthorityIssueRequestError::InvalidJobIr);
        }
        lease
            .validate()
            .map_err(|_| RuntimeAuthorityIssueRequestError::InvalidLease)?;
        let limits =
            durable_job_ir_limits().ok_or(RuntimeAuthorityIssueRequestError::InvalidJobIr)?;
        let encoded_job = encode_job_ir(job, &limits)
            .map_err(|_| RuntimeAuthorityIssueRequestError::InvalidJobIr)?;
        let encoded_size = u64::try_from(encoded_job.len())
            .map_err(|_| RuntimeAuthorityIssueRequestError::JobIrMetadataMismatch)?;
        if job_ir_metadata.job_id() != job.job().job_id()
            || job_ir_metadata.run_id() != job.job().run_id()
            || job_ir_metadata.version() != job.version()
            || job_ir_metadata.encoded_size() != encoded_size
            || job_ir_metadata.digest()
                != Sha256Digest::from_bytes(Sha256::digest(encoded_job).into())
        {
            return Err(RuntimeAuthorityIssueRequestError::JobIrMetadataMismatch);
        }
        if lease.runner_id() != session.runner_id() {
            return Err(RuntimeAuthorityIssueRequestError::LeaseRunnerMismatch);
        }
        if issued_at != lease.issued_at() || issued_at.get() < 0 || lease.expires_at().get() < 0 {
            return Err(RuntimeAuthorityIssueRequestError::InvalidIssuanceAnchor);
        }
        if [
            job.workflow_id().as_uuid(),
            job.job().job_id().as_uuid(),
            job.job().run_id().as_uuid(),
            lease.lease_id().as_uuid(),
            lease.attempt_id().as_uuid(),
            lease.runner_id().as_uuid(),
            session.session_id().as_uuid(),
        ]
        .into_iter()
        .any(|identity| identity.is_nil())
        {
            return Err(RuntimeAuthorityIssueRequestError::NilIdentity);
        }
        Ok(Self {
            job,
            job_ir_metadata,
            lease,
            issued_at,
            session,
            slot,
        })
    }

    /// Returns the verified semantic job.
    #[must_use]
    pub const fn job(self) -> &'a JobIrEnvelope {
        self.job
    }

    /// Returns immutable metadata for the exact verified `JobIR` object.
    #[must_use]
    pub const fn job_ir_metadata(self) -> &'a JobIrMetadata {
        self.job_ir_metadata
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

    /// Returns the exact authenticated runner session fence.
    #[must_use]
    pub const fn session(self) -> RunnerSessionFence {
        self.session
    }

    /// Returns the stable slot that claimed the lease.
    #[must_use]
    pub const fn slot(self) -> StableRunnerSlot {
        self.slot
    }
}

/// Invalid cross-binding at the runtime-authority issuance boundary.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum RuntimeAuthorityIssueRequestError {
    /// The job envelope or metadata is not the only schema supported by this build.
    #[error("runtime-authority issuance requires current JobIR")]
    UnsupportedJobIr,
    /// Current-version semantic job validation failed.
    #[error("runtime-authority issuance JobIR is invalid")]
    InvalidJobIr,
    /// Immutable metadata does not name the verified job and run.
    #[error("runtime-authority issuance JobIR metadata does not match the job")]
    JobIrMetadataMismatch,
    /// The exclusive lease is structurally invalid.
    #[error("runtime-authority issuance lease is invalid")]
    InvalidLease,
    /// The authenticated session and lease name different runners.
    #[error("runtime-authority issuance lease does not belong to the runner session")]
    LeaseRunnerMismatch,
    /// The trusted deterministic issuance anchor does not match the durable lease.
    #[error("runtime-authority issuance anchor is invalid")]
    InvalidIssuanceAnchor,
    /// An execution identity uses the nil sentinel.
    #[error("runtime-authority issuance identity is nil")]
    NilIdentity,
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

/// Issues value-free secret bindings after the exact attempt lease exists.
///
/// Implementations may persist grant identities and immutable selected-version
/// identities, but never plaintext values or delivery credentials. Repeated
/// issuance for identical request coordinates must return the same overlay.
#[async_trait]
pub trait ManagedSecretBindingIssuer: fmt::Debug + Send + Sync {
    /// Issues or replays the binding overlay for one exact leased attempt.
    async fn issue(
        &self,
        request: RuntimeAuthorityIssueRequest<'_>,
    ) -> Result<ManagedSecretBindingOverlay, ControlPortError>;
}

/// Server-side issuer for the value-free capability consumed by a restricted
/// Windows host broker.
pub trait WindowsHyperVBrokerGrantIssuer: fmt::Debug + Send + Sync {
    /// Builds the exact unsigned proposal for transactional durable admission.
    ///
    /// # Errors
    ///
    /// Returns a sanitized configuration or contract failure when the current
    /// admission, accepted offer, or durable `JobIR` do not bind exactly.
    fn propose(
        &self,
        request: &WindowsHyperVBrokerGrantIssueRequest<'_>,
    ) -> Result<WindowsHyperVBrokerGrantProposal, ControlPortError>;

    /// Signs only a proposal carrying a store-minted one-use authorization.
    ///
    /// # Errors
    ///
    /// Returns a sanitized configuration or signing failure when the runner
    /// has no exact host mapping or the placement cannot be signed.
    fn issue(
        &self,
        authorization: &WindowsHyperVBrokerGrantIssuanceAuthorization,
    ) -> Result<WindowsHyperVBrokerGrant, ControlPortError>;
}

/// Current server-verified Windows placement admission.
///
/// This is deliberately not the short-lived enrollment receipt. Implementations
/// return this value only while the latest broker-signed, independently
/// refreshed host/input/promotion evidence remains fresh and equal to the
/// durable revocation/serial high-water state. Mutable runner inventory or
/// configuration is not an authority source for this record.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WindowsHyperVCurrentAdmission {
    runner_id: RunnerId,
    broker_host_id: Sha256Digest,
    environment_profile: EnvironmentProfile,
    profile_contract_sha256: Sha256Digest,
    sealed_action_policy_sha256: Sha256Digest,
    windows_action_graph_sha256: Option<Sha256Digest>,
    sandbox_pids_limit: u32,
    placement_valid_until: UnixMillis,
}

impl WindowsHyperVCurrentAdmission {
    /// Constructs a current admission returned by a server-owned durable store.
    ///
    /// # Errors
    ///
    /// Rejects nil identities, zero digests/process limits, or an already
    /// expired record.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        runner_id: RunnerId,
        broker_host_id: Sha256Digest,
        environment_profile: EnvironmentProfile,
        profile_contract_sha256: Sha256Digest,
        sealed_action_policy_sha256: Sha256Digest,
        windows_action_graph_sha256: Option<Sha256Digest>,
        sandbox_pids_limit: u32,
        placement_valid_until: UnixMillis,
        observed_at: UnixMillis,
    ) -> Result<Self, ControlPortError> {
        if runner_id.as_uuid().is_nil()
            || [
                broker_host_id,
                environment_profile.digest(),
                profile_contract_sha256,
                sealed_action_policy_sha256,
            ]
            .iter()
            .any(|digest| digest.as_bytes().iter().all(|byte| *byte == 0))
            || windows_action_graph_sha256
                .as_ref()
                .is_some_and(|digest| digest.as_bytes().iter().all(|byte| *byte == 0))
            || sandbox_pids_limit == 0
            || sealed_action_policy_sha256 != windows_action_archive_policy_sha256()
            || placement_valid_until <= observed_at
        {
            return Err(ControlPortError::Corrupt);
        }
        Ok(Self {
            runner_id,
            broker_host_id,
            environment_profile,
            profile_contract_sha256,
            sealed_action_policy_sha256,
            windows_action_graph_sha256,
            sandbox_pids_limit,
            placement_valid_until,
        })
    }

    /// Returns the admitted runner.
    #[must_use]
    pub const fn runner_id(&self) -> RunnerId {
        self.runner_id
    }

    /// Returns the exact broker host bound by the signed enrollment receipt.
    #[must_use]
    pub const fn broker_host_id(&self) -> Sha256Digest {
        self.broker_host_id
    }

    /// Returns the exact admitted environment profile.
    #[must_use]
    pub const fn environment_profile(&self) -> &EnvironmentProfile {
        &self.environment_profile
    }

    /// Returns the broker-minted durable launch contract identity.
    #[must_use]
    pub const fn profile_contract_sha256(&self) -> Sha256Digest {
        self.profile_contract_sha256
    }

    /// Returns the current sealed-action namespace policy admitted by the broker.
    #[must_use]
    pub const fn sealed_action_policy_sha256(&self) -> Sha256Digest {
        self.sealed_action_policy_sha256
    }

    /// Returns the exact durable action graph admitted for the current job.
    #[must_use]
    pub const fn windows_action_graph_sha256(&self) -> Option<Sha256Digest> {
        self.windows_action_graph_sha256
    }

    /// Returns the broker-admitted hard process ceiling.
    #[must_use]
    pub const fn sandbox_pids_limit(&self) -> u32 {
        self.sandbox_pids_limit
    }

    /// Returns the exclusive placement-admission freshness horizon.
    ///
    /// This horizon is bounded by the latest broker host/input observation and
    /// signed image-promotion expiry. It must never be populated from the
    /// one-time enrollment receipt expiry.
    #[must_use]
    pub const fn placement_valid_until(&self) -> UnixMillis {
        self.placement_valid_until
    }
}

/// Reads the current signed Windows placement admission from durable state.
///
/// Implementations atomically choose the latest broker-signed renewal, require
/// its promotion serial and revocation generation to equal current server
/// high-water marks, sample database time only after locking the exact session,
/// require that time before the independently attested placement horizon, and
/// return `None` after expiry or revocation. The immutable enrollment receipt
/// is not a renewable placement record.
#[async_trait]
pub trait WindowsHyperVCurrentAdmissionReader: fmt::Debug + Send + Sync {
    /// Resolves the sole Windows placement authority for an exact runner/profile.
    async fn current(
        &self,
        session: RunnerSessionFence,
        environment_profile: &EnvironmentProfile,
    ) -> Result<Option<WindowsHyperVCurrentAdmission>, ControlPortError>;
}

/// Exact authenticated-session request to advance a Windows placement head.
///
/// Signature verification performed by the handler is deliberately only a
/// fail-fast check. The durable implementation must verify the raw envelope
/// again with its own configured trust store after locking renewal head,
/// promotion/revocation high-water, runner, and the exact session fence. It
/// samples database time only after those locks.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CommitWindowsHyperVPlacementRenewal {
    session: RunnerSessionFence,
    envelope: WindowsRunnerPlacementRenewalEnvelope,
    verified: VerifiedWindowsRunnerPlacementRenewal,
}

impl CommitWindowsHyperVPlacementRenewal {
    /// Constructs one structurally and cryptographically fail-fast-verified
    /// renewal for an exact authenticated session.
    ///
    /// # Errors
    ///
    /// Rejects runner, envelope-digest, or network-policy substitution.
    pub fn new(
        session: RunnerSessionFence,
        envelope: WindowsRunnerPlacementRenewalEnvelope,
        verified: VerifiedWindowsRunnerPlacementRenewal,
    ) -> Result<Self, ControlPortError> {
        let claims = verified.claims();
        if claims.runner_id() != session.runner_id()
            || claims.binding().transaction().runner_id() != session.runner_id()
            || !claims.binding().broker_profile().network_disabled()
            || verified.envelope_sha256() != envelope.envelope_sha256()
        {
            return Err(ControlPortError::Corrupt);
        }
        Ok(Self {
            session,
            envelope,
            verified,
        })
    }

    /// Returns the exact authenticated runner-session fence.
    #[must_use]
    pub const fn session(&self) -> RunnerSessionFence {
        self.session
    }

    /// Returns the complete untrusted wire envelope for independent durable
    /// verification and byte-exact replay comparison.
    #[must_use]
    pub const fn envelope(&self) -> &WindowsRunnerPlacementRenewalEnvelope {
        &self.envelope
    }

    /// Returns the handler's fail-fast verification result.
    #[must_use]
    pub const fn fail_fast_verified(&self) -> &VerifiedWindowsRunnerPlacementRenewal {
        &self.verified
    }
}

/// Whether an exact placement renewal advanced the durable head or replayed it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WindowsHyperVPlacementRenewalDisposition {
    /// The exact next serial was appended and made current.
    Committed,
    /// The same runner, serial, envelope, and nonce were already current.
    Replayed,
}

/// Atomic durable Windows placement-renewal boundary.
///
/// A new envelope is valid only at exactly `current_serial + 1`. Repeating the
/// same runner/serial/envelope/nonce is idempotent; a lower serial, a gap, or an
/// equal serial with different bytes is a conflict. The implementation must
/// append the verified renewal and advance its current pointer in one
/// transaction. The signed exclusive placement horizon is at most fifteen
/// minutes and never exceeds promotion expiry.
#[async_trait]
pub trait WindowsHyperVPlacementRenewalRepository: fmt::Debug + Send + Sync {
    /// Independently verifies and atomically commits one renewal.
    async fn commit(
        &self,
        request: CommitWindowsHyperVPlacementRenewal,
    ) -> Result<WindowsHyperVPlacementRenewalDisposition, ControlPortError>;
}

/// Exact accepted-offer evidence passed to the server-owned broker signer.
pub struct WindowsHyperVBrokerGrantIssueRequest<'a> {
    placement: &'a WindowsHyperVPlacementEvidence,
    admission: &'a WindowsHyperVCurrentAdmission,
    offer: &'a AcceptedRuntimeAuthorityOffer,
    job: &'a JobIrEnvelope,
    post_accept_request: &'a RunnerOperationRequest,
}

impl fmt::Debug for WindowsHyperVBrokerGrantIssueRequest<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("WindowsHyperVBrokerGrantIssueRequest")
            .field(
                "placement_binding_digest",
                &self.placement.placement_binding_digest(),
            )
            .field(
                "profile_contract_sha256",
                &self.admission.profile_contract_sha256(),
            )
            .field("offer_operation_id", &self.offer.command().operation_id())
            .field(
                "post_accept_operation_id",
                &self.post_accept_request.operation_id(),
            )
            .finish_non_exhaustive()
    }
}

impl<'a> WindowsHyperVBrokerGrantIssueRequest<'a> {
    /// Constructs issuance input only after the durable store authorized the
    /// post-accept delivery for this exact offer.
    ///
    /// # Errors
    ///
    /// Rejects any session, lease, `JobIR`, environment, or request mismatch.
    pub fn new(
        placement: &'a WindowsHyperVPlacementEvidence,
        admission: &'a WindowsHyperVCurrentAdmission,
        offer: &'a AcceptedRuntimeAuthorityOffer,
        job: &'a JobIrEnvelope,
        post_accept_request: &'a RunnerOperationRequest,
    ) -> Result<Self, ControlPortError> {
        if post_accept_request.session() != offer.request().session()
            || post_accept_request.kind().as_str() != "automata.runner.runtime-authority-request.v2"
            || job.version() != offer.job_ir().version()
            || job.job().job_id() != offer.job_ir().job_id()
            || job.job().run_id() != offer.job_ir().run_id()
            || job.job().requirements().resource_allocation().is_none()
            || job.job().requirements().environment_profile()
                != Some(placement.environment_profile())
            || admission.runner_id() != offer.lease().runner_id()
            || admission.environment_profile() != placement.environment_profile()
            || admission.placement_valid_until() < offer.lease().expires_at()
            || admission.windows_action_graph_sha256()
                != job
                    .execution()
                    .windows_action_graph()
                    .map(automata_ci_core::WindowsRepositoryActionGraph::graph_sha256)
            || job.execution().windows_action_graph().is_some_and(|graph| {
                graph.policy_sha256() != admission.sealed_action_policy_sha256()
            })
        {
            return Err(ControlPortError::Corrupt);
        }
        Ok(Self {
            placement,
            admission,
            offer,
            job,
            post_accept_request,
        })
    }

    /// Returns the server-retained placement evidence.
    #[must_use]
    pub const fn placement(&self) -> &WindowsHyperVPlacementEvidence {
        self.placement
    }

    /// Returns the current durable signed runner admission.
    #[must_use]
    pub const fn admission(&self) -> &WindowsHyperVCurrentAdmission {
        self.admission
    }

    /// Returns the exact accepted durable offer.
    #[must_use]
    pub const fn offer(&self) -> &AcceptedRuntimeAuthorityOffer {
        self.offer
    }

    /// Returns the verified immutable `JobIR`.
    #[must_use]
    pub const fn job(&self) -> &JobIrEnvelope {
        self.job
    }

    /// Returns the post-accept request admitted by durable state.
    #[must_use]
    pub const fn post_accept_request(&self) -> &RunnerOperationRequest {
        self.post_accept_request
    }

    fn proposal(
        &self,
        key_id: Sha256Digest,
        host_id: Sha256Digest,
    ) -> Result<WindowsHyperVBrokerGrantProposal, ControlPortError> {
        let offer = self.offer();
        let lease = offer.lease();
        let session = offer.request().session();
        let metadata = offer.job_ir();
        let object_key_digest = {
            let mut digest = Sha256::new();
            digest.update(b"automata.windows-hyperv-job-ir-object-key.v1\0");
            digest.update(metadata.object_key().as_str().as_bytes());
            Sha256Digest::from_bytes(digest.finalize().into())
        };
        let resource_allocation = self
            .job()
            .job()
            .requirements()
            .resource_allocation()
            .ok_or(ControlPortError::Corrupt)?;
        let claims = WindowsHyperVBrokerGrantClaims::new(
            host_id,
            self.placement().placement_binding_digest(),
            lease.attempt_id(),
            metadata.job_id(),
            metadata.run_id(),
            offer.request().operation_id(),
            offer.command().operation_id(),
            offer.command().sequence().get(),
            self.post_accept_request().operation_id(),
            self.post_accept_request().request_digest(),
            session.runner_id(),
            session.session_id(),
            session.runner_generation().get(),
            session.session_epoch().get(),
            offer.slot().ordinal(),
            lease.lease_id(),
            lease.fencing_token(),
            metadata.version(),
            metadata.encoded_size(),
            metadata.digest(),
            object_key_digest,
            resource_allocation,
            self.admission().sandbox_pids_limit(),
            self.placement().trust_binding_digest(),
            self.placement().environment_profile().clone(),
            self.admission().profile_contract_sha256(),
            self.admission().sealed_action_policy_sha256(),
            self.admission().windows_action_graph_sha256(),
            lease.issued_at(),
            lease.expires_at(),
        )
        .map_err(|_| ControlPortError::Corrupt)?;
        Ok(WindowsHyperVBrokerGrantProposal::new(key_id, claims))
    }
}

/// Exact unsigned Windows broker grant proposed for transactional admission.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WindowsHyperVBrokerGrantProposal {
    key_id: Sha256Digest,
    claims: WindowsHyperVBrokerGrantClaims,
    signing_payload_sha256: Sha256Digest,
}

impl WindowsHyperVBrokerGrantProposal {
    fn new(key_id: Sha256Digest, claims: WindowsHyperVBrokerGrantClaims) -> Self {
        let payload = WindowsHyperVBrokerGrant::signing_bytes_for(key_id, &claims);
        let signing_payload_sha256 = Sha256Digest::from_bytes(Sha256::digest(payload).into());
        Self {
            key_id,
            claims,
            signing_payload_sha256,
        }
    }

    /// Returns the exact signing-key identity.
    #[must_use]
    pub const fn key_id(&self) -> Sha256Digest {
        self.key_id
    }

    /// Returns every proposed value-free grant claim.
    #[must_use]
    pub const fn claims(&self) -> &WindowsHyperVBrokerGrantClaims {
        &self.claims
    }

    /// Returns the commitment reserved by the transactional store.
    #[must_use]
    pub const fn signing_payload_sha256(&self) -> Sha256Digest {
        self.signing_payload_sha256
    }
}

/// Store request which must revalidate a current renewal, exact session, and
/// accepted offer under one lock order before grant signing can occur.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthorizeWindowsHyperVBrokerGrant {
    delivery: RuntimeAuthorityDeliveryAdmission,
    admission: WindowsHyperVCurrentAdmission,
    proposal: WindowsHyperVBrokerGrantProposal,
}

impl AuthorizeWindowsHyperVBrokerGrant {
    /// Binds a proposal to the exact durable post-accept delivery admission.
    ///
    /// # Errors
    ///
    /// Rejects session, offer, runner, or post-accept request substitution.
    pub fn new(
        delivery: RuntimeAuthorityDeliveryAdmission,
        admission: WindowsHyperVCurrentAdmission,
        proposal: WindowsHyperVBrokerGrantProposal,
    ) -> Result<Self, ControlPortError> {
        let offer = delivery.offer();
        let claims = proposal.claims();
        if claims.runner_id() != offer.lease().runner_id()
            || claims.runner_session_id() != offer.request().session().session_id()
            || claims.runner_generation() != offer.request().session().runner_generation().get()
            || claims.session_epoch() != offer.request().session().session_epoch().get()
            || claims.accepted_offer_operation_id() != offer.command().operation_id()
            || claims.post_accept_operation_id() != delivery.request().request().operation_id()
            || claims.post_accept_request_digest() != delivery.request().request().request_digest()
            || claims.runner_id() != admission.runner_id()
            || claims.host_id() != admission.broker_host_id()
            || claims.environment_profile() != admission.environment_profile()
            || claims.profile_contract_sha256() != admission.profile_contract_sha256()
            || claims.sealed_action_policy_sha256() != admission.sealed_action_policy_sha256()
            || claims.windows_action_graph_sha256() != admission.windows_action_graph_sha256()
            || claims.sandbox_pids_limit() != admission.sandbox_pids_limit()
            || claims.expires_at() > admission.placement_valid_until()
        {
            return Err(ControlPortError::Corrupt);
        }
        Ok(Self {
            delivery,
            admission,
            proposal,
        })
    }

    /// Returns the exact accepted runtime-authority delivery.
    #[must_use]
    pub const fn delivery(&self) -> &RuntimeAuthorityDeliveryAdmission {
        &self.delivery
    }

    /// Returns the server-owned current admission revalidated transactionally.
    #[must_use]
    pub const fn admission(&self) -> &WindowsHyperVCurrentAdmission {
        &self.admission
    }

    /// Returns the exact unsigned grant payload.
    #[must_use]
    pub const fn proposal(&self) -> &WindowsHyperVBrokerGrantProposal {
        &self.proposal
    }
}

/// One-use grant reservation minted only by the transactional durable port.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WindowsHyperVBrokerGrantIssuanceAuthorization {
    request: AuthorizeWindowsHyperVBrokerGrant,
    reservation_nonce: Sha256Digest,
    authorized_at: UnixMillis,
    valid_until: UnixMillis,
}

impl WindowsHyperVBrokerGrantIssuanceAuthorization {
    /// Constructs a durable reservation after the store completed all locks
    /// and sampled its own clock.
    ///
    /// # Errors
    ///
    /// Rejects placeholder or out-of-horizon reservations.
    pub fn new(
        request: AuthorizeWindowsHyperVBrokerGrant,
        reservation_nonce: Sha256Digest,
        authorized_at: UnixMillis,
        valid_until: UnixMillis,
    ) -> Result<Self, ControlPortError> {
        let claims = request.proposal().claims();
        if reservation_nonce.as_bytes().iter().all(|byte| *byte == 0)
            || authorized_at < claims.issued_at()
            || authorized_at >= valid_until
            || valid_until > claims.expires_at()
            || valid_until > request.delivery().offer().offer_valid_until()
            || valid_until > request.admission().placement_valid_until()
        {
            return Err(ControlPortError::Corrupt);
        }
        Ok(Self {
            request,
            reservation_nonce,
            authorized_at,
            valid_until,
        })
    }

    /// Returns the exact durable reservation request.
    #[must_use]
    pub const fn request(&self) -> &AuthorizeWindowsHyperVBrokerGrant {
        &self.request
    }

    /// Returns the one-use durable reservation identity.
    #[must_use]
    pub const fn reservation_nonce(&self) -> Sha256Digest {
        self.reservation_nonce
    }

    /// Returns the database time sampled after all authorization locks.
    #[must_use]
    pub const fn authorized_at(&self) -> UnixMillis {
        self.authorized_at
    }

    /// Returns the exclusive reservation horizon.
    #[must_use]
    pub const fn valid_until(&self) -> UnixMillis {
        self.valid_until
    }
}

/// Exact atomic commit consuming a Windows grant reservation together with its
/// metadata-only runtime-authority delivery.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CommitWindowsHyperVBrokerGrantDelivery {
    authorization: WindowsHyperVBrokerGrantIssuanceAuthorization,
    delivery: CommitRuntimeAuthorityDelivery,
    grant_digest: Sha256Digest,
}

impl CommitWindowsHyperVBrokerGrantDelivery {
    /// Binds the signed grant and normal delivery commit to one reservation.
    ///
    /// # Errors
    ///
    /// Rejects a delivery, proposal, key, claims, digest, or horizon mismatch.
    pub fn new(
        authorization: WindowsHyperVBrokerGrantIssuanceAuthorization,
        delivery: CommitRuntimeAuthorityDelivery,
        grant: &WindowsHyperVBrokerGrant,
    ) -> Result<Self, ControlPortError> {
        if delivery.admission() != authorization.request().delivery()
            || grant.key_id() != authorization.request().proposal().key_id()
            || grant.claims() != authorization.request().proposal().claims()
            || delivery.committed_at() < authorization.authorized_at()
            || delivery.committed_at() >= authorization.valid_until()
        {
            return Err(ControlPortError::Corrupt);
        }
        Ok(Self {
            authorization,
            delivery,
            grant_digest: grant.digest(),
        })
    }

    /// Returns the exact one-use reservation to consume.
    #[must_use]
    pub const fn authorization(&self) -> &WindowsHyperVBrokerGrantIssuanceAuthorization {
        &self.authorization
    }

    /// Returns the metadata-only runtime-authority delivery commit.
    #[must_use]
    pub const fn delivery(&self) -> &CommitRuntimeAuthorityDelivery {
        &self.delivery
    }

    /// Returns the digest of the exact signed grant delivered to the runner.
    #[must_use]
    pub const fn grant_digest(&self) -> Sha256Digest {
        self.grant_digest
    }
}

/// Transactional store boundary for post-accept Windows grant delivery.
///
/// `authorize` locks renewal head, promotion/revocation high-water, runner,
/// exact session, and accepted offer in that order, samples database time, and
/// atomically persists a one-use reservation for the exact proposal. Any head,
/// high-water, or session transition must serialize against live reservations.
/// `commit` atomically consumes that reservation while committing the normal
/// runtime-authority delivery digest. A detached current read is never grant
/// authority.
#[async_trait]
pub trait WindowsHyperVBrokerGrantAuthorizationRepository: fmt::Debug + Send + Sync {
    /// Reserves one exact unsigned grant after all current-state checks.
    async fn authorize(
        &self,
        request: AuthorizeWindowsHyperVBrokerGrant,
    ) -> Result<WindowsHyperVBrokerGrantIssuanceAuthorization, ControlPortError>;

    /// Atomically consumes the exact reservation and commits delivery.
    async fn commit(
        &self,
        request: CommitWindowsHyperVBrokerGrantDelivery,
    ) -> Result<RuntimeAuthorityDeliveryDisposition, ControlPortError>;
}

/// Deterministic Ed25519 issuer backed by a server-owned signing seed and an
/// explicit runner-to-host registry.
pub struct Ed25519WindowsHyperVBrokerGrantIssuer {
    signing_seed: Zeroizing<[u8; 32]>,
    public_key: [u8; 32],
    key_id: Sha256Digest,
    hosts: BTreeMap<RunnerId, Sha256Digest>,
}

impl fmt::Debug for Ed25519WindowsHyperVBrokerGrantIssuer {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Ed25519WindowsHyperVBrokerGrantIssuer")
            .field("key_id", &self.key_id)
            .field("mapped_runners", &self.hosts.len())
            .finish_non_exhaustive()
    }
}

impl Ed25519WindowsHyperVBrokerGrantIssuer {
    /// Creates an issuer from an exact 32-byte server secret and an explicit
    /// durable runner-to-broker-host mapping.
    ///
    /// # Errors
    ///
    /// Rejects an empty map, nil runner identity, zero host digest, or invalid
    /// Ed25519 seed.
    pub fn new(
        signing_seed: Zeroizing<[u8; 32]>,
        hosts: BTreeMap<RunnerId, Sha256Digest>,
    ) -> Result<Self, WindowsHyperVBrokerGrantIssuerError> {
        if hosts.is_empty() {
            return Err(WindowsHyperVBrokerGrantIssuerError::EmptyHostMap);
        }
        if hosts.iter().any(|(runner, host)| {
            runner.as_uuid().is_nil() || host.as_bytes().iter().all(|byte| *byte == 0)
        }) {
            return Err(WindowsHyperVBrokerGrantIssuerError::InvalidHostMap);
        }
        let key_pair = Ed25519KeyPair::from_seed_unchecked(signing_seed.as_ref())
            .map_err(|_| WindowsHyperVBrokerGrantIssuerError::InvalidSigningSeed)?;
        let public_key = key_pair
            .public_key()
            .as_ref()
            .try_into()
            .map_err(|_| WindowsHyperVBrokerGrantIssuerError::InvalidSigningSeed)?;
        let key_id = Sha256Digest::from_bytes(Sha256::digest(public_key).into());
        Ok(Self {
            signing_seed,
            public_key,
            key_id,
            hosts,
        })
    }

    /// Returns the public verification key installed on broker hosts.
    #[must_use]
    pub fn public_key(&self) -> &[u8] {
        &self.public_key
    }

    /// Returns the digest used to select this verification key.
    #[must_use]
    pub const fn key_id(&self) -> Sha256Digest {
        self.key_id
    }
}

impl WindowsHyperVBrokerGrantIssuer for Ed25519WindowsHyperVBrokerGrantIssuer {
    fn propose(
        &self,
        request: &WindowsHyperVBrokerGrantIssueRequest<'_>,
    ) -> Result<WindowsHyperVBrokerGrantProposal, ControlPortError> {
        let runner_id = request.offer().lease().runner_id();
        let host_id = self
            .hosts
            .get(&runner_id)
            .copied()
            .ok_or(ControlPortError::Corrupt)?;
        if request.admission().broker_host_id() != host_id {
            return Err(ControlPortError::Corrupt);
        }
        request.proposal(self.key_id, host_id)
    }

    fn issue(
        &self,
        authorization: &WindowsHyperVBrokerGrantIssuanceAuthorization,
    ) -> Result<WindowsHyperVBrokerGrant, ControlPortError> {
        let proposal = authorization.request().proposal();
        let claims = proposal.claims();
        let expected_host_id = self
            .hosts
            .get(&claims.runner_id())
            .copied()
            .ok_or(ControlPortError::Corrupt)?;
        if proposal.key_id() != self.key_id || claims.host_id() != expected_host_id {
            return Err(ControlPortError::Corrupt);
        }
        let key_pair = Ed25519KeyPair::from_seed_unchecked(self.signing_seed.as_ref())
            .map_err(|_| ControlPortError::Corrupt)?;
        let signing_bytes = WindowsHyperVBrokerGrant::signing_bytes_for(self.key_id, claims);
        if Sha256Digest::from_bytes(Sha256::digest(&signing_bytes).into())
            != proposal.signing_payload_sha256()
        {
            return Err(ControlPortError::Corrupt);
        }
        let signature = key_pair.sign(&signing_bytes);
        WindowsHyperVBrokerGrant::new(self.key_id, claims.clone(), signature.as_ref())
            .map_err(|_| ControlPortError::Corrupt)
    }
}

/// Invalid configuration of the Ed25519 Windows broker grant issuer.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum WindowsHyperVBrokerGrantIssuerError {
    /// No restricted host mapping was configured.
    #[error("Windows Hyper-V broker host map cannot be empty")]
    EmptyHostMap,
    /// A runner identity or host digest used a zero sentinel.
    #[error("Windows Hyper-V broker host map contains an invalid identity")]
    InvalidHostMap,
    /// The server signing seed could not initialize an Ed25519 key.
    #[error("Windows Hyper-V broker signing seed is invalid")]
    InvalidSigningSeed,
}

/// Optional server-side authority contribution for permission-gated features.
///
/// Returning `None` means the exact job is not entitled to this authority. It
/// is not an error and does not create a placeholder credential. A returned
/// bundle is still revalidated by [`CompositeRuntimeAuthorityIssuer`] against
/// the exact job and lease before it can enter the protected offer.
#[async_trait]
pub trait OptionalRuntimeAuthorityIssuer: fmt::Debug + Send + Sync {
    /// Optionally issues one or more authorities for the exact request.
    async fn issue_optional(
        &self,
        request: RuntimeAuthorityIssueRequest<'_>,
    ) -> Result<Option<JobRuntimeAuthorities>, ControlPortError>;
}

/// Deterministic union of independent job-runtime authority issuers.
///
/// Every child bundle is revalidated against the exact request before any
/// authority is accepted. The final bundle is sorted by authority name, so its
/// protected representation does not depend on composition order, and
/// duplicate adapter namespaces fail closed.
pub struct CompositeRuntimeAuthorityIssuer {
    issuers: Vec<Arc<dyn RuntimeAuthorityIssuer>>,
    optional_issuers: Vec<Arc<dyn OptionalRuntimeAuthorityIssuer>>,
}

impl CompositeRuntimeAuthorityIssuer {
    /// Composes one or more independent issuers.
    ///
    /// # Errors
    ///
    /// Rejects an empty composition or one exceeding the protocol authority
    /// bound.
    pub fn new(issuers: Vec<Arc<dyn RuntimeAuthorityIssuer>>) -> Result<Self, ControlPortError> {
        if issuers.is_empty() || issuers.len() > automata_ci_protocol::MAX_RUNTIME_AUTHORITIES {
            return Err(ControlPortError::Corrupt);
        }
        Ok(Self {
            issuers,
            optional_issuers: Vec::new(),
        })
    }

    /// Adds permission-gated issuers whose valid outcome may be no contribution.
    ///
    /// # Errors
    ///
    /// Rejects a combined issuer count beyond the protocol authority bound.
    /// The required issuer set remains non-empty, so the final protected bundle
    /// can never become empty merely because every optional issuer declined.
    pub fn with_optional_issuers(
        mut self,
        optional_issuers: Vec<Arc<dyn OptionalRuntimeAuthorityIssuer>>,
    ) -> Result<Self, ControlPortError> {
        if self
            .issuers
            .len()
            .checked_add(optional_issuers.len())
            .is_none_or(|count| count > automata_ci_protocol::MAX_RUNTIME_AUTHORITIES)
        {
            return Err(ControlPortError::Corrupt);
        }
        self.optional_issuers = optional_issuers;
        Ok(self)
    }
}

impl fmt::Debug for CompositeRuntimeAuthorityIssuer {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CompositeRuntimeAuthorityIssuer")
            .field("issuer_count", &self.issuers.len())
            .field("optional_issuer_count", &self.optional_issuers.len())
            .finish_non_exhaustive()
    }
}

#[async_trait]
impl RuntimeAuthorityIssuer for CompositeRuntimeAuthorityIssuer {
    async fn issue(
        &self,
        request: RuntimeAuthorityIssueRequest<'_>,
    ) -> Result<JobRuntimeAuthorities, ControlPortError> {
        let mut authorities = Vec::new();
        for issuer in &self.issuers {
            let bundle = issuer.issue(request).await?;
            bundle
                .validate_for(request.job(), request.lease())
                .map_err(|_| ControlPortError::Corrupt)?;
            authorities.extend(bundle.as_slice().iter().cloned());
            if authorities.len() > automata_ci_protocol::MAX_RUNTIME_AUTHORITIES {
                return Err(ControlPortError::Corrupt);
            }
        }
        for issuer in &self.optional_issuers {
            let Some(bundle) = issuer.issue_optional(request).await? else {
                continue;
            };
            bundle
                .validate_for(request.job(), request.lease())
                .map_err(|_| ControlPortError::Corrupt)?;
            authorities.extend(bundle.as_slice().iter().cloned());
            if authorities.len() > automata_ci_protocol::MAX_RUNTIME_AUTHORITIES {
                return Err(ControlPortError::Corrupt);
            }
        }
        authorities.sort_by(|left, right| left.name().cmp(right.name()));
        JobRuntimeAuthorities::new(authorities, request.job(), request.lease())
            .map_err(|_| ControlPortError::Corrupt)
    }
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
    lease: automata_ci_core::Lease,
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
        lease: automata_ci_core::Lease,
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
    pub const fn lease(&self) -> &automata_ci_core::Lease {
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

/// Value-free server-retained evidence needed to mint a broker capability
/// only after the exact offer has been durably accepted.
#[derive(Clone, Debug, serde::Deserialize, Eq, PartialEq, serde::Serialize)]
#[serde(deny_unknown_fields)]
pub struct WindowsHyperVPlacementEvidence {
    placement_binding_digest: Sha256Digest,
    trust_binding_digest: Sha256Digest,
    environment_profile: EnvironmentProfile,
}

impl WindowsHyperVPlacementEvidence {
    fn from_placement(placement: &crate::lease::WindowsHyperVPlacementGrant) -> Self {
        Self {
            placement_binding_digest: placement.binding_digest(),
            trust_binding_digest: placement.trust_binding_digest(),
            environment_profile: placement.environment_profile().clone(),
        }
    }

    /// Returns the digest of the original locked placement decision.
    #[must_use]
    pub const fn placement_binding_digest(&self) -> Sha256Digest {
        self.placement_binding_digest
    }

    /// Returns the authenticated trust/requirements binding.
    #[must_use]
    pub const fn trust_binding_digest(&self) -> Sha256Digest {
        self.trust_binding_digest
    }

    /// Returns the exact content-attested environment profile.
    #[must_use]
    pub const fn environment_profile(&self) -> &EnvironmentProfile {
        &self.environment_profile
    }

    fn is_valid_for(
        &self,
        job: &JobIrEnvelope,
        placement: &crate::lease::WindowsHyperVPlacementGrant,
    ) -> bool {
        self == &Self::from_placement(placement)
            && job.job().requirements().environment_profile() == Some(&self.environment_profile)
            && [self.placement_binding_digest, self.trust_binding_digest]
                .iter()
                .all(|digest| digest.as_bytes().iter().any(|byte| *byte != 0))
    }
}

/// Fully verified lease-offer body awaiting one durable command identity.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LeaseOfferCommand {
    claim: LeaseOfferClaim,
    job: JobIrEnvelope,
    managed_secret_bindings: ManagedSecretBindingOverlay,
    windows_hyperv_placement: Option<WindowsHyperVPlacementEvidence>,
    offer_valid_until: UnixMillis,
    created_at: UnixMillis,
}

/// Invalid input for one durable lease-offer command.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum LeaseOfferCommandError {
    /// The session and lease name different runners.
    #[error("lease-offer session and lease runners do not match")]
    LeaseRunnerMismatch,
    /// The `JobIR` cannot be encoded within durable protocol limits.
    #[error("lease-offer JobIR cannot be encoded")]
    InvalidJobIr,
    /// The encoded `JobIR` does not match the immutable object metadata.
    #[error("lease-offer JobIR metadata does not match its payload")]
    JobIrMetadataMismatch,
    /// Secret-binding metadata is not bound to the exact leased attempt.
    #[error("lease-offer managed-secret bindings are invalid")]
    InvalidManagedSecretBindings,
    /// The Windows broker capability does not match the exact claim and `JobIR`.
    #[error("lease-offer Windows Hyper-V broker grant is invalid")]
    InvalidWindowsHyperVBrokerGrant,
    /// The command was created outside the lease validity interval.
    #[error("lease-offer creation time is outside its validity interval")]
    InvalidCreationTime,
}

impl LeaseOfferCommand {
    /// Creates a command after validating every payload binding required by the
    /// durable store adapter.
    ///
    /// # Errors
    ///
    /// Rejects cross-runner leases, unencodable or metadata-mismatched `JobIR`,
    /// and command times outside the lease validity interval.
    pub fn try_new(
        claim: LeaseOfferClaim,
        job: JobIrEnvelope,
        created_at: UnixMillis,
    ) -> Result<Self, LeaseOfferCommandError> {
        if claim.session().runner_id() != claim.lease().runner_id() {
            return Err(LeaseOfferCommandError::LeaseRunnerMismatch);
        }
        validate_lease_offer_payload(
            &job,
            claim.lease(),
            &ManagedSecretBindingOverlay::empty(claim.lease()),
            claim.job_ir_metadata(),
        )?;
        if created_at < claim.lease().issued_at() || created_at >= claim.lease().expires_at() {
            return Err(LeaseOfferCommandError::InvalidCreationTime);
        }
        let offer_valid_until = claim.lease().expires_at();
        Ok(Self {
            managed_secret_bindings: ManagedSecretBindingOverlay::empty(claim.lease()),
            windows_hyperv_placement: None,
            claim,
            job,
            offer_valid_until,
            created_at,
        })
    }

    /// Retains value-free placement evidence for post-accept broker issuance.
    ///
    /// # Errors
    ///
    /// Rejects every cross-binding disagreement with the durable claim,
    /// verified `JobIR`, environment profile, session, slot, or lease fence.
    pub fn with_windows_hyperv_placement(
        mut self,
        placement: &crate::lease::WindowsHyperVPlacementGrant,
    ) -> Result<Self, LeaseOfferCommandError> {
        if placement.attempt_id() != self.claim.lease().attempt_id()
            || placement.lease_id() != self.claim.lease().lease_id()
            || placement.session() != self.claim.session()
            || placement.slot().ordinal() != self.claim.slot().get()
            || placement.job_ir() != self.claim.job_ir_metadata()
            || placement.issued_at() != self.claim.lease().issued_at()
            || placement.expires_at() != self.claim.lease().expires_at()
        {
            return Err(LeaseOfferCommandError::InvalidWindowsHyperVBrokerGrant);
        }
        let evidence = WindowsHyperVPlacementEvidence::from_placement(placement);
        if !evidence.is_valid_for(&self.job, placement) {
            return Err(LeaseOfferCommandError::InvalidWindowsHyperVBrokerGrant);
        }
        self.windows_hyperv_placement = Some(evidence);
        Ok(self)
    }

    /// Replaces the empty default with the exact lease-scoped binding overlay.
    ///
    /// # Errors
    ///
    /// Rejects an overlay bound to another attempt, lease, or fencing token.
    pub fn with_managed_secret_bindings(
        mut self,
        overlay: ManagedSecretBindingOverlay,
    ) -> Result<Self, LeaseOfferCommandError> {
        overlay
            .validate_for(self.claim.lease())
            .map_err(|_| LeaseOfferCommandError::InvalidManagedSecretBindings)?;
        self.managed_secret_bindings = overlay;
        Ok(self)
    }

    /// Returns the exact fenced session.
    #[must_use]
    pub const fn session(&self) -> RunnerSessionFence {
        self.claim.session()
    }
    /// Returns the runner poll operation being answered.
    #[must_use]
    pub const fn request_operation_id(&self) -> OperationId {
        self.claim.request_operation_id()
    }
    /// Returns the digest of canonical runner request bytes.
    #[must_use]
    pub const fn request_digest(&self) -> Sha256Digest {
        self.claim.request_digest()
    }
    /// Returns the negotiated protocol.
    #[must_use]
    pub const fn protocol_version(&self) -> ProtocolVersion {
        self.claim.protocol_version()
    }
    /// Returns the stable runner slot.
    #[must_use]
    pub const fn slot(&self) -> RunnerSlotOrdinal {
        self.claim.slot()
    }
    /// Returns the exclusive lease.
    #[must_use]
    pub const fn lease(&self) -> &automata_ci_core::Lease {
        self.claim.lease()
    }
    /// Returns the immutable storage metadata that was verified.
    #[must_use]
    pub const fn job_ir_metadata(&self) -> &JobIrMetadata {
        self.claim.job_ir_metadata()
    }
    /// Returns the validated `JobIR` envelope.
    #[must_use]
    pub const fn job(&self) -> &JobIrEnvelope {
        &self.job
    }
    /// Returns the value-free binding overlay committed to this command.
    #[must_use]
    pub const fn managed_secret_bindings(&self) -> &ManagedSecretBindingOverlay {
        &self.managed_secret_bindings
    }
    /// Returns server-retained evidence for post-accept broker issuance.
    #[must_use]
    pub const fn windows_hyperv_placement(&self) -> Option<&WindowsHyperVPlacementEvidence> {
        self.windows_hyperv_placement.as_ref()
    }
    /// Returns the exclusive minimum of the lease and runtime-authority expiries.
    #[must_use]
    pub const fn offer_valid_until(&self) -> UnixMillis {
        self.offer_valid_until
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
    replayed: bool,
}

impl PublishedCommand {
    /// Creates a published command identity.
    #[must_use]
    pub const fn new(operation_id: OperationId, sequence: CommandSequence, replayed: bool) -> Self {
        Self {
            operation_id,
            sequence,
            replayed,
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

    /// Reports whether the publication was loaded from an earlier commit.
    #[must_use]
    pub const fn was_replayed(self) -> bool {
        self.replayed
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

/// Atomic classification of one outbox command at typed offer authority resolution.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum LeaseOfferReplayResolution {
    /// No typed publication owns this command identity.
    NotPublished,
    /// A publication owns the command, but its attempt fence or authority horizon is no longer live.
    Revoked,
    /// The exact typed publication remains live and its authenticated command is safe to decode.
    Published(DurableRunnerCommand),
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
    ) -> Result<LeaseOfferReplayResolution, ControlPortError>;

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
    if command.session() != published.request().session() {
        return false;
    }
    match (command.kind().as_str(), command.payload().schema().get()) {
        (LEASE_OFFER_COMMAND_KIND, LEASE_OFFER_COMMAND_SCHEMA) => {
            let Ok(payload) = serde_json::from_slice::<DurableLeaseOfferCommandPayload>(
                command.payload().bytes(),
            ) else {
                return false;
            };
            let mut canonical = Zeroizing::new(Vec::new());
            if serde_json::to_writer(
                &mut *canonical,
                &LeaseOfferCommandPayloadRef {
                    job: &payload.job,
                    lease: &payload.lease,
                    managed_secret_bindings: &payload.managed_secret_bindings,
                    windows_hyperv_placement: &payload.windows_hyperv_placement,
                    protocol_version: payload.protocol_version,
                    schema: payload.schema,
                    slot: payload.slot,
                },
            )
            .is_err()
                || canonical.as_slice() != command.payload().bytes()
            {
                return false;
            }
            durable_payload_matches(
                published,
                &payload.job,
                &payload.lease,
                &payload.managed_secret_bindings,
                payload.windows_hyperv_placement.as_ref(),
                payload.protocol_version,
                payload.schema,
                LEASE_OFFER_COMMAND_SCHEMA,
                payload.slot,
            )
        }
        (LEGACY_LEASE_OFFER_COMMAND_KIND, LEGACY_LEASE_OFFER_COMMAND_SCHEMA) => {
            let Ok(payload) = serde_json::from_slice::<LegacyDurableLeaseOfferCommandPayload>(
                command.payload().bytes(),
            ) else {
                return false;
            };
            let mut canonical = Zeroizing::new(Vec::new());
            if serde_json::to_writer(
                &mut *canonical,
                &LegacyLeaseOfferCommandPayloadRef {
                    job: &payload.job,
                    lease: &payload.lease,
                    managed_secret_bindings: &payload.managed_secret_bindings,
                    protocol_version: payload.protocol_version,
                    schema: payload.schema,
                    slot: payload.slot,
                },
            )
            .is_err()
                || canonical.as_slice() != command.payload().bytes()
            {
                return false;
            }
            durable_payload_matches(
                published,
                &payload.job,
                &payload.lease,
                &payload.managed_secret_bindings,
                None,
                payload.protocol_version,
                payload.schema,
                LEGACY_LEASE_OFFER_COMMAND_SCHEMA,
                payload.slot,
            )
        }
        _ => false,
    }
}

#[allow(clippy::too_many_arguments)]
fn durable_payload_matches(
    published: &PublishedLeaseOffer,
    job: &JobIrEnvelope,
    lease: &Lease,
    managed_secret_bindings: &ManagedSecretBindingOverlay,
    windows_hyperv_placement: Option<&WindowsHyperVPlacementEvidence>,
    protocol_version: u16,
    schema: u16,
    expected_schema: u16,
    slot: u16,
) -> bool {
    if schema != expected_schema
        || protocol_version != published.protocol_version().get()
        || slot != published.slot().get()
        || lease != published.lease()
    {
        return false;
    }
    if validate_lease_offer_payload(job, lease, managed_secret_bindings, published.job_ir())
        .is_err()
    {
        return false;
    }
    if windows_hyperv_placement.is_some_and(|placement| {
        placement.environment_profile()
            != job
                .job()
                .requirements()
                .environment_profile()
                .unwrap_or_else(|| {
                    // A retained Windows placement is invalid for a job without
                    // an exact environment profile.
                    placement.environment_profile()
                })
            || job.job().requirements().environment_profile().is_none()
            || [
                placement.placement_binding_digest(),
                placement.trust_binding_digest(),
            ]
            .iter()
            .any(|digest| digest.as_bytes().iter().all(|byte| *byte == 0))
    }) {
        return false;
    }
    let created_at = published.command().request().created_at();
    created_at >= lease.issued_at()
        && created_at < lease.expires_at()
        && lease.expires_at() == published.offer_valid_until()
}

fn validate_lease_offer_payload(
    job: &JobIrEnvelope,
    lease: &Lease,
    managed_secret_bindings: &ManagedSecretBindingOverlay,
    metadata: &JobIrMetadata,
) -> Result<(), LeaseOfferCommandError> {
    let Some(limits) = durable_job_ir_limits() else {
        return Err(LeaseOfferCommandError::InvalidJobIr);
    };
    let encoded_job =
        encode_job_ir(job, &limits).map_err(|_| LeaseOfferCommandError::InvalidJobIr)?;
    let encoded_size = u64::try_from(encoded_job.len())
        .map_err(|_| LeaseOfferCommandError::JobIrMetadataMismatch)?;
    if job.version() != metadata.version()
        || job.job().job_id() != metadata.job_id()
        || job.job().run_id() != metadata.run_id()
        || encoded_size != metadata.encoded_size()
        || Sha256Digest::from_bytes(Sha256::digest(encoded_job).into()) != metadata.digest()
    {
        return Err(LeaseOfferCommandError::JobIrMetadataMismatch);
    }
    managed_secret_bindings
        .validate_for(lease)
        .map_err(|_| LeaseOfferCommandError::InvalidManagedSecretBindings)
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
    ) -> Result<LeaseOfferReplayResolution, ControlPortError> {
        let store_sequence =
            StoreCommandSequence::new(sequence.get()).map_err(|_| ControlPortError::Corrupt)?;
        let published = match self
            .repository
            .resolve_lease_offer_command(StoreLeaseOfferCommandIdentity::new(
                session,
                operation_id,
                store_sequence,
            ))
            .await
        {
            Ok(Some(published)) => published,
            Ok(None) => return Ok(LeaseOfferReplayResolution::NotPublished),
            Err(automata_ci_store::StoreError::AttemptFenceRejected(_)) => {
                return Ok(LeaseOfferReplayResolution::Revoked);
            }
            Err(error) => return Err(lease_offer_port_error(&error)),
        };
        if published.request().kind().as_str() != LEASE_REQUEST_KIND
            || published.command().request().session() != session
            || published.command().request().operation_id() != operation_id
            || published.command().sequence() != store_sequence
            || !durable_lease_offer_payload_matches(&published)
        {
            return Err(ControlPortError::Corrupt);
        }
        Ok(LeaseOfferReplayResolution::Published(
            published.command().clone(),
        ))
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
                managed_secret_bindings: command.managed_secret_bindings(),
                windows_hyperv_placement: &command.windows_hyperv_placement,
                protocol_version: command.protocol_version().get(),
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
            command.offer_valid_until(),
            durable_command,
        )
        .map_err(|_| ControlPortError::Corrupt)?;
        let published = match self.repository.publish_lease_offer(publication).await {
            Ok(published) => published,
            Err(automata_ci_store::StoreError::AttemptFenceRejected(attempt_id))
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
            published.was_replayed(),
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
        LEASE_OFFER_COMMAND_KIND | LEGACY_LEASE_OFFER_COMMAND_KIND => {
            let (
                job,
                lease,
                managed_secret_bindings,
                windows_hyperv_placement,
                payload_version,
                payload_schema,
                payload_slot,
            ) = if request.kind().as_str() == LEASE_OFFER_COMMAND_KIND {
                if request.payload().schema().get() != LEASE_OFFER_COMMAND_SCHEMA {
                    return Err(ControlPortError::Corrupt);
                }
                let payload: DurableLeaseOfferCommandPayload =
                    serde_json::from_slice(request.payload().bytes())
                        .map_err(|_| ControlPortError::Corrupt)?;
                (
                    payload.job,
                    payload.lease,
                    payload.managed_secret_bindings,
                    payload.windows_hyperv_placement,
                    payload.protocol_version,
                    payload.schema,
                    payload.slot,
                )
            } else {
                if request.payload().schema().get() != LEGACY_LEASE_OFFER_COMMAND_SCHEMA {
                    return Err(ControlPortError::Corrupt);
                }
                let payload: LegacyDurableLeaseOfferCommandPayload =
                    serde_json::from_slice(request.payload().bytes())
                        .map_err(|_| ControlPortError::Corrupt)?;
                (
                    payload.job,
                    payload.lease,
                    payload.managed_secret_bindings,
                    None,
                    payload.protocol_version,
                    payload.schema,
                    payload.slot,
                )
            };
            if payload_schema != request.payload().schema().get()
                || payload_version != protocol_version.get()
                || lease.runner_id() != request.session().runner_id()
                || managed_secret_bindings.validate_for(&lease).is_err()
            {
                return Err(ControlPortError::Corrupt);
            }
            let slot =
                RunnerSlotOrdinal::new(payload_slot).map_err(|_| ControlPortError::Corrupt)?;
            let offer = LeaseOffer::new(header, slot, lease, job)
                .with_managed_secret_bindings(managed_secret_bindings)
                .map_err(|_| ControlPortError::Corrupt)?;
            let _ = windows_hyperv_placement;
            ServerToRunner::LeaseOffer(Box::new(offer))
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

/// Loads the server-retained broker grant from an exact durable lease offer.
///
/// This value is deliberately omitted from [`LeaseOffer`] and becomes
/// runner-visible only through the accepted runtime-authority delivery path.
pub(crate) fn durable_windows_hyperv_placement(
    command: &DurableRunnerCommand,
) -> Result<Option<WindowsHyperVPlacementEvidence>, ControlPortError> {
    match command.request().kind().as_str() {
        LEASE_OFFER_COMMAND_KIND => {
            if command.request().payload().schema().get() != LEASE_OFFER_COMMAND_SCHEMA {
                return Err(ControlPortError::Corrupt);
            }
            let payload: DurableLeaseOfferCommandPayload =
                serde_json::from_slice(command.request().payload().bytes())
                    .map_err(|_| ControlPortError::Corrupt)?;
            Ok(payload.windows_hyperv_placement)
        }
        LEGACY_LEASE_OFFER_COMMAND_KIND => Ok(None),
        _ => Err(ControlPortError::Corrupt),
    }
}

/// Loads the exact value-free managed-secret overlay committed to a durable
/// lease offer. This is rechecked before any post-accept Windows authority is
/// minted so a substituted durable command cannot reach an issuer.
pub(crate) fn durable_managed_secret_bindings(
    command: &DurableRunnerCommand,
) -> Result<ManagedSecretBindingOverlay, ControlPortError> {
    match command.request().kind().as_str() {
        LEASE_OFFER_COMMAND_KIND => {
            if command.request().payload().schema().get() != LEASE_OFFER_COMMAND_SCHEMA {
                return Err(ControlPortError::Corrupt);
            }
            let payload: DurableLeaseOfferCommandPayload =
                serde_json::from_slice(command.request().payload().bytes())
                    .map_err(|_| ControlPortError::Corrupt)?;
            Ok(payload.managed_secret_bindings)
        }
        LEGACY_LEASE_OFFER_COMMAND_KIND => {
            if command.request().payload().schema().get() != LEGACY_LEASE_OFFER_COMMAND_SCHEMA {
                return Err(ControlPortError::Corrupt);
            }
            let payload: LegacyDurableLeaseOfferCommandPayload =
                serde_json::from_slice(command.request().payload().bytes())
                    .map_err(|_| ControlPortError::Corrupt)?;
            Ok(payload.managed_secret_bindings)
        }
        _ => Err(ControlPortError::Corrupt),
    }
}

pub(crate) fn is_durable_lease_offer_command(command: &DurableRunnerCommand) -> bool {
    matches!(
        command.request().kind().as_str(),
        LEASE_OFFER_COMMAND_KIND | LEGACY_LEASE_OFFER_COMMAND_KIND
    )
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
    attempt_gate: Option<Arc<dyn RunnableAttemptGate>>,
    observer: Arc<dyn LeasePollObserver>,
    config: LeasePollConfig,
}

impl fmt::Debug for LeasePollAdapter {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LeasePollAdapter")
            .field("config", &self.config)
            .field("attempt_gate", &self.attempt_gate)
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
            attempt_gate: None,
            observer: Arc::new(NoopLeasePollObserver),
            config,
        }
    }

    /// Installs a provider-neutral observer without changing scheduling semantics.
    #[must_use]
    pub fn with_observer(mut self, observer: Arc<dyn LeasePollObserver>) -> Self {
        self.observer = observer;
        self
    }

    /// Installs the value-free pre-scheduling attempt gate.
    #[must_use]
    pub fn with_attempt_gate(mut self, gate: Arc<dyn RunnableAttemptGate>) -> Self {
        self.attempt_gate = Some(gate);
        self
    }
}

#[async_trait]
impl LeasePoller for LeasePollAdapter {
    async fn poll(
        &self,
        authenticated: AuthenticatedRunnerSession,
        request: &LeaseRequest,
    ) -> Result<LeasePollOutcome, LeasePollError> {
        let service = LeasePollService::new(
            self.repository.as_ref(),
            self.scheduler.as_ref(),
            self.clock.as_ref(),
            self.lease_ids.as_ref(),
            self.config,
        )
        .with_observer(self.observer.as_ref());
        let service = match self.attempt_gate.as_deref() {
            Some(gate) => service.with_attempt_gate(gate),
            None => service,
        };
        service.poll(authenticated, request).await
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

fn store_port_error(error: &automata_ci_store::StoreError) -> ControlPortError {
    match error {
        automata_ci_store::StoreError::Operation(_) => ControlPortError::Unavailable,
        automata_ci_store::StoreError::OperationConflict { .. }
        | automata_ci_store::StoreError::AttemptFenceRejected(_)
        | automata_ci_store::StoreError::CommandCursorAhead { .. }
        | automata_ci_store::StoreError::ImmutableConflict(_)
        | automata_ci_store::StoreError::RunnerNotFound(_)
        | automata_ci_store::StoreError::RunnerDisabled(_)
        | automata_ci_store::StoreError::RunnerNotAcceptingWork(_)
        | automata_ci_store::StoreError::RunnerGenerationMismatch { .. }
        | automata_ci_store::StoreError::SessionNotFound(_)
        | automata_ci_store::StoreError::SessionClosed(_)
        | automata_ci_store::StoreError::SessionFenceRejected(_) => ControlPortError::Conflict,
        _ => ControlPortError::Corrupt,
    }
}

fn lease_offer_port_error(error: &automata_ci_store::StoreError) -> ControlPortError {
    if matches!(
        error,
        automata_ci_store::StoreError::RunnerNotAcceptingWork(_)
    ) {
        ControlPortError::Unavailable
    } else {
        store_port_error(error)
    }
}
