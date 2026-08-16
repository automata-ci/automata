//! Idempotent lease-poll operation values and durable claim outcomes.

use automata_ci_core::{
    Architecture, AttemptId, EnvironmentProfile, IsolationLevel, JobLifecycle, Lease, LeaseId,
    OperatingSystem, OperationId, SandboxFeature, TrustSourceClass, UnixMillis,
};
use automata_ci_store::{
    AttemptAssignment, AttemptAssignmentError, DocumentSchema, JobIrMetadata,
    LeaseOfferCommandIdentity, RunnerOperationResponse, RunnerSessionFence, Sha256Digest,
    StableRunnerSlot,
};
use sha2::{Digest as _, Sha256};
use thiserror::Error;

use super::runnable::{AuthenticatedPlacementTrust, RunnableAttempt, RunnableCursorAdvance};

const LEASE_REQUEST_DIGEST_DOMAIN: &[u8] = b"automata.store.lease-request.v2\0";
const WINDOWS_PLACEMENT_GRANT_DIGEST_DOMAIN: &[u8] =
    b"automata.control.windows-hyperv-placement-grant.v1\0";
const WINDOWS_PLACEMENT_TRUST_DIGEST_DOMAIN: &[u8] =
    b"automata.control.windows-hyperv-placement-trust.v1\0";

/// Canonical identity of one runner lease poll before scheduling selects work.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LeaseRequestKey {
    session: RunnerSessionFence,
    operation_id: OperationId,
    slot: StableRunnerSlot,
    acknowledges_operation_id: Option<OperationId>,
}

impl LeaseRequestKey {
    /// Creates the first request in one session-slot chain.
    #[must_use]
    pub const fn first(
        session: RunnerSessionFence,
        operation_id: OperationId,
        slot: StableRunnerSlot,
    ) -> Self {
        Self {
            session,
            operation_id,
            slot,
            acknowledges_operation_id: None,
        }
    }

    /// Creates a request which acknowledges the exact preceding head.
    ///
    /// # Errors
    ///
    /// Rejects a request which acknowledges its own operation identity.
    pub fn successor(
        session: RunnerSessionFence,
        operation_id: OperationId,
        slot: StableRunnerSlot,
        acknowledges_operation_id: OperationId,
    ) -> Result<Self, LeaseRequestKeyError> {
        if acknowledges_operation_id == operation_id {
            return Err(LeaseRequestKeyError::SelfAcknowledgement);
        }
        Ok(Self {
            session,
            operation_id,
            slot,
            acknowledges_operation_id: Some(acknowledges_operation_id),
        })
    }

    /// Returns the authenticated runner-session fence.
    #[must_use]
    pub const fn session(self) -> RunnerSessionFence {
        self.session
    }

    /// Returns this request's idempotency identity.
    #[must_use]
    pub const fn operation_id(self) -> OperationId {
        self.operation_id
    }

    /// Returns the stable runner slot being polled.
    #[must_use]
    pub const fn slot(self) -> StableRunnerSlot {
        self.slot
    }

    /// Returns the preceding operation acknowledged by this request, if any.
    #[must_use]
    pub const fn acknowledges_operation_id(self) -> Option<OperationId> {
        self.acknowledges_operation_id
    }

    /// Computes the canonical digest of the actual wire poll request. Server
    /// selections are deliberately excluded so a retry can be replayed before
    /// the scheduler reselects a now-non-runnable attempt.
    #[must_use]
    pub fn request_digest(self) -> Sha256Digest {
        let mut digest = Sha256::new();
        digest.update(LEASE_REQUEST_DIGEST_DOMAIN);
        digest.update(self.operation_id.as_uuid().as_bytes());
        digest.update(self.session.session_id().as_uuid().as_bytes());
        digest.update(self.session.runner_id().as_uuid().as_bytes());
        digest.update(self.session.runner_generation().get().to_be_bytes());
        digest.update(self.session.session_epoch().get().to_be_bytes());
        digest.update(self.slot.ordinal().to_be_bytes());
        match self.acknowledges_operation_id {
            Some(operation_id) => {
                digest.update([1]);
                digest.update(operation_id.as_uuid().as_bytes());
            }
            None => digest.update([0]),
        }
        Sha256Digest::from_bytes(digest.finalize().into())
    }
}

/// Invalid lease-request chain identity.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum LeaseRequestKeyError {
    /// The request acknowledges its own operation identity.
    #[error("a lease request cannot acknowledge its own operation identity")]
    SelfAcknowledgement,
}

/// Exact request admitted at the durable head of one session-slot chain.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BeginLeaseRequest {
    request_key: LeaseRequestKey,
    request_digest: Sha256Digest,
}

impl BeginLeaseRequest {
    /// Creates an admitted request from its canonical key and digest.
    #[must_use]
    pub const fn new(request_key: LeaseRequestKey, request_digest: Sha256Digest) -> Self {
        Self {
            request_key,
            request_digest,
        }
    }

    /// Returns the canonical request key.
    #[must_use]
    pub const fn request_key(self) -> LeaseRequestKey {
        self.request_key
    }

    /// Returns the request digest admitted at the durable head.
    #[must_use]
    pub const fn request_digest(self) -> Sha256Digest {
        self.request_digest
    }
}

/// Result of locking and admitting an exact lease request.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BegunLeaseRequest {
    request: BeginLeaseRequest,
    completion: Option<LeaseRequestCompletion>,
}

impl BegunLeaseRequest {
    /// Builds an admission result from a legacy response-only completion.
    #[must_use]
    pub fn new(
        request: BeginLeaseRequest,
        completed_response: Option<RunnerOperationResponse>,
    ) -> Self {
        Self {
            request,
            completion: completed_response.map(LeaseRequestCompletion::Response),
        }
    }

    /// Builds an admission result with the exact typed durable completion.
    #[must_use]
    pub const fn completed(request: BeginLeaseRequest, completion: LeaseRequestCompletion) -> Self {
        Self {
            request,
            completion: Some(completion),
        }
    }

    /// Builds an exact retry result whose previously committed offer is no longer live.
    #[must_use]
    pub const fn revoked_offer(
        request: BeginLeaseRequest,
        offer_operation_id: OperationId,
        fallback: RevokedLeaseOfferFallback,
    ) -> Self {
        Self::completed(
            request,
            LeaseRequestCompletion::RevokedLeaseOffer {
                offer_operation_id,
                fallback,
            },
        )
    }

    /// Returns the request that was admitted.
    #[must_use]
    pub const fn request(&self) -> BeginLeaseRequest {
        self.request
    }

    /// Returns a previously completed replayable response, if present.
    #[must_use]
    pub const fn completed_response(&self) -> Option<&RunnerOperationResponse> {
        match &self.completion {
            Some(completion) => completion.response(),
            None => None,
        }
    }

    /// Returns the exact typed durable completion, when this request already completed.
    #[must_use]
    pub const fn completion(&self) -> Option<&LeaseRequestCompletion> {
        self.completion.as_ref()
    }

    /// Returns the exact offer operation whose committed response must be replaced by no work.
    #[must_use]
    pub const fn revoked_offer_operation_id(&self) -> Option<OperationId> {
        match &self.completion {
            Some(LeaseRequestCompletion::RevokedLeaseOffer {
                offer_operation_id, ..
            }) => Some(*offer_operation_id),
            Some(
                LeaseRequestCompletion::Response(_) | LeaseRequestCompletion::LiveLeaseOffer { .. },
            )
            | None => None,
        }
    }
}

/// Version of the canonical structured fallback retained for a revoked lease offer.
const REVOKED_LEASE_OFFER_FALLBACK_VERSION: u16 = 1;

/// Minimal durable data needed to rebuild one canonical revoked-offer `NoWork` response.
///
/// The projection deliberately contains no encrypted response bytes and no reference to
/// replica-local retry configuration. Its schema and digest authenticate the canonical wire
/// response rebuilt by the runner-control boundary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RevokedLeaseOfferFallback {
    representation_version: u16,
    response_operation_id: OperationId,
    retry_after_millis: u32,
    response_schema: DocumentSchema,
    response_digest: Sha256Digest,
}

impl RevokedLeaseOfferFallback {
    /// Builds the current durable fallback representation.
    ///
    /// # Errors
    ///
    /// Rejects a nil response operation identity or a zero retry delay.
    pub fn new(
        response_operation_id: OperationId,
        retry_after_millis: u32,
        response_schema: DocumentSchema,
        response_digest: Sha256Digest,
    ) -> Result<Self, LeaseOfferCompletionError> {
        Self::from_persisted(
            REVOKED_LEASE_OFFER_FALLBACK_VERSION,
            response_operation_id,
            retry_after_millis,
            response_schema,
            response_digest,
        )
    }

    /// Rehydrates and validates a versioned durable fallback representation.
    ///
    /// # Errors
    ///
    /// Rejects an unsupported representation, nil operation identity, or zero
    /// retry delay.
    pub(crate) fn from_persisted(
        representation_version: u16,
        response_operation_id: OperationId,
        retry_after_millis: u32,
        response_schema: DocumentSchema,
        response_digest: Sha256Digest,
    ) -> Result<Self, LeaseOfferCompletionError> {
        if representation_version != REVOKED_LEASE_OFFER_FALLBACK_VERSION {
            return Err(LeaseOfferCompletionError::UnsupportedFallbackVersion);
        }
        if response_operation_id.as_uuid().is_nil() {
            return Err(LeaseOfferCompletionError::NilFallbackOperationId);
        }
        if retry_after_millis == 0 {
            return Err(LeaseOfferCompletionError::ZeroFallbackRetry);
        }
        Ok(Self {
            representation_version,
            response_operation_id,
            retry_after_millis,
            response_schema,
            response_digest,
        })
    }

    /// Returns the durable representation version.
    #[must_use]
    pub const fn representation_version(self) -> u16 {
        self.representation_version
    }

    /// Returns the operation identity used for the rebuilt response.
    #[must_use]
    pub const fn response_operation_id(self) -> OperationId {
        self.response_operation_id
    }

    /// Returns the retry delay carried by the rebuilt response.
    #[must_use]
    pub const fn retry_after_millis(self) -> u32 {
        self.retry_after_millis
    }

    /// Returns the expected canonical response schema.
    #[must_use]
    pub const fn response_schema(self) -> DocumentSchema {
        self.response_schema
    }

    /// Returns the expected canonical response digest.
    #[must_use]
    pub const fn response_digest(self) -> Sha256Digest {
        self.response_digest
    }
}

/// Exact semantic disposition of one durable lease-request completion.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum LeaseRequestCompletion {
    /// A response which did not publish a lease offer.
    Response(RunnerOperationResponse),
    /// A still-live lease offer plus the already-persisted fallback needed if it later revokes.
    LiveLeaseOffer {
        /// The replayable live-offer response.
        response: RunnerOperationResponse,
        /// The canonical fallback retained for later revocation.
        fallback: RevokedLeaseOfferFallback,
    },
    /// A lease offer whose bearer response is no longer eligible for replay.
    RevokedLeaseOffer {
        /// The operation identity of the revoked offer.
        offer_operation_id: OperationId,
        /// The canonical replacement response projection.
        fallback: RevokedLeaseOfferFallback,
    },
}

impl LeaseRequestCompletion {
    /// Returns the replayable response when this completion still has one.
    #[must_use]
    pub const fn response(&self) -> Option<&RunnerOperationResponse> {
        match self {
            Self::Response(response) | Self::LiveLeaseOffer { response, .. } => Some(response),
            Self::RevokedLeaseOffer { .. } => None,
        }
    }

    /// Returns the retained revoked-offer fallback, if any.
    #[must_use]
    pub const fn revoked_offer_fallback(&self) -> Option<RevokedLeaseOfferFallback> {
        match self {
            Self::LiveLeaseOffer { fallback, .. } | Self::RevokedLeaseOffer { fallback, .. } => {
                Some(*fallback)
            }
            Self::Response(_) => None,
        }
    }
}

impl PartialEq<RunnerOperationResponse> for LeaseRequestCompletion {
    fn eq(&self, other: &RunnerOperationResponse) -> bool {
        self.response().is_some_and(|response| response == other)
    }
}

impl PartialEq<LeaseRequestCompletion> for RunnerOperationResponse {
    fn eq(&self, other: &LeaseRequestCompletion) -> bool {
        other == self
    }
}

/// Invalid typed composition of a lease offer and its canonical revocation fallback.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum LeaseOfferCompletionError {
    /// The offer command belongs to another durable session.
    #[error("lease-offer completion crosses durable sessions")]
    SessionMismatch,
    /// The persisted fallback representation version is unsupported.
    #[error("lease-offer fallback representation version is unsupported")]
    UnsupportedFallbackVersion,
    /// The fallback response operation identity is nil.
    #[error("lease-offer fallback response operation identity is nil")]
    NilFallbackOperationId,
    /// The fallback retry delay is zero.
    #[error("lease-offer fallback retry delay is zero")]
    ZeroFallbackRetry,
    /// The fallback projection disagrees with the canonical response.
    #[error("lease-offer fallback response metadata does not match its canonical bytes")]
    FallbackResponseMismatch,
}

/// Final exact response committed only while the request remains current.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CompleteLeaseRequest {
    request: BeginLeaseRequest,
    response: RunnerOperationResponse,
    completed_at: UnixMillis,
    lease_offer: Option<LeaseOfferCompletion>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct LeaseOfferCompletion {
    command: LeaseOfferCommandIdentity,
    revoked_response: RunnerOperationResponse,
    revoked_fallback: RevokedLeaseOfferFallback,
}

impl CompleteLeaseRequest {
    /// Builds a response which does not contain a full lease-offer command.
    #[must_use]
    pub const fn without_lease_offer(
        request: BeginLeaseRequest,
        response: RunnerOperationResponse,
        completed_at: UnixMillis,
    ) -> Self {
        Self {
            request,
            response,
            completed_at,
            lease_offer: None,
        }
    }

    /// Builds a full lease-offer response with its typed canonical revocation fallback.
    ///
    /// # Errors
    ///
    /// Rejects a command from another session or fallback bytes whose schema/digest disagree
    /// with the structured projection.
    pub fn for_lease_offer_with_fallback(
        request: BeginLeaseRequest,
        response: RunnerOperationResponse,
        revoked_response: RunnerOperationResponse,
        revoked_fallback: RevokedLeaseOfferFallback,
        completed_at: UnixMillis,
        command: LeaseOfferCommandIdentity,
    ) -> Result<Self, LeaseOfferCompletionError> {
        if command.session() != request.request_key().session() {
            return Err(LeaseOfferCompletionError::SessionMismatch);
        }
        if revoked_response.schema() != revoked_fallback.response_schema()
            || revoked_response.digest() != revoked_fallback.response_digest()
        {
            return Err(LeaseOfferCompletionError::FallbackResponseMismatch);
        }
        Ok(Self {
            request,
            response,
            completed_at,
            lease_offer: Some(LeaseOfferCompletion {
                command,
                revoked_response,
                revoked_fallback,
            }),
        })
    }

    /// Returns the admitted request being completed.
    #[must_use]
    pub const fn request(&self) -> BeginLeaseRequest {
        self.request
    }

    /// Returns the canonical response being committed.
    #[must_use]
    pub const fn response(&self) -> &RunnerOperationResponse {
        &self.response
    }

    /// Returns the trusted completion time.
    #[must_use]
    pub const fn completed_at(&self) -> UnixMillis {
        self.completed_at
    }

    /// Returns the exact typed offer command carried by this response, when present.
    #[must_use]
    pub const fn lease_offer_command(&self) -> Option<LeaseOfferCommandIdentity> {
        match &self.lease_offer {
            Some(lease_offer) => Some(lease_offer.command),
            None => None,
        }
    }

    /// Returns the response to commit if the typed offer is revoked before
    /// the primary response reaches the durable lease-request ledger.
    #[must_use]
    pub const fn revoked_lease_offer_response(&self) -> Option<&RunnerOperationResponse> {
        match &self.lease_offer {
            Some(lease_offer) => Some(&lease_offer.revoked_response),
            None => None,
        }
    }

    /// Returns the typed canonical revocation projection for a strict offer completion.
    #[must_use]
    pub const fn revoked_lease_offer_fallback(&self) -> Option<RevokedLeaseOfferFallback> {
        match &self.lease_offer {
            Some(lease_offer) => Some(lease_offer.revoked_fallback),
            None => None,
        }
    }
}

/// Idempotent, server-routed attempt claim.
///
/// It intentionally contains no labels, groups, or capability claims. Those
/// are loaded through the session from server-owned durable registration.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TryClaimAttempt {
    request_key: LeaseRequestKey,
    attempt_id: AttemptId,
    lease_id: LeaseId,
    observed_at: UnixMillis,
    expires_at: UnixMillis,
    cursor: RunnableCursorAdvance,
    windows_placement_grant: Option<Box<WindowsHyperVPlacementGrant>>,
}

/// Server-only one-use authority for one exact Windows Hyper-V placement.
///
/// The value is neither serialized nor accepted from a runner. It binds the
/// authenticated trust root and immutable job plan to one poll operation,
/// runner generation/session/slot, proposed lease, exact image-profile
/// manifest, and half-open validity interval. A first-party durable adapter
/// re-derives it from locked current state immediately before leasing.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WindowsHyperVPlacementGrant {
    attempt_id: AttemptId,
    job_id: automata_ci_core::JobId,
    run_id: automata_ci_core::RunId,
    operation_id: OperationId,
    session: RunnerSessionFence,
    slot: StableRunnerSlot,
    lease_id: LeaseId,
    job_ir: JobIrMetadata,
    trust_binding_digest: Sha256Digest,
    environment_profile: EnvironmentProfile,
    issued_at: UnixMillis,
    expires_at: UnixMillis,
    binding_digest: Sha256Digest,
}

impl WindowsHyperVPlacementGrant {
    fn for_candidate(
        request_key: LeaseRequestKey,
        lease_id: LeaseId,
        issued_at: UnixMillis,
        expires_at: UnixMillis,
        candidate: &RunnableAttempt,
    ) -> Result<Option<Self>, WindowsPlacementGrantError> {
        let requirements = candidate.requirements();
        if requirements.operating_system() != Some(&OperatingSystem::Windows) {
            return Ok(None);
        }
        if requirements.minimum_isolation() < IsolationLevel::VirtualMachine
            || !requirements
                .sandbox_features()
                .contains(&SandboxFeature::WINDOWS_HYPERV_CONTAINER)
        {
            return Err(WindowsPlacementGrantError::InexactIsolation);
        }
        if requirements.architecture() != Some(&Architecture::X86_64) {
            return Err(WindowsPlacementGrantError::UnsupportedArchitecture);
        }
        let environment_profile = requirements
            .environment_profile()
            .cloned()
            .ok_or(WindowsPlacementGrantError::MissingEnvironmentProfile)?;
        let trust = candidate
            .placement_trust()
            .cloned()
            .ok_or(WindowsPlacementGrantError::MissingAuthenticatedTrust)?;
        if !trust.evidence_complete() || trust.source() == TrustSourceClass::Incomplete {
            return Err(WindowsPlacementGrantError::IncompleteAuthenticatedTrust);
        }
        if expires_at <= issued_at {
            return Err(WindowsPlacementGrantError::InvalidValidityInterval);
        }
        let trust_binding_digest = trust_binding_digest(&trust);
        let mut grant = Self {
            attempt_id: candidate.attempt_id(),
            job_id: candidate.job_id(),
            run_id: candidate.run_id(),
            operation_id: request_key.operation_id(),
            session: request_key.session(),
            slot: request_key.slot(),
            lease_id,
            job_ir: candidate.job_ir().clone(),
            trust_binding_digest,
            environment_profile,
            issued_at,
            expires_at,
            binding_digest: Sha256Digest::from_bytes([0; 32]),
        };
        grant.binding_digest = grant.compute_binding_digest();
        Ok(Some(grant))
    }

    #[cfg(feature = "adapter-spi")]
    fn rebased(
        &self,
        issued_at: UnixMillis,
        expires_at: UnixMillis,
    ) -> Result<Self, WindowsPlacementGrantError> {
        if expires_at <= issued_at {
            return Err(WindowsPlacementGrantError::InvalidValidityInterval);
        }
        let mut grant = self.clone();
        grant.issued_at = issued_at;
        grant.expires_at = expires_at;
        grant.binding_digest = grant.compute_binding_digest();
        Ok(grant)
    }

    fn compute_binding_digest(&self) -> Sha256Digest {
        fn field(digest: &mut Sha256, value: &[u8]) {
            digest.update(u64::try_from(value.len()).unwrap_or(u64::MAX).to_be_bytes());
            digest.update(value);
        }

        let mut digest = Sha256::new();
        digest.update(WINDOWS_PLACEMENT_GRANT_DIGEST_DOMAIN);
        digest.update(self.attempt_id.as_uuid().as_bytes());
        digest.update(self.job_id.as_uuid().as_bytes());
        digest.update(self.run_id.as_uuid().as_bytes());
        digest.update(self.operation_id.as_uuid().as_bytes());
        digest.update(self.session.runner_id().as_uuid().as_bytes());
        digest.update(self.session.session_id().as_uuid().as_bytes());
        digest.update(self.session.runner_generation().get().to_be_bytes());
        digest.update(self.session.session_epoch().get().to_be_bytes());
        digest.update(self.slot.ordinal().to_be_bytes());
        digest.update(self.lease_id.as_uuid().as_bytes());
        digest.update(self.job_ir.version().get().to_be_bytes());
        digest.update(self.job_ir.encoded_size().to_be_bytes());
        digest.update(self.job_ir.digest().as_bytes());
        field(&mut digest, self.job_ir.object_key().as_str().as_bytes());
        digest.update(self.trust_binding_digest.as_bytes());
        field(
            &mut digest,
            self.environment_profile.id().as_str().as_bytes(),
        );
        digest.update(self.environment_profile.digest().as_bytes());
        digest.update(self.issued_at.get().to_be_bytes());
        digest.update(self.expires_at.get().to_be_bytes());
        Sha256Digest::from_bytes(digest.finalize().into())
    }

    /// Returns the exact attempt authorized by this one-use value.
    #[must_use]
    pub const fn attempt_id(&self) -> AttemptId {
        self.attempt_id
    }

    /// Returns the exact job authorized by this value.
    #[must_use]
    pub const fn job_id(&self) -> automata_ci_core::JobId {
        self.job_id
    }

    /// Returns the exact workflow run authorized by this value.
    #[must_use]
    pub const fn run_id(&self) -> automata_ci_core::RunId {
        self.run_id
    }

    /// Returns the exact poll operation authorized by this one-use value.
    #[must_use]
    pub const fn operation_id(&self) -> OperationId {
        self.operation_id
    }

    /// Returns the exact runner generation/session bound into this value.
    #[must_use]
    pub const fn session(&self) -> RunnerSessionFence {
        self.session
    }

    /// Returns the exact stable slot bound into this value.
    #[must_use]
    pub const fn slot(&self) -> StableRunnerSlot {
        self.slot
    }

    /// Returns the exact proposed lease identity.
    #[must_use]
    pub const fn lease_id(&self) -> LeaseId {
        self.lease_id
    }

    /// Returns the immutable `JobIR` object metadata bound into this value.
    #[must_use]
    pub const fn job_ir(&self) -> &JobIrMetadata {
        &self.job_ir
    }

    /// Returns the compact digest of authenticated trust and requirements.
    #[must_use]
    pub const fn trust_binding_digest(&self) -> Sha256Digest {
        self.trust_binding_digest
    }

    /// Returns the immutable content-attested Windows environment profile.
    #[must_use]
    pub const fn environment_profile(&self) -> &EnvironmentProfile {
        &self.environment_profile
    }

    /// Returns the exclusive authority horizon.
    #[must_use]
    pub const fn expires_at(&self) -> UnixMillis {
        self.expires_at
    }

    /// Returns the inclusive issue time.
    #[must_use]
    pub const fn issued_at(&self) -> UnixMillis {
        self.issued_at
    }

    /// Returns the canonical domain-separated binding digest.
    #[must_use]
    pub const fn binding_digest(&self) -> Sha256Digest {
        self.binding_digest
    }

    #[cfg(feature = "adapter-spi")]
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn from_persisted(
        request_key: LeaseRequestKey,
        attempt_id: AttemptId,
        lease_id: LeaseId,
        job_ir: JobIrMetadata,
        trust_binding_digest: Sha256Digest,
        environment_profile: EnvironmentProfile,
        issued_at: UnixMillis,
        expires_at: UnixMillis,
        binding_digest: Sha256Digest,
    ) -> Result<Self, WindowsPlacementGrantError> {
        let grant = Self {
            attempt_id,
            job_id: job_ir.job_id(),
            run_id: job_ir.run_id(),
            operation_id: request_key.operation_id(),
            session: request_key.session(),
            slot: request_key.slot(),
            lease_id,
            job_ir,
            trust_binding_digest,
            environment_profile,
            issued_at,
            expires_at,
            binding_digest,
        };
        if expires_at <= issued_at || grant.compute_binding_digest() != binding_digest {
            return Err(WindowsPlacementGrantError::PersistedBindingMismatch);
        }
        Ok(grant)
    }
}

fn trust_binding_digest(trust: &AuthenticatedPlacementTrust) -> Sha256Digest {
    let encoded = serde_json::to_vec(&(
        trust.snapshot_schema(),
        trust.policy_revision(),
        trust.policy_digest(),
        trust.snapshot_digest(),
        trust.source(),
        trust.authority(),
        trust.evidence_complete(),
        trust.authority_profile(),
        trust.requirements_digest(),
    ))
    .expect("closed authenticated placement trust is infallibly serializable");
    domain_digest(WINDOWS_PLACEMENT_TRUST_DIGEST_DOMAIN, &encoded)
}

fn domain_digest(domain: &[u8], value: &[u8]) -> Sha256Digest {
    let mut digest = Sha256::new();
    digest.update(domain);
    digest.update(u64::try_from(value.len()).unwrap_or(u64::MAX).to_be_bytes());
    digest.update(value);
    Sha256Digest::from_bytes(digest.finalize().into())
}

/// Closed local reasons that prevent a Windows candidate becoming a lease.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum WindowsPlacementGrantError {
    /// The candidate does not require the exact Hyper-V-container boundary.
    #[error("Windows placement does not require exact Hyper-V-container isolation")]
    InexactIsolation,
    /// Wave 1 admits only native Windows AMD64 profiles.
    #[error("Windows placement architecture is unsupported")]
    UnsupportedArchitecture,
    /// No immutable profile-manifest digest was selected.
    #[error("Windows placement is missing an exact environment profile")]
    MissingEnvironmentProfile,
    /// The durable run has no authenticated trust/materialization lineage.
    #[error("Windows placement is missing authenticated trust evidence")]
    MissingAuthenticatedTrust,
    /// Authenticated facts were incomplete and therefore cannot authorize execution.
    #[error("Windows placement trust evidence is incomplete")]
    IncompleteAuthenticatedTrust,
    /// The proposed grant has an empty or reversed validity interval.
    #[error("Windows placement grant validity interval is invalid")]
    InvalidValidityInterval,
    /// Persisted grant material no longer matches its canonical digest.
    #[error("persisted Windows placement grant binding is corrupt")]
    PersistedBindingMismatch,
    /// A grant was attached to a different durable claimed attempt fence.
    #[error("Windows placement grant does not match the claimed attempt fence")]
    ClaimBindingMismatch,
}

impl TryClaimAttempt {
    /// Creates a claim with a valid half-open lease interval.
    ///
    /// # Errors
    ///
    /// Rejects expiration at or before trusted observation time.
    pub fn new(
        request_key: LeaseRequestKey,
        attempt_id: AttemptId,
        lease_id: LeaseId,
        observed_at: UnixMillis,
        expires_at: UnixMillis,
        cursor: RunnableCursorAdvance,
    ) -> Result<Self, ClaimCommandError> {
        if expires_at <= observed_at {
            return Err(ClaimCommandError::InvalidLeaseInterval);
        }
        if cursor.session() != request_key.session()
            || cursor.slot() != request_key.slot()
            || cursor
                .through()
                .is_none_or(|key| key.attempt_id() != attempt_id)
        {
            return Err(ClaimCommandError::CursorMismatch);
        }
        Ok(Self {
            request_key,
            attempt_id,
            lease_id,
            observed_at,
            expires_at,
            cursor,
            windows_placement_grant: None,
        })
    }

    /// Creates a claim and derives any mandatory Windows placement authority.
    ///
    /// # Errors
    ///
    /// Rejects cursor/attempt disagreement or a Windows candidate without
    /// complete authenticated trust, an exact AMD64 environment profile, and
    /// the non-fallback Hyper-V-container requirement.
    pub fn for_candidate(
        request_key: LeaseRequestKey,
        candidate: &RunnableAttempt,
        lease_id: LeaseId,
        observed_at: UnixMillis,
        expires_at: UnixMillis,
        cursor: RunnableCursorAdvance,
    ) -> Result<Self, ClaimCommandError> {
        let mut request = Self::new(
            request_key,
            candidate.attempt_id(),
            lease_id,
            observed_at,
            expires_at,
            cursor,
        )?;
        request.windows_placement_grant = WindowsHyperVPlacementGrant::for_candidate(
            request_key,
            lease_id,
            observed_at,
            expires_at,
            candidate,
        )
        .map_err(ClaimCommandError::InvalidWindowsPlacementGrant)?
        .map(Box::new);
        Ok(request)
    }

    /// Returns the claim operation identity.
    #[must_use]
    pub const fn operation_id(&self) -> OperationId {
        self.request_key.operation_id()
    }

    /// Returns the target attempt identity.
    #[must_use]
    pub const fn attempt_id(&self) -> AttemptId {
        self.attempt_id
    }

    /// Returns the authenticated runner-session fence.
    #[must_use]
    pub const fn session(&self) -> RunnerSessionFence {
        self.request_key.session()
    }

    /// Returns the stable runner slot receiving the claim.
    #[must_use]
    pub const fn slot(&self) -> StableRunnerSlot {
        self.request_key.slot()
    }

    /// Returns the proposed lease identity.
    #[must_use]
    pub const fn lease_id(&self) -> LeaseId {
        self.lease_id
    }

    /// Returns the trusted observation time.
    #[must_use]
    pub const fn observed_at(&self) -> UnixMillis {
        self.observed_at
    }

    /// Returns the proposed lease expiration.
    #[must_use]
    pub const fn expires_at(&self) -> UnixMillis {
        self.expires_at
    }

    /// Returns the canonical lease-request key.
    #[must_use]
    pub const fn request_key(&self) -> LeaseRequestKey {
        self.request_key
    }

    /// Returns the canonical pre-scheduling lease-request digest.
    #[must_use]
    pub fn request_digest(&self) -> Sha256Digest {
        self.request_key.request_digest()
    }

    /// Returns a server-only Windows placement grant when this is a Windows claim.
    #[must_use]
    pub fn windows_placement_grant(&self) -> Option<&WindowsHyperVPlacementGrant> {
        self.windows_placement_grant.as_deref()
    }

    #[cfg(feature = "adapter-spi")]
    pub(crate) fn rebased(
        &self,
        observed_at: UnixMillis,
        expires_at: UnixMillis,
    ) -> Result<Self, ClaimCommandError> {
        let mut request = Self::new(
            self.request_key,
            self.attempt_id,
            self.lease_id,
            observed_at,
            expires_at,
            self.cursor,
        )?;
        request.windows_placement_grant = self
            .windows_placement_grant
            .as_ref()
            .map(|grant| grant.rebased(observed_at, expires_at))
            .transpose()
            .map_err(ClaimCommandError::InvalidWindowsPlacementGrant)?
            .map(Box::new);
        Ok(request)
    }

    #[cfg(feature = "adapter-spi")]
    pub(crate) fn placement_matches(&self, candidate: &RunnableAttempt) -> bool {
        WindowsHyperVPlacementGrant::for_candidate(
            self.request_key,
            self.lease_id,
            self.observed_at,
            self.expires_at,
            candidate,
        )
        .is_ok_and(|expected| expected.as_ref() == self.windows_placement_grant.as_deref())
    }

    /// Returns the opaque authoritative scan cursor used by an adapter.
    #[cfg(feature = "adapter-spi")]
    #[must_use]
    pub(crate) const fn cursor(&self) -> RunnableCursorAdvance {
        self.cursor
    }
}

/// Terminal no-work decision for one exact lease poll.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NoWorkLeaseRequest {
    request_key: LeaseRequestKey,
    observed_at: UnixMillis,
    cursor: RunnableCursorAdvance,
}

impl NoWorkLeaseRequest {
    /// Creates a terminal no-work command bound to an authoritative scan.
    ///
    /// # Errors
    ///
    /// Rejects a cursor proof for another session fence or stable slot.
    pub fn new(
        request_key: LeaseRequestKey,
        observed_at: UnixMillis,
        cursor: RunnableCursorAdvance,
    ) -> Result<Self, ClaimCommandError> {
        if cursor.session() != request_key.session() || cursor.slot() != request_key.slot() {
            return Err(ClaimCommandError::CursorMismatch);
        }
        Ok(Self {
            request_key,
            observed_at,
            cursor,
        })
    }

    /// Returns the canonical lease-request key.
    #[must_use]
    pub const fn request_key(&self) -> LeaseRequestKey {
        self.request_key
    }

    /// Returns the trusted no-work observation time.
    #[must_use]
    pub const fn observed_at(&self) -> UnixMillis {
        self.observed_at
    }

    /// Returns the opaque authoritative scan cursor used by an adapter.
    #[cfg(feature = "adapter-spi")]
    #[must_use]
    pub(crate) const fn cursor(&self) -> RunnableCursorAdvance {
        self.cursor
    }
}

/// Invalid composition of a durable attempt-claim command.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum ClaimCommandError {
    /// The proposed lease does not extend past trusted observation time.
    #[error("lease expiration must be strictly later than trusted observation time")]
    InvalidLeaseInterval,
    /// The cursor proof belongs to another request, slot, or attempt.
    #[error("queue cursor proof does not match the lease request")]
    CursorMismatch,
    /// Mandatory Windows placement evidence is missing or invalid.
    #[error("invalid Windows Hyper-V placement grant: {0}")]
    InvalidWindowsPlacementGrant(WindowsPlacementGrantError),
}

/// Successfully fenced claim and its stable connection assignment.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ClaimedAttempt {
    lease: Lease,
    assignment: AttemptAssignment,
    job_ir: JobIrMetadata,
    windows_placement_grant: Option<Box<WindowsHyperVPlacementGrant>>,
}

impl ClaimedAttempt {
    /// Constructs a claimed attempt returned by an adapter.
    ///
    /// # Errors
    ///
    /// Rejects a lease owned by another runner.
    pub fn try_new(
        lease: Lease,
        assignment: AttemptAssignment,
        job_ir: JobIrMetadata,
    ) -> Result<Self, AttemptAssignmentError> {
        assignment.validate_lease(&lease)?;
        Ok(Self {
            lease,
            assignment,
            job_ir,
            windows_placement_grant: None,
        })
    }

    /// Attaches the exact locked Windows placement authority to the claimed fence.
    ///
    /// # Errors
    ///
    /// Rejects any disagreement in attempt, lease, session, slot, `JobIR`, or
    /// validity interval. A non-Windows claim leaves this field absent.
    pub fn with_windows_placement_grant(
        mut self,
        grant: WindowsHyperVPlacementGrant,
    ) -> Result<Self, WindowsPlacementGrantError> {
        if grant.attempt_id() != self.lease.attempt_id()
            || grant.lease_id() != self.lease.lease_id()
            || grant.session() != self.assignment.session()
            || grant.slot() != self.assignment.slot()
            || grant.job_ir() != &self.job_ir
            || grant.issued_at() != self.lease.issued_at()
            || grant.expires_at() != self.lease.expires_at()
        {
            return Err(WindowsPlacementGrantError::ClaimBindingMismatch);
        }
        self.windows_placement_grant = Some(Box::new(grant));
        Ok(self)
    }

    /// Returns the acquired lease.
    #[must_use]
    pub const fn lease(&self) -> &Lease {
        &self.lease
    }

    /// Returns the stable runner-session assignment.
    #[must_use]
    pub const fn assignment(&self) -> AttemptAssignment {
        self.assignment
    }

    /// Returns the selected job intermediate-representation metadata.
    #[must_use]
    pub const fn job_ir(&self) -> &JobIrMetadata {
        &self.job_ir
    }

    /// Returns the server-derived Windows placement authority, when required.
    #[must_use]
    pub fn windows_placement_grant(&self) -> Option<&WindowsHyperVPlacementGrant> {
        self.windows_placement_grant.as_deref()
    }
}

/// Durable negative claim decision. Retrying the same operation replays it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ClaimRejection {
    /// A claim that never produced a replayable runner response reached its
    /// lease deadline and can no longer be delivered.
    ClaimExpired,
    /// The exact attempt fence stopped being current before the claimed lease
    /// could be delivered.
    ClaimSuperseded,
    /// The selected attempt no longer exists.
    AttemptNotFound,
    /// The selected attempt is no longer queued.
    AttemptNotQueued(JobLifecycle),
    /// Durable execution gates no longer consider the attempt runnable.
    NoLongerRunnable,
    /// The attempt no longer routes to this runner.
    NotRoutable,
    /// The requested stable slot is outside the registered capacity.
    SlotOutOfRange,
    /// The requested stable slot already owns another attempt.
    SlotOccupied {
        /// The attempt currently occupying the stable slot.
        attempt_id: AttemptId,
    },
    /// Another operation advanced this slot's cursor after the page was read.
    ScanSuperseded,
}

/// Exact durable outcome of a claim operation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TryClaimOutcome {
    /// The attempt was claimed and fenced successfully.
    Claimed(Box<ClaimedAttempt>),
    /// The durable claim was rejected without a repository failure.
    Rejected(ClaimRejection),
    /// The authoritative scan produced no claimable work.
    NoWork,
}

impl TryClaimOutcome {
    /// Returns selected job metadata for a successful claim.
    #[must_use]
    pub const fn claimed_job_ir(&self) -> Option<&JobIrMetadata> {
        match self {
            Self::Claimed(claimed) => Some(claimed.job_ir()),
            Self::Rejected(_) | Self::NoWork => None,
        }
    }
}

/// Receipt returned for a first execution or an exact retry.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TryClaimReceipt {
    request_key: LeaseRequestKey,
    outcome: TryClaimOutcome,
    replayed: bool,
}

impl TryClaimReceipt {
    /// Creates a durable claim receipt.
    #[must_use]
    pub const fn new(
        request_key: LeaseRequestKey,
        outcome: TryClaimOutcome,
        replayed: bool,
    ) -> Self {
        Self {
            request_key,
            outcome,
            replayed,
        }
    }

    /// Returns the runner-session identity owning the request.
    #[must_use]
    pub const fn session_id(&self) -> automata_ci_core::RunnerSessionId {
        self.request_key.session().session_id()
    }

    /// Returns the claim operation identity.
    #[must_use]
    pub const fn operation_id(&self) -> OperationId {
        self.request_key.operation_id()
    }

    /// Returns the canonical lease-request digest.
    #[must_use]
    pub fn request_digest(&self) -> Sha256Digest {
        self.request_key.request_digest()
    }

    /// Returns the canonical lease-request key.
    #[must_use]
    pub const fn request_key(&self) -> LeaseRequestKey {
        self.request_key
    }

    /// Returns the durable claim outcome.
    #[must_use]
    pub const fn outcome(&self) -> &TryClaimOutcome {
        &self.outcome
    }

    /// Reports whether this receipt came from an exact retry.
    #[must_use]
    pub const fn was_replayed(&self) -> bool {
        self.replayed
    }
}
