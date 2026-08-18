use std::{collections::BTreeMap, fmt, str::FromStr as _, sync::Arc};

use async_trait::async_trait;
use automata_ci_core::{
    Architecture, EnvironmentProfile, IsolationLevel, JobAuthorityProfile, JobIrEnvelope, Lease,
    OperatingSystem, RunnerId, SandboxAuthorization, SandboxAuthorizationName, SandboxFeature,
    Sha256Digest, TrustSourceClass, UnixMillis, WINDOWS_HYPERV_BROKER_GRANT_SCHEMA_V4,
    WINDOWS_HYPERV_SANDBOX_AUTHORIZATION_NAME, WindowsHyperVBrokerGrant,
    WindowsHyperVBrokerGrantClaims,
};
use automata_ci_protocol::{
    LeaseAuthorityName, LeaseAuthorityPollContribution, VerifiedWindowsRunnerPlacementRenewal,
    WINDOWS_RUNNER_PLACEMENT_RENEWAL_SCHEMA_VERSION, WindowsRunnerAdmissionTrustStore,
    WindowsRunnerPlacementRenewalEnvelope, verify_windows_runner_placement_renewal,
};
use automata_ci_protocol_protobuf::{
    decode_windows_runner_placement_renewal_payload, encode_windows_hyperv_broker_grant_payload,
};
use automata_ci_store::{JobIrMetadata, RunnerOperationRequest, RunnerSessionFence};
use ring::signature::{Ed25519KeyPair, KeyPair as _};
use sha2::{Digest as _, Sha256};
use thiserror::Error;
use zeroize::Zeroizing;

use super::{
    durable::{
        AcceptedRuntimeAuthorityOffer, CommitRuntimeAuthorityDelivery,
        RuntimeAuthorityDeliveryAdmission, RuntimeAuthorityDeliveryDisposition,
    },
    lease_authority::{
        LeaseAuthorityEvidence, LeaseAuthorityExtension, LeaseAuthorityOfferRequest,
        LeaseAuthorityPollAcceptance, PreparedSandboxAuthorization,
    },
    port::ControlPortError,
};

const WINDOWS_PLACEMENT_EVIDENCE_DIGEST_DOMAIN: &[u8] =
    b"automata.control.windows-hyperv-placement-evidence.v3\0";
const WINDOWS_PLACEMENT_TRUST_DIGEST_DOMAIN: &[u8] =
    b"automata.control.windows-hyperv-placement-trust.v1\0";

/// Value-free server-retained evidence needed to mint a broker capability
/// only after the exact offer has been durably accepted.
#[derive(Clone, Debug, serde::Deserialize, Eq, PartialEq, serde::Serialize)]
#[serde(deny_unknown_fields)]
pub struct WindowsHyperVPlacementEvidence {
    placement_binding_digest: Sha256Digest,
    trust_binding_digest: Sha256Digest,
    broker_host_id: Sha256Digest,
    environment_profile: EnvironmentProfile,
    profile_contract_sha256: Sha256Digest,
    sandbox_pids_limit: u32,
    placement_valid_until: UnixMillis,
    poll_contributions_sha256: Sha256Digest,
    placement_renewal_serial: u64,
    placement_renewal_envelope_sha256: Sha256Digest,
}

impl WindowsHyperVPlacementEvidence {
    fn from_offer_request(
        request: LeaseAuthorityOfferRequest<'_>,
        verified: &VerifiedWindowsRunnerPlacementRenewal,
    ) -> Result<Self, ControlPortError> {
        let claimed = request.claimed();
        let claims = verified.claims();
        let broker = claims.binding().broker_profile();
        let broker_host_id = Sha256Digest::from_str(broker.broker_host_id())
            .map_err(|_| ControlPortError::Corrupt)?;
        let placement_valid_until = UnixMillis::new(
            i64::try_from(claims.validity().expires_at_unix_millis())
                .map_err(|_| ControlPortError::Corrupt)?,
        );
        Self::from_coordinates(
            request.session(),
            claimed.lease(),
            claimed.slot().get(),
            claimed.job_ir(),
            request.job(),
            broker_host_id,
            claims.evidence().broker().profile_contract_sha256(),
            broker.sandbox_pids_limit(),
            placement_valid_until,
            claimed.authority_contributions().sha256_digest(),
            claims.renewal_serial(),
            verified.envelope_sha256(),
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn from_coordinates(
        session: RunnerSessionFence,
        lease: &Lease,
        slot: u16,
        metadata: &JobIrMetadata,
        job: &JobIrEnvelope,
        broker_host_id: Sha256Digest,
        profile_contract_sha256: Sha256Digest,
        sandbox_pids_limit: u32,
        placement_valid_until: UnixMillis,
        poll_contributions_sha256: Sha256Digest,
        placement_renewal_serial: u64,
        placement_renewal_envelope_sha256: Sha256Digest,
    ) -> Result<Self, ControlPortError> {
        let planned = job.job();
        let requirements = planned.requirements();
        if lease.runner_id() != session.runner_id()
            || lease.expires_at() <= lease.issued_at()
            || metadata.version() != job.version()
            || metadata.job_id() != planned.job_id()
            || metadata.run_id() != planned.run_id()
            || requirements.operating_system() != Some(&OperatingSystem::Windows)
            || requirements.minimum_isolation() < IsolationLevel::VirtualMachine
            || !requirements
                .sandbox_features()
                .contains(&SandboxFeature::WINDOWS_HYPERV_CONTAINER)
            || requirements.architecture() != Some(&Architecture::X86_64)
            || !windows_job_is_offline_credential_free(job)
            || broker_host_id.as_bytes().iter().all(|byte| *byte == 0)
            || profile_contract_sha256
                .as_bytes()
                .iter()
                .all(|byte| *byte == 0)
            || sandbox_pids_limit == 0
            || placement_valid_until < lease.expires_at()
            || placement_renewal_serial == 0
            || placement_renewal_envelope_sha256
                .as_bytes()
                .iter()
                .all(|byte| *byte == 0)
        {
            return Err(ControlPortError::Unavailable);
        }
        let environment_profile = requirements
            .environment_profile()
            .cloned()
            .ok_or(ControlPortError::Unavailable)?;
        let trust_binding_digest = windows_trust_binding_digest(job)?;
        let mut evidence = Self {
            placement_binding_digest: Sha256Digest::from_bytes([0; 32]),
            trust_binding_digest,
            broker_host_id,
            environment_profile,
            profile_contract_sha256,
            sandbox_pids_limit,
            placement_valid_until,
            poll_contributions_sha256,
            placement_renewal_serial,
            placement_renewal_envelope_sha256,
        };
        evidence.placement_binding_digest =
            evidence.compute_binding_digest(session, lease, slot, metadata);
        Ok(evidence)
    }

    fn compute_binding_digest(
        &self,
        session: RunnerSessionFence,
        lease: &Lease,
        slot: u16,
        metadata: &JobIrMetadata,
    ) -> Sha256Digest {
        fn field(digest: &mut Sha256, value: &[u8]) {
            digest.update(u64::try_from(value.len()).unwrap_or(u64::MAX).to_be_bytes());
            digest.update(value);
        }

        let mut digest = Sha256::new();
        digest.update(WINDOWS_PLACEMENT_EVIDENCE_DIGEST_DOMAIN);
        digest.update(lease.attempt_id().as_uuid().as_bytes());
        digest.update(metadata.job_id().as_uuid().as_bytes());
        digest.update(metadata.run_id().as_uuid().as_bytes());
        digest.update(session.runner_id().as_uuid().as_bytes());
        digest.update(session.session_id().as_uuid().as_bytes());
        digest.update(session.runner_generation().get().to_be_bytes());
        digest.update(session.session_epoch().get().to_be_bytes());
        digest.update(slot.to_be_bytes());
        digest.update(lease.lease_id().as_uuid().as_bytes());
        digest.update(lease.fencing_token().get().to_be_bytes());
        digest.update(metadata.version().get().to_be_bytes());
        digest.update(metadata.encoded_size().to_be_bytes());
        digest.update(metadata.digest().as_bytes());
        field(&mut digest, metadata.object_key().as_str().as_bytes());
        digest.update(self.trust_binding_digest.as_bytes());
        digest.update(self.broker_host_id.as_bytes());
        field(
            &mut digest,
            self.environment_profile.id().as_str().as_bytes(),
        );
        digest.update(self.environment_profile.digest().as_bytes());
        digest.update(self.profile_contract_sha256.as_bytes());
        digest.update(self.sandbox_pids_limit.to_be_bytes());
        digest.update(self.placement_valid_until.get().to_be_bytes());
        digest.update(lease.issued_at().get().to_be_bytes());
        digest.update(lease.expires_at().get().to_be_bytes());
        digest.update(self.poll_contributions_sha256.as_bytes());
        digest.update(self.placement_renewal_serial.to_be_bytes());
        digest.update(self.placement_renewal_envelope_sha256.as_bytes());
        Sha256Digest::from_bytes(digest.finalize().into())
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

    /// Returns the exact broker host authenticated by the accepted renewal.
    #[must_use]
    pub const fn broker_host_id(&self) -> Sha256Digest {
        self.broker_host_id
    }

    /// Returns the exact content-attested environment profile.
    #[must_use]
    pub const fn environment_profile(&self) -> &EnvironmentProfile {
        &self.environment_profile
    }

    /// Returns the exact broker-minted launch contract authenticated by the renewal.
    #[must_use]
    pub const fn profile_contract_sha256(&self) -> Sha256Digest {
        self.profile_contract_sha256
    }

    /// Returns the exact hard process ceiling authenticated by the renewal.
    #[must_use]
    pub const fn sandbox_pids_limit(&self) -> u32 {
        self.sandbox_pids_limit
    }

    /// Returns the exact exclusive freshness horizon authenticated by the renewal.
    #[must_use]
    pub const fn placement_valid_until(&self) -> UnixMillis {
        self.placement_valid_until
    }

    /// Returns the exact broker-durable serial of the accepted placement renewal.
    #[must_use]
    pub const fn placement_renewal_serial(&self) -> u64 {
        self.placement_renewal_serial
    }

    /// Returns the digest of the exact accepted placement-renewal envelope.
    #[must_use]
    pub const fn placement_renewal_envelope_sha256(&self) -> Sha256Digest {
        self.placement_renewal_envelope_sha256
    }

    fn is_valid_for_offer(
        &self,
        job: &JobIrEnvelope,
        offer: &AcceptedRuntimeAuthorityOffer,
    ) -> Result<bool, ControlPortError> {
        let expected = Self::from_coordinates(
            offer.request().session(),
            offer.lease(),
            offer.slot().ordinal(),
            offer.job_ir(),
            job,
            self.broker_host_id,
            self.profile_contract_sha256,
            self.sandbox_pids_limit,
            self.placement_valid_until,
            self.poll_contributions_sha256,
            self.placement_renewal_serial,
            self.placement_renewal_envelope_sha256,
        )?;
        Ok(self == &expected)
    }
}

fn windows_trust_binding_digest(job: &JobIrEnvelope) -> Result<Sha256Digest, ControlPortError> {
    let planned = job.job();
    let snapshot = planned.trust_snapshot();
    if snapshot.is_construction_placeholder()
        || !snapshot.evidence_complete()
        || snapshot.source_class() == TrustSourceClass::Incomplete
    {
        return Err(ControlPortError::Unavailable);
    }
    let requirements = serde_json::to_value(planned.requirements())
        .and_then(|value| serde_json::to_vec(&value))
        .map_err(|_| ControlPortError::Corrupt)?;
    let requirements_digest = Sha256Digest::from_bytes(Sha256::digest(requirements).into());
    let encoded = serde_json::to_vec(&(
        snapshot.schema(),
        snapshot.policy_revision(),
        snapshot.policy_digest(),
        snapshot.digest(),
        snapshot.source_class(),
        snapshot.authority(),
        snapshot.evidence_complete(),
        planned.authority_profile(),
        requirements_digest,
    ))
    .map_err(|_| ControlPortError::Corrupt)?;
    let mut digest = Sha256::new();
    digest.update(WINDOWS_PLACEMENT_TRUST_DIGEST_DOMAIN);
    digest.update(
        u64::try_from(encoded.len())
            .unwrap_or(u64::MAX)
            .to_be_bytes(),
    );
    digest.update(encoded);
    Ok(Sha256Digest::from_bytes(digest.finalize().into()))
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
    renewal_serial: u64,
    renewal_envelope_sha256: Sha256Digest,
    broker_host_id: Sha256Digest,
    environment_profile: EnvironmentProfile,
    profile_contract_sha256: Sha256Digest,
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
        renewal_serial: u64,
        renewal_envelope_sha256: Sha256Digest,
        broker_host_id: Sha256Digest,
        environment_profile: EnvironmentProfile,
        profile_contract_sha256: Sha256Digest,
        sandbox_pids_limit: u32,
        placement_valid_until: UnixMillis,
        observed_at: UnixMillis,
    ) -> Result<Self, ControlPortError> {
        if runner_id.as_uuid().is_nil()
            || renewal_serial == 0
            || [
                renewal_envelope_sha256,
                broker_host_id,
                environment_profile.digest(),
                profile_contract_sha256,
            ]
            .iter()
            .any(|digest| digest.as_bytes().iter().all(|byte| *byte == 0))
            || sandbox_pids_limit == 0
            || placement_valid_until <= observed_at
        {
            return Err(ControlPortError::Corrupt);
        }
        Ok(Self {
            runner_id,
            renewal_serial,
            renewal_envelope_sha256,
            broker_host_id,
            environment_profile,
            profile_contract_sha256,
            sandbox_pids_limit,
            placement_valid_until,
        })
    }

    /// Returns the admitted runner.
    #[must_use]
    pub const fn runner_id(&self) -> RunnerId {
        self.runner_id
    }

    /// Returns the exact broker-durable serial of the current placement renewal.
    #[must_use]
    pub const fn renewal_serial(&self) -> u64 {
        self.renewal_serial
    }

    /// Returns the digest of the exact current placement-renewal envelope.
    #[must_use]
    pub const fn renewal_envelope_sha256(&self) -> Sha256Digest {
        self.renewal_envelope_sha256
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
            || admission.broker_host_id() != placement.broker_host_id()
            || admission.environment_profile() != placement.environment_profile()
            || admission.profile_contract_sha256() != placement.profile_contract_sha256()
            || admission.sandbox_pids_limit() != placement.sandbox_pids_limit()
            || admission.placement_valid_until() != placement.placement_valid_until()
            || admission.renewal_serial() != placement.placement_renewal_serial()
            || admission.renewal_envelope_sha256() != placement.placement_renewal_envelope_sha256()
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
            lease.issued_at(),
            lease.expires_at(),
        )
        .map_err(|_| ControlPortError::Corrupt)?;
        Ok(WindowsHyperVBrokerGrantProposal::new(
            key_id,
            claims,
            self.placement().placement_renewal_serial(),
            self.placement().placement_renewal_envelope_sha256(),
        ))
    }
}

/// Exact unsigned Windows broker grant proposed for transactional admission.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WindowsHyperVBrokerGrantProposal {
    key_id: Sha256Digest,
    claims: WindowsHyperVBrokerGrantClaims,
    signing_payload_sha256: Sha256Digest,
    renewal_serial: u64,
    renewal_envelope_sha256: Sha256Digest,
}

impl WindowsHyperVBrokerGrantProposal {
    fn new(
        key_id: Sha256Digest,
        claims: WindowsHyperVBrokerGrantClaims,
        renewal_serial: u64,
        renewal_envelope_sha256: Sha256Digest,
    ) -> Self {
        let payload = WindowsHyperVBrokerGrant::signing_bytes_for(key_id, &claims);
        let signing_payload_sha256 = Sha256Digest::from_bytes(Sha256::digest(payload).into());
        Self {
            key_id,
            claims,
            signing_payload_sha256,
            renewal_serial,
            renewal_envelope_sha256,
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

    /// Returns the exact broker-durable renewal serial which produced the placement binding.
    #[must_use]
    pub const fn renewal_serial(&self) -> u64 {
        self.renewal_serial
    }

    /// Returns the exact renewal-envelope digest which produced the placement binding.
    #[must_use]
    pub const fn renewal_envelope_sha256(&self) -> Sha256Digest {
        self.renewal_envelope_sha256
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
            || claims.sandbox_pids_limit() != admission.sandbox_pids_limit()
            || claims.expires_at() > admission.placement_valid_until()
            || proposal.renewal_serial() != admission.renewal_serial()
            || proposal.renewal_envelope_sha256() != admission.renewal_envelope_sha256()
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
/// requires the current renewal serial and envelope digest to equal the exact
/// admission carried by the proposal before atomically persisting a one-use
/// reservation. Any head, high-water, or session transition must serialize
/// against live reservations.
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

const WINDOWS_HYPERV_EVIDENCE_SCHEMA_VERSION: u16 = 3;

/// Windows Hyper-V implementation of the provider-neutral lease-authority lifecycle.
pub struct WindowsHyperVLeaseAuthorityExtension {
    name: LeaseAuthorityName,
    broker_grants: Arc<dyn WindowsHyperVBrokerGrantIssuer>,
    grant_authorizations: Arc<dyn WindowsHyperVBrokerGrantAuthorizationRepository>,
    current_admissions: Arc<dyn WindowsHyperVCurrentAdmissionReader>,
    placement_renewals: Arc<dyn WindowsHyperVPlacementRenewalRepository>,
    admission_trust: Arc<dyn WindowsRunnerAdmissionTrustStore>,
}

impl fmt::Debug for WindowsHyperVLeaseAuthorityExtension {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("WindowsHyperVLeaseAuthorityExtension")
            .field("name", &self.name)
            .finish_non_exhaustive()
    }
}

impl WindowsHyperVLeaseAuthorityExtension {
    /// Composes every Windows-specific authority dependency behind one extension.
    ///
    /// # Errors
    ///
    /// Returns a corrupt configuration error if the canonical namespace cannot
    /// be constructed.
    pub fn new(
        broker_grants: Arc<dyn WindowsHyperVBrokerGrantIssuer>,
        grant_authorizations: Arc<dyn WindowsHyperVBrokerGrantAuthorizationRepository>,
        current_admissions: Arc<dyn WindowsHyperVCurrentAdmissionReader>,
        placement_renewals: Arc<dyn WindowsHyperVPlacementRenewalRepository>,
        admission_trust: Arc<dyn WindowsRunnerAdmissionTrustStore>,
    ) -> Result<Self, ControlPortError> {
        let name = LeaseAuthorityName::new(WINDOWS_HYPERV_SANDBOX_AUTHORIZATION_NAME)
            .map_err(|_| ControlPortError::Corrupt)?;
        Ok(Self {
            name,
            broker_grants,
            grant_authorizations,
            current_admissions,
            placement_renewals,
            admission_trust,
        })
    }
}

#[async_trait]
impl LeaseAuthorityExtension for WindowsHyperVLeaseAuthorityExtension {
    fn name(&self) -> &LeaseAuthorityName {
        &self.name
    }

    async fn accept_poll_contribution(
        &self,
        context: LeaseAuthorityPollAcceptance,
        contribution: &LeaseAuthorityPollContribution,
    ) -> Result<(), ControlPortError> {
        if contribution.name() != &self.name
            || contribution.payload_schema_version()
                != WINDOWS_RUNNER_PLACEMENT_RENEWAL_SCHEMA_VERSION
        {
            return Err(ControlPortError::Conflict);
        }
        let envelope = decode_windows_runner_placement_renewal_payload(contribution.payload())
            .map_err(|_| ControlPortError::Conflict)?;
        let now =
            u64::try_from(context.observed_at().get()).map_err(|_| ControlPortError::Corrupt)?;
        let verified =
            verify_windows_runner_placement_renewal(&envelope, self.admission_trust.as_ref(), now)
                .map_err(|_| ControlPortError::Conflict)?;
        let commit =
            CommitWindowsHyperVPlacementRenewal::new(context.session(), envelope, verified)?;
        self.placement_renewals.commit(commit).await?;
        Ok(())
    }

    async fn prepare_offer_evidence(
        &self,
        request: LeaseAuthorityOfferRequest<'_>,
    ) -> Result<Option<LeaseAuthorityEvidence>, ControlPortError> {
        let contribution = request
            .claimed()
            .authority_contributions()
            .get(self.name.as_str());
        let windows_job = request.job().job().requirements().operating_system()
            == Some(&OperatingSystem::Windows);
        if !windows_job {
            return if contribution.is_none() {
                Ok(None)
            } else {
                Err(ControlPortError::Conflict)
            };
        }
        let contribution = contribution.ok_or(ControlPortError::Unavailable)?;
        if contribution.payload_schema_version() != WINDOWS_RUNNER_PLACEMENT_RENEWAL_SCHEMA_VERSION
        {
            return Err(ControlPortError::Conflict);
        }
        let envelope = decode_windows_runner_placement_renewal_payload(contribution.payload())
            .map_err(|_| ControlPortError::Conflict)?;
        let observed_at = u64::try_from(request.claimed().lease().issued_at().get())
            .map_err(|_| ControlPortError::Corrupt)?;
        let verified = verify_windows_runner_placement_renewal(
            &envelope,
            self.admission_trust.as_ref(),
            observed_at,
        )
        .map_err(|_| ControlPortError::Conflict)?;
        let evidence = WindowsHyperVPlacementEvidence::from_offer_request(request, &verified)?;
        let claims = verified.claims();
        let broker = claims.binding().broker_profile();
        if claims.runner_id() != request.session().runner_id()
            || claims.binding().transaction().runner_id() != request.session().runner_id()
            || broker.profile() != evidence.environment_profile()
            || !broker.network_disabled()
        {
            return Err(ControlPortError::Unavailable);
        }
        let current = self
            .current_admissions
            .current(request.session(), evidence.environment_profile())
            .await?
            .ok_or(ControlPortError::Unavailable)?;
        if current.runner_id() != request.claimed().lease().runner_id()
            || current.broker_host_id() != evidence.broker_host_id()
            || current.environment_profile() != evidence.environment_profile()
            || current.profile_contract_sha256() != evidence.profile_contract_sha256()
            || current.sandbox_pids_limit() != evidence.sandbox_pids_limit()
            || current.placement_valid_until() != evidence.placement_valid_until()
            || current.renewal_serial() != evidence.placement_renewal_serial()
            || current.renewal_envelope_sha256() != evidence.placement_renewal_envelope_sha256()
        {
            return Err(ControlPortError::Unavailable);
        }
        let payload = serde_json::to_vec(&evidence).map_err(|_| ControlPortError::Corrupt)?;
        LeaseAuthorityEvidence::new(
            self.name.clone(),
            WINDOWS_HYPERV_EVIDENCE_SCHEMA_VERSION,
            payload,
        )
        .map(Some)
        .map_err(|_| ControlPortError::Corrupt)
    }

    async fn prepare_sandbox_authorization(
        &self,
        evidence: &LeaseAuthorityEvidence,
        job: &JobIrEnvelope,
        delivery: &RuntimeAuthorityDeliveryAdmission,
    ) -> Result<Box<dyn PreparedSandboxAuthorization>, ControlPortError> {
        if evidence.name() != &self.name
            || evidence.payload_schema_version() != WINDOWS_HYPERV_EVIDENCE_SCHEMA_VERSION
            || !windows_job_is_offline_credential_free(job)
            || !delivery.offer().command_projection_valid()
            || !delivery.offer().managed_secret_bindings_empty()
        {
            return Err(ControlPortError::Unavailable);
        }
        let placement: WindowsHyperVPlacementEvidence =
            serde_json::from_slice(evidence.payload()).map_err(|_| ControlPortError::Corrupt)?;
        let canonical = serde_json::to_vec(&placement).map_err(|_| ControlPortError::Corrupt)?;
        if canonical.as_slice() != evidence.payload() {
            return Err(ControlPortError::Corrupt);
        }
        let offer = delivery.offer();
        if !placement.is_valid_for_offer(job, offer)? {
            return Err(ControlPortError::Corrupt);
        }
        let current = self
            .current_admissions
            .current(offer.request().session(), placement.environment_profile())
            .await?
            .ok_or(ControlPortError::Unavailable)?;
        if current.runner_id() != offer.lease().runner_id()
            || current.broker_host_id() != placement.broker_host_id()
            || current.environment_profile() != placement.environment_profile()
            || current.profile_contract_sha256() != placement.profile_contract_sha256()
            || current.sandbox_pids_limit() != placement.sandbox_pids_limit()
            || current.placement_valid_until() != placement.placement_valid_until()
            || current.renewal_serial() != placement.placement_renewal_serial()
            || current.renewal_envelope_sha256() != placement.placement_renewal_envelope_sha256()
        {
            return Err(ControlPortError::Unavailable);
        }
        let issuance = WindowsHyperVBrokerGrantIssueRequest::new(
            &placement,
            &current,
            offer,
            job,
            delivery.request().request(),
        )?;
        let proposal = self.broker_grants.propose(&issuance)?;
        let request = AuthorizeWindowsHyperVBrokerGrant::new(delivery.clone(), current, proposal)?;
        let reservation = self.grant_authorizations.authorize(request).await?;
        let grant = self.broker_grants.issue(&reservation)?;
        let payload = encode_windows_hyperv_broker_grant_payload(&grant);
        let authorization = SandboxAuthorization::new(
            SandboxAuthorizationName::new(WINDOWS_HYPERV_SANDBOX_AUTHORIZATION_NAME)
                .map_err(|_| ControlPortError::Corrupt)?,
            WINDOWS_HYPERV_BROKER_GRANT_SCHEMA_V4,
            payload,
        )
        .map_err(|_| ControlPortError::Corrupt)?;
        Ok(Box::new(PreparedWindowsHyperVAuthorization {
            authorization,
            grant,
            reservation,
            repository: Arc::clone(&self.grant_authorizations),
        }))
    }
}

struct PreparedWindowsHyperVAuthorization {
    authorization: SandboxAuthorization,
    grant: WindowsHyperVBrokerGrant,
    reservation: WindowsHyperVBrokerGrantIssuanceAuthorization,
    repository: Arc<dyn WindowsHyperVBrokerGrantAuthorizationRepository>,
}

impl fmt::Debug for PreparedWindowsHyperVAuthorization {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PreparedWindowsHyperVAuthorization")
            .field("authorization", &self.authorization)
            .finish_non_exhaustive()
    }
}

#[async_trait]
impl PreparedSandboxAuthorization for PreparedWindowsHyperVAuthorization {
    fn authorization(&self) -> &SandboxAuthorization {
        &self.authorization
    }

    async fn commit(
        self: Box<Self>,
        delivery: CommitRuntimeAuthorityDelivery,
    ) -> Result<RuntimeAuthorityDeliveryDisposition, ControlPortError> {
        let commit =
            CommitWindowsHyperVBrokerGrantDelivery::new(self.reservation, delivery, &self.grant)?;
        self.repository.commit(commit).await
    }
}

fn windows_job_is_offline_credential_free(job: &JobIrEnvelope) -> bool {
    let job = job.job();
    job.requirements().operating_system() == Some(&OperatingSystem::Windows)
        && job.authority_profile() == JobAuthorityProfile::CredentialFree
        && job
            .permission_request()
            .grants()
            .is_some_and(<[_]>::is_empty)
}

#[cfg(test)]
mod tests {
    use std::sync::{
        Mutex,
        atomic::{AtomicUsize, Ordering},
    };

    use automata_ci_core::{
        AttemptId, EnvironmentProfileId, FencingToken, GitObjectId, JobContentReference,
        JobExecutionContext, JobId, JobInstanceIdentity, JobIr, JobPermissionRequest,
        JobResourceAllocation, JobSource, LeaseId, OperationId, ResourceCapacity, RunId,
        RunValueTemplates, RunnerCapabilities, RunnerFeature, RunnerPlatform, RunnerRequirements,
        RunnerSessionId, RuntimeBoolean, SandboxCapabilities, SemanticStep, ShellTemplate, StepId,
        StepIr, TrustActorEvidence, TrustActorKind, TrustAutomationKind, TrustEventKind,
        TrustEvidence, TrustOriginKind, TrustPolicy, TrustRepositoryEvidence, TrustSnapshot,
        TrustTokenRecursion, ValueTemplate, WorkflowId,
    };
    use automata_ci_protocol::{
        CommandSequence as ProtocolCommandSequence, INITIAL_RUNTIME_AUTHORITY_GENERATION,
        LeaseAuthorityPollContributions, ProtocolLimits, RunnerSlotOrdinal,
        RuntimeAuthorityDeliveryBinding, WINDOWS_RUNNER_ADMISSION_PROVIDER_ID,
        WindowsAdmissionImage, WindowsAdmissionValidity, WindowsAuthorityAdmissionEvidence,
        WindowsBrokerAdmissionEvidence, WindowsBrokerProfileBinding,
        WindowsEnrollmentTransactionBinding, WindowsImagePromotionBinding,
        WindowsPromotionValidity, WindowsRunnerAdmissionBinding, WindowsRunnerAdmissionEvidence,
        WindowsRunnerAdmissionTrustAnchor, WindowsRunnerPlacementRenewalClaims,
    };
    use automata_ci_protocol_protobuf::{
        decode_windows_hyperv_broker_grant_payload, encode_job_ir,
        encode_windows_runner_placement_renewal_payload,
    };
    use automata_ci_store::{
        CommandSequence as StoreCommandSequence, JobIrMetadata, ObjectKey, RunnerGeneration,
        RunnerOperationKind, RunnerProtocolVersion, SessionEpoch, StableRunnerSlot,
    };

    use crate::{
        lease::ClaimedLeasePoll,
        runner_control::durable::{
            AuthorizeRuntimeAuthorityDelivery, RuntimeAuthorityOfferCommand,
        },
    };

    use super::*;

    const NOW: u64 = 1_800_000_000_000;

    fn digest(byte: u8) -> Sha256Digest {
        Sha256Digest::from_bytes([byte; 32])
    }

    #[derive(Debug)]
    struct TrustStore(BTreeMap<String, WindowsRunnerAdmissionTrustAnchor>);

    impl WindowsRunnerAdmissionTrustStore for TrustStore {
        fn admission_trust_anchor(
            &self,
            issuer_key_id: &str,
        ) -> Option<WindowsRunnerAdmissionTrustAnchor> {
            self.0.get(issuer_key_id).cloned()
        }
    }

    #[derive(Debug, Default)]
    struct RenewalRepository {
        commits: AtomicUsize,
    }

    #[async_trait]
    impl WindowsHyperVPlacementRenewalRepository for RenewalRepository {
        async fn commit(
            &self,
            _request: CommitWindowsHyperVPlacementRenewal,
        ) -> Result<WindowsHyperVPlacementRenewalDisposition, ControlPortError> {
            self.commits.fetch_add(1, Ordering::SeqCst);
            Ok(WindowsHyperVPlacementRenewalDisposition::Committed)
        }
    }

    #[derive(Debug)]
    struct CurrentAdmissions(Mutex<WindowsHyperVCurrentAdmission>);

    impl CurrentAdmissions {
        fn new(current: WindowsHyperVCurrentAdmission) -> Self {
            Self(Mutex::new(current))
        }

        fn replace(&self, current: WindowsHyperVCurrentAdmission) {
            *self.0.lock().expect("current admission") = current;
        }

        fn snapshot(&self) -> WindowsHyperVCurrentAdmission {
            self.0.lock().expect("current admission").clone()
        }
    }

    #[async_trait]
    impl WindowsHyperVCurrentAdmissionReader for CurrentAdmissions {
        async fn current(
            &self,
            session: RunnerSessionFence,
            environment_profile: &EnvironmentProfile,
        ) -> Result<Option<WindowsHyperVCurrentAdmission>, ControlPortError> {
            let current = self.snapshot();
            Ok((current.runner_id() == session.runner_id()
                && current.environment_profile() == environment_profile)
                .then_some(current))
        }
    }

    #[derive(Debug, Default)]
    struct GrantRepository {
        authorizations: AtomicUsize,
        commits: AtomicUsize,
    }

    #[async_trait]
    impl WindowsHyperVBrokerGrantAuthorizationRepository for GrantRepository {
        async fn authorize(
            &self,
            request: AuthorizeWindowsHyperVBrokerGrant,
        ) -> Result<WindowsHyperVBrokerGrantIssuanceAuthorization, ControlPortError> {
            self.authorizations.fetch_add(1, Ordering::SeqCst);
            let issued_at = request.proposal().claims().issued_at().get();
            let valid_until = request.proposal().claims().expires_at();
            WindowsHyperVBrokerGrantIssuanceAuthorization::new(
                request,
                digest(0x40),
                UnixMillis::new(issued_at + 200),
                valid_until,
            )
        }

        async fn commit(
            &self,
            _request: CommitWindowsHyperVBrokerGrantDelivery,
        ) -> Result<RuntimeAuthorityDeliveryDisposition, ControlPortError> {
            self.commits.fetch_add(1, Ordering::SeqCst);
            Ok(RuntimeAuthorityDeliveryDisposition::Committed)
        }
    }

    #[derive(Debug)]
    struct CountingIssuer {
        inner: Ed25519WindowsHyperVBrokerGrantIssuer,
        proposals: AtomicUsize,
        issues: AtomicUsize,
    }

    impl WindowsHyperVBrokerGrantIssuer for CountingIssuer {
        fn propose(
            &self,
            request: &WindowsHyperVBrokerGrantIssueRequest<'_>,
        ) -> Result<WindowsHyperVBrokerGrantProposal, ControlPortError> {
            self.proposals.fetch_add(1, Ordering::SeqCst);
            self.inner.propose(request)
        }

        fn issue(
            &self,
            authorization: &WindowsHyperVBrokerGrantIssuanceAuthorization,
        ) -> Result<WindowsHyperVBrokerGrant, ControlPortError> {
            self.issues.fetch_add(1, Ordering::SeqCst);
            self.inner.issue(authorization)
        }
    }

    struct ContractFixture {
        extension: WindowsHyperVLeaseAuthorityExtension,
        renewal_repository: Arc<RenewalRepository>,
        grant_repository: Arc<GrantRepository>,
        current_admissions: Arc<CurrentAdmissions>,
        issuer: Arc<CountingIssuer>,
        session: RunnerSessionFence,
        contribution: LeaseAuthorityPollContribution,
        claimed: ClaimedLeasePoll,
        job: JobIrEnvelope,
    }

    fn trusted_snapshot() -> TrustSnapshot {
        TrustPolicy::current()
            .evaluate(
                TrustEvidence::new(TrustOriginKind::ProviderWebhook, TrustEventKind::Push)
                    .with_original_actor(
                        TrustActorEvidence::new(
                            "windows-contract",
                            TrustActorKind::User,
                            TrustAutomationKind::None,
                        )
                        .expect("actor evidence"),
                    )
                    .with_repositories(
                        TrustRepositoryEvidence::new("42", "7").expect("source repository"),
                        TrustRepositoryEvidence::new("42", "7").expect("target repository"),
                    )
                    .with_refs("refs/heads/main", "refs/heads/main", "refs/heads/main")
                    .with_revisions("source-sha", "target-sha", "execution-sha")
                    .with_fork(false)
                    .with_token_recursion(TrustTokenRecursion::Suppressed),
            )
            .expect("complete trust snapshot")
    }

    fn windows_job(profile: EnvironmentProfile) -> JobIrEnvelope {
        let capacity = ResourceCapacity::new(1_000, 1 << 30, 1 << 30, 0);
        let requirements = RunnerRequirements::default()
            .with_windows_hyperv_container()
            .with_architecture(Architecture::X86_64)
            .with_environment_profile(profile)
            .with_resource_allocation(
                JobResourceAllocation::new(capacity, capacity).expect("resource allocation"),
            );
        JobIrEnvelope::new(
            WorkflowId::new(),
            JobSource::new(
                "github",
                "automata-ci/automata",
                GitObjectId::from_provider_hex("0123456789abcdef0123456789abcdef01234567")
                    .expect("revision"),
                ".github/workflows/windows.yml",
                "push",
            ),
            JobExecutionContext::new(
                "Windows",
                "refs/heads/main",
                "C:\\__w\\automata\\automata",
                JobContentReference::new("events/push.json", digest(0x71), 2, "application/json"),
                JobContentReference::new(
                    "contexts/windows.pb",
                    digest(0x72),
                    2,
                    "application/vnd.automata.job-runtime-context.protobuf",
                ),
            ),
            JobIr::new(
                JobId::new(),
                RunId::new(),
                "windows-contract",
                requirements,
                JobInstanceIdentity::new("windows-contract", 0, 1, digest(0x73))
                    .expect("job instance"),
                false,
                vec![StepIr::new(
                    StepId::new("test").expect("step ID"),
                    ValueTemplate::literal("Test").expect("step name"),
                    RuntimeBoolean::literal(false),
                    SemanticStep::run(RunValueTemplates::new(
                        ValueTemplate::literal("cargo test").expect("command"),
                        ShellTemplate::default_shell(),
                    )),
                )],
            )
            .with_trust_snapshot(trusted_snapshot())
            .with_authority_profile(JobAuthorityProfile::CredentialFree)
            .with_permission_request(JobPermissionRequest::mapping([])),
        )
    }

    fn renewal_binding(
        runner_id: RunnerId,
        broker_host_id: &str,
        profile: EnvironmentProfile,
    ) -> WindowsRunnerAdmissionBinding {
        let capabilities = RunnerCapabilities::new(
            runner_id,
            RunnerPlatform::new(OperatingSystem::Windows, Architecture::X86_64),
        )
        .with_sandbox(SandboxCapabilities::new(
            IsolationLevel::VirtualMachine,
            [SandboxFeature::WINDOWS_HYPERV_CONTAINER],
        ))
        .with_features([RunnerFeature::SHELL_STEPS])
        .with_environment_profiles([profile.clone()]);
        let transaction = WindowsEnrollmentTransactionBinding::new(
            runner_id,
            OperationId::new(),
            "https://control.example.test/",
            "https://enroll.example.test/",
            digest(1),
            digest(2),
            digest(3),
        )
        .expect("transaction binding");
        let image_digest = digest(5);
        let image = WindowsAdmissionImage::new(
            format!("registry.example.test/automata/windows@sha256:{image_digest}"),
            image_digest,
        )
        .expect("image");
        let broker_profile = WindowsBrokerProfileBinding::new(
            broker_host_id,
            WINDOWS_RUNNER_ADMISSION_PROVIDER_ID,
            digest(6),
            profile,
            image,
            digest(7),
            true,
            false,
            64,
        )
        .expect("broker profile");
        let promotion = WindowsImagePromotionBinding::new(
            "production.windows.v1",
            "promotion-key-v1",
            digest(8),
            digest(9),
            41,
            19,
            WindowsPromotionValidity::new(NOW - 60_000, NOW + 600_000).expect("promotion validity"),
        )
        .expect("promotion");
        WindowsRunnerAdmissionBinding::new(transaction, broker_profile, promotion, capabilities)
            .expect("admission binding")
    }

    fn renewal_evidence() -> WindowsRunnerAdmissionEvidence {
        let broker = WindowsBrokerAdmissionEvidence::new(
            digest(10),
            digest(11),
            digest(12),
            digest(13),
            digest(14),
        )
        .expect("broker evidence");
        let authority =
            WindowsAuthorityAdmissionEvidence::new(digest(15), digest(16), digest(17), digest(18))
                .expect("authority evidence");
        WindowsRunnerAdmissionEvidence::new(broker, authority)
    }

    fn signed_renewal(
        runner_id: RunnerId,
        broker_host: &str,
        profile: EnvironmentProfile,
        renewal_serial: u64,
        nonce: Sha256Digest,
        renewal_key: &Ed25519KeyPair,
    ) -> WindowsRunnerPlacementRenewalEnvelope {
        let issuer = "broker-admission-v1";
        let claims = WindowsRunnerPlacementRenewalClaims::new(
            issuer,
            runner_id,
            renewal_serial,
            nonce,
            digest(21),
            renewal_binding(runner_id, broker_host, profile),
            renewal_evidence(),
            WindowsAdmissionValidity::new(NOW - 1_000, NOW + 60_000).expect("renewal validity"),
        )
        .expect("renewal claims");
        WindowsRunnerPlacementRenewalEnvelope::new(
            issuer,
            claims.canonical_bytes().expect("canonical claims"),
            renewal_key
                .sign(&claims.signing_bytes().expect("signing bytes"))
                .as_ref()
                .to_vec(),
        )
        .expect("renewal envelope")
    }

    fn renewal_trust_store(
        renewal_key: &Ed25519KeyPair,
        broker_host: String,
        profile: EnvironmentProfile,
    ) -> TrustStore {
        let anchor = WindowsRunnerAdmissionTrustAnchor::new(
            renewal_key
                .public_key()
                .as_ref()
                .try_into()
                .expect("public key"),
            broker_host,
            profile,
            "production.windows.v1",
        )
        .expect("trust anchor");
        TrustStore(BTreeMap::from([("broker-admission-v1".to_owned(), anchor)]))
    }

    #[allow(clippy::too_many_lines)]
    fn fixture() -> ContractFixture {
        let runner_id = RunnerId::new();
        let session = RunnerSessionFence::new(
            RunnerSessionId::new(),
            runner_id,
            RunnerGeneration::new(7).expect("runner generation"),
            SessionEpoch::new(11).expect("session epoch"),
        );
        let profile = EnvironmentProfile::new(
            EnvironmentProfileId::new("automata.example/windows-server-2025").expect("profile ID"),
            digest(4),
        );
        let broker_host_id = digest(0xaa);
        let broker_host = broker_host_id.to_string();
        let renewal_key =
            Ed25519KeyPair::from_seed_unchecked(&[0x25; 32]).expect("renewal signing key");
        let envelope = signed_renewal(
            runner_id,
            &broker_host,
            profile.clone(),
            7,
            digest(20),
            &renewal_key,
        );
        let renewal_envelope_sha256 = envelope.envelope_sha256();
        let contribution = LeaseAuthorityPollContribution::new(
            LeaseAuthorityName::new(WINDOWS_HYPERV_SANDBOX_AUTHORIZATION_NAME)
                .expect("Windows namespace"),
            WINDOWS_RUNNER_PLACEMENT_RENEWAL_SCHEMA_VERSION,
            encode_windows_runner_placement_renewal_payload(&envelope),
        )
        .expect("poll contribution");
        let contributions = LeaseAuthorityPollContributions::new(vec![contribution.clone()])
            .expect("contribution bundle");
        let job = windows_job(profile.clone());
        let encoded = encode_job_ir(&job, &ProtocolLimits::default()).expect("encoded JobIR");
        let metadata = JobIrMetadata::new(
            job.job().job_id(),
            job.job().run_id(),
            job.version(),
            u64::try_from(encoded.len()).expect("encoded size"),
            Sha256Digest::from_bytes(Sha256::digest(&encoded).into()),
            ObjectKey::new("job-ir/windows-contract.pb").expect("object key"),
        )
        .expect("JobIR metadata");
        let lease = Lease::new(
            LeaseId::new(),
            AttemptId::new(),
            runner_id,
            FencingToken::new(5).expect("fencing token"),
            UnixMillis::new(i64::try_from(NOW).expect("now")),
            UnixMillis::new(i64::try_from(NOW + 30_000).expect("lease expiry")),
        )
        .expect("lease");
        let claimed = ClaimedLeasePoll::new(
            lease,
            RunnerSlotOrdinal::new(1).expect("slot"),
            metadata,
            contributions,
            true,
        );
        let trust_store = renewal_trust_store(&renewal_key, broker_host, profile.clone());
        let current = WindowsHyperVCurrentAdmission::new(
            runner_id,
            7,
            renewal_envelope_sha256,
            broker_host_id,
            profile,
            digest(14),
            64,
            UnixMillis::new(i64::try_from(NOW + 60_000).expect("renewal expiry")),
            UnixMillis::new(i64::try_from(NOW).expect("observed at")),
        )
        .expect("current admission");
        let current_admissions = Arc::new(CurrentAdmissions::new(current));
        let renewal_repository = Arc::new(RenewalRepository::default());
        let grant_repository = Arc::new(GrantRepository::default());
        let issuer = Arc::new(CountingIssuer {
            inner: Ed25519WindowsHyperVBrokerGrantIssuer::new(
                Zeroizing::new([0x35; 32]),
                BTreeMap::from([(runner_id, broker_host_id)]),
            )
            .expect("broker grant issuer"),
            proposals: AtomicUsize::new(0),
            issues: AtomicUsize::new(0),
        });
        let extension = WindowsHyperVLeaseAuthorityExtension::new(
            issuer.clone(),
            grant_repository.clone(),
            current_admissions.clone(),
            renewal_repository.clone(),
            Arc::new(trust_store),
        )
        .expect("Windows authority extension");
        ContractFixture {
            extension,
            renewal_repository,
            grant_repository,
            current_admissions,
            issuer,
            session,
            contribution,
            claimed,
            job,
        }
    }

    fn next_identical_projection_admission(
        previous: &WindowsHyperVCurrentAdmission,
    ) -> WindowsHyperVCurrentAdmission {
        let renewal_key =
            Ed25519KeyPair::from_seed_unchecked(&[0x25; 32]).expect("renewal signing key");
        let newer_envelope = signed_renewal(
            previous.runner_id(),
            &previous.broker_host_id().to_string(),
            previous.environment_profile().clone(),
            previous.renewal_serial() + 1,
            digest(0x22),
            &renewal_key,
        );
        WindowsHyperVCurrentAdmission::new(
            previous.runner_id(),
            previous.renewal_serial() + 1,
            newer_envelope.envelope_sha256(),
            previous.broker_host_id(),
            previous.environment_profile().clone(),
            previous.profile_contract_sha256(),
            previous.sandbox_pids_limit(),
            previous.placement_valid_until(),
            UnixMillis::new(i64::try_from(NOW).expect("observed at")),
        )
        .expect("newer current admission")
    }

    fn delivery(fixture: &ContractFixture) -> RuntimeAuthorityDeliveryAdmission {
        let lease = fixture.claimed.lease();
        let metadata = fixture.claimed.job_ir();
        let protocol = RunnerProtocolVersion::new(3).expect("protocol");
        let offer_operation_id = OperationId::new();
        let sequence = 1;
        let accepted = AcceptedRuntimeAuthorityOffer::new(
            RunnerOperationRequest::new(
                fixture.session,
                OperationId::new(),
                RunnerOperationKind::new("automata.runner.lease-request.v2")
                    .expect("lease request kind"),
                digest(0x31),
            ),
            protocol,
            StableRunnerSlot::new(fixture.claimed.slot().get()).expect("stable slot"),
            lease.clone(),
            metadata.clone(),
            lease.expires_at(),
            RuntimeAuthorityOfferCommand::new(
                offer_operation_id,
                StoreCommandSequence::new(sequence).expect("store command sequence"),
                UnixMillis::new(i64::try_from(NOW + 100).expect("command time")),
            ),
        )
        .expect("accepted offer");
        let binding = RuntimeAuthorityDeliveryBinding::new(
            lease.attempt_id(),
            fixture.claimed.slot(),
            lease.guard(),
            offer_operation_id,
            ProtocolCommandSequence::new(sequence).expect("protocol command sequence"),
            metadata.digest(),
            INITIAL_RUNTIME_AUTHORITY_GENERATION,
        );
        let authorization = AuthorizeRuntimeAuthorityDelivery::new(
            RunnerOperationRequest::new(
                fixture.session,
                OperationId::new(),
                RunnerOperationKind::new("automata.runner.runtime-authority-request.v2")
                    .expect("authority request kind"),
                digest(0x32),
            ),
            protocol,
            binding,
            UnixMillis::new(i64::try_from(NOW + 150).expect("authorization time")),
        )
        .expect("delivery authorization");
        RuntimeAuthorityDeliveryAdmission::new(authorization, accepted, None)
            .expect("delivery admission")
    }

    #[tokio::test]
    async fn accepted_renewal_survives_replayed_generic_claim_and_commits_specialized_delivery() {
        let fixture = fixture();
        fixture
            .extension
            .accept_poll_contribution(
                LeaseAuthorityPollAcceptance::new(
                    fixture.session,
                    UnixMillis::new(i64::try_from(NOW).expect("observed at")),
                ),
                &fixture.contribution,
            )
            .await
            .expect("accepted renewal");
        assert_eq!(fixture.renewal_repository.commits.load(Ordering::SeqCst), 1);
        assert!(fixture.claimed.was_replayed());
        assert_eq!(
            fixture
                .claimed
                .authority_contributions()
                .get(WINDOWS_HYPERV_SANDBOX_AUTHORIZATION_NAME),
            Some(&fixture.contribution)
        );

        let evidence = fixture
            .extension
            .prepare_offer_evidence(LeaseAuthorityOfferRequest::new(
                fixture.session,
                &fixture.claimed,
                &fixture.job,
            ))
            .await
            .expect("offer evidence")
            .expect("Windows evidence");
        let delivery = delivery(&fixture);
        let prepared = fixture
            .extension
            .prepare_sandbox_authorization(&evidence, &fixture.job, &delivery)
            .await
            .expect("prepared authorization");
        assert_eq!(
            prepared.authorization().name().as_str(),
            WINDOWS_HYPERV_SANDBOX_AUTHORIZATION_NAME
        );
        let grant = decode_windows_hyperv_broker_grant_payload(prepared.authorization().payload())
            .expect("canonical Windows grant");
        assert_eq!(
            grant.claims().lease_id(),
            fixture.claimed.lease().lease_id()
        );
        assert_eq!(
            fixture
                .grant_repository
                .authorizations
                .load(Ordering::SeqCst),
            1
        );
        let commit = CommitRuntimeAuthorityDelivery::new(
            delivery,
            digest(0x51),
            UnixMillis::new(i64::try_from(NOW + 500).expect("commit time")),
        )
        .expect("generic delivery commit");
        assert_eq!(
            prepared.commit(commit).await.expect("specialized commit"),
            RuntimeAuthorityDeliveryDisposition::Committed
        );
        assert_eq!(fixture.grant_repository.commits.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn identical_projection_newer_renewal_rejects_stale_evidence_before_reservation() {
        let fixture = fixture();
        let evidence = fixture
            .extension
            .prepare_offer_evidence(LeaseAuthorityOfferRequest::new(
                fixture.session,
                &fixture.claimed,
                &fixture.job,
            ))
            .await
            .expect("offer evidence")
            .expect("Windows evidence");

        let previous = fixture.current_admissions.snapshot();
        let newer = next_identical_projection_admission(&previous);
        assert_eq!(newer.broker_host_id(), previous.broker_host_id());
        assert_eq!(newer.environment_profile(), previous.environment_profile());
        assert_eq!(
            newer.profile_contract_sha256(),
            previous.profile_contract_sha256()
        );
        assert_eq!(newer.sandbox_pids_limit(), previous.sandbox_pids_limit());
        assert_eq!(
            newer.placement_valid_until(),
            previous.placement_valid_until()
        );
        assert_ne!(newer.renewal_serial(), previous.renewal_serial());
        assert_ne!(
            newer.renewal_envelope_sha256(),
            previous.renewal_envelope_sha256()
        );
        fixture.current_admissions.replace(newer);

        let error = fixture
            .extension
            .prepare_sandbox_authorization(&evidence, &fixture.job, &delivery(&fixture))
            .await
            .expect_err("stale renewal evidence must fail closed");
        assert_eq!(error, ControlPortError::Unavailable);
        assert_eq!(
            fixture
                .grant_repository
                .authorizations
                .load(Ordering::SeqCst),
            0
        );
        assert_eq!(fixture.issuer.proposals.load(Ordering::SeqCst), 0);
        assert_eq!(fixture.issuer.issues.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn identical_projection_newer_renewal_rejects_stale_claim_at_offer() {
        let fixture = fixture();
        let previous = fixture.current_admissions.snapshot();
        fixture
            .current_admissions
            .replace(next_identical_projection_admission(&previous));

        let error = fixture
            .extension
            .prepare_offer_evidence(LeaseAuthorityOfferRequest::new(
                fixture.session,
                &fixture.claimed,
                &fixture.job,
            ))
            .await
            .expect_err("stale claimed renewal must fail closed");
        assert_eq!(error, ControlPortError::Unavailable);
        assert_eq!(
            fixture
                .grant_repository
                .authorizations
                .load(Ordering::SeqCst),
            0
        );
        assert_eq!(fixture.issuer.proposals.load(Ordering::SeqCst), 0);
        assert_eq!(fixture.issuer.issues.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn authorize_rejects_stale_proposal_against_identical_newer_renewal() {
        let fixture = fixture();
        let evidence = fixture
            .extension
            .prepare_offer_evidence(LeaseAuthorityOfferRequest::new(
                fixture.session,
                &fixture.claimed,
                &fixture.job,
            ))
            .await
            .expect("offer evidence")
            .expect("Windows evidence");
        let placement: WindowsHyperVPlacementEvidence =
            serde_json::from_slice(evidence.payload()).expect("placement evidence");
        let delivery = delivery(&fixture);
        let previous = fixture.current_admissions.snapshot();
        let issuance = WindowsHyperVBrokerGrantIssueRequest::new(
            &placement,
            &previous,
            delivery.offer(),
            &fixture.job,
            delivery.request().request(),
        )
        .expect("grant issue request");
        let proposal = fixture.issuer.propose(&issuance).expect("grant proposal");
        assert_eq!(proposal.renewal_serial(), previous.renewal_serial());
        assert_eq!(
            proposal.renewal_envelope_sha256(),
            previous.renewal_envelope_sha256()
        );

        let newer = next_identical_projection_admission(&previous);
        assert_eq!(
            AuthorizeWindowsHyperVBrokerGrant::new(delivery, newer, proposal)
                .expect_err("stale proposal must fail before durable reservation"),
            ControlPortError::Corrupt
        );
        assert_eq!(
            fixture
                .grant_repository
                .authorizations
                .load(Ordering::SeqCst),
            0
        );
        assert_eq!(fixture.issuer.proposals.load(Ordering::SeqCst), 1);
        assert_eq!(fixture.issuer.issues.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn missing_or_substituted_windows_contribution_fails_closed() {
        let fixture = fixture();
        let missing = ClaimedLeasePoll::new(
            fixture.claimed.lease().clone(),
            fixture.claimed.slot(),
            fixture.claimed.job_ir().clone(),
            LeaseAuthorityPollContributions::empty(),
            true,
        );
        assert_eq!(
            fixture
                .extension
                .prepare_offer_evidence(LeaseAuthorityOfferRequest::new(
                    fixture.session,
                    &missing,
                    &fixture.job,
                ))
                .await,
            Err(ControlPortError::Unavailable)
        );

        let substituted = LeaseAuthorityPollContribution::new(
            LeaseAuthorityName::new("automata.test.substituted-windows")
                .expect("substituted namespace"),
            fixture.contribution.payload_schema_version(),
            fixture.contribution.payload().to_vec(),
        )
        .expect("substituted contribution");
        let substituted = ClaimedLeasePoll::new(
            fixture.claimed.lease().clone(),
            fixture.claimed.slot(),
            fixture.claimed.job_ir().clone(),
            LeaseAuthorityPollContributions::new(vec![substituted]).expect("substituted bundle"),
            true,
        );
        assert_eq!(
            fixture
                .extension
                .prepare_offer_evidence(LeaseAuthorityOfferRequest::new(
                    fixture.session,
                    &substituted,
                    &fixture.job,
                ))
                .await,
            Err(ControlPortError::Unavailable)
        );
    }
}
