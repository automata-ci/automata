//! Value-free authority carried from Windows placement to the restricted host broker.

use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use thiserror::Error;

use crate::{
    AttemptId, EnvironmentProfile, FencingToken, JobId, JobIrVersion, JobResourceAllocation,
    LeaseId, OperationId, RunId, RunnerId, RunnerSessionId, Sha256Digest, UnixMillis,
};

/// Current schema for a signed Windows Hyper-V broker grant.
pub const WINDOWS_HYPERV_BROKER_GRANT_SCHEMA_V4: u16 = 4;
/// Provider-neutral sandbox-authorization namespace owned by the Windows Hyper-V adapter.
pub const WINDOWS_HYPERV_SANDBOX_AUTHORIZATION_NAME: &str = "windows-hyperv";
/// Exact Ed25519 signature size accepted by the broker contract.
pub const WINDOWS_HYPERV_BROKER_GRANT_SIGNATURE_BYTES: usize = 64;

const SIGNING_DOMAIN: &[u8] = b"automata.windows-hyperv-broker-grant.v4\0";
const DIGEST_DOMAIN: &[u8] = b"automata.windows-hyperv-broker-grant-digest.v4\0";
const SANDBOX_SPEC_DOMAIN: &[u8] = b"automata.windows-hyperv-sandbox-spec.v4\0";
const WINDOWS_HYPERV_PROVIDER_ID: &[u8] = b"windows-hyperv";

/// Immutable, value-free claims authorizing one exact Windows Hyper-V placement.
///
/// The claims deliberately contain no credential material, runtime command line,
/// host path, container-engine endpoint, or caller-selected HCS document. The
/// placement digest is derived by the control plane from its server-only grant;
/// the restricted broker verifies the signature and consumes it once.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WindowsHyperVBrokerGrantClaims {
    host_id: Sha256Digest,
    placement_binding_digest: Sha256Digest,
    attempt_id: AttemptId,
    job_id: JobId,
    run_id: RunId,
    poll_operation_id: OperationId,
    accepted_offer_operation_id: OperationId,
    accepted_offer_sequence: u64,
    post_accept_operation_id: OperationId,
    post_accept_request_digest: Sha256Digest,
    runner_id: RunnerId,
    runner_session_id: RunnerSessionId,
    runner_generation: u64,
    session_epoch: u64,
    slot: u16,
    lease_id: LeaseId,
    fencing_token: FencingToken,
    job_ir_version: JobIrVersion,
    job_ir_encoded_size: u64,
    job_ir_digest: Sha256Digest,
    job_ir_object_key_digest: Sha256Digest,
    job_resource_allocation: JobResourceAllocation,
    sandbox_pids_limit: u32,
    trust_binding_digest: Sha256Digest,
    environment_profile: EnvironmentProfile,
    profile_contract_sha256: Sha256Digest,
    sandbox_spec_sha256: Sha256Digest,
    issued_at: UnixMillis,
    expires_at: UnixMillis,
}

impl WindowsHyperVBrokerGrantClaims {
    /// Builds and validates the complete metadata binding for one placement.
    ///
    /// # Errors
    ///
    /// Rejects nil identities, zero counters, empty `JobIR`, zero security
    /// digests, or a non-positive validity interval.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        host_id: Sha256Digest,
        placement_binding_digest: Sha256Digest,
        attempt_id: AttemptId,
        job_id: JobId,
        run_id: RunId,
        poll_operation_id: OperationId,
        accepted_offer_operation_id: OperationId,
        accepted_offer_sequence: u64,
        post_accept_operation_id: OperationId,
        post_accept_request_digest: Sha256Digest,
        runner_id: RunnerId,
        runner_session_id: RunnerSessionId,
        runner_generation: u64,
        session_epoch: u64,
        slot: u16,
        lease_id: LeaseId,
        fencing_token: FencingToken,
        job_ir_version: JobIrVersion,
        job_ir_encoded_size: u64,
        job_ir_digest: Sha256Digest,
        job_ir_object_key_digest: Sha256Digest,
        job_resource_allocation: JobResourceAllocation,
        sandbox_pids_limit: u32,
        trust_binding_digest: Sha256Digest,
        environment_profile: EnvironmentProfile,
        profile_contract_sha256: Sha256Digest,
        issued_at: UnixMillis,
        expires_at: UnixMillis,
    ) -> Result<Self, WindowsHyperVBrokerGrantError> {
        let mut claims = Self {
            host_id,
            placement_binding_digest,
            attempt_id,
            job_id,
            run_id,
            poll_operation_id,
            accepted_offer_operation_id,
            accepted_offer_sequence,
            post_accept_operation_id,
            post_accept_request_digest,
            runner_id,
            runner_session_id,
            runner_generation,
            session_epoch,
            slot,
            lease_id,
            fencing_token,
            job_ir_version,
            job_ir_encoded_size,
            job_ir_digest,
            job_ir_object_key_digest,
            job_resource_allocation,
            sandbox_pids_limit,
            trust_binding_digest,
            environment_profile,
            profile_contract_sha256,
            sandbox_spec_sha256: Sha256Digest::from_bytes([0; 32]),
            issued_at,
            expires_at,
        };
        claims.sandbox_spec_sha256 = claims.compute_sandbox_spec_sha256();
        claims.validate()?;
        Ok(claims)
    }

    /// Validates claims after deserialization or before signing.
    ///
    /// # Errors
    ///
    /// Returns the first violated invariant.
    pub fn validate(&self) -> Result<(), WindowsHyperVBrokerGrantError> {
        if self.attempt_id.as_uuid().is_nil()
            || self.job_id.as_uuid().is_nil()
            || self.run_id.as_uuid().is_nil()
            || self.poll_operation_id.as_uuid().is_nil()
            || self.accepted_offer_operation_id.as_uuid().is_nil()
            || self.post_accept_operation_id.as_uuid().is_nil()
            || self.runner_id.as_uuid().is_nil()
            || self.runner_session_id.as_uuid().is_nil()
            || self.lease_id.as_uuid().is_nil()
        {
            return Err(WindowsHyperVBrokerGrantError::NilIdentity);
        }
        if self.runner_generation == 0
            || self.session_epoch == 0
            || self.slot == 0
            || self.accepted_offer_sequence == 0
        {
            return Err(WindowsHyperVBrokerGrantError::ZeroFence);
        }
        if self.job_ir_encoded_size == 0 {
            return Err(WindowsHyperVBrokerGrantError::EmptyJobIr);
        }
        if [
            self.host_id,
            self.placement_binding_digest,
            self.post_accept_request_digest,
            self.job_ir_digest,
            self.job_ir_object_key_digest,
            self.trust_binding_digest,
            self.environment_profile.digest(),
            self.profile_contract_sha256,
            self.sandbox_spec_sha256,
        ]
        .iter()
        .any(is_zero_digest)
        {
            return Err(WindowsHyperVBrokerGrantError::ZeroDigest);
        }
        if self.sandbox_pids_limit == 0 {
            return Err(WindowsHyperVBrokerGrantError::ZeroProcessLimit);
        }
        if self.sandbox_spec_sha256 != self.compute_sandbox_spec_sha256() {
            return Err(WindowsHyperVBrokerGrantError::SandboxSpecBindingMismatch);
        }
        if self.expires_at <= self.issued_at {
            return Err(WindowsHyperVBrokerGrantError::InvalidValidityInterval);
        }
        Ok(())
    }

    /// Returns the stable identity of the only host allowed to consume the grant.
    #[must_use]
    pub const fn host_id(&self) -> Sha256Digest {
        self.host_id
    }

    /// Returns the digest of the original server-only placement grant.
    #[must_use]
    pub const fn placement_binding_digest(&self) -> Sha256Digest {
        self.placement_binding_digest
    }

    /// Returns the authorized attempt identity.
    #[must_use]
    pub const fn attempt_id(&self) -> AttemptId {
        self.attempt_id
    }

    /// Returns the authorized job identity.
    #[must_use]
    pub const fn job_id(&self) -> JobId {
        self.job_id
    }

    /// Returns the authorized workflow-run identity.
    #[must_use]
    pub const fn run_id(&self) -> RunId {
        self.run_id
    }

    /// Returns the lease-poll operation that selected the placement.
    #[must_use]
    pub const fn poll_operation_id(&self) -> OperationId {
        self.poll_operation_id
    }

    /// Returns the durable offer command admitted by the acceptance transaction.
    #[must_use]
    pub const fn accepted_offer_operation_id(&self) -> OperationId {
        self.accepted_offer_operation_id
    }

    /// Returns the nonzero durable sequence of the accepted offer command.
    #[must_use]
    pub const fn accepted_offer_sequence(&self) -> u64 {
        self.accepted_offer_sequence
    }

    /// Returns the exact post-accept delivery request that caused issuance.
    #[must_use]
    pub const fn post_accept_operation_id(&self) -> OperationId {
        self.post_accept_operation_id
    }

    /// Returns the canonical digest of that post-accept request.
    #[must_use]
    pub const fn post_accept_request_digest(&self) -> Sha256Digest {
        self.post_accept_request_digest
    }

    /// Returns the authorized runner identity.
    #[must_use]
    pub const fn runner_id(&self) -> RunnerId {
        self.runner_id
    }

    /// Returns the authorized runner-session identity.
    #[must_use]
    pub const fn runner_session_id(&self) -> RunnerSessionId {
        self.runner_session_id
    }

    /// Returns the registered-runner generation fence.
    #[must_use]
    pub const fn runner_generation(&self) -> u64 {
        self.runner_generation
    }

    /// Returns the authenticated session epoch fence.
    #[must_use]
    pub const fn session_epoch(&self) -> u64 {
        self.session_epoch
    }

    /// Returns the one-based stable runner slot.
    #[must_use]
    pub const fn slot(&self) -> u16 {
        self.slot
    }

    /// Returns the authorized lease identity.
    #[must_use]
    pub const fn lease_id(&self) -> LeaseId {
        self.lease_id
    }

    /// Returns the durable lease fencing token.
    #[must_use]
    pub const fn fencing_token(&self) -> FencingToken {
        self.fencing_token
    }

    /// Returns the exact `JobIR` schema version.
    #[must_use]
    pub const fn job_ir_version(&self) -> JobIrVersion {
        self.job_ir_version
    }

    /// Returns the exact encoded `JobIR` byte length.
    #[must_use]
    pub const fn job_ir_encoded_size(&self) -> u64 {
        self.job_ir_encoded_size
    }

    /// Returns the exact `JobIR` content digest.
    #[must_use]
    pub const fn job_ir_digest(&self) -> Sha256Digest {
        self.job_ir_digest
    }

    /// Returns a digest of the credential-free durable `JobIR` object key.
    #[must_use]
    pub const fn job_ir_object_key_digest(&self) -> Sha256Digest {
        self.job_ir_object_key_digest
    }

    /// Returns the exact server-verified request and hard-limit allocation.
    #[must_use]
    pub const fn job_resource_allocation(&self) -> JobResourceAllocation {
        self.job_resource_allocation
    }

    /// Returns the exact hard process ceiling admitted for this sandbox.
    #[must_use]
    pub const fn sandbox_pids_limit(&self) -> u32 {
        self.sandbox_pids_limit
    }

    /// Returns the digest binding authenticated trust and requirements evidence.
    #[must_use]
    pub const fn trust_binding_digest(&self) -> Sha256Digest {
        self.trust_binding_digest
    }

    /// Returns the exact server-attested environment profile.
    #[must_use]
    pub const fn environment_profile(&self) -> &EnvironmentProfile {
        &self.environment_profile
    }

    /// Returns the broker-minted durable launch/profile contract identity.
    #[must_use]
    pub const fn profile_contract_sha256(&self) -> Sha256Digest {
        self.profile_contract_sha256
    }

    /// Returns the canonical signed authorization for the exact sandbox spec.
    #[must_use]
    pub const fn sandbox_spec_sha256(&self) -> Sha256Digest {
        self.sandbox_spec_sha256
    }

    /// Verifies the dynamic typed sandbox fields covered by the signed spec binding.
    ///
    /// The immutable image/argv/workspace/default-environment fields are
    /// resolved independently by the broker from `profile_contract_sha256`.
    #[must_use]
    #[allow(clippy::too_many_arguments)]
    pub fn authorizes_sandbox_spec(
        &self,
        profile_contract_sha256: Sha256Digest,
        generation: u64,
        allocation: JobResourceAllocation,
        pids_limit: u32,
        network_disabled: bool,
    ) -> bool {
        profile_contract_sha256 == self.profile_contract_sha256
            && generation == self.fencing_token.get()
            && allocation == self.job_resource_allocation
            && pids_limit == self.sandbox_pids_limit
            && network_disabled
            && self.sandbox_spec_sha256 == self.compute_sandbox_spec_sha256()
    }

    /// Returns the inclusive issue time.
    #[must_use]
    pub const fn issued_at(&self) -> UnixMillis {
        self.issued_at
    }

    /// Returns the exclusive expiry time.
    #[must_use]
    pub const fn expires_at(&self) -> UnixMillis {
        self.expires_at
    }

    /// Reports whether the grant is valid at `now` under `[issued, expires)` semantics.
    #[must_use]
    pub const fn is_valid_at(&self, now: UnixMillis) -> bool {
        now.get() >= self.issued_at.get() && now.get() < self.expires_at.get()
    }

    fn append_signing_fields(&self, bytes: &mut Vec<u8>) {
        field(bytes, self.host_id.as_bytes());
        field(bytes, self.placement_binding_digest.as_bytes());
        field(bytes, self.attempt_id.as_uuid().as_bytes());
        field(bytes, self.job_id.as_uuid().as_bytes());
        field(bytes, self.run_id.as_uuid().as_bytes());
        field(bytes, self.poll_operation_id.as_uuid().as_bytes());
        field(bytes, self.accepted_offer_operation_id.as_uuid().as_bytes());
        field(bytes, &self.accepted_offer_sequence.to_be_bytes());
        field(bytes, self.post_accept_operation_id.as_uuid().as_bytes());
        field(bytes, self.post_accept_request_digest.as_bytes());
        field(bytes, self.runner_id.as_uuid().as_bytes());
        field(bytes, self.runner_session_id.as_uuid().as_bytes());
        field(bytes, &self.runner_generation.to_be_bytes());
        field(bytes, &self.session_epoch.to_be_bytes());
        field(bytes, &self.slot.to_be_bytes());
        field(bytes, self.lease_id.as_uuid().as_bytes());
        field(bytes, &self.fencing_token.get().to_be_bytes());
        field(bytes, &self.job_ir_version.get().to_be_bytes());
        field(bytes, &self.job_ir_encoded_size.to_be_bytes());
        field(bytes, self.job_ir_digest.as_bytes());
        field(bytes, self.job_ir_object_key_digest.as_bytes());
        for capacity in [
            self.job_resource_allocation.requests(),
            self.job_resource_allocation.limits(),
        ] {
            field(bytes, &capacity.cpu_millis().to_be_bytes());
            field(bytes, &capacity.memory_bytes().to_be_bytes());
            field(bytes, &capacity.ephemeral_disk_bytes().to_be_bytes());
            field(bytes, &capacity.gpu_count().to_be_bytes());
        }
        field(bytes, &self.sandbox_pids_limit.to_be_bytes());
        field(bytes, self.trust_binding_digest.as_bytes());
        field(bytes, self.environment_profile.id().as_str().as_bytes());
        field(bytes, self.environment_profile.digest().as_bytes());
        field(bytes, self.profile_contract_sha256.as_bytes());
        field(bytes, self.sandbox_spec_sha256.as_bytes());
        field(bytes, &self.issued_at.get().to_be_bytes());
        field(bytes, &self.expires_at.get().to_be_bytes());
    }

    fn compute_sandbox_spec_sha256(&self) -> Sha256Digest {
        let mut bytes = Vec::with_capacity(640);
        bytes.extend_from_slice(SANDBOX_SPEC_DOMAIN);
        field(&mut bytes, WINDOWS_HYPERV_PROVIDER_ID);
        field(&mut bytes, &[1]);
        field(&mut bytes, self.host_id.as_bytes());
        field(&mut bytes, self.placement_binding_digest.as_bytes());
        field(&mut bytes, self.profile_contract_sha256.as_bytes());
        field(&mut bytes, self.post_accept_request_digest.as_bytes());
        field(&mut bytes, self.runner_id.as_uuid().as_bytes());
        field(&mut bytes, self.runner_session_id.as_uuid().as_bytes());
        field(&mut bytes, &self.runner_generation.to_be_bytes());
        field(&mut bytes, &self.session_epoch.to_be_bytes());
        field(&mut bytes, &self.slot.to_be_bytes());
        field(&mut bytes, self.attempt_id.as_uuid().as_bytes());
        field(&mut bytes, self.job_id.as_uuid().as_bytes());
        field(&mut bytes, self.run_id.as_uuid().as_bytes());
        field(&mut bytes, self.lease_id.as_uuid().as_bytes());
        field(&mut bytes, &self.fencing_token.get().to_be_bytes());
        field(&mut bytes, &self.job_ir_version.get().to_be_bytes());
        field(&mut bytes, &self.job_ir_encoded_size.to_be_bytes());
        field(&mut bytes, self.job_ir_digest.as_bytes());
        field(&mut bytes, self.job_ir_object_key_digest.as_bytes());
        field(&mut bytes, self.trust_binding_digest.as_bytes());
        field(
            &mut bytes,
            self.environment_profile.id().as_str().as_bytes(),
        );
        field(&mut bytes, self.environment_profile.digest().as_bytes());
        for capacity in [
            self.job_resource_allocation.requests(),
            self.job_resource_allocation.limits(),
        ] {
            field(&mut bytes, &capacity.cpu_millis().to_be_bytes());
            field(&mut bytes, &capacity.memory_bytes().to_be_bytes());
            field(&mut bytes, &capacity.ephemeral_disk_bytes().to_be_bytes());
            field(&mut bytes, &capacity.gpu_count().to_be_bytes());
        }
        field(&mut bytes, &self.sandbox_pids_limit.to_be_bytes());
        Sha256Digest::from_bytes(Sha256::digest(bytes).into())
    }
}

/// Versioned signed envelope consumed only by the restricted Windows host broker.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WindowsHyperVBrokerGrant {
    schema: u16,
    key_id: Sha256Digest,
    claims: WindowsHyperVBrokerGrantClaims,
    signature: Box<[u8]>,
}

impl WindowsHyperVBrokerGrant {
    /// Builds a current signed envelope from an issuer-produced signature.
    ///
    /// # Errors
    ///
    /// Rejects malformed claims, a zero key identifier, or any signature that
    /// is not exactly the Ed25519 signature length.
    pub fn new(
        key_id: Sha256Digest,
        claims: WindowsHyperVBrokerGrantClaims,
        signature: impl Into<Box<[u8]>>,
    ) -> Result<Self, WindowsHyperVBrokerGrantError> {
        Self::from_parts(
            WINDOWS_HYPERV_BROKER_GRANT_SCHEMA_V4,
            key_id,
            claims,
            signature,
        )
    }

    /// Rehydrates a versioned grant at a protocol or durable boundary.
    ///
    /// # Errors
    ///
    /// Rejects an unsupported schema or any malformed envelope field.
    pub fn from_parts(
        schema: u16,
        key_id: Sha256Digest,
        claims: WindowsHyperVBrokerGrantClaims,
        signature: impl Into<Box<[u8]>>,
    ) -> Result<Self, WindowsHyperVBrokerGrantError> {
        if schema != WINDOWS_HYPERV_BROKER_GRANT_SCHEMA_V4 {
            return Err(WindowsHyperVBrokerGrantError::UnsupportedSchema(schema));
        }
        if is_zero_digest(&key_id) {
            return Err(WindowsHyperVBrokerGrantError::ZeroKeyId);
        }
        claims.validate()?;
        let signature = signature.into();
        if signature.len() != WINDOWS_HYPERV_BROKER_GRANT_SIGNATURE_BYTES {
            return Err(WindowsHyperVBrokerGrantError::InvalidSignatureLength {
                received: signature.len(),
            });
        }
        Ok(Self {
            schema,
            key_id,
            claims,
            signature,
        })
    }

    /// Returns the envelope schema.
    #[must_use]
    pub const fn schema(&self) -> u16 {
        self.schema
    }

    /// Returns the issuer verification-key identifier.
    #[must_use]
    pub const fn key_id(&self) -> Sha256Digest {
        self.key_id
    }

    /// Returns the signed metadata claims.
    #[must_use]
    pub const fn claims(&self) -> &WindowsHyperVBrokerGrantClaims {
        &self.claims
    }

    /// Returns the exact detached Ed25519 signature bytes.
    #[must_use]
    pub fn signature(&self) -> &[u8] {
        &self.signature
    }

    /// Returns the exact domain-separated bytes an issuer signs and a broker verifies.
    #[must_use]
    pub fn signing_bytes_for(
        key_id: Sha256Digest,
        claims: &WindowsHyperVBrokerGrantClaims,
    ) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(640);
        bytes.extend_from_slice(SIGNING_DOMAIN);
        field(
            &mut bytes,
            &WINDOWS_HYPERV_BROKER_GRANT_SCHEMA_V4.to_be_bytes(),
        );
        field(&mut bytes, key_id.as_bytes());
        claims.append_signing_fields(&mut bytes);
        bytes
    }

    /// Returns the exact bytes covered by this envelope's signature.
    #[must_use]
    pub fn signing_bytes(&self) -> Vec<u8> {
        Self::signing_bytes_for(self.key_id, &self.claims)
    }

    /// Computes the stable one-use ledger identity of the complete envelope.
    #[must_use]
    pub fn digest(&self) -> Sha256Digest {
        let signing_bytes = self.signing_bytes();
        let mut digest = Sha256::new();
        digest.update(DIGEST_DOMAIN);
        digest.update((signing_bytes.len() as u64).to_be_bytes());
        digest.update(signing_bytes);
        digest.update((self.signature.len() as u64).to_be_bytes());
        digest.update(&self.signature);
        Sha256Digest::from_bytes(digest.finalize().into())
    }
}

fn field(bytes: &mut Vec<u8>, value: &[u8]) {
    bytes.extend_from_slice(&(value.len() as u64).to_be_bytes());
    bytes.extend_from_slice(value);
}

fn is_zero_digest(digest: &Sha256Digest) -> bool {
    digest.as_bytes().iter().all(|byte| *byte == 0)
}

/// Invalid signed Windows broker grant metadata or envelope.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum WindowsHyperVBrokerGrantError {
    /// A UUID identity was nil.
    #[error("Windows Hyper-V broker grant identities cannot be nil")]
    NilIdentity,
    /// A generation, epoch, or stable slot fence was zero.
    #[error("Windows Hyper-V broker grant fences must be positive")]
    ZeroFence,
    /// The selected `JobIR` had no encoded content.
    #[error("Windows Hyper-V broker grant cannot bind an empty JobIR")]
    EmptyJobIr,
    /// The admitted sandbox process ceiling was zero.
    #[error("Windows Hyper-V broker grant process limit must be positive")]
    ZeroProcessLimit,
    /// A security-relevant content digest was the all-zero sentinel.
    #[error("Windows Hyper-V broker grant digests cannot use the zero sentinel")]
    ZeroDigest,
    /// The stored exact-spec binding did not match the remaining claims.
    #[error("Windows Hyper-V broker sandbox-spec binding is inconsistent")]
    SandboxSpecBindingMismatch,
    /// The validity interval was empty or negative.
    #[error("Windows Hyper-V broker grant expiry must be after issuance")]
    InvalidValidityInterval,
    /// The envelope schema is not supported by this build.
    #[error("unsupported Windows Hyper-V broker grant schema {0}")]
    UnsupportedSchema(u16),
    /// The verification-key identity was the all-zero sentinel.
    #[error("Windows Hyper-V broker verification-key identity cannot be zero")]
    ZeroKeyId,
    /// The detached signature did not have the exact Ed25519 size.
    #[error(
        "Windows Hyper-V broker grant signature must contain exactly {WINDOWS_HYPERV_BROKER_GRANT_SIGNATURE_BYTES} bytes; received {received}"
    )]
    InvalidSignatureLength {
        /// Actual signature byte length.
        received: usize,
    },
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{EnvironmentProfileId, ResourceCapacity};

    fn claims() -> WindowsHyperVBrokerGrantClaims {
        let capacity = ResourceCapacity::new(2_000, 2 * 1024 * 1024 * 1024, 0, 0);
        WindowsHyperVBrokerGrantClaims::new(
            Sha256Digest::from_bytes([1; 32]),
            Sha256Digest::from_bytes([2; 32]),
            AttemptId::new(),
            JobId::new(),
            RunId::new(),
            OperationId::new(),
            OperationId::new(),
            1,
            OperationId::new(),
            Sha256Digest::from_bytes([3; 32]),
            RunnerId::new(),
            RunnerSessionId::new(),
            1,
            1,
            1,
            LeaseId::new(),
            FencingToken::new(1).expect("fencing token"),
            JobIrVersion::current(),
            128,
            Sha256Digest::from_bytes([4; 32]),
            Sha256Digest::from_bytes([5; 32]),
            JobResourceAllocation::new(capacity, capacity).expect("allocation"),
            64,
            Sha256Digest::from_bytes([6; 32]),
            EnvironmentProfile::new(
                EnvironmentProfileId::new("example.test/windows").expect("profile id"),
                Sha256Digest::from_bytes([7; 32]),
            ),
            Sha256Digest::from_bytes([8; 32]),
            UnixMillis::new(100),
            UnixMillis::new(200),
        )
        .expect("claims")
    }

    #[test]
    fn v4_signing_and_sandbox_binding_commit_to_exact_placement() {
        let key_id = Sha256Digest::from_bytes([9; 32]);
        let exact = claims();
        let mut substituted = exact.clone();
        substituted.sandbox_pids_limit += 1;
        substituted.sandbox_spec_sha256 = substituted.compute_sandbox_spec_sha256();
        let mut another_create_request = exact.clone();
        another_create_request.post_accept_operation_id = OperationId::new();

        assert_ne!(
            exact.sandbox_spec_sha256(),
            substituted.sandbox_spec_sha256()
        );
        assert_eq!(
            exact.sandbox_spec_sha256(),
            another_create_request.sandbox_spec_sha256(),
            "a retry's operation identity is not part of the sandbox spec"
        );
        assert_ne!(
            WindowsHyperVBrokerGrant::signing_bytes_for(key_id, &exact),
            WindowsHyperVBrokerGrant::signing_bytes_for(key_id, &substituted)
        );
        assert_ne!(
            WindowsHyperVBrokerGrant::signing_bytes_for(key_id, &exact),
            WindowsHyperVBrokerGrant::signing_bytes_for(key_id, &another_create_request),
            "the signed issuance evidence still commits to its request identity"
        );
        assert!(exact.authorizes_sandbox_spec(
            exact.profile_contract_sha256(),
            exact.fencing_token().get(),
            exact.job_resource_allocation(),
            exact.sandbox_pids_limit(),
            true,
        ));
        assert!(!exact.authorizes_sandbox_spec(
            exact.profile_contract_sha256(),
            exact.fencing_token().get(),
            exact.job_resource_allocation(),
            exact.sandbox_pids_limit() + 1,
            true,
        ));
    }
}
