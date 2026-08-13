//! Durable execution authority and key-retention ports for GitHub-compatible OIDC.

use std::{collections::BTreeMap, fmt};

use async_trait::async_trait;
use automata_ci_core::{
    AttemptId, FencingToken, JobId, JobIrVersion, Lease, RunId, RunnerId, RunnerSessionId,
    Sha256Digest, UnixMillis, WorkflowId,
};
pub use automata_ci_oidc_github::{
    MAXIMUM_OIDC_KEYS_PER_KEYRING, MAXIMUM_REQUEST_BEARER_CLOCK_SKEW_SECONDS,
    OIDC_JWKS_CACHE_SECONDS,
};
use automata_ci_oidc_github::{
    MAXIMUM_REQUEST_BEARER_LIFETIME_SECONDS, OidcAudience, OidcAuthorityId, OidcClaimSet,
    OidcKeyId, OidcSubject, RsaPublicJwk,
};
use sha2::{Digest as _, Sha256};
use thiserror::Error;

use crate::{
    GithubRepositoryName, JobIrMetadata, RunnerGeneration, RunnerSessionFence, StableRunnerSlot,
};

/// Maximum number of distinct default-or-explicit audience slots retained per authority.
pub const MAX_GITHUB_OIDC_ISSUANCE_SLOTS: usize = 64;
/// Domain prefix for the request-bearer HMAC key-material fingerprint.
///
/// The key loader computes SHA-256 over this prefix, then the raw key byte
/// length as an unsigned 64-bit big-endian integer, then the raw key bytes.
/// Only the resulting digest crosses the store boundary.
// foundation-governance: derived-contract owner=store kind=digest-domain
pub const GITHUB_OIDC_REQUEST_BEARER_KEY_FINGERPRINT_DOMAIN: &[u8] =
    b"automata/github-oidc/request-bearer-key-fingerprint:v1\0";
/// Domain prefix for the canonical public RS256 JWK fingerprint.
// foundation-governance: derived-contract owner=store kind=digest-domain
pub const GITHUB_OIDC_RS256_PUBLIC_KEY_FINGERPRINT_DOMAIN: &[u8] =
    b"automata/github-oidc/rs256-public-key-fingerprint:v1\0";
// foundation-governance: derived-contract owner=store kind=digest-domain
const GITHUB_OIDC_CLAIM_EVIDENCE_DOMAIN: &[u8] = b"automata/github-oidc/claim-evidence:v1\0";

/// Fingerprints canonical public RS256 key material without accepting a private key.
///
/// The preimage is the domain prefix followed by the canonical base64url modulus
/// byte length as unsigned 64-bit big endian and modulus ASCII bytes, then the
/// corresponding exponent length and ASCII bytes. The JWK `kid` is deliberately
/// excluded: the durable `(use, kid)` identity separately prevents one ID from
/// being reused for a different fingerprint.
#[must_use]
pub fn github_oidc_rs256_public_key_fingerprint(key: &RsaPublicJwk) -> Sha256Digest {
    let mut hasher = Sha256::new();
    hasher.update(GITHUB_OIDC_RS256_PUBLIC_KEY_FINGERPRINT_DOMAIN);
    hash_length_prefixed(&mut hasher, key.modulus().as_bytes());
    hash_length_prefixed(&mut hasher, key.exponent().as_bytes());
    Sha256Digest::from_bytes(hasher.finalize().into())
}

fn hash_length_prefixed(hasher: &mut Sha256, value: &[u8]) {
    hasher.update(
        u64::try_from(value.len())
            .expect("validated OIDC key material is bounded")
            .to_be_bytes(),
    );
    hasher.update(value);
}

/// Exact current execution coordinates authenticated before OIDC authority is reserved.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GithubOidcExecutionIdentity {
    workflow_id: WorkflowId,
    github_repository_name: GithubRepositoryName,
    run_id: RunId,
    job_id: JobId,
    lease: Lease,
    session: RunnerSessionFence,
    slot: StableRunnerSlot,
    job_ir: JobIrMetadata,
}

impl GithubOidcExecutionIdentity {
    /// Binds a verified current `JobIR` to one exact lease, runner session, and repository.
    ///
    /// # Errors
    ///
    /// Rejects cross-bound identities, non-current `JobIR`, negative lease time, or nil IDs.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        workflow_id: WorkflowId,
        github_repository_name: GithubRepositoryName,
        run_id: RunId,
        job_id: JobId,
        lease: Lease,
        session: RunnerSessionFence,
        slot: StableRunnerSlot,
        job_ir_metadata: JobIrMetadata,
    ) -> Result<Self, GithubOidcValueError> {
        lease
            .validate()
            .map_err(|_| GithubOidcValueError::InvalidExecution)?;
        if job_ir_metadata.version() != JobIrVersion::current()
            || job_ir_metadata.run_id() != run_id
            || job_ir_metadata.job_id() != job_id
            || lease.runner_id() != session.runner_id()
            || lease.issued_at().get() < 0
            || lease.expires_at().get() < 0
            || i64::try_from(lease.fencing_token().get()).is_err()
            || i64::try_from(session.session_epoch().get()).is_err()
            || i64::try_from(session.runner_generation().get()).is_err()
            || [
                workflow_id.as_uuid(),
                run_id.as_uuid(),
                job_id.as_uuid(),
                lease.attempt_id().as_uuid(),
                lease.lease_id().as_uuid(),
                lease.runner_id().as_uuid(),
                session.session_id().as_uuid(),
            ]
            .into_iter()
            .any(|identity| identity.is_nil())
        {
            return Err(GithubOidcValueError::InvalidExecution);
        }
        Ok(Self {
            workflow_id,
            github_repository_name,
            run_id,
            job_id,
            lease,
            session,
            slot,
            job_ir: job_ir_metadata,
        })
    }

    /// Returns the workflow definition identity encoded by the verified `JobIR`.
    #[must_use]
    pub const fn workflow_id(&self) -> WorkflowId {
        self.workflow_id
    }

    /// Returns the authenticated provider repository name.
    #[must_use]
    pub const fn github_repository_name(&self) -> &GithubRepositoryName {
        &self.github_repository_name
    }

    /// Returns the workflow run identity.
    #[must_use]
    pub const fn run_id(&self) -> RunId {
        self.run_id
    }

    /// Returns the concrete job identity.
    #[must_use]
    pub const fn job_id(&self) -> JobId {
        self.job_id
    }

    /// Returns the attempt identity.
    #[must_use]
    pub const fn attempt_id(&self) -> AttemptId {
        self.lease.attempt_id()
    }

    /// Returns the execution fencing token.
    #[must_use]
    pub const fn fencing_token(&self) -> FencingToken {
        self.lease.fencing_token()
    }

    /// Returns the exact lease proposed for durable authentication.
    #[must_use]
    pub const fn lease(&self) -> &Lease {
        &self.lease
    }

    /// Returns the exact authenticated runner identity.
    #[must_use]
    pub const fn runner_id(&self) -> RunnerId {
        self.lease.runner_id()
    }

    /// Returns the exact authenticated runner-session fence.
    #[must_use]
    pub const fn session(&self) -> RunnerSessionFence {
        self.session
    }

    /// Returns the exact runner session identity.
    #[must_use]
    pub const fn runner_session_id(&self) -> RunnerSessionId {
        self.session.session_id()
    }

    /// Returns the exact runner generation.
    #[must_use]
    pub const fn runner_generation(&self) -> RunnerGeneration {
        self.session.runner_generation()
    }

    /// Returns the stable runner slot that owns the lease.
    #[must_use]
    pub const fn slot(&self) -> StableRunnerSlot {
        self.slot
    }

    /// Returns immutable metadata for the verified current `JobIR` bytes.
    #[must_use]
    pub const fn job_ir(&self) -> &JobIrMetadata {
        &self.job_ir
    }
}

/// Closed subject-policy mode used to derive authenticated OIDC identity claims.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GithubOidcSubjectPolicyMode {
    /// Immutable-ID policy requiring signed positive numeric owner evidence.
    StableOwnerEvidence,
}

impl GithubOidcSubjectPolicyMode {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::StableOwnerEvidence => "stable_owner_evidence",
        }
    }

    pub(crate) fn from_str(value: &str) -> Result<Self, GithubOidcStoreError> {
        match value {
            "stable_owner_evidence" => Ok(Self::StableOwnerEvidence),
            _ => Err(GithubOidcStoreError::CorruptData),
        }
    }
}

/// Positive revision of the configured subject-claim policy.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct GithubOidcSubjectPolicyRevision(u64);

impl GithubOidcSubjectPolicyRevision {
    /// Creates a positive policy revision.
    ///
    /// # Errors
    ///
    /// Rejects zero.
    pub const fn new(value: u64) -> Result<Self, GithubOidcValueError> {
        if value == 0 || value > i64::MAX as u64 {
            return Err(GithubOidcValueError::InvalidPolicy);
        }
        Ok(Self(value))
    }

    /// Returns the positive revision.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn github_oidc_claim_evidence_digest(
    permission_evidence_sha256: Sha256Digest,
    subject_policy_mode: GithubOidcSubjectPolicyMode,
    subject_policy_revision: GithubOidcSubjectPolicyRevision,
    subject_policy_sha256: Sha256Digest,
    github_run_subject_evidence_sha256: Sha256Digest,
    github_owner_id: u64,
    subject: &OidcSubject,
    default_audience: &OidcAudience,
    additional_claims: &OidcClaimSet,
    configuration_sha256: Sha256Digest,
    request_bearer_verification_skew_seconds: u64,
    id_token_verifier_skew_seconds: u64,
) -> Sha256Digest {
    let mut hasher = Sha256::new();
    hasher.update(GITHUB_OIDC_CLAIM_EVIDENCE_DOMAIN);
    hash_length_prefixed(&mut hasher, subject_policy_mode.as_str().as_bytes());
    hasher.update(subject_policy_revision.get().to_be_bytes());
    hasher.update(permission_evidence_sha256.as_bytes());
    hasher.update(subject_policy_sha256.as_bytes());
    hasher.update(github_run_subject_evidence_sha256.as_bytes());
    hasher.update([1]);
    hasher.update(github_owner_id.to_be_bytes());
    hash_length_prefixed(&mut hasher, subject.as_str().as_bytes());
    hash_length_prefixed(&mut hasher, default_audience.as_str().as_bytes());
    hasher.update(
        u64::try_from(additional_claims.len())
            .expect("validated OIDC claim count is bounded")
            .to_be_bytes(),
    );
    for (name, value) in additional_claims.as_map() {
        hash_length_prefixed(&mut hasher, name.as_bytes());
        hash_length_prefixed(&mut hasher, value.as_bytes());
    }
    hasher.update(configuration_sha256.as_bytes());
    hasher.update(request_bearer_verification_skew_seconds.to_be_bytes());
    hasher.update(id_token_verifier_skew_seconds.to_be_bytes());
    Sha256Digest::from_bytes(hasher.finalize().into())
}

/// Current product policy evidence required before any ID-token slot is reserved.
///
/// This descriptor excludes per-execution subject and claim evidence. It binds the
/// configured subject-policy universe and issuer/claim configuration shared by the
/// authority resolver and issuance service, including the request and ID-token
/// verifier skews used for durable key retention. The same value must be passed to
/// authority policy resolution and the issuance adapter. Loaded key IDs are
/// deliberately outside the configuration fingerprint so normal key rotation does
/// not invalidate an otherwise current execution authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GithubOidcCurrentPolicy {
    subject_policy_mode: GithubOidcSubjectPolicyMode,
    subject_policy_revision: GithubOidcSubjectPolicyRevision,
    subject_policy_sha256: Sha256Digest,
    configuration_sha256: Sha256Digest,
    request_bearer_verification_skew_seconds: u64,
    id_token_verifier_skew_seconds: u64,
}

impl GithubOidcCurrentPolicy {
    /// Creates an exact current policy descriptor from authenticated configuration.
    ///
    /// # Errors
    ///
    /// Rejects either verifier skew above the shared five-minute safety bound.
    pub const fn new(
        subject_policy_mode: GithubOidcSubjectPolicyMode,
        subject_policy_revision: GithubOidcSubjectPolicyRevision,
        subject_policy_sha256: Sha256Digest,
        configuration_sha256: Sha256Digest,
        request_bearer_verification_skew_seconds: u64,
        id_token_verifier_skew_seconds: u64,
    ) -> Result<Self, GithubOidcValueError> {
        if !matches!(
            subject_policy_mode,
            GithubOidcSubjectPolicyMode::StableOwnerEvidence
        ) || request_bearer_verification_skew_seconds > MAXIMUM_REQUEST_BEARER_CLOCK_SKEW_SECONDS
            || id_token_verifier_skew_seconds > MAXIMUM_REQUEST_BEARER_CLOCK_SKEW_SECONDS
        {
            return Err(GithubOidcValueError::InvalidPolicy);
        }
        Ok(Self {
            subject_policy_mode,
            subject_policy_revision,
            subject_policy_sha256,
            configuration_sha256,
            request_bearer_verification_skew_seconds,
            id_token_verifier_skew_seconds,
        })
    }

    /// Returns the exact current subject-policy mode.
    #[must_use]
    pub const fn subject_policy_mode(&self) -> GithubOidcSubjectPolicyMode {
        self.subject_policy_mode
    }

    /// Returns the exact current subject-policy revision.
    #[must_use]
    pub const fn subject_policy_revision(&self) -> GithubOidcSubjectPolicyRevision {
        self.subject_policy_revision
    }

    /// Returns the exact current subject-policy fingerprint.
    #[must_use]
    pub const fn subject_policy_sha256(&self) -> Sha256Digest {
        self.subject_policy_sha256
    }

    /// Returns the exact current issuer/claim-universe fingerprint.
    #[must_use]
    pub const fn configuration_sha256(&self) -> Sha256Digest {
        self.configuration_sha256
    }

    /// Returns the request-bearer verifier skew bound into configuration.
    #[must_use]
    pub const fn request_bearer_verification_skew_seconds(&self) -> u64 {
        self.request_bearer_verification_skew_seconds
    }

    /// Returns the ID-token verifier skew covered by signing-key retention.
    #[must_use]
    pub const fn id_token_verifier_skew_seconds(&self) -> u64 {
        self.id_token_verifier_skew_seconds
    }
}

/// Exact private request-bearer proposal; only its digest crosses this boundary.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GithubOidcAuthorityProposal {
    authority_id: OidcAuthorityId,
    request_bearer_key_id: OidcKeyId,
    request_bearer_key_sha256: Sha256Digest,
    request_bearer_verification_skew_seconds: u64,
    issued_at_seconds: u64,
    expires_at_seconds: u64,
    request_bearer_sha256: Sha256Digest,
}

impl GithubOidcAuthorityProposal {
    /// Creates an exact bounded request-bearer proposal without credential bytes.
    ///
    /// # Errors
    ///
    /// Rejects an empty, inverted, or greater-than-24-hour interval.
    pub fn new(
        authority_id: OidcAuthorityId,
        request_bearer_key_id: OidcKeyId,
        request_bearer_key_sha256: Sha256Digest,
        request_bearer_verification_skew_seconds: u64,
        issued_at_seconds: u64,
        expires_at_seconds: u64,
        request_bearer_sha256: Sha256Digest,
    ) -> Result<Self, GithubOidcValueError> {
        if expires_at_seconds <= issued_at_seconds
            || expires_at_seconds.saturating_sub(issued_at_seconds)
                > MAXIMUM_REQUEST_BEARER_LIFETIME_SECONDS
            || request_bearer_verification_skew_seconds > MAXIMUM_REQUEST_BEARER_CLOCK_SKEW_SECONDS
            || expires_at_seconds
                .checked_add(request_bearer_verification_skew_seconds)
                .and_then(|deadline| i64::try_from(deadline).ok())
                .is_none()
            || issued_at_seconds
                .checked_mul(1_000)
                .and_then(|value| i64::try_from(value).ok())
                .is_none()
            || expires_at_seconds
                .checked_mul(1_000)
                .and_then(|value| i64::try_from(value).ok())
                .is_none()
        {
            return Err(GithubOidcValueError::InvalidBearerInterval);
        }
        Ok(Self {
            authority_id,
            request_bearer_key_id,
            request_bearer_key_sha256,
            request_bearer_verification_skew_seconds,
            issued_at_seconds,
            expires_at_seconds,
            request_bearer_sha256,
        })
    }

    /// Returns the fresh authority identity proposed for a new record.
    #[must_use]
    pub const fn authority_id(&self) -> OidcAuthorityId {
        self.authority_id
    }

    /// Returns the request-bearer key proposed for a new record.
    #[must_use]
    pub const fn request_bearer_key_id(&self) -> &OidcKeyId {
        &self.request_bearer_key_id
    }

    /// Returns the exact non-secret key-material fingerprint.
    #[must_use]
    pub const fn request_bearer_key_sha256(&self) -> Sha256Digest {
        self.request_bearer_key_sha256
    }

    /// Returns the configured verification skew covered by key retention.
    #[must_use]
    pub const fn request_bearer_verification_skew_seconds(&self) -> u64 {
        self.request_bearer_verification_skew_seconds
    }

    /// Returns the deadline through which the request-bearer key must remain loaded.
    #[must_use]
    pub const fn request_bearer_key_not_after_seconds(&self) -> u64 {
        self.expires_at_seconds + self.request_bearer_verification_skew_seconds
    }

    /// Returns the inclusive request-bearer issuance second.
    #[must_use]
    pub const fn issued_at_seconds(&self) -> u64 {
        self.issued_at_seconds
    }

    /// Returns the exclusive request-bearer deadline.
    #[must_use]
    pub const fn expires_at_seconds(&self) -> u64 {
        self.expires_at_seconds
    }

    /// Returns the digest of the exact deterministic request-bearer bytes.
    #[must_use]
    pub const fn request_bearer_sha256(&self) -> Sha256Digest {
        self.request_bearer_sha256
    }
}

/// Atomic request to authenticate and reserve one immutable OIDC execution authority.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReserveGithubOidcAuthority {
    execution: GithubOidcExecutionIdentity,
    current_policy: GithubOidcCurrentPolicy,
    proposal: GithubOidcAuthorityProposal,
    observed_at: UnixMillis,
}

impl ReserveGithubOidcAuthority {
    /// Binds an exact proposal to its execution, current policy, and trusted time.
    ///
    /// # Errors
    ///
    /// Rejects a non-stable-owner policy, a request-bearer skew that differs from
    /// current policy, an issuance second other than the floor of lease issuance,
    /// an observation outside the exact lease, or a bearer already expired at that
    /// observation. The durable adapter independently derives all owner, source,
    /// subject, audience, and claim evidence after locking the signed run receipt.
    pub fn new(
        execution: GithubOidcExecutionIdentity,
        current_policy: GithubOidcCurrentPolicy,
        proposal: GithubOidcAuthorityProposal,
        observed_at: UnixMillis,
    ) -> Result<Self, GithubOidcValueError> {
        let lease_issued_at = u64::try_from(execution.lease().issued_at().get())
            .map_err(|_| GithubOidcValueError::InvalidExecution)?;
        let bearer_expires_at_ms = proposal
            .expires_at_seconds()
            .checked_mul(1_000)
            .and_then(|value| i64::try_from(value).ok())
            .ok_or(GithubOidcValueError::InvalidBearerInterval)?;
        if proposal.issued_at_seconds() != lease_issued_at / 1_000
            || proposal.request_bearer_verification_skew_seconds()
                != current_policy.request_bearer_verification_skew_seconds()
            || observed_at < execution.lease().issued_at()
            || observed_at >= execution.lease().expires_at()
            || observed_at.get() >= bearer_expires_at_ms
        {
            return Err(GithubOidcValueError::InvalidBearerInterval);
        }
        Ok(Self {
            execution,
            current_policy,
            proposal,
            observed_at,
        })
    }

    /// Returns the exact current execution proposal.
    #[must_use]
    pub const fn execution(&self) -> &GithubOidcExecutionIdentity {
        &self.execution
    }

    /// Returns the exact current stable-owner policy configuration.
    #[must_use]
    pub const fn current_policy(&self) -> GithubOidcCurrentPolicy {
        self.current_policy
    }

    /// Returns the exact new-record proposal.
    #[must_use]
    pub const fn proposal(&self) -> &GithubOidcAuthorityProposal {
        &self.proposal
    }

    /// Returns the trusted wall-clock anchor used for currentness revalidation.
    #[must_use]
    pub const fn observed_at(&self) -> UnixMillis {
        self.observed_at
    }
}

/// Immutable request-bearer coordinates returned from durable reservation or replay.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReservedGithubOidcAuthority {
    authority_id: OidcAuthorityId,
    request_bearer_key_id: OidcKeyId,
    issued_at_seconds: u64,
    expires_at_seconds: u64,
    request_bearer_sha256: Sha256Digest,
}

impl ReservedGithubOidcAuthority {
    pub(crate) const fn new(
        authority_id: OidcAuthorityId,
        request_bearer_key_id: OidcKeyId,
        issued_at_seconds: u64,
        expires_at_seconds: u64,
        request_bearer_sha256: Sha256Digest,
    ) -> Self {
        Self {
            authority_id,
            request_bearer_key_id,
            issued_at_seconds,
            expires_at_seconds,
            request_bearer_sha256,
        }
    }

    /// Returns the opaque durable authority identity.
    #[must_use]
    pub const fn authority_id(&self) -> OidcAuthorityId {
        self.authority_id
    }

    /// Returns the retained request-bearer key ID.
    #[must_use]
    pub const fn request_bearer_key_id(&self) -> &OidcKeyId {
        &self.request_bearer_key_id
    }

    /// Returns the inclusive request-bearer issuance second.
    #[must_use]
    pub const fn issued_at_seconds(&self) -> u64 {
        self.issued_at_seconds
    }

    /// Returns the exclusive request-bearer deadline.
    #[must_use]
    pub const fn expires_at_seconds(&self) -> u64 {
        self.expires_at_seconds
    }

    /// Returns the digest of the exact deterministic private bearer.
    #[must_use]
    pub const fn request_bearer_sha256(&self) -> Sha256Digest {
        self.request_bearer_sha256
    }
}

/// Closed use-domain for an OIDC key-retention deadline.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum GithubOidcKeyUse {
    /// HS256 key used only for private mint-request bearers.
    RequestBearer,
    /// RS256 key used only for workload ID-token signatures.
    IdTokenSigning,
}

/// Exact loaded-key evidence compared with durable retirement deadlines at startup.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GithubOidcLoadedKey {
    use_domain: GithubOidcKeyUse,
    id: OidcKeyId,
    fingerprint: Sha256Digest,
}

impl GithubOidcLoadedKey {
    /// Describes one loaded key without exposing its HMAC or private-key bytes.
    ///
    /// RS256 callers use [`github_oidc_rs256_public_key_fingerprint`]. HMAC
    /// loaders compute the documented domain-separated digest before calling
    /// this boundary.
    #[must_use]
    pub const fn new(
        key_use: GithubOidcKeyUse,
        key_id: OidcKeyId,
        key_sha256: Sha256Digest,
    ) -> Self {
        Self {
            use_domain: key_use,
            id: key_id,
            fingerprint: key_sha256,
        }
    }

    /// Returns the disjoint use-domain of the loaded key.
    #[must_use]
    pub const fn key_use(&self) -> GithubOidcKeyUse {
        self.use_domain
    }

    /// Returns the loaded public key identifier.
    #[must_use]
    pub const fn key_id(&self) -> &OidcKeyId {
        &self.id
    }

    /// Returns the exact non-secret key-material fingerprint.
    #[must_use]
    pub const fn key_sha256(&self) -> Sha256Digest {
        self.fingerprint
    }
}

impl GithubOidcKeyUse {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::RequestBearer => "request_bearer",
            Self::IdTokenSigning => "id_token_signing",
        }
    }

    pub(crate) fn from_str(value: &str) -> Result<Self, GithubOidcStoreError> {
        match value {
            "request_bearer" => Ok(Self::RequestBearer),
            "id_token_signing" => Ok(Self::IdTokenSigning),
            _ => Err(GithubOidcStoreError::CorruptData),
        }
    }
}

/// Monotonic non-secret proposal for retaining one key through a token deadline.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RetainGithubOidcKey {
    key_use: GithubOidcKeyUse,
    key_id: OidcKeyId,
    key_sha256: Sha256Digest,
    not_after_seconds: u64,
    observed_at_seconds: u64,
}

impl RetainGithubOidcKey {
    /// Creates a request-bearer key deadline covering bearer expiry and verifier skew.
    ///
    /// # Errors
    ///
    /// Rejects excessive skew, overflow, or a deadline before observation.
    pub fn request_bearer(
        key_id: OidcKeyId,
        key_sha256: Sha256Digest,
        bearer_expires_at_seconds: u64,
        verification_skew_seconds: u64,
        observed_at_seconds: u64,
    ) -> Result<Self, GithubOidcValueError> {
        if verification_skew_seconds > MAXIMUM_REQUEST_BEARER_CLOCK_SKEW_SECONDS {
            return Err(GithubOidcValueError::InvalidKeyDeadline);
        }
        let not_after_seconds = bearer_expires_at_seconds
            .checked_add(verification_skew_seconds)
            .ok_or(GithubOidcValueError::InvalidKeyDeadline)?;
        Self::new(
            GithubOidcKeyUse::RequestBearer,
            key_id,
            key_sha256,
            not_after_seconds,
            observed_at_seconds,
        )
    }

    /// Creates a signing-key deadline covering token expiry, JWKS cache, and verifier skew.
    ///
    /// # Errors
    ///
    /// Rejects excessive skew, overflow, or a deadline before observation.
    pub fn id_token_signing(
        key_id: OidcKeyId,
        key_sha256: Sha256Digest,
        token_expires_at_seconds: u64,
        verification_skew_seconds: u64,
        observed_at_seconds: u64,
    ) -> Result<Self, GithubOidcValueError> {
        if verification_skew_seconds > MAXIMUM_REQUEST_BEARER_CLOCK_SKEW_SECONDS {
            return Err(GithubOidcValueError::InvalidKeyDeadline);
        }
        let not_after_seconds = token_expires_at_seconds
            .checked_add(OIDC_JWKS_CACHE_SECONDS)
            .and_then(|deadline| deadline.checked_add(verification_skew_seconds))
            .ok_or(GithubOidcValueError::InvalidKeyDeadline)?;
        Self::new(
            GithubOidcKeyUse::IdTokenSigning,
            key_id,
            key_sha256,
            not_after_seconds,
            observed_at_seconds,
        )
    }

    fn new(
        key_use: GithubOidcKeyUse,
        key_id: OidcKeyId,
        key_sha256: Sha256Digest,
        not_after_seconds: u64,
        observed_at_seconds: u64,
    ) -> Result<Self, GithubOidcValueError> {
        if not_after_seconds == 0
            || not_after_seconds < observed_at_seconds
            || i64::try_from(not_after_seconds).is_err()
            || i64::try_from(observed_at_seconds).is_err()
        {
            return Err(GithubOidcValueError::InvalidKeyDeadline);
        }
        Ok(Self {
            key_use,
            key_id,
            key_sha256,
            not_after_seconds,
            observed_at_seconds,
        })
    }

    /// Returns the disjoint key use-domain.
    #[must_use]
    pub const fn key_use(&self) -> GithubOidcKeyUse {
        self.key_use
    }

    /// Returns the public key identifier.
    #[must_use]
    pub const fn key_id(&self) -> &OidcKeyId {
        &self.key_id
    }

    /// Returns the exact non-secret key-material fingerprint.
    #[must_use]
    pub const fn key_sha256(&self) -> Sha256Digest {
        self.key_sha256
    }

    /// Returns the proposed exclusive retain-through deadline.
    #[must_use]
    pub const fn not_after_seconds(&self) -> u64 {
        self.not_after_seconds
    }

    /// Returns the trusted observation second.
    #[must_use]
    pub const fn observed_at_seconds(&self) -> u64 {
        self.observed_at_seconds
    }
}

/// Durable monotonic retention evidence for one OIDC key.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GithubOidcKeyDeadline {
    key_use: GithubOidcKeyUse,
    key_id: OidcKeyId,
    key_sha256: Option<Sha256Digest>,
    not_after_seconds: u64,
}

impl GithubOidcKeyDeadline {
    pub(crate) const fn new(
        key_use: GithubOidcKeyUse,
        key_id: OidcKeyId,
        key_sha256: Option<Sha256Digest>,
        not_after_seconds: u64,
    ) -> Self {
        Self {
            key_use,
            key_id,
            key_sha256,
            not_after_seconds,
        }
    }

    /// Builds exact deadline evidence from a validated monotonic retention request.
    ///
    /// This is primarily useful to backend-neutral repository implementations and
    /// mocks; durable adapters must still enforce monotonicity and fingerprint
    /// immutability before returning the value.
    #[must_use]
    pub fn from_retention(request: &RetainGithubOidcKey) -> Self {
        Self::new(
            request.key_use(),
            request.key_id().clone(),
            Some(request.key_sha256()),
            request.not_after_seconds(),
        )
    }

    /// Rehydrates exact deadline evidence returned by a durable backend.
    ///
    /// A nullable fingerprint remains representable so readiness can identify
    /// and fail closed on corrupt or administratively tombstoned state. Normal
    /// retention requests always require a concrete fingerprint.
    ///
    /// # Errors
    ///
    /// Rejects zero or values outside the `PostgreSQL` timestamp domain.
    pub fn from_durable_parts(
        key_use: GithubOidcKeyUse,
        key_id: OidcKeyId,
        key_sha256: Option<Sha256Digest>,
        not_after_seconds: u64,
    ) -> Result<Self, GithubOidcValueError> {
        if not_after_seconds == 0 || i64::try_from(not_after_seconds).is_err() {
            return Err(GithubOidcValueError::InvalidKeyDeadline);
        }
        Ok(Self::new(key_use, key_id, key_sha256, not_after_seconds))
    }

    /// Returns the disjoint key use-domain.
    #[must_use]
    pub const fn key_use(&self) -> GithubOidcKeyUse {
        self.key_use
    }

    /// Returns the public key identifier.
    #[must_use]
    pub const fn key_id(&self) -> &OidcKeyId {
        &self.key_id
    }

    /// Returns the optional immutable key-material fingerprint.
    #[must_use]
    pub const fn key_sha256(&self) -> Option<Sha256Digest> {
        self.key_sha256
    }

    /// Returns the greatest durable retain-through deadline ever proposed.
    #[must_use]
    pub const fn not_after_seconds(&self) -> u64 {
        self.not_after_seconds
    }
}

/// Sanitized durable GitHub-compatible OIDC store failure.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum GithubOidcStoreError {
    /// No current execution authority permits the operation.
    #[error("GitHub-compatible OIDC execution authority is unavailable")]
    Unauthorized,
    /// Immutable proposal or key identity conflicts with durable state.
    #[error("GitHub-compatible OIDC durable identity conflicts")]
    Conflict,
    /// A configured durable count ceiling was reached.
    #[error("GitHub-compatible OIDC durable capacity is exhausted")]
    ResourceExhausted,
    /// Persisted state violates the current contract.
    #[error("GitHub-compatible OIDC durable state is corrupt")]
    CorruptData,
    /// The durable provider is temporarily unavailable.
    #[error("GitHub-compatible OIDC durable state is unavailable")]
    Unavailable,
}

/// Sanitized value-construction failure at the durable OIDC boundary.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum GithubOidcValueError {
    /// Execution coordinates do not form one exact current identity.
    #[error("GitHub-compatible OIDC execution identity is invalid")]
    InvalidExecution,
    /// Permission or subject-policy evidence is incomplete or incoherent.
    #[error("GitHub-compatible OIDC policy evidence is invalid")]
    InvalidPolicy,
    /// The request-bearer interval is not exact or bounded.
    #[error("GitHub-compatible OIDC request-bearer interval is invalid")]
    InvalidBearerInterval,
    /// A key-retention deadline is invalid.
    #[error("GitHub-compatible OIDC key-retention deadline is invalid")]
    InvalidKeyDeadline,
    /// A loaded key set is empty, duplicated, excessive, or incoherent.
    #[error("GitHub-compatible OIDC loaded-key configuration is invalid")]
    InvalidKeyConfiguration,
}

/// Failure to sample the trusted OIDC currentness clock.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
#[error("GitHub-compatible OIDC trusted time is unavailable")]
pub struct GithubOidcCurrentnessClockError;

/// Trusted clock sampled only after durable OIDC currentness locks are held.
pub trait GithubOidcCurrentnessClock: fmt::Debug + Send + Sync {
    /// Returns a fresh non-runner-controlled wall-clock observation.
    ///
    /// # Errors
    ///
    /// Returns a sanitized error when the clock cannot represent current time.
    fn now_millis(&self) -> Result<UnixMillis, GithubOidcCurrentnessClockError>;
}

/// Object-safe authority reservation boundary for a current GitHub OIDC execution.
#[async_trait]
pub trait GithubOidcAuthorityRepository: fmt::Debug + Send + Sync {
    /// Atomically authenticates and reserves or replays one execution authority.
    async fn reserve_github_oidc_authority(
        &self,
        request: ReserveGithubOidcAuthority,
    ) -> Result<ReservedGithubOidcAuthority, GithubOidcStoreError>;
}

/// Object-safe monotonic retention boundary for request-bearer and signing keys.
#[async_trait]
pub trait GithubOidcKeyRetentionRepository: fmt::Debug + Send + Sync {
    /// Extends a key deadline without ever shortening or changing its fingerprint.
    async fn retain_github_oidc_key(
        &self,
        request: RetainGithubOidcKey,
    ) -> Result<GithubOidcKeyDeadline, GithubOidcStoreError>;

    /// Loads the exact deadline for one key use and public key identifier.
    async fn github_oidc_key_deadline(
        &self,
        key_use: GithubOidcKeyUse,
        key_id: &OidcKeyId,
    ) -> Result<Option<GithubOidcKeyDeadline>, GithubOidcStoreError>;

    /// Lists every deterministically ordered key still required after an observation time.
    ///
    /// The result is bounded to the two disjoint 16-key foundation keyrings.
    /// Exceeding either use-domain bound is durable corruption or configuration exhaustion.
    async fn required_github_oidc_keys(
        &self,
        observed_at_seconds: u64,
    ) -> Result<Vec<GithubOidcKeyDeadline>, GithubOidcStoreError>;

    /// Proves that every unexpired durable key is present with its exact fingerprint.
    ///
    /// Callers must provide the complete bounded HMAC and RS256 key metadata loaded
    /// by the product. A durable deadline without a fingerprint is corrupt and a
    /// missing or mismatched loaded key is a configuration conflict. Extra loaded
    /// keys are permitted so a rotation can be deployed before it is first used.
    async fn verify_github_oidc_key_readiness(
        &self,
        observed_at_seconds: u64,
        loaded_keys: &[GithubOidcLoadedKey],
    ) -> Result<(), GithubOidcStoreError> {
        if loaded_keys.len() > MAXIMUM_OIDC_KEYS_PER_KEYRING * 2 {
            return Err(GithubOidcStoreError::ResourceExhausted);
        }
        let mut loaded = BTreeMap::new();
        let mut request_bearers = 0_usize;
        let mut signing_keys = 0_usize;
        for key in loaded_keys {
            match key.key_use() {
                GithubOidcKeyUse::RequestBearer => request_bearers += 1,
                GithubOidcKeyUse::IdTokenSigning => signing_keys += 1,
            }
            if request_bearers > MAXIMUM_OIDC_KEYS_PER_KEYRING
                || signing_keys > MAXIMUM_OIDC_KEYS_PER_KEYRING
            {
                return Err(GithubOidcStoreError::ResourceExhausted);
            }
            if loaded
                .insert((key.key_use(), key.key_id().clone()), key.key_sha256())
                .is_some()
            {
                return Err(GithubOidcStoreError::Conflict);
            }
        }
        for deadline in self.required_github_oidc_keys(observed_at_seconds).await? {
            let durable_fingerprint = deadline
                .key_sha256()
                .ok_or(GithubOidcStoreError::CorruptData)?;
            if loaded.get(&(deadline.key_use(), deadline.key_id().clone()))
                != Some(&durable_fingerprint)
            {
                return Err(GithubOidcStoreError::Conflict);
            }
        }
        Ok(())
    }
}
