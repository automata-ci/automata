//! Durable GitHub installation-token issuance and revocation coordination.
//!
//! The next credential/runner-control adapter must cross the mint boundary
//! before provider I/O, seal any recovered token with
//! [`GithubRuntimeAuthorityEnvelopeMetadata::encryption_context`], commit the
//! protected envelope, then load/decrypt it into key-management `SecretBytes`
//! only for an exact-fence runner-command publication. Provider and KMS calls
//! never belong inside a repository transaction. Erasing this issuance
//! envelope retires this copy only: independently encrypted runner-command and
//! RPC-receipt copies retain their own acknowledgement/retention lifecycle.

use std::num::{NonZeroU16, NonZeroU64};

use async_trait::async_trait;
use automata_ci_core::{
    AttemptId, FencingToken, JobId, JobIrVersion, LeaseId, RunId, RunnerId, RunnerSessionId,
    UnixMillis,
};
use automata_ci_key_management::{
    ENVELOPE_SCHEMA_V1, EncryptedEnvelope, KeyEncryptionContext, KeyPurpose,
};
use sha2::{Digest as _, Sha256};
use thiserror::Error;
use uuid::Uuid;

use crate::{
    GithubInstallationId, GithubRepositoryId, GithubServerServiceAppClientId,
    GithubServerServiceAppId, GithubServerServiceJwtIssuer, LogicalActivationGeneration,
    LogicalActivationPreparationGeneration, LogicalActivationWorkerId,
    LogicalMaterializationGeneration, LogicalMaterializationWorkerId, LogicalWorkSelectionId,
    MAX_LOGICAL_ACTIVATION_CLAIM_MILLIS, MAX_LOGICAL_ACTIVATION_PREPARATION_CLAIM_MILLIS,
    MAX_LOGICAL_MATERIALIZATION_CLAIM_MILLIS, RepositoryId, RepositoryOperationError,
    RunnerGeneration, SessionEpoch, Sha256Digest, StableRunnerSlot, TenantScope,
};
use automata_ci_provider::ProviderConnectionId;

/// Maximum time held by a pre-mint repository claim.
pub const MAX_GITHUB_AUTHORITY_MINT_CLAIM_MILLIS: i64 = 2 * 60 * 1_000;
/// Maximum time held by a revocation repository claim.
pub const MAX_GITHUB_AUTHORITY_REVOKE_CLAIM_MILLIS: i64 = 2 * 60 * 1_000;
/// Maximum provider-request deadline interval accepted by the durable boundary.
pub const MAX_GITHUB_AUTHORITY_REQUEST_MILLIS: i64 = 2 * 60 * 1_000;
/// Conservative maximum lifetime of a GitHub installation access token.
pub const GITHUB_AUTHORITY_TOKEN_LIFETIME_MILLIS: i64 = 60 * 60 * 1_000;
/// Maximum provider-clock lead accepted by the GitHub broker.
pub const GITHUB_AUTHORITY_PROVIDER_CLOCK_SKEW_MILLIS: i64 = 60 * 1_000;
/// Clock and propagation skew retained beyond the provider token expiration.
pub const GITHUB_AUTHORITY_EXPIRY_SKEW_MILLIS: i64 = 2 * 60 * 1_000;
/// Maximum delay before a definitively rejected no-token mint is eligible again.
pub const MAX_GITHUB_AUTHORITY_MINT_RETRY_BACKOFF_MILLIS: i64 = 2 * 60 * 1_000;
/// Maximum delay before a failed revocation is eligible again.
pub const MAX_GITHUB_AUTHORITY_REVOKE_BACKOFF_MILLIS: i64 = 24 * 60 * 60 * 1_000;
/// Maximum number of pre-mint claim owners retained for one issuance.
pub const MAX_GITHUB_AUTHORITY_MINT_ATTEMPTS: u16 = 32;
/// Maximum number of provider revocation attempts before conservative expiry.
pub const MAX_GITHUB_AUTHORITY_REVOKE_ATTEMPTS: u16 = 64;
/// Maximum protected runtime-authority plaintext size.
pub const MAX_ACTIONS_RUNTIME_AUTHORITY_PLAINTEXT_BYTES: u64 = 64 * 1024;
/// Maximum records changed by one reconciliation transaction.
pub const MAX_GITHUB_AUTHORITY_RECONCILE_BATCH: u16 = 512;

const MAX_GITHUB_REPOSITORY_OWNER_BYTES: usize = 39;
const MAX_GITHUB_REPOSITORY_COMPONENT_BYTES: usize = 100;
const MAX_GITHUB_REPOSITORY_NAME_BYTES: usize =
    MAX_GITHUB_REPOSITORY_OWNER_BYTES + 1 + MAX_GITHUB_REPOSITORY_COMPONENT_BYTES;
const MAX_GITHUB_AUTHORITY_NAMESPACE_BYTES: usize = 128;
const MAX_FAILURE_KIND_BYTES: usize = 128;
const PROTECTED_PAYLOAD_SCHEMA: u16 = 1;
const AAD_DOMAIN: &[u8] = b"automata.store.github-runtime-authority-aad.v3\0";
const WRAPPING_AAD_DOMAIN: &[u8] = b"automata.store.github-runtime-authority-wrapping-aad.v3\0";
const ENCRYPTION_PURPOSE: &str = "control-plane/github-runtime-authority:v3";
const WRAPPING_ENCRYPTION_PURPOSE: &str = "control-plane/github-runtime-authority-wrapping:v3";

/// Stable key of one authority issuance.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct GithubRuntimeAuthorityKey {
    attempt_id: AttemptId,
    fencing_token: FencingToken,
}

impl GithubRuntimeAuthorityKey {
    /// Binds an issuance to one exact attempt lease fence.
    #[must_use]
    pub const fn new(attempt_id: AttemptId, fencing_token: FencingToken) -> Self {
        Self {
            attempt_id,
            fencing_token,
        }
    }

    /// Returns the exact attempt receiving the runtime authority.
    #[must_use]
    pub const fn attempt_id(self) -> AttemptId {
        self.attempt_id
    }

    /// Returns the attempt lease fence to which the issuance is bound.
    #[must_use]
    pub const fn fencing_token(self) -> FencingToken {
        self.fencing_token
    }
}

/// Durable worker identity used only to fence short repository claims.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct GithubRuntimeAuthorityWorkerId(Uuid);

impl GithubRuntimeAuthorityWorkerId {
    /// Constructs a non-nil worker identity.
    ///
    /// # Errors
    ///
    /// Rejects the nil UUID sentinel.
    pub fn from_uuid(value: Uuid) -> Result<Self, GithubRuntimeAuthorityValueError> {
        if value.is_nil() {
            return Err(GithubRuntimeAuthorityValueError::NilIdentity("worker ID"));
        }
        Ok(Self(value))
    }

    /// Returns the durable non-nil worker UUID.
    #[must_use]
    pub const fn as_uuid(self) -> Uuid {
        self.0
    }
}

/// Monotonic fence of a mint or revocation repository claim.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct GithubRuntimeAuthorityClaimFence(NonZeroU64);

impl GithubRuntimeAuthorityClaimFence {
    /// Constructs a positive claim fence within the signed 64-bit storage boundary.
    ///
    /// # Errors
    ///
    /// Rejects zero and values larger than `i64::MAX`.
    pub fn new(value: u64) -> Result<Self, GithubRuntimeAuthorityValueError> {
        let value =
            NonZeroU64::new(value).ok_or(GithubRuntimeAuthorityValueError::InvalidClaimFence)?;
        if value.get() > i64::MAX as u64 {
            return Err(GithubRuntimeAuthorityValueError::InvalidClaimFence);
        }
        Ok(Self(value))
    }

    /// Returns the positive monotonic claim fence.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0.get()
    }
}

/// Canonical `owner/repository` evidence bound to a numeric GitHub repository ID.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct GithubRepositoryName(String);

impl GithubRepositoryName {
    /// Constructs a bounded, canonical two-component GitHub repository name.
    ///
    /// # Errors
    ///
    /// Rejects whitespace, control characters, extra path components, or an
    /// empty owner/repository component.
    pub fn new(value: impl Into<String>) -> Result<Self, GithubRuntimeAuthorityValueError> {
        let value = value.into();
        let mut components = value.split('/');
        let owner = components.next().unwrap_or_default();
        let repository = components.next().unwrap_or_default();
        let valid_owner = !owner.is_empty()
            && owner.len() <= MAX_GITHUB_REPOSITORY_OWNER_BYTES
            && !owner.contains("--")
            && owner.bytes().enumerate().all(|(index, byte)| {
                byte.is_ascii_alphanumeric()
                    || (byte == b'-' && index > 0 && index + 1 < owner.len())
            });
        let valid_repository = !repository.is_empty()
            && repository.len() <= MAX_GITHUB_REPOSITORY_COMPONENT_BYTES
            && repository
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
            && !matches!(repository, "." | "..")
            && !repository.to_ascii_lowercase().ends_with(".git");
        let valid = valid_owner
            && valid_repository
            && components.next().is_none()
            && value.len() <= MAX_GITHUB_REPOSITORY_NAME_BYTES
            && value.is_ascii();
        if !valid {
            return Err(GithubRuntimeAuthorityValueError::InvalidRepositoryName);
        }
        Ok(Self(value))
    }

    /// Returns the exact canonical `owner/repository` evidence.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Domain-separated logical namespace of the issued GitHub authority.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct GithubRuntimeAuthorityNamespace(String);

impl GithubRuntimeAuthorityNamespace {
    /// Constructs a canonical bounded machine namespace.
    ///
    /// # Errors
    ///
    /// Rejects empty, oversized, or noncanonical values.
    pub fn new(value: impl Into<String>) -> Result<Self, GithubRuntimeAuthorityValueError> {
        let value = value.into();
        let valid = !value.is_empty()
            && value.len() <= MAX_GITHUB_AUTHORITY_NAMESPACE_BYTES
            && value.bytes().enumerate().all(|(index, byte)| {
                byte.is_ascii_lowercase()
                    || byte.is_ascii_digit()
                    || (index > 0 && matches!(byte, b'-' | b'_' | b'.' | b'/' | b':'))
            })
            && value
                .as_bytes()
                .last()
                .is_some_and(u8::is_ascii_alphanumeric);
        if !valid {
            return Err(GithubRuntimeAuthorityValueError::InvalidNamespace);
        }
        Ok(Self(value))
    }

    /// Returns the canonical domain-separated authority namespace.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Immutable preparation selection origin and its current renewal tail.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GithubRuntimeAuthorityPreparationSelectionTail {
    selection_id: LogicalWorkSelectionId,
    owner: LogicalActivationWorkerId,
    generation: LogicalActivationPreparationGeneration,
    descriptor_digest: Sha256Digest,
    claimed_at: UnixMillis,
    expires_at: UnixMillis,
}

impl GithubRuntimeAuthorityPreparationSelectionTail {
    /// Constructs exact preparation selection and current-claim evidence.
    ///
    /// # Errors
    ///
    /// Rejects a negative, empty, or overlong preparation claim interval.
    pub fn new(
        selection_id: LogicalWorkSelectionId,
        owner: LogicalActivationWorkerId,
        generation: LogicalActivationPreparationGeneration,
        descriptor_digest: Sha256Digest,
        claimed_at: UnixMillis,
        expires_at: UnixMillis,
    ) -> Result<Self, GithubRuntimeAuthorityValueError> {
        validate_selection_tail_interval(
            claimed_at,
            expires_at,
            MAX_LOGICAL_ACTIVATION_PREPARATION_CLAIM_MILLIS,
        )?;
        Ok(Self {
            selection_id,
            owner,
            generation,
            descriptor_digest,
            claimed_at,
            expires_at,
        })
    }

    /// Returns the immutable selector receipt identity.
    #[must_use]
    pub const fn selection_id(self) -> LogicalWorkSelectionId {
        self.selection_id
    }
    /// Returns the exact preparation owner retained by the current tail.
    #[must_use]
    pub const fn owner(self) -> LogicalActivationWorkerId {
        self.owner
    }
    /// Returns the current preparation generation.
    #[must_use]
    pub const fn generation(self) -> LogicalActivationPreparationGeneration {
        self.generation
    }
    /// Returns the immutable preparation descriptor digest.
    #[must_use]
    pub const fn descriptor_digest(self) -> Sha256Digest {
        self.descriptor_digest
    }
    /// Returns the current preparation tail's repository-issued start.
    #[must_use]
    pub const fn claimed_at(self) -> UnixMillis {
        self.claimed_at
    }
    /// Returns the current preparation tail's exclusive expiry.
    #[must_use]
    pub const fn expires_at(self) -> UnixMillis {
        self.expires_at
    }
}

/// Immutable activation selection origin and its current renewal tail.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GithubRuntimeAuthorityActivationSelectionTail {
    selection_id: LogicalWorkSelectionId,
    owner: LogicalActivationWorkerId,
    generation: LogicalActivationGeneration,
    activation_input_digest: Sha256Digest,
    claimed_at: UnixMillis,
    expires_at: UnixMillis,
}

impl GithubRuntimeAuthorityActivationSelectionTail {
    /// Constructs exact activation selection and current-claim evidence.
    ///
    /// # Errors
    ///
    /// Rejects a negative, empty, or overlong activation claim interval.
    pub fn new(
        selection_id: LogicalWorkSelectionId,
        owner: LogicalActivationWorkerId,
        generation: LogicalActivationGeneration,
        activation_input_digest: Sha256Digest,
        claimed_at: UnixMillis,
        expires_at: UnixMillis,
    ) -> Result<Self, GithubRuntimeAuthorityValueError> {
        validate_selection_tail_interval(
            claimed_at,
            expires_at,
            MAX_LOGICAL_ACTIVATION_CLAIM_MILLIS,
        )?;
        Ok(Self {
            selection_id,
            owner,
            generation,
            activation_input_digest,
            claimed_at,
            expires_at,
        })
    }

    /// Returns the immutable selector receipt identity.
    #[must_use]
    pub const fn selection_id(self) -> LogicalWorkSelectionId {
        self.selection_id
    }
    /// Returns the exact activation owner retained by the current tail.
    #[must_use]
    pub const fn owner(self) -> LogicalActivationWorkerId {
        self.owner
    }
    /// Returns the current activation generation.
    #[must_use]
    pub const fn generation(self) -> LogicalActivationGeneration {
        self.generation
    }
    /// Returns the immutable activation-input digest.
    #[must_use]
    pub const fn activation_input_digest(self) -> Sha256Digest {
        self.activation_input_digest
    }
    /// Returns the current activation tail's repository-issued start.
    #[must_use]
    pub const fn claimed_at(self) -> UnixMillis {
        self.claimed_at
    }
    /// Returns the current activation tail's exclusive expiry.
    #[must_use]
    pub const fn expires_at(self) -> UnixMillis {
        self.expires_at
    }
}

/// Immutable materialization selection origin and its current renewal tail.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GithubRuntimeAuthorityMaterializationSelectionTail {
    selection_id: LogicalWorkSelectionId,
    owner: LogicalMaterializationWorkerId,
    generation: LogicalMaterializationGeneration,
    descriptor_digest: Sha256Digest,
    claimed_at: UnixMillis,
    expires_at: UnixMillis,
}

impl GithubRuntimeAuthorityMaterializationSelectionTail {
    /// Constructs exact materialization selection and current-claim evidence.
    ///
    /// # Errors
    ///
    /// Rejects a negative, empty, or overlong materialization claim interval.
    pub fn new(
        selection_id: LogicalWorkSelectionId,
        owner: LogicalMaterializationWorkerId,
        generation: LogicalMaterializationGeneration,
        descriptor_digest: Sha256Digest,
        claimed_at: UnixMillis,
        expires_at: UnixMillis,
    ) -> Result<Self, GithubRuntimeAuthorityValueError> {
        validate_selection_tail_interval(
            claimed_at,
            expires_at,
            MAX_LOGICAL_MATERIALIZATION_CLAIM_MILLIS,
        )?;
        Ok(Self {
            selection_id,
            owner,
            generation,
            descriptor_digest,
            claimed_at,
            expires_at,
        })
    }

    /// Returns the immutable selector receipt identity.
    #[must_use]
    pub const fn selection_id(self) -> LogicalWorkSelectionId {
        self.selection_id
    }
    /// Returns the exact materialization owner retained by the current tail.
    #[must_use]
    pub const fn owner(self) -> LogicalMaterializationWorkerId {
        self.owner
    }
    /// Returns the current materialization generation.
    #[must_use]
    pub const fn generation(self) -> LogicalMaterializationGeneration {
        self.generation
    }
    /// Returns the immutable materialization descriptor digest.
    #[must_use]
    pub const fn descriptor_digest(self) -> Sha256Digest {
        self.descriptor_digest
    }
    /// Returns the current materialization tail's repository-issued start.
    #[must_use]
    pub const fn claimed_at(self) -> UnixMillis {
        self.claimed_at
    }
    /// Returns the current materialization tail's exclusive expiry.
    #[must_use]
    pub const fn expires_at(self) -> UnixMillis {
        self.expires_at
    }
}

/// Complete immutable execution, repository, and issuer identity of one mint.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GithubRuntimeAuthorityIdentity {
    tenant: TenantScope,
    key: GithubRuntimeAuthorityKey,
    lease_id: LeaseId,
    lease_issued_at: UnixMillis,
    lease_expires_at: UnixMillis,
    run_id: RunId,
    job_id: JobId,
    runner_id: RunnerId,
    runner_session_id: RunnerSessionId,
    runner_session_epoch: SessionEpoch,
    runner_generation: RunnerGeneration,
    runner_slot: StableRunnerSlot,
    job_ir_version: JobIrVersion,
    job_ir_size_bytes: u64,
    job_ir_digest: Sha256Digest,
    repository_id: RepositoryId,
    provider_connection_id: ProviderConnectionId,
    provider_installation_id: GithubInstallationId,
    github_app_id: GithubServerServiceAppId,
    github_app_client_id: GithubServerServiceAppClientId,
    github_app_jwt_issuer_kind: GithubServerServiceJwtIssuer,
    github_app_jwt_issuer_value: String,
    github_repository_id: GithubRepositoryId,
    github_repository_name: GithubRepositoryName,
    namespace: GithubRuntimeAuthorityNamespace,
    policy_digest: Sha256Digest,
    app_key_spki_sha256: Sha256Digest,
    configuration_fingerprint: Sha256Digest,
    preparation_selection_tail: GithubRuntimeAuthorityPreparationSelectionTail,
    activation_selection_tail: GithubRuntimeAuthorityActivationSelectionTail,
    materialization_selection_tail: GithubRuntimeAuthorityMaterializationSelectionTail,
    requested_at: UnixMillis,
    request_deadline: UnixMillis,
    conservative_expiry: UnixMillis,
}

impl GithubRuntimeAuthorityIdentity {
    /// Constructs current-only immutable GitHub authority identity.
    ///
    /// The conservative expiry is derived as request deadline plus the fixed
    /// GitHub one-hour token lifetime and Automata's safety skew. Callers may
    /// not choose a shorter uncertainty horizon.
    ///
    /// # Errors
    ///
    /// Rejects nil identities, noncurrent `JobIR`, invalid sizes, or inconsistent
    /// lease/request time bounds.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        tenant: TenantScope,
        attempt_id: AttemptId,
        fencing_token: FencingToken,
        lease_id: LeaseId,
        lease_issued_at: UnixMillis,
        lease_expires_at: UnixMillis,
        run_id: RunId,
        job_id: JobId,
        runner_id: RunnerId,
        runner_session_id: RunnerSessionId,
        runner_session_epoch: SessionEpoch,
        runner_generation: RunnerGeneration,
        runner_slot: StableRunnerSlot,
        job_ir_version: JobIrVersion,
        job_ir_size_bytes: u64,
        job_ir_digest: Sha256Digest,
        repository_id: RepositoryId,
        provider_connection_id: ProviderConnectionId,
        provider_installation_id: GithubInstallationId,
        github_app_id: GithubServerServiceAppId,
        github_app_client_id: GithubServerServiceAppClientId,
        github_app_jwt_issuer_kind: GithubServerServiceJwtIssuer,
        github_repository_id: GithubRepositoryId,
        github_repository_name: GithubRepositoryName,
        namespace: GithubRuntimeAuthorityNamespace,
        policy_digest: Sha256Digest,
        app_key_spki_sha256: Sha256Digest,
        configuration_fingerprint: Sha256Digest,
        preparation_selection_tail: GithubRuntimeAuthorityPreparationSelectionTail,
        activation_selection_tail: GithubRuntimeAuthorityActivationSelectionTail,
        materialization_selection_tail: GithubRuntimeAuthorityMaterializationSelectionTail,
        requested_at: UnixMillis,
        request_deadline: UnixMillis,
    ) -> Result<Self, GithubRuntimeAuthorityValueError> {
        for (value, field) in [
            (attempt_id.as_uuid(), "attempt ID"),
            (lease_id.as_uuid(), "lease ID"),
            (run_id.as_uuid(), "run ID"),
            (job_id.as_uuid(), "job ID"),
            (runner_id.as_uuid(), "runner ID"),
            (runner_session_id.as_uuid(), "runner session ID"),
            (repository_id.as_uuid(), "repository ID"),
        ] {
            if value.is_nil() {
                return Err(GithubRuntimeAuthorityValueError::NilIdentity(field));
            }
        }
        if job_ir_version != JobIrVersion::current() {
            return Err(GithubRuntimeAuthorityValueError::UnsupportedJobIr);
        }
        if job_ir_size_bytes == 0 || job_ir_size_bytes > crate::MAX_JOB_IR_BYTES {
            return Err(GithubRuntimeAuthorityValueError::InvalidJobIrSize);
        }
        if policy_digest != job_ir_digest {
            return Err(GithubRuntimeAuthorityValueError::PolicyDigestMismatch);
        }
        validate_nonnegative(lease_issued_at)?;
        validate_nonnegative(lease_expires_at)?;
        validate_nonnegative(requested_at)?;
        validate_nonnegative(request_deadline)?;
        if lease_expires_at <= lease_issued_at
            || requested_at < lease_issued_at
            || requested_at >= lease_expires_at
            || request_deadline <= requested_at
            || request_deadline > lease_expires_at
            || request_deadline.get() - requested_at.get() > MAX_GITHUB_AUTHORITY_REQUEST_MILLIS
        {
            return Err(GithubRuntimeAuthorityValueError::InvalidTimeInterval);
        }
        let conservative_expiry = request_deadline
            .get()
            .checked_add(GITHUB_AUTHORITY_TOKEN_LIFETIME_MILLIS)
            .and_then(|value| value.checked_add(GITHUB_AUTHORITY_PROVIDER_CLOCK_SKEW_MILLIS))
            .and_then(|value| value.checked_add(GITHUB_AUTHORITY_EXPIRY_SKEW_MILLIS))
            .map(UnixMillis::new)
            .ok_or(GithubRuntimeAuthorityValueError::TimestampOverflow)?;
        let github_app_jwt_issuer_value = match github_app_jwt_issuer_kind {
            GithubServerServiceJwtIssuer::AppClientId => github_app_client_id.as_str().to_owned(),
            GithubServerServiceJwtIssuer::AppId => github_app_id.get().to_string(),
        };
        Ok(Self {
            tenant,
            key: GithubRuntimeAuthorityKey::new(attempt_id, fencing_token),
            lease_id,
            lease_issued_at,
            lease_expires_at,
            run_id,
            job_id,
            runner_id,
            runner_session_id,
            runner_session_epoch,
            runner_generation,
            runner_slot,
            job_ir_version,
            job_ir_size_bytes,
            job_ir_digest,
            repository_id,
            provider_connection_id,
            provider_installation_id,
            github_app_id,
            github_app_client_id,
            github_app_jwt_issuer_kind,
            github_app_jwt_issuer_value,
            github_repository_id,
            github_repository_name,
            namespace,
            policy_digest,
            app_key_spki_sha256,
            configuration_fingerprint,
            preparation_selection_tail,
            activation_selection_tail,
            materialization_selection_tail,
            requested_at,
            request_deadline,
            conservative_expiry,
        })
    }

    /// Returns the tenant that owns every resource in this identity.
    #[must_use]
    pub const fn tenant(&self) -> &TenantScope {
        &self.tenant
    }
    /// Returns the exact attempt and lease-fence issuance key.
    #[must_use]
    pub const fn key(&self) -> GithubRuntimeAuthorityKey {
        self.key
    }
    /// Returns the exact current lease identity admitted for issuance.
    #[must_use]
    pub const fn lease_id(&self) -> LeaseId {
        self.lease_id
    }
    /// Returns the immutable lease issue time.
    #[must_use]
    pub const fn lease_issued_at(&self) -> UnixMillis {
        self.lease_issued_at
    }
    /// Returns the immutable lease expiry used as the request ceiling.
    #[must_use]
    pub const fn lease_expires_at(&self) -> UnixMillis {
        self.lease_expires_at
    }
    /// Returns the exact workflow run receiving the authority.
    #[must_use]
    pub const fn run_id(&self) -> RunId {
        self.run_id
    }
    /// Returns the exact workflow job receiving the authority.
    #[must_use]
    pub const fn job_id(&self) -> JobId {
        self.job_id
    }
    /// Returns the exact runner assigned to the attempt.
    #[must_use]
    pub const fn runner_id(&self) -> RunnerId {
        self.runner_id
    }
    /// Returns the exact authenticated runner session.
    #[must_use]
    pub const fn runner_session_id(&self) -> RunnerSessionId {
        self.runner_session_id
    }
    /// Returns the runner-session epoch bound into the authority.
    #[must_use]
    pub const fn runner_session_epoch(&self) -> SessionEpoch {
        self.runner_session_epoch
    }
    /// Returns the durable runner generation bound into the authority.
    #[must_use]
    pub const fn runner_generation(&self) -> RunnerGeneration {
        self.runner_generation
    }
    /// Returns the stable runner slot executing the job.
    #[must_use]
    pub const fn runner_slot(&self) -> StableRunnerSlot {
        self.runner_slot
    }
    /// Returns the exact current `JobIR` version admitted for the job.
    #[must_use]
    pub const fn job_ir_version(&self) -> JobIrVersion {
        self.job_ir_version
    }
    /// Returns the exact admitted `JobIR` byte length.
    #[must_use]
    pub const fn job_ir_size_bytes(&self) -> u64 {
        self.job_ir_size_bytes
    }
    /// Returns the digest of the exact admitted `JobIR` bytes.
    #[must_use]
    pub const fn job_ir_digest(&self) -> Sha256Digest {
        self.job_ir_digest
    }
    /// Returns the tenant-local repository identity admitted for the job.
    #[must_use]
    pub const fn repository_id(&self) -> RepositoryId {
        self.repository_id
    }
    /// Returns the exact provider connection selected for minting.
    #[must_use]
    pub const fn provider_connection_id(&self) -> ProviderConnectionId {
        self.provider_connection_id
    }
    /// Returns the exact GitHub App installation selected for minting.
    #[must_use]
    pub const fn provider_installation_id(&self) -> GithubInstallationId {
        self.provider_installation_id
    }
    /// Returns the exact numeric GitHub App identity used for this issuance.
    #[must_use]
    pub const fn github_app_id(&self) -> GithubServerServiceAppId {
        self.github_app_id
    }
    /// Returns the exact configured GitHub App client identity.
    #[must_use]
    pub const fn github_app_client_id(&self) -> &GithubServerServiceAppClientId {
        &self.github_app_client_id
    }
    /// Returns which GitHub-supported value family supplied the JWT `iss` claim.
    #[must_use]
    pub const fn github_app_jwt_issuer_kind(&self) -> GithubServerServiceJwtIssuer {
        self.github_app_jwt_issuer_kind
    }
    /// Returns the exact value signed into the GitHub App JWT `iss` claim.
    #[must_use]
    pub fn github_app_jwt_issuer_value(&self) -> &str {
        &self.github_app_jwt_issuer_value
    }
    /// Returns the provider-stable numeric repository identity.
    #[must_use]
    pub const fn github_repository_id(&self) -> GithubRepositoryId {
        self.github_repository_id
    }
    /// Returns the canonical repository name paired with the numeric identity.
    #[must_use]
    pub const fn github_repository_name(&self) -> &GithubRepositoryName {
        &self.github_repository_name
    }
    /// Returns the least-authority logical namespace requested by the job.
    #[must_use]
    pub const fn namespace(&self) -> &GithubRuntimeAuthorityNamespace {
        &self.namespace
    }
    /// Returns the digest of the immutable permission policy.
    #[must_use]
    pub const fn policy_digest(&self) -> Sha256Digest {
        self.policy_digest
    }
    /// Returns the exact DER-SPKI digest of the GitHub App signing key.
    #[must_use]
    pub const fn app_key_spki_sha256(&self) -> Sha256Digest {
        self.app_key_spki_sha256
    }
    /// Returns the digest of the issuer configuration used for this request.
    #[must_use]
    pub const fn configuration_fingerprint(&self) -> Sha256Digest {
        self.configuration_fingerprint
    }
    /// Returns the exact preparation selection origin and current renewal tail.
    #[must_use]
    pub const fn preparation_selection_tail(
        &self,
    ) -> GithubRuntimeAuthorityPreparationSelectionTail {
        self.preparation_selection_tail
    }
    /// Returns the exact activation selection origin and current renewal tail.
    #[must_use]
    pub const fn activation_selection_tail(&self) -> GithubRuntimeAuthorityActivationSelectionTail {
        self.activation_selection_tail
    }
    /// Returns the exact materialization selection origin and current renewal tail.
    #[must_use]
    pub const fn materialization_selection_tail(
        &self,
    ) -> GithubRuntimeAuthorityMaterializationSelectionTail {
        self.materialization_selection_tail
    }
    /// Returns the trusted time at which issuance was requested.
    #[must_use]
    pub const fn requested_at(&self) -> UnixMillis {
        self.requested_at
    }
    /// Returns the exclusive deadline for starting provider issuance.
    #[must_use]
    pub const fn request_deadline(&self) -> UnixMillis {
        self.request_deadline
    }
    /// Returns the conservative horizon after which unknown authority is safe to erase.
    #[must_use]
    pub const fn conservative_expiry(&self) -> UnixMillis {
        self.conservative_expiry
    }

    /// Returns a domain-separated digest of every immutable authority field.
    ///
    /// The digest is safe for non-secret routing and workload correlation; it
    /// does not authenticate mutable provider-token payload metadata.
    #[must_use]
    pub fn identity_digest(&self) -> Sha256Digest {
        compute_wrapping_aad_digest(self)
    }

    /// Builds the identity-only key-wrapping context for a prepared envelope.
    ///
    /// Every immutable tenant, execution, repository, provider, policy,
    /// issuer, configuration, fence, and time field contributes to the digest.
    /// Payload expiry, size, and digest metadata are deliberately absent so
    /// the wrapping provider can finish before a token-mint side effect.
    ///
    /// # Errors
    ///
    /// Returns an error only if a static domain or validated record identity
    /// cannot be represented by the generic key-management boundary.
    pub fn wrapping_encryption_context(
        &self,
    ) -> Result<KeyEncryptionContext, GithubRuntimeAuthorityValueError> {
        let purpose = KeyPurpose::new(WRAPPING_ENCRYPTION_PURPOSE)
            .map_err(|_| GithubRuntimeAuthorityValueError::InvalidEncryptionContext)?;
        let identity_digest = self.identity_digest();
        let record_id = format!(
            "github-runtime-authority-wrapping:v3:{}:{}:{identity_digest}",
            self.key().attempt_id(),
            self.key().fencing_token().get(),
        );
        KeyEncryptionContext::new(self.tenant().as_str(), purpose, record_id)
            .map_err(|_| GithubRuntimeAuthorityValueError::InvalidEncryptionContext)
    }
}

/// Authenticated metadata required before sealing a provider token.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GithubRuntimeAuthorityEnvelopeMetadata {
    identity: GithubRuntimeAuthorityIdentity,
    provider_expires_at: Option<UnixMillis>,
    safe_erase_after: UnixMillis,
    plaintext_schema: NonZeroU16,
    plaintext_size_bytes: u64,
    plaintext_digest: Sha256Digest,
    aad_digest: Sha256Digest,
}

impl GithubRuntimeAuthorityEnvelopeMetadata {
    /// Constructs the complete AAD contract for a newly minted token.
    ///
    /// # Errors
    ///
    /// Rejects an invalid provider expiry or protected plaintext shape.
    pub fn new(
        identity: GithubRuntimeAuthorityIdentity,
        provider_expires_at: Option<UnixMillis>,
        plaintext_size_bytes: u64,
        plaintext_digest: Sha256Digest,
    ) -> Result<Self, GithubRuntimeAuthorityValueError> {
        if let Some(provider_expires_at) = provider_expires_at {
            validate_nonnegative(provider_expires_at)?;
            if provider_expires_at <= identity.requested_at()
                || provider_expires_at.get()
                    > identity
                        .request_deadline()
                        .get()
                        .checked_add(GITHUB_AUTHORITY_TOKEN_LIFETIME_MILLIS)
                        .and_then(|value| {
                            value.checked_add(GITHUB_AUTHORITY_PROVIDER_CLOCK_SKEW_MILLIS)
                        })
                        .ok_or(GithubRuntimeAuthorityValueError::TimestampOverflow)?
            {
                return Err(GithubRuntimeAuthorityValueError::InvalidProviderExpiry);
            }
        }
        if plaintext_size_bytes == 0
            || plaintext_size_bytes > MAX_ACTIONS_RUNTIME_AUTHORITY_PLAINTEXT_BYTES
        {
            return Err(GithubRuntimeAuthorityValueError::InvalidProtectedPayloadSize);
        }
        let safe_erase_after = match provider_expires_at {
            Some(provider_expires_at) => provider_expires_at
                .get()
                .checked_add(GITHUB_AUTHORITY_EXPIRY_SKEW_MILLIS)
                .map(UnixMillis::new)
                .ok_or(GithubRuntimeAuthorityValueError::TimestampOverflow)?,
            None => identity.conservative_expiry(),
        };
        if safe_erase_after > identity.conservative_expiry() {
            return Err(GithubRuntimeAuthorityValueError::InvalidProviderExpiry);
        }
        let plaintext_schema = NonZeroU16::new(PROTECTED_PAYLOAD_SCHEMA)
            .ok_or(GithubRuntimeAuthorityValueError::InvalidProtectedEnvelope)?;
        let aad_digest = compute_aad_digest(
            &identity,
            provider_expires_at,
            safe_erase_after,
            plaintext_schema.get(),
            plaintext_size_bytes,
            plaintext_digest,
        );
        Ok(Self {
            identity,
            provider_expires_at,
            safe_erase_after,
            plaintext_schema,
            plaintext_size_bytes,
            plaintext_digest,
            aad_digest,
        })
    }

    /// Returns the complete immutable authority identity authenticated by this envelope.
    #[must_use]
    pub const fn identity(&self) -> &GithubRuntimeAuthorityIdentity {
        &self.identity
    }
    /// Returns the provider-reported expiry, or `None` when it was unavailable.
    #[must_use]
    pub const fn provider_expires_at(&self) -> Option<UnixMillis> {
        self.provider_expires_at
    }
    /// Returns the provider expiry reduced by the broker's clock-skew margin.
    ///
    /// This is the exclusive runner-publication horizon. Safe erasure remains
    /// based on the unreduced provider expiry.
    #[must_use]
    pub fn conservative_use_expires_at(&self) -> Option<UnixMillis> {
        self.provider_expires_at.and_then(|provider_expires_at| {
            provider_expires_at
                .get()
                .checked_sub(GITHUB_AUTHORITY_PROVIDER_CLOCK_SKEW_MILLIS)
                .map(UnixMillis::new)
        })
    }
    /// Returns the earliest instant at which this protected copy may be erased safely.
    #[must_use]
    pub const fn safe_erase_after(&self) -> UnixMillis {
        self.safe_erase_after
    }
    /// Returns the current-only protected plaintext schema.
    #[must_use]
    pub const fn plaintext_schema(&self) -> u16 {
        self.plaintext_schema.get()
    }
    /// Returns the authenticated plaintext byte length without exposing plaintext.
    #[must_use]
    pub const fn plaintext_size_bytes(&self) -> u64 {
        self.plaintext_size_bytes
    }
    /// Returns the authenticated digest of the protected plaintext.
    #[must_use]
    pub const fn plaintext_digest(&self) -> Sha256Digest {
        self.plaintext_digest
    }
    /// Returns the digest authenticating identity and payload metadata together.
    #[must_use]
    pub const fn aad_digest(&self) -> Sha256Digest {
        self.aad_digest
    }

    /// Builds the exact key-management context whose record ID commits to all
    /// canonical AAD fields through [`Self::aad_digest`].
    ///
    /// # Errors
    ///
    /// Returns an error only if a static domain or validated record identity
    /// cannot be represented by the generic key-management boundary.
    pub fn encryption_context(
        &self,
    ) -> Result<KeyEncryptionContext, GithubRuntimeAuthorityValueError> {
        let purpose = KeyPurpose::new(ENCRYPTION_PURPOSE)
            .map_err(|_| GithubRuntimeAuthorityValueError::InvalidEncryptionContext)?;
        let record_id = format!(
            "github-runtime-authority:v3:{}:{}:{}",
            self.identity.key().attempt_id(),
            self.identity.key().fencing_token().get(),
            self.aad_digest
        );
        KeyEncryptionContext::new(self.identity.tenant().as_str(), purpose, record_id)
            .map_err(|_| GithubRuntimeAuthorityValueError::InvalidEncryptionContext)
    }
}

/// Persistence-safe protected authority; plaintext is never present.
pub struct ProtectedGithubRuntimeAuthority {
    metadata: GithubRuntimeAuthorityEnvelopeMetadata,
    envelope: EncryptedEnvelope,
}

impl ProtectedGithubRuntimeAuthority {
    /// Pairs an authenticated metadata contract with one sealed envelope.
    ///
    /// # Errors
    ///
    /// Rejects unsupported envelope schemas or a ciphertext length inconsistent
    /// with the authenticated plaintext size.
    pub fn new(
        metadata: GithubRuntimeAuthorityEnvelopeMetadata,
        envelope: EncryptedEnvelope,
    ) -> Result<Self, GithubRuntimeAuthorityValueError> {
        let expected_ciphertext_size = metadata
            .plaintext_size_bytes()
            .checked_add(16)
            .ok_or(GithubRuntimeAuthorityValueError::InvalidProtectedPayloadSize)?;
        if envelope.schema() != ENVELOPE_SCHEMA_V1
            || u64::try_from(envelope.ciphertext().len()).ok() != Some(expected_ciphertext_size)
        {
            return Err(GithubRuntimeAuthorityValueError::InvalidProtectedEnvelope);
        }
        Ok(Self { metadata, envelope })
    }

    /// Returns the authenticated, value-free envelope metadata.
    #[must_use]
    pub const fn metadata(&self) -> &GithubRuntimeAuthorityEnvelopeMetadata {
        &self.metadata
    }
    /// Returns the sealed envelope without exposing provider-token plaintext.
    #[must_use]
    pub const fn envelope(&self) -> &EncryptedEnvelope {
        &self.envelope
    }
}

impl std::fmt::Debug for ProtectedGithubRuntimeAuthority {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ProtectedGithubRuntimeAuthority")
            .field("metadata", &self.metadata)
            .field("envelope", &"[PROTECTED]")
            .finish()
    }
}

/// Durable lifecycle of one GitHub runtime-authority issuance.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GithubRuntimeAuthorityState {
    /// A worker owns the sole pre-mint reservation.
    Claimed,
    /// The irreversible durable boundary was crossed before provider I/O.
    Minting,
    /// A definitive no-token result is eligible for bounded retry.
    MintRetryPending,
    /// Provider mint outcome is ambiguous and can never become deliverable.
    Indeterminate,
    /// Exact protected authority is eligible for fenced runner delivery.
    Ready,
    /// Protected authority is retained solely for revocation or expiry.
    RevokePending,
    /// Corrupt protected material is retained closed until safe erasure.
    Quarantined,
    /// Issuance ended with proof that no provider token remains usable.
    Rejected,
    /// Protected custody ended after confirmation or conservative expiry.
    Revoked,
}

/// Truthful terminal disposition after envelope erasure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GithubRuntimeAuthorityTerminalReason {
    /// A newer attempt fence superseded the issuance before provider I/O.
    SupersededBeforeMint,
    /// The provider request deadline elapsed before mint began.
    RequestExpiredBeforeMint,
    /// The provider definitively rejected the mint without creating a token.
    ProviderMintRejected,
    /// Bounded definitive no-token retries exhausted their deadline.
    ProviderMintRetryExpired,
    /// The provider confirmed revocation with the required response.
    ProviderRevocationConfirmed,
    /// Known provider expiry made the authority safe to erase.
    ProviderAuthorityExpired,
    /// Unknown provider expiry reached the conservative erasure horizon.
    ConservativeAuthorityExpired,
    /// Ambiguous issuance reached its conservative erasure horizon.
    IndeterminateAuthorityExpired,
    /// Quarantined protected material reached its safe erasure horizon.
    QuarantinedAuthorityExpired,
}

/// Intended use of one uniquely recovered protected provider token.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GithubRuntimeAuthorityCommitDisposition {
    /// The token passed semantic validation and may become runner-deliverable.
    Deliverable,
    /// The token is known but may only be retained for revocation or expiry.
    RevokeOnly,
}

/// Closed corruption observation for protected material that must not be opened again.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GithubRuntimeAuthorityCorruptionKind {
    /// Stored envelope fields are structurally invalid.
    InvalidEnvelope,
    /// The stored envelope schema is unsupported.
    UnsupportedEnvelopeSchema,
    /// Payload ciphertext or authenticated context did not verify.
    EnvelopeAuthenticationFailed,
    /// The wrapped data-key representation is invalid.
    InvalidWrappedDataKey,
    /// The referenced wrapping key is unknown.
    UnknownWrappingKey,
    /// The referenced wrapping key is deliberately retired.
    RetiredWrappingKey,
    /// A local cryptographic primitive rejected the operation.
    CryptographicFailure,
}

/// Compact durable state receipt containing no protected content.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GithubRuntimeAuthorityReceipt {
    pub(crate) key: GithubRuntimeAuthorityKey,
    pub(crate) state: GithubRuntimeAuthorityState,
    pub(crate) updated_at: UnixMillis,
    pub(crate) terminal_reason: Option<GithubRuntimeAuthorityTerminalReason>,
}

impl GithubRuntimeAuthorityReceipt {
    /// Reconstructs a sanitized receipt returned by a repository adapter.
    ///
    /// # Errors
    ///
    /// Rejects negative timestamps or a terminal reason on a nonterminal
    /// state. Terminal states require one truthful terminal reason.
    pub fn from_repository_parts(
        key: GithubRuntimeAuthorityKey,
        state: GithubRuntimeAuthorityState,
        updated_at: UnixMillis,
        terminal_reason: Option<GithubRuntimeAuthorityTerminalReason>,
    ) -> Result<Self, GithubRuntimeAuthorityValueError> {
        validate_nonnegative(updated_at)?;
        let valid_terminal = matches!(
            (state, terminal_reason),
            (
                GithubRuntimeAuthorityState::Rejected,
                Some(
                    GithubRuntimeAuthorityTerminalReason::ProviderMintRejected
                        | GithubRuntimeAuthorityTerminalReason::ProviderMintRetryExpired,
                ),
            ) | (
                GithubRuntimeAuthorityState::Revoked,
                Some(
                    GithubRuntimeAuthorityTerminalReason::SupersededBeforeMint
                        | GithubRuntimeAuthorityTerminalReason::RequestExpiredBeforeMint
                        | GithubRuntimeAuthorityTerminalReason::ProviderRevocationConfirmed
                        | GithubRuntimeAuthorityTerminalReason::ProviderAuthorityExpired
                        | GithubRuntimeAuthorityTerminalReason::ConservativeAuthorityExpired
                        | GithubRuntimeAuthorityTerminalReason::IndeterminateAuthorityExpired
                        | GithubRuntimeAuthorityTerminalReason::QuarantinedAuthorityExpired,
                ),
            ) | (
                GithubRuntimeAuthorityState::Claimed
                    | GithubRuntimeAuthorityState::Minting
                    | GithubRuntimeAuthorityState::MintRetryPending
                    | GithubRuntimeAuthorityState::Indeterminate
                    | GithubRuntimeAuthorityState::Ready
                    | GithubRuntimeAuthorityState::RevokePending
                    | GithubRuntimeAuthorityState::Quarantined,
                None,
            )
        );
        if !valid_terminal {
            return Err(GithubRuntimeAuthorityValueError::InvalidReceipt);
        }
        Ok(Self {
            key,
            state,
            updated_at,
            terminal_reason,
        })
    }

    /// Returns the exact issuance key represented by this receipt.
    #[must_use]
    pub const fn key(self) -> GithubRuntimeAuthorityKey {
        self.key
    }
    /// Returns the durable lifecycle state.
    #[must_use]
    pub const fn state(self) -> GithubRuntimeAuthorityState {
        self.state
    }
    /// Returns the time of the represented durable transition.
    #[must_use]
    pub const fn updated_at(self) -> UnixMillis {
        self.updated_at
    }
    /// Returns the closed reason required for a terminal state.
    #[must_use]
    pub const fn terminal_reason(self) -> Option<GithubRuntimeAuthorityTerminalReason> {
        self.terminal_reason
    }
}

/// Sanitized lifecycle inspection containing no provider token or claim owner.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GithubRuntimeAuthorityInspection {
    pub(crate) receipt: GithubRuntimeAuthorityReceipt,
    pub(crate) mint_attempts: u16,
    pub(crate) next_action_at: Option<UnixMillis>,
    pub(crate) commit_disposition: Option<GithubRuntimeAuthorityCommitDisposition>,
    pub(crate) provider_expiry_known: bool,
    pub(crate) safe_erase_after: Option<UnixMillis>,
    pub(crate) corruption: Option<GithubRuntimeAuthorityCorruptionKind>,
}

impl GithubRuntimeAuthorityInspection {
    /// Returns the value-free durable lifecycle receipt.
    #[must_use]
    pub const fn receipt(self) -> GithubRuntimeAuthorityReceipt {
        self.receipt
    }

    /// Returns the number of pre-mint claim attempts already consumed.
    #[must_use]
    pub const fn mint_attempts(self) -> u16 {
        self.mint_attempts
    }

    /// Returns the earliest known time for a retry or expiry transition.
    #[must_use]
    pub const fn next_action_at(self) -> Option<UnixMillis> {
        self.next_action_at
    }

    /// Returns whether committed custody is deliverable or revoke-only.
    #[must_use]
    pub const fn commit_disposition(self) -> Option<GithubRuntimeAuthorityCommitDisposition> {
        self.commit_disposition
    }

    /// Reports whether the protected metadata contains a provider expiry.
    #[must_use]
    pub const fn provider_expiry_known(self) -> bool {
        self.provider_expiry_known
    }

    /// Returns the safe-erasure horizon when protected custody exists.
    #[must_use]
    pub const fn safe_erase_after(self) -> Option<UnixMillis> {
        self.safe_erase_after
    }

    /// Returns the closed corruption class when custody is quarantined.
    #[must_use]
    pub const fn corruption(self) -> Option<GithubRuntimeAuthorityCorruptionKind> {
        self.corruption
    }
}

/// Exact immutable identity used for a sanitized lifecycle inspection.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InspectGithubRuntimeAuthority {
    identity: GithubRuntimeAuthorityIdentity,
    observed_at: UnixMillis,
}

impl InspectGithubRuntimeAuthority {
    /// Constructs an exact inspection at one trusted wall-clock observation.
    ///
    /// # Errors
    ///
    /// Rejects an observation before the authority request.
    pub fn new(
        identity: GithubRuntimeAuthorityIdentity,
        observed_at: UnixMillis,
    ) -> Result<Self, GithubRuntimeAuthorityValueError> {
        if observed_at < identity.requested_at() {
            return Err(GithubRuntimeAuthorityValueError::InvalidTimeInterval);
        }
        Ok(Self {
            identity,
            observed_at,
        })
    }

    /// Returns the exact immutable identity to inspect.
    #[must_use]
    pub const fn identity(&self) -> &GithubRuntimeAuthorityIdentity {
        &self.identity
    }

    /// Returns the trusted observation time used for lifecycle reduction.
    #[must_use]
    pub const fn observed_at(&self) -> UnixMillis {
        self.observed_at
    }
}

/// Request to establish or reclaim the sole pre-mint claim.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ClaimGithubRuntimeAuthorityMint {
    identity: GithubRuntimeAuthorityIdentity,
    owner: GithubRuntimeAuthorityWorkerId,
    observed_at: UnixMillis,
    expires_at: UnixMillis,
}

impl ClaimGithubRuntimeAuthorityMint {
    /// Constructs a bounded claim that cannot outlive the provider deadline.
    ///
    /// # Errors
    ///
    /// Rejects invalid or regressing claim times.
    pub fn new(
        identity: GithubRuntimeAuthorityIdentity,
        owner: GithubRuntimeAuthorityWorkerId,
        observed_at: UnixMillis,
        expires_at: UnixMillis,
    ) -> Result<Self, GithubRuntimeAuthorityValueError> {
        validate_claim_interval(
            observed_at,
            expires_at,
            identity.requested_at(),
            identity.request_deadline(),
            MAX_GITHUB_AUTHORITY_MINT_CLAIM_MILLIS,
        )?;
        Ok(Self {
            identity,
            owner,
            observed_at,
            expires_at,
        })
    }

    /// Returns the exact immutable identity to reserve for minting.
    #[must_use]
    pub const fn identity(&self) -> &GithubRuntimeAuthorityIdentity {
        &self.identity
    }
    /// Returns the worker requesting the sole mint reservation.
    #[must_use]
    pub const fn owner(&self) -> GithubRuntimeAuthorityWorkerId {
        self.owner
    }
    /// Returns the trusted instant at which claim eligibility is evaluated.
    #[must_use]
    pub const fn observed_at(&self) -> UnixMillis {
        self.observed_at
    }
    /// Returns the exclusive requested claim expiry.
    #[must_use]
    pub const fn expires_at(&self) -> UnixMillis {
        self.expires_at
    }
}

/// Sole live pre-mint claim returned by the repository.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ClaimedGithubRuntimeAuthorityMint {
    pub(crate) identity: GithubRuntimeAuthorityIdentity,
    pub(crate) owner: GithubRuntimeAuthorityWorkerId,
    pub(crate) fence: GithubRuntimeAuthorityClaimFence,
    pub(crate) attempt: u16,
    pub(crate) claimed_at: UnixMillis,
    pub(crate) expires_at: UnixMillis,
}

impl ClaimedGithubRuntimeAuthorityMint {
    /// Reconstructs one validated sole mint claim in a repository adapter.
    ///
    /// # Errors
    ///
    /// Rejects a zero or excessive attempt ordinal and any claim interval that
    /// is inconsistent with the immutable authority request.
    #[allow(clippy::too_many_arguments)]
    pub fn from_repository_parts(
        identity: GithubRuntimeAuthorityIdentity,
        owner: GithubRuntimeAuthorityWorkerId,
        fence: GithubRuntimeAuthorityClaimFence,
        attempt: u16,
        claimed_at: UnixMillis,
        expires_at: UnixMillis,
    ) -> Result<Self, GithubRuntimeAuthorityValueError> {
        if attempt == 0 || attempt > MAX_GITHUB_AUTHORITY_MINT_ATTEMPTS {
            return Err(GithubRuntimeAuthorityValueError::InvalidMintAttempt);
        }
        validate_claim_interval(
            claimed_at,
            expires_at,
            identity.requested_at(),
            identity.request_deadline(),
            MAX_GITHUB_AUTHORITY_MINT_CLAIM_MILLIS,
        )?;
        Ok(Self {
            identity,
            owner,
            fence,
            attempt,
            claimed_at,
            expires_at,
        })
    }

    /// Returns the exact immutable authority identity held by the claim.
    #[must_use]
    pub const fn identity(&self) -> &GithubRuntimeAuthorityIdentity {
        &self.identity
    }
    /// Returns the worker that owns the claim.
    #[must_use]
    pub const fn owner(&self) -> GithubRuntimeAuthorityWorkerId {
        self.owner
    }
    /// Returns the monotonic fence assigned to this claim.
    #[must_use]
    pub const fn fence(&self) -> GithubRuntimeAuthorityClaimFence {
        self.fence
    }
    /// Returns the bounded one-based mint-attempt ordinal.
    #[must_use]
    pub const fn attempt(&self) -> u16 {
        self.attempt
    }
    /// Returns the trusted time at which the claim began.
    #[must_use]
    pub const fn claimed_at(&self) -> UnixMillis {
        self.claimed_at
    }
    /// Returns the exclusive claim expiry.
    #[must_use]
    pub const fn expires_at(&self) -> UnixMillis {
        self.expires_at
    }
}

/// Exact mint custody used to authenticate erasure of an unprotected token.
///
/// This request deliberately contains no caller-selected observation time.
/// Only the repository's locked time observation may prove that an
/// ambiguous post-provider token has crossed its conservative expiry horizon.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthenticateGithubRuntimeAuthorityUnprotectedErasure {
    claim: ClaimedGithubRuntimeAuthorityMint,
}

impl AuthenticateGithubRuntimeAuthorityUnprotectedErasure {
    /// Retains the complete immutable identity and exact mint owner/fence.
    #[must_use]
    pub fn new(claim: &ClaimedGithubRuntimeAuthorityMint) -> Self {
        Self {
            claim: claim.clone(),
        }
    }

    /// Returns the exact claim that crossed the irreversible mint boundary.
    #[must_use]
    pub const fn claim(&self) -> &ClaimedGithubRuntimeAuthorityMint {
        &self.claim
    }
}

/// Exact claimed mint mutation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BeginGithubRuntimeAuthorityMint {
    claim: ClaimedGithubRuntimeAuthorityMint,
    observed_at: UnixMillis,
    provider_request_millis: i64,
}

impl BeginGithubRuntimeAuthorityMint {
    /// Marks the irreversible boundary immediately before provider I/O.
    ///
    /// # Errors
    ///
    /// Rejects observations outside the live claim interval.
    pub fn new(
        claim: ClaimedGithubRuntimeAuthorityMint,
        observed_at: UnixMillis,
        provider_request_millis: i64,
    ) -> Result<Self, GithubRuntimeAuthorityValueError> {
        if observed_at < claim.claimed_at()
            || observed_at >= claim.expires_at()
            || !(1..=MAX_GITHUB_AUTHORITY_REQUEST_MILLIS).contains(&provider_request_millis)
        {
            return Err(GithubRuntimeAuthorityValueError::InvalidTimeInterval);
        }
        Ok(Self {
            claim,
            observed_at,
            provider_request_millis,
        })
    }

    /// Returns the sole claim that is crossing the mint cutoff.
    #[must_use]
    pub const fn claim(&self) -> &ClaimedGithubRuntimeAuthorityMint {
        &self.claim
    }
    /// Returns the trusted time immediately preceding provider I/O.
    #[must_use]
    pub const fn observed_at(&self) -> UnixMillis {
        self.observed_at
    }
    /// Returns the exact maximum provider-request duration authorized at cutoff.
    #[must_use]
    pub const fn provider_request_millis(&self) -> i64 {
        self.provider_request_millis
    }
}

/// Result of attempting the irreversible mint transition.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BeginGithubRuntimeAuthorityMintOutcome {
    /// This caller committed the transition and may perform exactly one mint.
    Started(GithubRuntimeAuthorityReceipt),
    /// The exact claim already crossed the boundary; minting must not repeat.
    AlreadyStarted(GithubRuntimeAuthorityReceipt),
}

/// Records an ambiguous provider outcome without permitting another mint.
///
/// A token recovered after this transition may only finalize as
/// `revoke_pending`; it can never become runner-deliverable `ready` authority.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MarkGithubRuntimeAuthorityIndeterminate {
    key: GithubRuntimeAuthorityKey,
    owner: GithubRuntimeAuthorityWorkerId,
    fence: GithubRuntimeAuthorityClaimFence,
    observed_at: UnixMillis,
}

impl MarkGithubRuntimeAuthorityIndeterminate {
    /// Constructs the mutation from the claim that crossed the mint boundary.
    ///
    /// # Errors
    ///
    /// Rejects a timestamp before the claim or at/after the conservative
    /// uncertainty horizon.
    pub fn new(
        claim: &ClaimedGithubRuntimeAuthorityMint,
        observed_at: UnixMillis,
    ) -> Result<Self, GithubRuntimeAuthorityValueError> {
        if observed_at < claim.claimed_at() || observed_at >= claim.identity().conservative_expiry()
        {
            return Err(GithubRuntimeAuthorityValueError::InvalidTimeInterval);
        }
        Ok(Self {
            key: claim.identity.key,
            owner: claim.owner,
            fence: claim.fence,
            observed_at,
        })
    }

    /// Returns the exact issuance key whose provider outcome was ambiguous.
    #[must_use]
    pub const fn key(&self) -> GithubRuntimeAuthorityKey {
        self.key
    }
    /// Returns the worker that crossed the irreversible mint boundary.
    #[must_use]
    pub const fn owner(&self) -> GithubRuntimeAuthorityWorkerId {
        self.owner
    }
    /// Returns the exact claim fence that crossed the mint boundary.
    #[must_use]
    pub const fn fence(&self) -> GithubRuntimeAuthorityClaimFence {
        self.fence
    }
    /// Returns the trusted time at which ambiguity was recorded.
    #[must_use]
    pub const fn observed_at(&self) -> UnixMillis {
        self.observed_at
    }
}

/// Bounded, machine-readable reason a provider proved that no token was minted.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct GithubRuntimeAuthorityMintFailure(String);

impl GithubRuntimeAuthorityMintFailure {
    /// Constructs a sanitized definitive-rejection classification.
    ///
    /// # Errors
    ///
    /// Rejects empty, oversized, or noncanonical values.
    pub fn new(value: impl Into<String>) -> Result<Self, GithubRuntimeAuthorityValueError> {
        let value = value.into();
        validate_failure_kind(&value)?;
        Ok(Self(value))
    }

    /// Returns the sanitized definitive no-token failure class.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Schedules another provider call only after a definitive no-token outcome.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RetryGithubRuntimeAuthorityMint {
    key: GithubRuntimeAuthorityKey,
    owner: GithubRuntimeAuthorityWorkerId,
    fence: GithubRuntimeAuthorityClaimFence,
    failure: GithubRuntimeAuthorityMintFailure,
    observed_at: UnixMillis,
    retry_at: UnixMillis,
}

impl RetryGithubRuntimeAuthorityMint {
    /// Constructs a bounded no-token mint retry mutation.
    ///
    /// A retry at or beyond the request deadline is accepted by this value and
    /// becomes a truthful terminal rejection in the repository.
    ///
    /// # Errors
    ///
    /// Rejects observations outside the issuance horizon or invalid backoff.
    pub fn new(
        claim: &ClaimedGithubRuntimeAuthorityMint,
        failure: GithubRuntimeAuthorityMintFailure,
        observed_at: UnixMillis,
        retry_at: UnixMillis,
    ) -> Result<Self, GithubRuntimeAuthorityValueError> {
        if observed_at < claim.claimed_at()
            || observed_at >= claim.identity().conservative_expiry()
            || retry_at <= observed_at
            || retry_at >= claim.identity().conservative_expiry()
            || retry_at.get() - observed_at.get() > MAX_GITHUB_AUTHORITY_MINT_RETRY_BACKOFF_MILLIS
        {
            return Err(GithubRuntimeAuthorityValueError::InvalidTimeInterval);
        }
        Ok(Self {
            key: claim.identity().key(),
            owner: claim.owner(),
            fence: claim.fence(),
            failure,
            observed_at,
            retry_at,
        })
    }

    /// Returns the exact issuance key eligible for a definitive no-token retry.
    #[must_use]
    pub const fn key(&self) -> GithubRuntimeAuthorityKey {
        self.key
    }
    /// Returns the worker that owns the mint claim.
    #[must_use]
    pub const fn owner(&self) -> GithubRuntimeAuthorityWorkerId {
        self.owner
    }
    /// Returns the exact live mint fence.
    #[must_use]
    pub const fn fence(&self) -> GithubRuntimeAuthorityClaimFence {
        self.fence
    }
    /// Returns the sanitized provider failure classification.
    #[must_use]
    pub const fn failure(&self) -> &GithubRuntimeAuthorityMintFailure {
        &self.failure
    }
    /// Returns the trusted time of the definitive provider outcome.
    #[must_use]
    pub const fn observed_at(&self) -> UnixMillis {
        self.observed_at
    }
    /// Returns the earliest instant at which a new claim may retry.
    #[must_use]
    pub const fn retry_at(&self) -> UnixMillis {
        self.retry_at
    }
}

/// Records a definitive provider rejection for which no token can exist.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RejectGithubRuntimeAuthorityMint {
    key: GithubRuntimeAuthorityKey,
    owner: GithubRuntimeAuthorityWorkerId,
    fence: GithubRuntimeAuthorityClaimFence,
    failure: GithubRuntimeAuthorityMintFailure,
    observed_at: UnixMillis,
}

impl RejectGithubRuntimeAuthorityMint {
    /// Constructs an exact terminal no-token mutation.
    ///
    /// # Errors
    ///
    /// Rejects observations outside the conservative issuance horizon.
    pub fn new(
        claim: &ClaimedGithubRuntimeAuthorityMint,
        failure: GithubRuntimeAuthorityMintFailure,
        observed_at: UnixMillis,
    ) -> Result<Self, GithubRuntimeAuthorityValueError> {
        if observed_at < claim.claimed_at() || observed_at >= claim.identity().conservative_expiry()
        {
            return Err(GithubRuntimeAuthorityValueError::InvalidTimeInterval);
        }
        Ok(Self {
            key: claim.identity().key(),
            owner: claim.owner(),
            fence: claim.fence(),
            failure,
            observed_at,
        })
    }

    /// Returns the exact issuance key being terminally rejected.
    #[must_use]
    pub const fn key(&self) -> GithubRuntimeAuthorityKey {
        self.key
    }
    /// Returns the worker that owns the mint claim.
    #[must_use]
    pub const fn owner(&self) -> GithubRuntimeAuthorityWorkerId {
        self.owner
    }
    /// Returns the exact live mint fence.
    #[must_use]
    pub const fn fence(&self) -> GithubRuntimeAuthorityClaimFence {
        self.fence
    }
    /// Returns the sanitized definitive provider rejection class.
    #[must_use]
    pub const fn failure(&self) -> &GithubRuntimeAuthorityMintFailure {
        &self.failure
    }
    /// Returns the trusted time of terminal rejection.
    #[must_use]
    pub const fn observed_at(&self) -> UnixMillis {
        self.observed_at
    }
}

/// Commits a minted token envelope after all provider and encryption I/O.
#[derive(Debug)]
pub struct CommitGithubRuntimeAuthority {
    claim: ClaimedGithubRuntimeAuthorityMint,
    disposition: GithubRuntimeAuthorityCommitDisposition,
    protected: ProtectedGithubRuntimeAuthority,
    committed_at: UnixMillis,
}

impl CommitGithubRuntimeAuthority {
    /// Constructs an exact deliverable post-I/O commit.
    ///
    /// # Errors
    ///
    /// Rejects a commit before the original mint claim began or at/after the
    /// conservative uncertainty horizon.
    pub fn deliverable(
        claim: &ClaimedGithubRuntimeAuthorityMint,
        protected: ProtectedGithubRuntimeAuthority,
        committed_at: UnixMillis,
    ) -> Result<Self, GithubRuntimeAuthorityValueError> {
        if protected
            .metadata()
            .conservative_use_expires_at()
            .is_none_or(|expires_at| expires_at <= committed_at)
        {
            return Err(GithubRuntimeAuthorityValueError::InvalidCommit);
        }
        Self::new(
            claim,
            GithubRuntimeAuthorityCommitDisposition::Deliverable,
            protected,
            committed_at,
        )
    }

    /// Constructs an exact revoke-only post-I/O commit.
    ///
    /// # Errors
    ///
    /// Rejects a mismatched claim or a commit outside the custody horizon.
    pub fn revoke_only(
        claim: &ClaimedGithubRuntimeAuthorityMint,
        protected: ProtectedGithubRuntimeAuthority,
        committed_at: UnixMillis,
    ) -> Result<Self, GithubRuntimeAuthorityValueError> {
        Self::new(
            claim,
            GithubRuntimeAuthorityCommitDisposition::RevokeOnly,
            protected,
            committed_at,
        )
    }

    fn new(
        claim: &ClaimedGithubRuntimeAuthorityMint,
        disposition: GithubRuntimeAuthorityCommitDisposition,
        protected: ProtectedGithubRuntimeAuthority,
        committed_at: UnixMillis,
    ) -> Result<Self, GithubRuntimeAuthorityValueError> {
        if protected.metadata().identity() != claim.identity()
            || committed_at < claim.claimed_at()
            || committed_at >= claim.identity().conservative_expiry()
            || committed_at >= protected.metadata().safe_erase_after()
        {
            return Err(GithubRuntimeAuthorityValueError::InvalidCommit);
        }
        Ok(Self {
            claim: claim.clone(),
            disposition,
            protected,
            committed_at,
        })
    }

    /// Returns the worker that owns the commit's mint claim.
    #[must_use]
    pub const fn owner(&self) -> GithubRuntimeAuthorityWorkerId {
        self.claim.owner()
    }
    /// Returns the exact mint-claim fence required by the commit.
    #[must_use]
    pub const fn fence(&self) -> GithubRuntimeAuthorityClaimFence {
        self.claim.fence()
    }
    /// Returns the complete immutable mint predecessor.
    #[must_use]
    pub const fn claim(&self) -> &ClaimedGithubRuntimeAuthorityMint {
        &self.claim
    }
    /// Returns whether committed custody is deliverable or revoke-only.
    #[must_use]
    pub const fn disposition(&self) -> GithubRuntimeAuthorityCommitDisposition {
        self.disposition
    }
    /// Returns the exact protected bytes and authenticated metadata to persist.
    #[must_use]
    pub const fn protected(&self) -> &ProtectedGithubRuntimeAuthority {
        &self.protected
    }
    /// Returns the frozen commit timestamp used for exact replay.
    #[must_use]
    pub const fn committed_at(&self) -> UnixMillis {
        self.committed_at
    }
}

/// Expected exact identity for loading a ready token.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LoadGithubRuntimeAuthority {
    identity: GithubRuntimeAuthorityIdentity,
    observed_at: UnixMillis,
}

impl LoadGithubRuntimeAuthority {
    /// Constructs a fail-closed ready load.
    ///
    /// # Errors
    ///
    /// Rejects an observation before the authority request.
    pub fn new(
        identity: GithubRuntimeAuthorityIdentity,
        observed_at: UnixMillis,
    ) -> Result<Self, GithubRuntimeAuthorityValueError> {
        if observed_at < identity.requested_at() {
            return Err(GithubRuntimeAuthorityValueError::InvalidTimeInterval);
        }
        Ok(Self {
            identity,
            observed_at,
        })
    }

    /// Returns the exact immutable identity required from durable ready state.
    #[must_use]
    pub const fn identity(&self) -> &GithubRuntimeAuthorityIdentity {
        &self.identity
    }
    /// Returns the trusted time at which deliverability is evaluated.
    #[must_use]
    pub const fn observed_at(&self) -> UnixMillis {
        self.observed_at
    }
}

/// Ready protected authority returned only while the exact attempt is current.
#[derive(Debug)]
pub struct ReadyGithubRuntimeAuthority {
    pub(crate) protected: ProtectedGithubRuntimeAuthority,
    pub(crate) ready_at: UnixMillis,
}

impl ReadyGithubRuntimeAuthority {
    /// Reconstructs one deliverable ready authority in a repository adapter.
    ///
    /// # Errors
    ///
    /// Rejects revoke-only custody, an unknown provider expiry, or a ready
    /// timestamp outside the immutable request, lease, protected-custody, and
    /// conservative-use intervals.
    pub fn from_repository_parts(
        protected: ProtectedGithubRuntimeAuthority,
        disposition: GithubRuntimeAuthorityCommitDisposition,
        ready_at: UnixMillis,
    ) -> Result<Self, GithubRuntimeAuthorityValueError> {
        validate_nonnegative(ready_at)?;
        let metadata = protected.metadata();
        let identity = metadata.identity();
        if disposition != GithubRuntimeAuthorityCommitDisposition::Deliverable
            || ready_at < identity.requested_at()
            || ready_at >= identity.lease_expires_at()
            || ready_at >= metadata.safe_erase_after()
            || metadata
                .conservative_use_expires_at()
                .is_none_or(|expires_at| ready_at >= expires_at)
        {
            return Err(GithubRuntimeAuthorityValueError::InvalidReadyAuthority);
        }
        Ok(Self {
            protected,
            ready_at,
        })
    }

    /// Returns the protected provider authority without decrypting it.
    #[must_use]
    pub const fn protected(&self) -> &ProtectedGithubRuntimeAuthority {
        &self.protected
    }
    /// Returns the time at which the authority became durably ready.
    #[must_use]
    pub const fn ready_at(&self) -> UnixMillis {
        self.ready_at
    }
}

/// Records a non-retryable protected-material failure while retaining custody.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct QuarantineGithubRuntimeAuthority {
    key: GithubRuntimeAuthorityKey,
    aad_digest: Sha256Digest,
    kind: GithubRuntimeAuthorityCorruptionKind,
    observed_at: UnixMillis,
}

impl QuarantineGithubRuntimeAuthority {
    /// Constructs an exact quarantine observation for one protected envelope.
    ///
    /// # Errors
    ///
    /// Rejects an observation before issuance or at/after safe erasure.
    pub fn new(
        protected: &ProtectedGithubRuntimeAuthority,
        kind: GithubRuntimeAuthorityCorruptionKind,
        observed_at: UnixMillis,
    ) -> Result<Self, GithubRuntimeAuthorityValueError> {
        if observed_at < protected.metadata().identity().requested_at()
            || observed_at >= protected.metadata().safe_erase_after()
        {
            return Err(GithubRuntimeAuthorityValueError::InvalidTimeInterval);
        }
        Ok(Self {
            key: protected.metadata().identity().key(),
            aad_digest: protected.metadata().aad_digest(),
            kind,
            observed_at,
        })
    }

    /// Returns the exact issuance key placed in quarantine.
    #[must_use]
    pub const fn key(self) -> GithubRuntimeAuthorityKey {
        self.key
    }
    /// Returns the authenticated metadata digest of the quarantined envelope.
    #[must_use]
    pub const fn aad_digest(self) -> Sha256Digest {
        self.aad_digest
    }
    /// Returns the closed, non-secret corruption classification.
    #[must_use]
    pub const fn kind(self) -> GithubRuntimeAuthorityCorruptionKind {
        self.kind
    }
    /// Returns the trusted time at which corruption was observed.
    #[must_use]
    pub const fn observed_at(self) -> UnixMillis {
        self.observed_at
    }
}

/// Bounded reconciliation request using one trusted time observation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReconcileGithubRuntimeAuthorities {
    observed_at: UnixMillis,
    batch_size: NonZeroU16,
}

impl ReconcileGithubRuntimeAuthorities {
    /// Constructs a bounded reconciliation batch.
    ///
    /// # Errors
    ///
    /// Rejects negative time, zero, or oversized batches.
    pub fn new(
        observed_at: UnixMillis,
        batch_size: u16,
    ) -> Result<Self, GithubRuntimeAuthorityValueError> {
        validate_nonnegative(observed_at)?;
        let batch_size = NonZeroU16::new(batch_size)
            .ok_or(GithubRuntimeAuthorityValueError::InvalidBatchSize)?;
        if batch_size.get() > MAX_GITHUB_AUTHORITY_RECONCILE_BATCH {
            return Err(GithubRuntimeAuthorityValueError::InvalidBatchSize);
        }
        Ok(Self {
            observed_at,
            batch_size,
        })
    }

    /// Returns the trusted time used for every reduction in this batch.
    #[must_use]
    pub const fn observed_at(self) -> UnixMillis {
        self.observed_at
    }
    /// Returns the validated maximum number of records the transaction may change.
    #[must_use]
    pub const fn batch_size(self) -> u16 {
        self.batch_size.get()
    }
}

/// Counts of state reductions committed by one reconciliation batch.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct GithubRuntimeAuthorityReconciliationReport {
    pub(crate) revoked_before_mint: u16,
    pub(crate) mint_retries_rejected: u16,
    pub(crate) minting_marked_indeterminate: u16,
    pub(crate) ready_marked_revoke_pending: u16,
    pub(crate) indeterminate_authorities_expired: u16,
    pub(crate) expired_envelopes_erased: u16,
    pub(crate) quarantined_envelopes_erased: u16,
}

impl GithubRuntimeAuthorityReconciliationReport {
    /// Returns issuances rejected because their attempt was superseded before mint.
    #[must_use]
    pub const fn revoked_before_mint(self) -> u16 {
        self.revoked_before_mint
    }
    /// Returns definitive no-token retries terminally rejected by their deadline.
    #[must_use]
    pub const fn mint_retries_rejected(self) -> u16 {
        self.mint_retries_rejected
    }
    /// Returns abandoned `minting` records reduced to indeterminate custody.
    #[must_use]
    pub const fn minting_marked_indeterminate(self) -> u16 {
        self.minting_marked_indeterminate
    }
    /// Returns ready authorities moved to revoke-only custody after lease loss.
    #[must_use]
    pub const fn ready_marked_revoke_pending(self) -> u16 {
        self.ready_marked_revoke_pending
    }
    /// Returns indeterminate issuances erased at their conservative horizon.
    #[must_use]
    pub const fn indeterminate_authorities_expired(self) -> u16 {
        self.indeterminate_authorities_expired
    }
    /// Returns ordinary protected envelopes erased at a proven expiry.
    #[must_use]
    pub const fn expired_envelopes_erased(self) -> u16 {
        self.expired_envelopes_erased
    }
    /// Returns quarantined envelopes erased at their safe horizon.
    #[must_use]
    pub const fn quarantined_envelopes_erased(self) -> u16 {
        self.quarantined_envelopes_erased
    }
    /// Returns the total number of state reductions committed by the batch.
    #[must_use]
    pub const fn total(self) -> u16 {
        self.revoked_before_mint
            + self.mint_retries_rejected
            + self.minting_marked_indeterminate
            + self.ready_marked_revoke_pending
            + self.indeterminate_authorities_expired
            + self.expired_envelopes_erased
            + self.quarantined_envelopes_erased
    }
}

/// Request for the next eligible protected token revocation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ClaimGithubRuntimeAuthorityRevocation {
    owner: GithubRuntimeAuthorityWorkerId,
    observed_at: UnixMillis,
    expires_at: UnixMillis,
}

impl ClaimGithubRuntimeAuthorityRevocation {
    /// Constructs a bounded revocation claim.
    ///
    /// # Errors
    ///
    /// Rejects negative or oversized claim intervals.
    pub fn new(
        owner: GithubRuntimeAuthorityWorkerId,
        observed_at: UnixMillis,
        expires_at: UnixMillis,
    ) -> Result<Self, GithubRuntimeAuthorityValueError> {
        validate_nonnegative(observed_at)?;
        if expires_at <= observed_at
            || expires_at.get() - observed_at.get() > MAX_GITHUB_AUTHORITY_REVOKE_CLAIM_MILLIS
        {
            return Err(GithubRuntimeAuthorityValueError::InvalidTimeInterval);
        }
        Ok(Self {
            owner,
            observed_at,
            expires_at,
        })
    }

    /// Returns the worker requesting the next eligible revocation claim.
    #[must_use]
    pub const fn owner(self) -> GithubRuntimeAuthorityWorkerId {
        self.owner
    }
    /// Returns the trusted time at which revocation eligibility is evaluated.
    #[must_use]
    pub const fn observed_at(self) -> UnixMillis {
        self.observed_at
    }
    /// Returns the exclusive requested revocation-claim expiry.
    #[must_use]
    pub const fn expires_at(self) -> UnixMillis {
        self.expires_at
    }
}

/// Sole live revocation claim carrying only protected provider material.
#[derive(Debug)]
pub struct ClaimedGithubRuntimeAuthorityRevocation {
    pub(crate) protected: ProtectedGithubRuntimeAuthority,
    pub(crate) owner: GithubRuntimeAuthorityWorkerId,
    pub(crate) fence: GithubRuntimeAuthorityClaimFence,
    pub(crate) attempt: u16,
    pub(crate) claimed_at: UnixMillis,
    pub(crate) expires_at: UnixMillis,
}

impl ClaimedGithubRuntimeAuthorityRevocation {
    /// Reconstructs one exact protected revocation claim in an adapter.
    ///
    /// # Errors
    ///
    /// Rejects an invalid attempt ordinal or a claim outside the immutable
    /// issuance and safe-erasure horizons.
    pub fn from_repository_parts(
        protected: ProtectedGithubRuntimeAuthority,
        owner: GithubRuntimeAuthorityWorkerId,
        fence: GithubRuntimeAuthorityClaimFence,
        attempt: u16,
        claimed_at: UnixMillis,
        expires_at: UnixMillis,
    ) -> Result<Self, GithubRuntimeAuthorityValueError> {
        let metadata = protected.metadata();
        if attempt == 0
            || attempt > MAX_GITHUB_AUTHORITY_REVOKE_ATTEMPTS
            || claimed_at < metadata.identity().requested_at()
            || expires_at <= claimed_at
            || expires_at.get() - claimed_at.get() > MAX_GITHUB_AUTHORITY_REVOKE_CLAIM_MILLIS
            || expires_at >= metadata.safe_erase_after()
        {
            return Err(GithubRuntimeAuthorityValueError::InvalidTimeInterval);
        }
        Ok(Self {
            protected,
            owner,
            fence,
            attempt,
            claimed_at,
            expires_at,
        })
    }

    /// Returns the protected provider authority held for revocation.
    #[must_use]
    pub const fn protected(&self) -> &ProtectedGithubRuntimeAuthority {
        &self.protected
    }
    /// Returns the exact issuance key held by the claim.
    #[must_use]
    pub const fn key(&self) -> GithubRuntimeAuthorityKey {
        self.protected.metadata.identity.key
    }
    /// Returns the worker that owns the revocation claim.
    #[must_use]
    pub const fn owner(&self) -> GithubRuntimeAuthorityWorkerId {
        self.owner
    }
    /// Returns the monotonic fence assigned to this revocation claim.
    #[must_use]
    pub const fn fence(&self) -> GithubRuntimeAuthorityClaimFence {
        self.fence
    }
    /// Returns the bounded one-based provider revocation attempt.
    #[must_use]
    pub const fn attempt(&self) -> u16 {
        self.attempt
    }
    /// Returns the trusted time at which the revocation claim began.
    #[must_use]
    pub const fn claimed_at(&self) -> UnixMillis {
        self.claimed_at
    }
    /// Returns the exclusive revocation-claim expiry.
    #[must_use]
    pub const fn expires_at(&self) -> UnixMillis {
        self.expires_at
    }
}

/// Exact post-decrypt check required immediately before provider revocation.
///
/// The request carries no plaintext. It binds the live revocation claim to the
/// authenticated authority identity and envelope metadata and asks Store to
/// decide whether the complete provider request still fits using repository
/// time sampled after the authority graph and issuance record are locked.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RevalidateGithubRuntimeAuthorityRevocation {
    key: GithubRuntimeAuthorityKey,
    owner: GithubRuntimeAuthorityWorkerId,
    fence: GithubRuntimeAuthorityClaimFence,
    identity_digest: Sha256Digest,
    aad_digest: Sha256Digest,
    claimed_at: UnixMillis,
    expires_at: UnixMillis,
    safe_erase_after: UnixMillis,
    provider_request_millis: i64,
}

impl RevalidateGithubRuntimeAuthorityRevocation {
    /// Builds the value-free post-decrypt revalidation request.
    ///
    /// # Errors
    ///
    /// Rejects a zero, negative, or larger-than-claim provider request bound.
    pub fn new(
        claim: &ClaimedGithubRuntimeAuthorityRevocation,
        provider_request_millis: i64,
    ) -> Result<Self, GithubRuntimeAuthorityValueError> {
        if !(1..=MAX_GITHUB_AUTHORITY_REVOKE_CLAIM_MILLIS).contains(&provider_request_millis) {
            return Err(GithubRuntimeAuthorityValueError::InvalidTimeInterval);
        }
        let metadata = claim.protected().metadata();
        Ok(Self {
            key: claim.key(),
            owner: claim.owner(),
            fence: claim.fence(),
            identity_digest: metadata.identity().identity_digest(),
            aad_digest: metadata.aad_digest(),
            claimed_at: claim.claimed_at(),
            expires_at: claim.expires_at(),
            safe_erase_after: metadata.safe_erase_after(),
            provider_request_millis,
        })
    }

    /// Returns the exact issuance key being revalidated.
    #[must_use]
    pub const fn key(self) -> GithubRuntimeAuthorityKey {
        self.key
    }

    /// Returns the exact revocation-claim owner.
    #[must_use]
    pub const fn owner(self) -> GithubRuntimeAuthorityWorkerId {
        self.owner
    }

    /// Returns the exact live revocation fence.
    #[must_use]
    pub const fn fence(self) -> GithubRuntimeAuthorityClaimFence {
        self.fence
    }

    /// Returns the digest of the complete immutable authority identity.
    #[must_use]
    pub const fn identity_digest(self) -> Sha256Digest {
        self.identity_digest
    }

    /// Returns the authenticated protected-metadata digest.
    #[must_use]
    pub const fn aad_digest(self) -> Sha256Digest {
        self.aad_digest
    }

    /// Returns the durable start of the exact claim.
    #[must_use]
    pub const fn claimed_at(self) -> UnixMillis {
        self.claimed_at
    }

    /// Returns the exclusive durable claim horizon.
    #[must_use]
    pub const fn expires_at(self) -> UnixMillis {
        self.expires_at
    }

    /// Returns the authenticated safe-erasure horizon.
    #[must_use]
    pub const fn safe_erase_after(self) -> UnixMillis {
        self.safe_erase_after
    }

    /// Returns the complete provider-call duration that must still fit.
    #[must_use]
    pub const fn provider_request_millis(self) -> i64 {
        self.provider_request_millis
    }
}

/// Repository-time result of the exact post-decrypt revocation check.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RevalidatedGithubRuntimeAuthorityRevocation {
    observed_at: UnixMillis,
    provider_call_authorized: bool,
}

impl RevalidatedGithubRuntimeAuthorityRevocation {
    /// Reconstructs a Store-issued decision and verifies its exact boundaries.
    ///
    /// # Errors
    ///
    /// Rejects an observation outside the live claim or a decision that does
    /// not agree with the claim, safe-erasure, and provider-duration horizons.
    pub fn from_repository_parts(
        request: RevalidateGithubRuntimeAuthorityRevocation,
        observed_at: UnixMillis,
        provider_call_authorized: bool,
    ) -> Result<Self, GithubRuntimeAuthorityValueError> {
        if observed_at < request.claimed_at()
            || observed_at >= request.expires_at()
            || observed_at >= request.safe_erase_after()
        {
            return Err(GithubRuntimeAuthorityValueError::InvalidTimeInterval);
        }
        let expected = observed_at
            .get()
            .checked_add(request.provider_request_millis())
            .is_some_and(|completion| {
                completion <= request.expires_at().get()
                    && completion < request.safe_erase_after().get()
            });
        if expected != provider_call_authorized {
            return Err(GithubRuntimeAuthorityValueError::InvalidTimeInterval);
        }
        Ok(Self {
            observed_at,
            provider_call_authorized,
        })
    }

    /// Returns the repository observation sampled after every required lock.
    #[must_use]
    pub const fn observed_at(self) -> UnixMillis {
        self.observed_at
    }

    /// Reports whether the complete provider call still fits both horizons.
    #[must_use]
    pub const fn provider_call_authorized(self) -> bool {
        self.provider_call_authorized
    }
}

/// Bounded, machine-readable provider revocation failure class.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct GithubRuntimeAuthorityRevocationFailure(String);

impl GithubRuntimeAuthorityRevocationFailure {
    /// Constructs a sanitized retry classification.
    ///
    /// # Errors
    ///
    /// Rejects empty, oversized, or noncanonical values.
    pub fn new(value: impl Into<String>) -> Result<Self, GithubRuntimeAuthorityValueError> {
        let value = value.into();
        validate_failure_kind(&value)?;
        Ok(Self(value))
    }

    /// Returns the sanitized provider revocation failure class.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Releases a failed revocation claim for bounded retry.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RetryGithubRuntimeAuthorityRevocation {
    key: GithubRuntimeAuthorityKey,
    owner: GithubRuntimeAuthorityWorkerId,
    fence: GithubRuntimeAuthorityClaimFence,
    claimed_at: UnixMillis,
    expires_at: UnixMillis,
    failure: GithubRuntimeAuthorityRevocationFailure,
    observed_at: UnixMillis,
    retry_at: UnixMillis,
}

impl RetryGithubRuntimeAuthorityRevocation {
    /// Constructs an exact retry mutation.
    ///
    /// # Errors
    ///
    /// Rejects an expired claim or an invalid/backoff interval.
    pub fn new(
        claim: &ClaimedGithubRuntimeAuthorityRevocation,
        failure: GithubRuntimeAuthorityRevocationFailure,
        observed_at: UnixMillis,
        retry_at: UnixMillis,
    ) -> Result<Self, GithubRuntimeAuthorityValueError> {
        if observed_at < claim.claimed_at()
            || observed_at >= claim.expires_at()
            || retry_at <= observed_at
            || retry_at.get() - observed_at.get() > MAX_GITHUB_AUTHORITY_REVOKE_BACKOFF_MILLIS
            || retry_at >= claim.protected.metadata.safe_erase_after
        {
            return Err(GithubRuntimeAuthorityValueError::InvalidTimeInterval);
        }
        Ok(Self {
            key: claim.key(),
            owner: claim.owner,
            fence: claim.fence,
            claimed_at: claim.claimed_at,
            expires_at: claim.expires_at,
            failure,
            observed_at,
            retry_at,
        })
    }

    /// Returns the exact issuance key being released for retry.
    #[must_use]
    pub const fn key(&self) -> GithubRuntimeAuthorityKey {
        self.key
    }
    /// Returns the worker that owns the revocation claim.
    #[must_use]
    pub const fn owner(&self) -> GithubRuntimeAuthorityWorkerId {
        self.owner
    }
    /// Returns the exact live revocation fence.
    #[must_use]
    pub const fn fence(&self) -> GithubRuntimeAuthorityClaimFence {
        self.fence
    }
    /// Returns the immutable revocation predecessor's repository-issued start.
    #[must_use]
    pub const fn claimed_at(&self) -> UnixMillis {
        self.claimed_at
    }
    /// Returns the immutable revocation predecessor's exclusive expiry.
    #[must_use]
    pub const fn expires_at(&self) -> UnixMillis {
        self.expires_at
    }
    /// Returns the sanitized provider failure classification.
    #[must_use]
    pub const fn failure(&self) -> &GithubRuntimeAuthorityRevocationFailure {
        &self.failure
    }
    /// Returns the trusted time of the provider failure.
    #[must_use]
    pub const fn observed_at(&self) -> UnixMillis {
        self.observed_at
    }
    /// Returns the earliest instant at which another revocation may be claimed.
    #[must_use]
    pub const fn retry_at(&self) -> UnixMillis {
        self.retry_at
    }
}

/// Retains an unconfirmed token without another provider call before expiry.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DeferGithubRuntimeAuthorityRevocation {
    key: GithubRuntimeAuthorityKey,
    owner: GithubRuntimeAuthorityWorkerId,
    fence: GithubRuntimeAuthorityClaimFence,
    claimed_at: UnixMillis,
    expires_at: UnixMillis,
    failure: GithubRuntimeAuthorityRevocationFailure,
    observed_at: UnixMillis,
}

impl DeferGithubRuntimeAuthorityRevocation {
    /// Constructs an exact retain-until-expiry mutation.
    ///
    /// # Errors
    ///
    /// Rejects an observation outside the live revocation claim.
    pub fn new(
        claim: &ClaimedGithubRuntimeAuthorityRevocation,
        failure: GithubRuntimeAuthorityRevocationFailure,
        observed_at: UnixMillis,
    ) -> Result<Self, GithubRuntimeAuthorityValueError> {
        if observed_at < claim.claimed_at() || observed_at >= claim.expires_at() {
            return Err(GithubRuntimeAuthorityValueError::InvalidTimeInterval);
        }
        Ok(Self {
            key: claim.key(),
            owner: claim.owner(),
            fence: claim.fence(),
            claimed_at: claim.claimed_at(),
            expires_at: claim.expires_at(),
            failure,
            observed_at,
        })
    }

    /// Returns the exact issuance key retained until expiry.
    #[must_use]
    pub const fn key(&self) -> GithubRuntimeAuthorityKey {
        self.key
    }
    /// Returns the worker that owns the revocation claim.
    #[must_use]
    pub const fn owner(&self) -> GithubRuntimeAuthorityWorkerId {
        self.owner
    }
    /// Returns the exact live revocation fence.
    #[must_use]
    pub const fn fence(&self) -> GithubRuntimeAuthorityClaimFence {
        self.fence
    }
    /// Returns the immutable revocation predecessor's repository-issued start.
    #[must_use]
    pub const fn claimed_at(&self) -> UnixMillis {
        self.claimed_at
    }
    /// Returns the immutable revocation predecessor's exclusive expiry.
    #[must_use]
    pub const fn expires_at(&self) -> UnixMillis {
        self.expires_at
    }
    /// Returns the sanitized reason another provider call is unsafe.
    #[must_use]
    pub const fn failure(&self) -> &GithubRuntimeAuthorityRevocationFailure {
        &self.failure
    }
    /// Returns the trusted time at which custody was deferred.
    #[must_use]
    pub const fn observed_at(&self) -> UnixMillis {
        self.observed_at
    }
}

/// Exact terminal mutation permitted only after provider HTTP 204.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ConfirmGithubRuntimeAuthorityRevocation {
    key: GithubRuntimeAuthorityKey,
    owner: GithubRuntimeAuthorityWorkerId,
    fence: GithubRuntimeAuthorityClaimFence,
    claimed_at: UnixMillis,
    expires_at: UnixMillis,
    confirmed_at: UnixMillis,
}

impl ConfirmGithubRuntimeAuthorityRevocation {
    /// Constructs a provider-confirmed erasure mutation.
    ///
    /// Callers must construct this only for a GitHub revocation response whose
    /// exact status is HTTP 204. In particular, HTTP 401 is not confirmation.
    ///
    /// # Errors
    ///
    /// Rejects confirmation outside the live revocation claim.
    pub fn provider_no_content(
        claim: &ClaimedGithubRuntimeAuthorityRevocation,
        confirmed_at: UnixMillis,
    ) -> Result<Self, GithubRuntimeAuthorityValueError> {
        if confirmed_at < claim.claimed_at() || confirmed_at >= claim.expires_at() {
            return Err(GithubRuntimeAuthorityValueError::InvalidTimeInterval);
        }
        Ok(Self {
            key: claim.key(),
            owner: claim.owner,
            fence: claim.fence,
            claimed_at: claim.claimed_at,
            expires_at: claim.expires_at,
            confirmed_at,
        })
    }

    /// Returns the exact issuance key whose revocation was confirmed.
    #[must_use]
    pub const fn key(self) -> GithubRuntimeAuthorityKey {
        self.key
    }
    /// Returns the worker that owns the confirmed revocation claim.
    #[must_use]
    pub const fn owner(self) -> GithubRuntimeAuthorityWorkerId {
        self.owner
    }
    /// Returns the exact revocation fence accepted by confirmation.
    #[must_use]
    pub const fn fence(self) -> GithubRuntimeAuthorityClaimFence {
        self.fence
    }
    /// Returns the immutable revocation predecessor's repository-issued start.
    #[must_use]
    pub const fn claimed_at(self) -> UnixMillis {
        self.claimed_at
    }
    /// Returns the immutable revocation predecessor's exclusive expiry.
    #[must_use]
    pub const fn expires_at(self) -> UnixMillis {
        self.expires_at
    }
    /// Returns the trusted time associated with the provider HTTP 204.
    #[must_use]
    pub const fn confirmed_at(self) -> UnixMillis {
        self.confirmed_at
    }
}

/// Portable repository failures for durable GitHub runtime authority.
#[derive(Debug, Error)]
pub enum GithubRuntimeAuthorityStoreError {
    /// The backing repository operation failed without exposing credential data.
    #[error(transparent)]
    Operation(#[from] RepositoryOperationError),
    /// Durable records violate the current-only runtime-authority contract.
    #[error("durable GitHub runtime-authority data is corrupt")]
    CorruptData,
    /// An exact key already exists with different immutable identity evidence.
    #[error("GitHub runtime-authority immutable identity conflicts with durable state")]
    IdentityConflict,
    /// The requested mint mutation does not own the current live fence.
    #[error("GitHub runtime-authority mint claim was rejected")]
    MintClaimRejected,
    /// The requested revocation mutation does not own the current live fence.
    #[error("GitHub runtime-authority revocation claim was rejected")]
    RevocationClaimRejected,
    /// Quarantine did not match the exact protected envelope and live state.
    #[error("GitHub runtime-authority quarantine observation was rejected")]
    QuarantineRejected,
    /// A new positive repository claim fence cannot be represented safely.
    #[error("GitHub runtime-authority claim fence is exhausted")]
    FenceExhausted,
    /// The closed mint or revocation attempt ceiling has been reached.
    #[error("GitHub runtime-authority claim retry bound is exhausted")]
    RetryLimitReached,
}

impl GithubRuntimeAuthorityStoreError {
    /// Wraps an external adapter failure in the sanitized repository error type.
    #[must_use]
    pub fn operation(source: impl std::error::Error + Send + Sync + 'static) -> Self {
        RepositoryOperationError::from_source(source).into()
    }
}

/// Value-construction failures at the runtime-authority trust boundary.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum GithubRuntimeAuthorityValueError {
    /// A required UUID identity used the nil sentinel.
    #[error("runtime-authority identity field is nil: {0}")]
    NilIdentity(&'static str),
    /// Repository name evidence is not canonical bounded `owner/repository`.
    #[error("GitHub repository name is invalid")]
    InvalidRepositoryName,
    /// The requested logical authority namespace is not canonical and bounded.
    #[error("runtime-authority namespace is invalid")]
    InvalidNamespace,
    /// A claim fence is zero or cannot be represented by the durable adapter.
    #[error("runtime-authority claim fence is invalid")]
    InvalidClaimFence,
    /// A mint attempt is zero or exceeds the closed retry ceiling.
    #[error("runtime-authority mint attempt ordinal is invalid")]
    InvalidMintAttempt,
    /// The immutable execution identity does not use current `JobIR`.
    #[error("runtime authority requires the current JobIR schema")]
    UnsupportedJobIr,
    /// The permission-policy pin does not identify the admitted `JobIR` bytes.
    #[error("runtime-authority policy digest does not match the JobIR digest")]
    PolicyDigestMismatch,
    /// The authenticated `JobIR` byte length is zero or oversized.
    #[error("runtime-authority JobIR size is invalid")]
    InvalidJobIrSize,
    /// A trusted wall-clock observation is before the Unix epoch.
    #[error("runtime-authority timestamp is negative")]
    NegativeTimestamp,
    /// Deriving an expiry exceeded the timestamp representation.
    #[error("runtime-authority timestamp overflowed")]
    TimestampOverflow,
    /// Claim, request, retry, or custody times violate their ordering or bound.
    #[error("runtime-authority time interval is invalid")]
    InvalidTimeInterval,
    /// Provider expiry is inconsistent with the request and lifetime ceiling.
    #[error("provider token expiry is invalid")]
    InvalidProviderExpiry,
    /// Protected plaintext length is zero or exceeds its closed limit.
    #[error("protected runtime-authority payload size is invalid")]
    InvalidProtectedPayloadSize,
    /// Envelope schema or ciphertext size disagrees with authenticated metadata.
    #[error("protected runtime-authority envelope is invalid")]
    InvalidProtectedEnvelope,
    /// A validated identity cannot form the required key-management context.
    #[error("runtime-authority encryption context is invalid")]
    InvalidEncryptionContext,
    /// A post-I/O commit disagrees with its exact claim, fence, or custody horizon.
    #[error("runtime-authority commit does not match its mint claim")]
    InvalidCommit,
    /// A reconciliation batch is zero or exceeds the transaction ceiling.
    #[error("runtime-authority reconciliation batch is invalid")]
    InvalidBatchSize,
    /// A provider failure class is empty, oversized, or noncanonical.
    #[error("runtime-authority failure kind is invalid")]
    InvalidFailureKind,
    /// A reconstructed receipt has inconsistent state or terminal reason.
    #[error("runtime-authority receipt is invalid")]
    InvalidReceipt,
    /// Reconstructed ready custody is revoke-only, expired, or otherwise inconsistent.
    #[error("ready runtime authority is invalid")]
    InvalidReadyAuthority,
}

/// Short-transaction storage port for single-winner mint and revocation state.
#[async_trait]
pub trait GithubRuntimeAuthorityRepository: Send + Sync {
    /// Inspects one exact immutable identity without returning protected bytes.
    ///
    /// Adapters must reject immutable conflicts and may reduce expired state at
    /// `observed_at`; absence is returned only when the exact key is unknown.
    async fn inspect_github_runtime_authority(
        &self,
        request: InspectGithubRuntimeAuthority,
    ) -> Result<Option<GithubRuntimeAuthorityInspection>, GithubRuntimeAuthorityStoreError>;

    /// Creates, replays, or reclaims the sole bounded pre-mint reservation.
    ///
    /// Exact live-owner replay returns the same fence. A different immutable
    /// identity, stale attempt lease, expired request, or exhausted attempt bound
    /// fails closed without granting provider-call authority.
    async fn claim_github_runtime_authority_mint(
        &self,
        request: ClaimGithubRuntimeAuthorityMint,
    ) -> Result<Option<ClaimedGithubRuntimeAuthorityMint>, GithubRuntimeAuthorityStoreError>;

    /// Atomically crosses the irreversible cutoff immediately before mint I/O.
    ///
    /// `Started` authorizes one provider call. Exact replay returns
    /// `AlreadyStarted` and never authorizes a second call.
    async fn begin_github_runtime_authority_mint(
        &self,
        request: BeginGithubRuntimeAuthorityMint,
    ) -> Result<BeginGithubRuntimeAuthorityMintOutcome, GithubRuntimeAuthorityStoreError>;

    /// Authenticates when an unprotected post-provider token is safe to erase.
    ///
    /// Adapters must lock the request's complete graph, issuance, and exact
    /// mint predecessor before sampling repository time. `None` means exact
    /// minting or indeterminate custody remains inside its conservative
    /// horizon. `Some` is returned only after the exact issuance is durably
    /// terminal with the indeterminate-expiry reason. Protected or otherwise
    /// incompatible lifecycle states fail closed.
    async fn authenticate_github_runtime_authority_unprotected_erasure(
        &self,
        request: AuthenticateGithubRuntimeAuthorityUnprotectedErasure,
    ) -> Result<Option<GithubRuntimeAuthorityReceipt>, GithubRuntimeAuthorityStoreError>;

    /// Records an ambiguous post-cutoff provider outcome as indeterminate.
    ///
    /// Exact replay is idempotent; the resulting issuance can never transition
    /// to deliverable authority or authorize another mint.
    async fn mark_github_runtime_authority_indeterminate(
        &self,
        request: MarkGithubRuntimeAuthorityIndeterminate,
    ) -> Result<GithubRuntimeAuthorityReceipt, GithubRuntimeAuthorityStoreError>;

    /// Schedules a bounded retry after proof that no token was minted.
    ///
    /// The transaction revalidates the exact live owner and fence. Deadline or
    /// attempt exhaustion becomes a truthful terminal rejection.
    async fn retry_github_runtime_authority_mint(
        &self,
        request: RetryGithubRuntimeAuthorityMint,
    ) -> Result<GithubRuntimeAuthorityReceipt, GithubRuntimeAuthorityStoreError>;

    /// Terminally rejects a mint after definitive no-token provider evidence.
    ///
    /// The mutation is exact-fence bound and idempotent only for the same
    /// sanitized failure classification and observation.
    async fn reject_github_runtime_authority_mint(
        &self,
        request: RejectGithubRuntimeAuthorityMint,
    ) -> Result<GithubRuntimeAuthorityReceipt, GithubRuntimeAuthorityStoreError>;

    /// Commits one frozen protected envelope after provider and KMS I/O.
    ///
    /// Adapters must validate the exact `minting` owner, fence, immutable
    /// identity, disposition, metadata, and bytes. Exact replay must compare and
    /// retain byte-identical envelope custody rather than regenerating it.
    async fn commit_github_runtime_authority(
        &self,
        request: &CommitGithubRuntimeAuthority,
    ) -> Result<GithubRuntimeAuthorityReceipt, GithubRuntimeAuthorityStoreError>;

    /// Loads protected authority only for the exact current executable fence.
    ///
    /// Revoke-only, indeterminate, quarantined, expired, foreign, or stale
    /// authority returns no deliverable value and must never expose ciphertext.
    async fn load_ready_github_runtime_authority(
        &self,
        request: LoadGithubRuntimeAuthority,
    ) -> Result<Option<ReadyGithubRuntimeAuthority>, GithubRuntimeAuthorityStoreError>;

    /// Quarantines one exact authenticated envelope after non-retryable corruption.
    ///
    /// The AAD digest prevents quarantining a different envelope; custody stays
    /// closed and protected until its validated safe-erasure horizon.
    async fn quarantine_github_runtime_authority(
        &self,
        request: QuarantineGithubRuntimeAuthority,
    ) -> Result<GithubRuntimeAuthorityReceipt, GithubRuntimeAuthorityStoreError>;

    /// Applies bounded, deterministic expiry and recovery reductions.
    ///
    /// Reconciliation must never mint, decrypt, or deliver authority. Protected
    /// bytes may be erased only when their known or conservative horizon permits.
    async fn reconcile_github_runtime_authorities(
        &self,
        request: ReconcileGithubRuntimeAuthorities,
    ) -> Result<GithubRuntimeAuthorityReconciliationReport, GithubRuntimeAuthorityStoreError>;

    /// Claims the next eligible protected authority for provider revocation.
    ///
    /// Adapters return one sole, bounded, monotonic fence and never return
    /// deliverable plaintext. Expired custody is erased instead of claimed.
    async fn claim_github_runtime_authority_revocation(
        &self,
        request: ClaimGithubRuntimeAuthorityRevocation,
    ) -> Result<Option<ClaimedGithubRuntimeAuthorityRevocation>, GithubRuntimeAuthorityStoreError>;

    /// Revalidates the exact claim immediately after KMS decrypt and before
    /// provider I/O using repository time under the full graph and record locks.
    ///
    /// `None` means the owner, fence, protected metadata, or live claim no
    /// longer matches. A present result distinguishes a live claim whose
    /// remaining window is too short from one authorized for the full call.
    async fn revalidate_github_runtime_authority_revocation(
        &self,
        request: RevalidateGithubRuntimeAuthorityRevocation,
    ) -> Result<Option<RevalidatedGithubRuntimeAuthorityRevocation>, GithubRuntimeAuthorityStoreError>;

    /// Releases an exact failed revocation claim for bounded retry.
    ///
    /// The retry remains before safe erasure and is accepted only under the live
    /// owner and fence with a sanitized failure classification.
    async fn retry_github_runtime_authority_revocation(
        &self,
        request: RetryGithubRuntimeAuthorityRevocation,
    ) -> Result<GithubRuntimeAuthorityReceipt, GithubRuntimeAuthorityStoreError>;

    /// Retains custody until expiry when another provider call is unsafe.
    ///
    /// The exact live claim is released without treating an ambiguous provider
    /// response as confirmation and without making the authority deliverable.
    async fn defer_github_runtime_authority_revocation(
        &self,
        request: DeferGithubRuntimeAuthorityRevocation,
    ) -> Result<GithubRuntimeAuthorityReceipt, GithubRuntimeAuthorityStoreError>;

    /// Erases exact protected custody after provider-confirmed revocation.
    ///
    /// Callers may construct this mutation only for HTTP 204. Adapters must
    /// revalidate the live owner and fence and make exact replay idempotent.
    async fn confirm_github_runtime_authority_revocation(
        &self,
        request: ConfirmGithubRuntimeAuthorityRevocation,
    ) -> Result<GithubRuntimeAuthorityReceipt, GithubRuntimeAuthorityStoreError>;
}

fn validate_nonnegative(value: UnixMillis) -> Result<(), GithubRuntimeAuthorityValueError> {
    if value.get() < 0 {
        return Err(GithubRuntimeAuthorityValueError::NegativeTimestamp);
    }
    Ok(())
}

fn validate_selection_tail_interval(
    claimed_at: UnixMillis,
    expires_at: UnixMillis,
    maximum: i64,
) -> Result<(), GithubRuntimeAuthorityValueError> {
    validate_nonnegative(claimed_at)?;
    if expires_at <= claimed_at || expires_at.get() - claimed_at.get() > maximum {
        return Err(GithubRuntimeAuthorityValueError::InvalidTimeInterval);
    }
    Ok(())
}

fn validate_failure_kind(value: &str) -> Result<(), GithubRuntimeAuthorityValueError> {
    let valid = !value.is_empty()
        && value.len() <= MAX_FAILURE_KIND_BYTES
        && value.bytes().enumerate().all(|(index, byte)| {
            byte.is_ascii_alphanumeric() || (index > 0 && matches!(byte, b'-' | b'_' | b'.' | b':'))
        });
    if !valid {
        return Err(GithubRuntimeAuthorityValueError::InvalidFailureKind);
    }
    Ok(())
}

fn validate_claim_interval(
    observed_at: UnixMillis,
    expires_at: UnixMillis,
    not_before: UnixMillis,
    deadline: UnixMillis,
    maximum: i64,
) -> Result<(), GithubRuntimeAuthorityValueError> {
    validate_nonnegative(observed_at)?;
    if observed_at < not_before
        || expires_at <= observed_at
        || expires_at > deadline
        || expires_at.get() - observed_at.get() > maximum
    {
        return Err(GithubRuntimeAuthorityValueError::InvalidTimeInterval);
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn compute_aad_digest(
    identity: &GithubRuntimeAuthorityIdentity,
    provider_expires_at: Option<UnixMillis>,
    safe_erase_after: UnixMillis,
    plaintext_schema: u16,
    plaintext_size_bytes: u64,
    plaintext_digest: Sha256Digest,
) -> Sha256Digest {
    let mut hasher = Sha256::new();
    append_aad(&mut hasher, AAD_DOMAIN);
    append_identity_aad(&mut hasher, identity);
    match provider_expires_at {
        Some(provider_expires_at) => {
            append_u64(&mut hasher, 1);
            append_i64(&mut hasher, provider_expires_at.get());
        }
        None => append_u64(&mut hasher, 0),
    }
    append_i64(&mut hasher, safe_erase_after.get());
    append_u64(&mut hasher, u64::from(plaintext_schema));
    append_u64(&mut hasher, plaintext_size_bytes);
    append_aad(&mut hasher, plaintext_digest.as_bytes());
    Sha256Digest::from_bytes(hasher.finalize().into())
}

fn compute_wrapping_aad_digest(identity: &GithubRuntimeAuthorityIdentity) -> Sha256Digest {
    let mut hasher = Sha256::new();
    append_aad(&mut hasher, WRAPPING_AAD_DOMAIN);
    append_identity_aad(&mut hasher, identity);
    Sha256Digest::from_bytes(hasher.finalize().into())
}

fn append_identity_aad(hasher: &mut Sha256, identity: &GithubRuntimeAuthorityIdentity) {
    append_aad(hasher, identity.tenant().as_str().as_bytes());
    append_aad(hasher, identity.key().attempt_id().as_uuid().as_bytes());
    append_u64(hasher, identity.key().fencing_token().get());
    append_aad(hasher, identity.lease_id().as_uuid().as_bytes());
    append_i64(hasher, identity.lease_issued_at().get());
    append_i64(hasher, identity.lease_expires_at().get());
    append_aad(hasher, identity.run_id().as_uuid().as_bytes());
    append_aad(hasher, identity.job_id().as_uuid().as_bytes());
    append_aad(hasher, identity.runner_id().as_uuid().as_bytes());
    append_aad(hasher, identity.runner_session_id().as_uuid().as_bytes());
    append_u64(hasher, identity.runner_session_epoch().get());
    append_u64(hasher, identity.runner_generation().get());
    append_u64(hasher, u64::from(identity.runner_slot().get()));
    append_u64(hasher, u64::from(identity.job_ir_version().get()));
    append_u64(hasher, identity.job_ir_size_bytes());
    append_aad(hasher, identity.job_ir_digest().as_bytes());
    append_aad(hasher, identity.repository_id().as_uuid().as_bytes());
    append_aad(
        hasher,
        identity.provider_connection_id().as_uuid().as_bytes(),
    );
    append_u64(hasher, identity.provider_installation_id().get());
    append_u64(hasher, identity.github_app_id().get());
    append_aad(hasher, identity.github_app_client_id().as_str().as_bytes());
    append_aad(
        hasher,
        identity.github_app_jwt_issuer_kind().as_str().as_bytes(),
    );
    append_aad(hasher, identity.github_app_jwt_issuer_value().as_bytes());
    append_u64(hasher, identity.github_repository_id().get());
    append_aad(
        hasher,
        identity.github_repository_name().as_str().as_bytes(),
    );
    append_aad(hasher, identity.namespace().as_str().as_bytes());
    append_aad(hasher, identity.policy_digest().as_bytes());
    append_aad(hasher, identity.app_key_spki_sha256().as_bytes());
    append_aad(hasher, identity.configuration_fingerprint().as_bytes());
    let preparation = identity.preparation_selection_tail();
    append_aad(hasher, preparation.selection_id().as_uuid().as_bytes());
    append_aad(hasher, preparation.owner().as_uuid().as_bytes());
    append_u64(hasher, preparation.generation().get());
    append_aad(hasher, preparation.descriptor_digest().as_bytes());
    append_i64(hasher, preparation.claimed_at().get());
    append_i64(hasher, preparation.expires_at().get());
    let activation = identity.activation_selection_tail();
    append_aad(hasher, activation.selection_id().as_uuid().as_bytes());
    append_aad(hasher, activation.owner().as_uuid().as_bytes());
    append_u64(hasher, activation.generation().get());
    append_aad(hasher, activation.activation_input_digest().as_bytes());
    append_i64(hasher, activation.claimed_at().get());
    append_i64(hasher, activation.expires_at().get());
    let materialization = identity.materialization_selection_tail();
    append_aad(hasher, materialization.selection_id().as_uuid().as_bytes());
    append_aad(hasher, materialization.owner().as_uuid().as_bytes());
    append_u64(hasher, materialization.generation().get());
    append_aad(hasher, materialization.descriptor_digest().as_bytes());
    append_i64(hasher, materialization.claimed_at().get());
    append_i64(hasher, materialization.expires_at().get());
    append_i64(hasher, identity.requested_at().get());
    append_i64(hasher, identity.request_deadline().get());
    append_i64(hasher, identity.conservative_expiry().get());
}

fn append_aad(hasher: &mut Sha256, value: &[u8]) {
    let length = u64::try_from(value.len()).expect("bounded AAD field length fits in u64");
    hasher.update(length.to_be_bytes());
    hasher.update(value);
}

fn append_u64(hasher: &mut Sha256, value: u64) {
    append_aad(hasher, &value.to_be_bytes());
}

fn append_i64(hasher: &mut Sha256, value: i64) {
    append_aad(hasher, &value.to_be_bytes());
}
