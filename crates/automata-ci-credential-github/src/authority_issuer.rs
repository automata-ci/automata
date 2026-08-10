use std::{fmt, sync::Arc};

use async_trait::async_trait;
use automata_ci_key_management::{EnvelopeCodec, EnvelopeError, KeyEncryptionError, SecretBytes};
use automata_ci_protocol::{
    JobRuntimeAuthorities, JobRuntimeAuthority, MAX_RUNTIME_AUTHORITY_CREDENTIAL_BYTES,
    RuntimeAuthorityCredential, RuntimeAuthorityEndpoint, RuntimeAuthorityEndpointSecurity,
    RuntimeAuthorityName,
};
use automata_ci_runner_control::{
    ControlPortError, RuntimeAuthorityIssueRequest, RuntimeAuthorityIssuer,
};
use automata_ci_store::{
    GithubRuntimeAuthorityCorruptionKind, GithubRuntimeAuthorityIdentity,
    GithubRuntimeAuthorityRepository, LoadGithubRuntimeAuthority, QuarantineGithubRuntimeAuthority,
    ReadyGithubRuntimeAuthority, Sha256Digest,
};
use sha2::{Digest as _, Sha256};
use thiserror::Error;

use crate::{
    GithubRuntimeAuthorityCoordinatorClock, GithubRuntimeAuthorityCoordinatorError,
    GithubRuntimeAuthorityMintCoordinator,
};

/// Stable repository credential namespace consumed by the GitHub job executor.
pub const GITHUB_REPOSITORY_RUNTIME_AUTHORITY: &str = "github-repository";
/// Durable namespace required on a GitHub repository-token issuance.
pub const GITHUB_REPOSITORY_AUTHORITY_NAMESPACE: &str = "github.repository";

const INSTALLATION_TOKEN_FRAME_DOMAIN: &[u8] = b"automata-ci/github-installation-token/v1\0";
const READY_ENVELOPE_DIGEST_DOMAIN: &[u8] =
    b"automata-ci/github-runtime-authority/ready-envelope/v1\0";

/// Exact durable authority identity revalidated for one lease offer.
///
/// Construction proves that all execution coordinates visible at the runner
/// control boundary match the durable identity. Tenant, internal repository,
/// provider connection/installation, numeric GitHub repository, policy,
/// issuer, and configuration fields remain an attestation of the injected
/// resolver and must be revalidated transactionally by that implementation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResolvedGithubRuntimeAuthorityIdentity {
    identity: GithubRuntimeAuthorityIdentity,
}

impl ResolvedGithubRuntimeAuthorityIdentity {
    /// Cross-binds one resolver result to an exact runtime-authority request.
    ///
    /// # Errors
    ///
    /// Rejects a non-GitHub source, changed repository name, job/object digest,
    /// lease, fence, runner session, slot, or deterministic issuance anchor.
    pub fn new(
        request: RuntimeAuthorityIssueRequest<'_>,
        identity: GithubRuntimeAuthorityIdentity,
    ) -> Result<Self, GithubRuntimeAuthorityIdentityResolutionValueError> {
        let job = request.job();
        let metadata = request.job_ir_metadata();
        let lease = request.lease();
        let session = request.session();
        let exact = job.source().provider() == "github"
            && identity.github_repository_name().as_str() == job.source().repository()
            && identity.key().attempt_id() == lease.attempt_id()
            && identity.key().fencing_token() == lease.fencing_token()
            && identity.lease_id() == lease.lease_id()
            && identity.lease_issued_at() == lease.issued_at()
            && identity.lease_expires_at() == lease.expires_at()
            && identity.run_id() == job.job().run_id()
            && identity.job_id() == job.job().job_id()
            && identity.runner_id() == lease.runner_id()
            && identity.runner_session_id() == session.session_id()
            && identity.runner_session_epoch() == session.session_epoch()
            && identity.runner_generation() == session.runner_generation()
            && identity.runner_slot() == request.slot()
            && identity.job_ir_version() == metadata.version()
            && identity.job_ir_size_bytes() == metadata.encoded_size()
            && identity.job_ir_digest() == metadata.digest()
            && identity.policy_digest() == metadata.digest()
            && identity.requested_at() == request.issued_at();
        if !exact {
            return Err(GithubRuntimeAuthorityIdentityResolutionValueError);
        }
        Ok(Self { identity })
    }

    /// Returns the complete identity attested by the durable resolver.
    #[must_use]
    pub const fn identity(&self) -> &GithubRuntimeAuthorityIdentity {
        &self.identity
    }
}

/// A durable identity resolver returned inconsistent lease-offer evidence.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
#[error("GitHub runtime-authority durable identity is inconsistent")]
pub struct GithubRuntimeAuthorityIdentityResolutionValueError;

/// Invalid GitHub repository-authority issuer configuration.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum GithubRuntimeAuthorityIssuerConfigurationError {
    /// Repository credentials may be delivered only to a TLS-protected origin.
    #[error("the GitHub runtime-authority endpoint must use TLS")]
    InsecureEndpoint,
}

/// Sanitized failure from the durable identity-resolution boundary.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum GithubRuntimeAuthorityIdentityResolutionError {
    /// Authoritative repository or execution state was temporarily unavailable.
    #[error("GitHub runtime-authority durable identity is unavailable")]
    Unavailable,
    /// Authoritative state was present but internally inconsistent.
    #[error("GitHub runtime-authority durable identity is inconsistent")]
    Inconsistent,
}

/// Least-authority durable resolver for a GitHub repository-token identity.
///
/// Implementations must transactionally revalidate the exact current attempt,
/// lease, session epoch/generation/slot, immutable `JobIR`, tenant and internal
/// repository, provider connection/installation, numeric and named GitHub
/// repository, policy digest, issuer fingerprint, and configuration
/// fingerprint. A repeated request must return the same identity, including its
/// lease-anchored request time and fixed deadline; it must never fall back to a
/// global/default installation.
#[async_trait]
pub trait GithubRuntimeAuthorityIdentityResolver: Send + Sync {
    /// Resolves the sole durable identity authorized for `request`.
    async fn resolve_github_runtime_authority_identity(
        &self,
        request: RuntimeAuthorityIssueRequest<'_>,
    ) -> Result<
        Option<ResolvedGithubRuntimeAuthorityIdentity>,
        GithubRuntimeAuthorityIdentityResolutionError,
    >;
}

/// Production GitHub repository authority issuer for lease offers.
///
/// Provider creation is never treated as idempotent. Only a protected token
/// committed as durable `Ready` is decrypted and returned. Every known
/// candidate transfers to bounded independent custody before its first commit; a
/// restarted `minting` issuance remains unavailable and is never reminted while
/// the durable reconciler reduces it to `indeterminate` at the fixed deadline.
pub struct GithubRepositoryRuntimeAuthorityIssuer {
    identities: Arc<dyn GithubRuntimeAuthorityIdentityResolver>,
    coordinator: Arc<GithubRuntimeAuthorityMintCoordinator>,
    repository: Arc<dyn GithubRuntimeAuthorityRepository>,
    envelopes: Arc<EnvelopeCodec>,
    clock: Arc<dyn GithubRuntimeAuthorityCoordinatorClock>,
    endpoint: RuntimeAuthorityEndpoint,
}

impl GithubRepositoryRuntimeAuthorityIssuer {
    /// Constructs an issuer from explicit durable, provider, encryption, and
    /// protected-candidate supervision boundaries.
    ///
    /// # Errors
    ///
    /// Rejects a development/plaintext runtime-authority endpoint. The runner
    /// independently requires this origin to equal its configured GitHub
    /// server before exposing the credential.
    pub fn new(
        identities: Arc<dyn GithubRuntimeAuthorityIdentityResolver>,
        coordinator: Arc<GithubRuntimeAuthorityMintCoordinator>,
        repository: Arc<dyn GithubRuntimeAuthorityRepository>,
        envelopes: Arc<EnvelopeCodec>,
        clock: Arc<dyn GithubRuntimeAuthorityCoordinatorClock>,
        endpoint: RuntimeAuthorityEndpoint,
    ) -> Result<Self, GithubRuntimeAuthorityIssuerConfigurationError> {
        if endpoint.security() != RuntimeAuthorityEndpointSecurity::Tls {
            return Err(GithubRuntimeAuthorityIssuerConfigurationError::InsecureEndpoint);
        }
        Ok(Self {
            identities,
            coordinator,
            repository,
            envelopes,
            clock,
            endpoint,
        })
    }

    /// Issues from one already-resolved exact identity.
    ///
    /// This entry point lets a no-default installation router resolve durable
    /// evidence once, select the sole broker by the attested installation ID,
    /// and avoid either name-based guesses or broker iteration. The identity is
    /// cross-bound to `request` again before any ready load or mint transition.
    ///
    /// # Errors
    ///
    /// Fails closed for a mismatched request, unavailable protected custody,
    /// coordinator failure, or corrupt authority state.
    pub async fn issue_resolved(
        &self,
        request: RuntimeAuthorityIssueRequest<'_>,
        resolved: ResolvedGithubRuntimeAuthorityIdentity,
    ) -> Result<JobRuntimeAuthorities, ControlPortError> {
        let resolved =
            ResolvedGithubRuntimeAuthorityIdentity::new(request, resolved.identity().clone())
                .map_err(|_| ControlPortError::Corrupt)?;
        let identity = resolved.identity();
        if identity.namespace().as_str() != GITHUB_REPOSITORY_AUTHORITY_NAMESPACE {
            return Err(ControlPortError::Corrupt);
        }
        if let Some(authority) = self.load_ready(request, identity).await? {
            return Ok(authority);
        }

        let _outcome = self
            .coordinator
            .coordinate_once(identity.clone())
            .await
            .map_err(coordinator_error)?;

        self.load_ready(request, identity)
            .await?
            .ok_or(ControlPortError::Unavailable)
    }

    async fn load_ready(
        &self,
        request: RuntimeAuthorityIssueRequest<'_>,
        identity: &GithubRuntimeAuthorityIdentity,
    ) -> Result<Option<JobRuntimeAuthorities>, ControlPortError> {
        let observed_at = self.clock.now().max(identity.requested_at());
        let load = LoadGithubRuntimeAuthority::new(identity.clone(), observed_at)
            .map_err(|_| ControlPortError::Corrupt)?;
        let ready = self
            .repository
            .load_ready_github_runtime_authority(load)
            .await
            .map_err(|error| store_error(&error))?;
        let Some(ready) = ready else { return Ok(None) };
        self.open_ready(request, ready, observed_at).await.map(Some)
    }

    async fn open_ready(
        &self,
        request: RuntimeAuthorityIssueRequest<'_>,
        ready: ReadyGithubRuntimeAuthority,
        observed_at: automata_ci_core::UnixMillis,
    ) -> Result<JobRuntimeAuthorities, ControlPortError> {
        let protected = ready.protected();
        let metadata = protected.metadata();
        let wrapping_context = metadata
            .identity()
            .wrapping_encryption_context()
            .map_err(|_| ControlPortError::Corrupt)?;
        let payload_context = metadata
            .encryption_context()
            .map_err(|_| ControlPortError::Corrupt)?;
        let plaintext = match self
            .envelopes
            .open_with_contexts(&wrapping_context, &payload_context, protected.envelope())
            .await
        {
            Ok(plaintext) => plaintext,
            Err(EnvelopeError::KeyEncryption(KeyEncryptionError::Unavailable)) => {
                return Err(ControlPortError::Unavailable);
            }
            Err(error) => {
                self.quarantine(protected, envelope_corruption(error), observed_at)
                    .await?;
                return Err(ControlPortError::Corrupt);
            }
        };
        let Ok(token) = decode_installation_token_frame(&plaintext, metadata) else {
            self.quarantine(
                protected,
                GithubRuntimeAuthorityCorruptionKind::InvalidEnvelope,
                observed_at,
            )
            .await?;
            return Err(ControlPortError::Corrupt);
        };
        let credential =
            RuntimeAuthorityCredential::new(token).map_err(|_| ControlPortError::Corrupt)?;
        drop(plaintext);
        let expected_metadata = metadata.clone();
        let expected_envelope_digest = protected_envelope_digest(protected);
        let expected_ready_at = ready.ready_at();
        let revalidated_at = self.clock.now().max(metadata.identity().requested_at());
        let revalidation =
            LoadGithubRuntimeAuthority::new(metadata.identity().clone(), revalidated_at)
                .map_err(|_| ControlPortError::Corrupt)?;
        let fresh = self
            .repository
            .load_ready_github_runtime_authority(revalidation)
            .await
            .map_err(|error| store_error(&error))?
            .ok_or(ControlPortError::Unavailable)?;
        if fresh.ready_at() != expected_ready_at
            || fresh.protected().metadata() != &expected_metadata
            || protected_envelope_digest(fresh.protected()) != expected_envelope_digest
        {
            return Err(ControlPortError::Corrupt);
        }
        let expires_at = metadata
            .conservative_use_expires_at()
            .ok_or(ControlPortError::Corrupt)?;
        let authority = JobRuntimeAuthority::new(
            RuntimeAuthorityName::new(GITHUB_REPOSITORY_RUNTIME_AUTHORITY)
                .map_err(|_| ControlPortError::Corrupt)?,
            metadata.identity().run_id(),
            metadata.identity().job_id(),
            metadata.identity().key().attempt_id(),
            metadata.identity().key().fencing_token(),
            self.endpoint.clone(),
            credential,
            ready.ready_at(),
            expires_at,
        )
        .map_err(|_| ControlPortError::Corrupt)?;
        JobRuntimeAuthorities::new(vec![authority], request.job(), request.lease())
            .map_err(|_| ControlPortError::Corrupt)
    }

    async fn quarantine(
        &self,
        protected: &automata_ci_store::ProtectedGithubRuntimeAuthority,
        kind: GithubRuntimeAuthorityCorruptionKind,
        observed_at: automata_ci_core::UnixMillis,
    ) -> Result<(), ControlPortError> {
        let request = QuarantineGithubRuntimeAuthority::new(protected, kind, observed_at)
            .map_err(|_| ControlPortError::Corrupt)?;
        self.repository
            .quarantine_github_runtime_authority(request)
            .await
            .map(|_| ())
            .map_err(|error| store_error(&error))
    }
}

fn protected_envelope_digest(
    protected: &automata_ci_store::ProtectedGithubRuntimeAuthority,
) -> Sha256Digest {
    let envelope = protected.envelope();
    let mut digest = Sha256::new();
    digest.update(READY_ENVELOPE_DIGEST_DOMAIN);
    digest.update(envelope.schema().to_be_bytes());
    update_digest_bytes(&mut digest, envelope.wrapping_key_id().as_str().as_bytes());
    update_digest_bytes(&mut digest, envelope.wrapped_data_key().ciphertext());
    update_digest_bytes(&mut digest, envelope.nonce());
    update_digest_bytes(&mut digest, envelope.ciphertext());
    Sha256Digest::from_bytes(digest.finalize().into())
}

fn update_digest_bytes(digest: &mut Sha256, value: &[u8]) {
    digest.update(u64::try_from(value.len()).unwrap_or(u64::MAX).to_be_bytes());
    digest.update(value);
}

impl fmt::Debug for GithubRepositoryRuntimeAuthorityIssuer {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GithubRepositoryRuntimeAuthorityIssuer")
            .field("identities", &"[DURABLE IDENTITY RESOLVER]")
            .field("coordinator", &self.coordinator)
            .field("repository", &"[AUTHORITY REPOSITORY]")
            .field("envelopes", &self.envelopes)
            .field("clock", &self.clock)
            .field("endpoint", &self.endpoint)
            .finish()
    }
}

#[async_trait]
impl RuntimeAuthorityIssuer for GithubRepositoryRuntimeAuthorityIssuer {
    async fn issue(
        &self,
        request: RuntimeAuthorityIssueRequest<'_>,
    ) -> Result<JobRuntimeAuthorities, ControlPortError> {
        let resolved = self
            .identities
            .resolve_github_runtime_authority_identity(request)
            .await
            .map_err(identity_resolution_error)?
            .ok_or(ControlPortError::Unavailable)?;
        self.issue_resolved(request, resolved).await
    }
}

fn decode_installation_token_frame(
    plaintext: &SecretBytes,
    metadata: &automata_ci_store::GithubRuntimeAuthorityEnvelopeMetadata,
) -> Result<String, ()> {
    let bytes = plaintext.expose_secret();
    if u64::try_from(bytes.len()).ok() != Some(metadata.plaintext_size_bytes())
        || Sha256Digest::from_bytes(Sha256::digest(bytes).into()) != metadata.plaintext_digest()
        || !bytes.starts_with(INSTALLATION_TOKEN_FRAME_DOMAIN)
    {
        return Err(());
    }
    let length_start = INSTALLATION_TOKEN_FRAME_DOMAIN.len();
    let length_end = length_start.checked_add(size_of::<u32>()).ok_or(())?;
    let length: [u8; size_of::<u32>()] = bytes
        .get(length_start..length_end)
        .ok_or(())?
        .try_into()
        .map_err(|_| ())?;
    let token_length = usize::try_from(u32::from_be_bytes(length)).map_err(|_| ())?;
    let token = bytes.get(length_end..).ok_or(())?;
    if token.len() != token_length
        || token.is_empty()
        || token.len() > MAX_RUNTIME_AUTHORITY_CREDENTIAL_BYTES
        || !token.iter().all(u8::is_ascii_graphic)
    {
        return Err(());
    }
    String::from_utf8(token.to_vec()).map_err(|_| ())
}

const fn identity_resolution_error(
    error: GithubRuntimeAuthorityIdentityResolutionError,
) -> ControlPortError {
    match error {
        GithubRuntimeAuthorityIdentityResolutionError::Unavailable => ControlPortError::Unavailable,
        GithubRuntimeAuthorityIdentityResolutionError::Inconsistent => ControlPortError::Corrupt,
    }
}

const fn coordinator_error(error: GithubRuntimeAuthorityCoordinatorError) -> ControlPortError {
    match error {
        GithubRuntimeAuthorityCoordinatorError::ResolutionIdentityMismatch
        | GithubRuntimeAuthorityCoordinatorError::BrokerIdentityMismatch
        | GithubRuntimeAuthorityCoordinatorError::InvalidTime => ControlPortError::Corrupt,
        GithubRuntimeAuthorityCoordinatorError::Repository
        | GithubRuntimeAuthorityCoordinatorError::Resolution
        | GithubRuntimeAuthorityCoordinatorError::Unauthorized
        | GithubRuntimeAuthorityCoordinatorError::EnvelopePreparation
        | GithubRuntimeAuthorityCoordinatorError::CandidateProtection
        | GithubRuntimeAuthorityCoordinatorError::MintWindowExhausted
        | GithubRuntimeAuthorityCoordinatorError::SupervisionCapacity => {
            ControlPortError::Unavailable
        }
    }
}

fn store_error(error: &automata_ci_store::GithubRuntimeAuthorityStoreError) -> ControlPortError {
    match error {
        automata_ci_store::GithubRuntimeAuthorityStoreError::Operation(_) => {
            ControlPortError::Unavailable
        }
        automata_ci_store::GithubRuntimeAuthorityStoreError::IdentityConflict
        | automata_ci_store::GithubRuntimeAuthorityStoreError::MintClaimRejected
        | automata_ci_store::GithubRuntimeAuthorityStoreError::RevocationClaimRejected
        | automata_ci_store::GithubRuntimeAuthorityStoreError::QuarantineRejected
        | automata_ci_store::GithubRuntimeAuthorityStoreError::FenceExhausted
        | automata_ci_store::GithubRuntimeAuthorityStoreError::RetryLimitReached => {
            ControlPortError::Conflict
        }
        automata_ci_store::GithubRuntimeAuthorityStoreError::CorruptData => {
            ControlPortError::Corrupt
        }
    }
}

fn envelope_corruption(error: EnvelopeError) -> GithubRuntimeAuthorityCorruptionKind {
    match error {
        EnvelopeError::InvalidEnvelope => GithubRuntimeAuthorityCorruptionKind::InvalidEnvelope,
        EnvelopeError::UnsupportedSchema => {
            GithubRuntimeAuthorityCorruptionKind::UnsupportedEnvelopeSchema
        }
        EnvelopeError::AuthenticationFailed
        | EnvelopeError::KeyEncryption(KeyEncryptionError::AuthenticationFailed) => {
            GithubRuntimeAuthorityCorruptionKind::EnvelopeAuthenticationFailed
        }
        EnvelopeError::KeyEncryption(KeyEncryptionError::InvalidCiphertext) => {
            GithubRuntimeAuthorityCorruptionKind::InvalidWrappedDataKey
        }
        EnvelopeError::KeyEncryption(KeyEncryptionError::UnknownKey) => {
            GithubRuntimeAuthorityCorruptionKind::UnknownWrappingKey
        }
        EnvelopeError::KeyEncryption(KeyEncryptionError::RetiredKey) => {
            GithubRuntimeAuthorityCorruptionKind::RetiredWrappingKey
        }
        EnvelopeError::RandomnessUnavailable
        | EnvelopeError::CryptographicFailure
        | EnvelopeError::KeyEncryption(
            KeyEncryptionError::InvalidDataKey | KeyEncryptionError::RandomnessUnavailable,
        ) => GithubRuntimeAuthorityCorruptionKind::CryptographicFailure,
        EnvelopeError::KeyEncryption(KeyEncryptionError::Unavailable) => {
            unreachable!("provider unavailability is handled before corruption classification")
        }
    }
}
