use std::{fmt, sync::Arc, time::Duration};

use async_trait::async_trait;
use automata_ci_core::{
    JobAuthorityProfile, JobIrEnvelope, JobPermissionRequest,
    PermissionLevel as JobPermissionLevel, UnixMillis,
};
use automata_ci_key_management::{EnvelopeCodec, SecretBytes};
use automata_ci_scm::credential::{
    CredentialError, CredentialErrorKind, MinimumValidity, PermissionLevel, PermissionName,
    PermissionSet, ProviderResourceId, RepositoryCredentialRequest, RepositoryScope,
    WorkloadIdentity,
};
use automata_ci_scm::{RepositoryId as ScmRepositoryId, ScmProviderId};
use automata_ci_store::{
    AuthenticateGithubRuntimeAuthorityUnprotectedErasure, BeginGithubRuntimeAuthorityMint,
    BeginGithubRuntimeAuthorityMintOutcome, ClaimGithubRuntimeAuthorityMint,
    ClaimedGithubRuntimeAuthorityMint, CommitGithubRuntimeAuthority,
    GithubRuntimeAuthorityEnvelopeMetadata, GithubRuntimeAuthorityInspection,
    GithubRuntimeAuthorityMintFailure, GithubRuntimeAuthorityReceipt,
    GithubRuntimeAuthorityRepository, GithubRuntimeAuthorityState,
    GithubRuntimeAuthorityTerminalReason, GithubRuntimeAuthorityWorkerId,
    GithubServerServiceAppClientId, GithubServerServiceAppId, GithubServerServiceJwtIssuer,
    InspectGithubRuntimeAuthority, MAX_GITHUB_AUTHORITY_MINT_CLAIM_MILLIS,
    MAX_GITHUB_AUTHORITY_MINT_RETRY_BACKOFF_MILLIS, MarkGithubRuntimeAuthorityIndeterminate,
    ProtectedGithubRuntimeAuthority, RejectGithubRuntimeAuthorityMint,
    RetryGithubRuntimeAuthorityMint, Sha256Digest,
};
use sha2::{Digest as _, Sha256};
use thiserror::Error;
use tokio::{runtime::Handle, sync::oneshot};

use crate::{
    GithubAppCredentialBroker, GithubInstallationTokenMintOutcome,
    GithubInstallationTokenRevocationCandidate,
    config::whole_milliseconds,
    supervised_custody::{Entry, Reservation, SupervisedCustody},
};

const INSTALLATION_TOKEN_FRAME_DOMAIN: &[u8] = b"automata-ci/github-installation-token/v1\0";
const DEFAULT_MINT_RETRY_BACKOFF_MILLIS: i64 = 1_000;
const MAX_SUPERVISED_PENDING_COMMITS: usize = 1_024;
const MAX_PENDING_COMMIT_RETRY_DELAY: Duration = Duration::from_mins(1);

/// Canonical workload identity bound to every immutable authority field.
///
/// The compact digest includes tenant, provider connection and installation,
/// numeric and named repository, run/job/attempt/fence, namespace, policy,
/// issuer, configuration, lease, runner, and `JobIR` evidence.
///
/// # Panics
///
/// Panics only if a fixed ASCII prefix plus one SHA-256 digest no longer fits
/// the provider-neutral workload-identity bound.
#[must_use]
pub fn github_runtime_authority_workload_identity(
    identity: &automata_ci_store::GithubRuntimeAuthorityIdentity,
) -> WorkloadIdentity {
    WorkloadIdentity::new(format!(
        "automata-ci/github-runtime-authority/v3/{}",
        identity.identity_digest()
    ))
    .expect("a fixed prefix and SHA-256 digest fit the workload identity boundary")
}

/// Derives the exact GitHub App repository request from verified Standard `JobIR`.
///
/// Explicit permission mappings are total: `none` entries and the separately
/// served `id-token` capability are omitted, while every remaining GitHub name
/// is converted from workflow kebab-case to the provider's snake-case API.
/// Provider defaults and wildcard modes are deliberately not expanded from a
/// guessed permission universe.
///
/// # Errors
///
/// Rejects a foreign source, changed run/job/repository, `CredentialFree` job,
/// unresolved provider-default/read-all/write-all request, or an empty GitHub
/// permission set.
pub fn github_job_runtime_authority_request(
    identity: &automata_ci_store::GithubRuntimeAuthorityIdentity,
    job: &JobIrEnvelope,
) -> Result<RepositoryCredentialRequest, GithubJobRuntimeAuthorityRequestValueError> {
    if job.source().provider() != "github"
        || job.source().repository() != identity.github_repository_name().as_str()
        || job.job().run_id() != identity.run_id()
        || job.job().job_id() != identity.job_id()
        || job.job().authority_profile() != JobAuthorityProfile::Standard
    {
        return Err(GithubJobRuntimeAuthorityRequestValueError);
    }
    let JobPermissionRequest::Mapping(grants) = job.job().permission_request() else {
        return Err(GithubJobRuntimeAuthorityRequestValueError);
    };
    let permissions = grants
        .iter()
        .filter(|grant| grant.name() != "id-token" && grant.level() != JobPermissionLevel::None)
        .map(|grant| {
            let name = PermissionName::new(grant.name().replace('-', "_"))
                .map_err(|_| GithubJobRuntimeAuthorityRequestValueError)?;
            let level = match grant.level() {
                JobPermissionLevel::Read => PermissionLevel::Read,
                JobPermissionLevel::Write => PermissionLevel::Write,
                JobPermissionLevel::None => return Err(GithubJobRuntimeAuthorityRequestValueError),
            };
            Ok((name, level))
        })
        .collect::<Result<Vec<_>, _>>()?;
    let permissions =
        PermissionSet::new(permissions).map_err(|_| GithubJobRuntimeAuthorityRequestValueError)?;
    let repository = RepositoryScope::new(
        ScmProviderId::new("github").map_err(|_| GithubJobRuntimeAuthorityRequestValueError)?,
        ScmRepositoryId::new(identity.github_repository_name().as_str())
            .map_err(|_| GithubJobRuntimeAuthorityRequestValueError)?,
        ProviderResourceId::new(identity.github_repository_id().get().to_string())
            .map_err(|_| GithubJobRuntimeAuthorityRequestValueError)?,
    );
    Ok(RepositoryCredentialRequest::new(
        github_runtime_authority_workload_identity(identity),
        repository,
        permissions,
        MinimumValidity::default(),
    ))
}

/// Verified `JobIR` could not form one exact GitHub App request.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
#[error("GitHub job runtime-authority request is not exactly representable")]
pub struct GithubJobRuntimeAuthorityRequestValueError;

/// One exact least-authority resolution for an immutable mint identity.
///
/// The embedded identity is an attestation that the resolver revalidated the
/// complete tenant, provider connection and installation, numeric and named
/// repository, workload/fence, policy, issuer, and configuration evidence.
/// Construction also proves that the provider-neutral request selects exactly
/// the identity's GitHub repository and canonical workload subject.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResolvedGithubRuntimeAuthorityRequest {
    identity: automata_ci_store::GithubRuntimeAuthorityIdentity,
    request: RepositoryCredentialRequest,
}

impl ResolvedGithubRuntimeAuthorityRequest {
    /// Binds one exact request to the identity revalidated by a resolver.
    ///
    /// # Errors
    ///
    /// Rejects any provider, numeric repository ID, repository name, or
    /// workload mismatch. There is no default or global credential fallback.
    ///
    /// # Panics
    ///
    /// Panics only if the static `github` provider identifier or the fixed
    /// workload-identity representation violates its compile-time-known bound.
    pub fn new(
        identity: automata_ci_store::GithubRuntimeAuthorityIdentity,
        request: RepositoryCredentialRequest,
    ) -> Result<Self, GithubRuntimeAuthorityResolutionValueError> {
        let repository = request.repository();
        let expected_provider =
            ScmProviderId::new("github").expect("static GitHub provider ID is valid");
        let expected_repository_id = identity.github_repository_id().get().to_string();
        let exact = repository.provider() == &expected_provider
            && repository.stable_id().as_str() == expected_repository_id
            && repository.repository().as_str() == identity.github_repository_name().as_str()
            && request.workload() == &github_runtime_authority_workload_identity(&identity);
        if !exact {
            return Err(GithubRuntimeAuthorityResolutionValueError);
        }
        Ok(Self { identity, request })
    }

    /// Returns the complete identity revalidated by the resolver.
    #[must_use]
    pub const fn identity(&self) -> &automata_ci_store::GithubRuntimeAuthorityIdentity {
        &self.identity
    }

    /// Returns the exact provider-neutral credential request.
    #[must_use]
    pub const fn request(&self) -> &RepositoryCredentialRequest {
        &self.request
    }
}

/// A resolved request did not match its immutable authority identity.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
#[error("GitHub runtime-authority request resolution is inconsistent")]
pub struct GithubRuntimeAuthorityResolutionValueError;

/// Sanitized failure of the least-authority request resolver.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum GithubRuntimeAuthorityResolutionError {
    /// The exact authoritative policy/provider data was temporarily unavailable.
    #[error("GitHub runtime-authority resolution is unavailable")]
    Unavailable,
    /// Authoritative data was present but internally inconsistent.
    #[error("GitHub runtime-authority resolution is inconsistent")]
    Inconsistent,
}

/// Least-authority resolver for one immutable GitHub authority identity.
///
/// An implementation must transactionally revalidate the exact tenant,
/// internal repository, provider connection and installation, numeric and
/// named GitHub repository, workload/fence, policy digest, issuer fingerprint,
/// and configuration fingerprint before returning a request. Absence means the
/// identity is not currently authorized; implementations must never search for
/// or return a global/default installation token.
#[async_trait]
pub trait GithubRuntimeAuthorityRequestResolver: Send + Sync {
    /// Resolves the sole credential request authorized by `identity`.
    async fn resolve_github_runtime_authority_request(
        &self,
        identity: &automata_ci_store::GithubRuntimeAuthorityIdentity,
    ) -> Result<Option<ResolvedGithubRuntimeAuthorityRequest>, GithubRuntimeAuthorityResolutionError>;
}

/// Exact single-attempt provider boundary used by the coordinator.
///
/// Implementations must enforce the returned request-duration bound. A
/// uniquely recovered token must always remain in `Ready` or `RevokePending`.
#[async_trait]
pub trait GithubRuntimeAuthorityMintBroker: fmt::Debug + Send + Sync {
    /// Returns the sole GitHub App installation this broker can mint for.
    fn installation_id(&self) -> u64;

    /// Returns the exact live numeric GitHub App identity.
    fn github_app_id(&self) -> GithubServerServiceAppId;

    /// Returns the configured GitHub App client identity.
    fn github_app_client_id(&self) -> &GithubServerServiceAppClientId;

    /// Returns which GitHub-supported JWT issuer value family is configured.
    fn github_app_jwt_issuer_kind(&self) -> GithubServerServiceJwtIssuer;

    /// Returns the exact live JWT `iss` value used by the signer.
    fn github_app_jwt_issuer_value(&self) -> &str;

    /// Returns the SPKI fingerprint of the exact live App signing key.
    fn app_key_spki_sha256(&self) -> Sha256Digest;

    /// Returns the exact scope-specific live broker configuration fingerprint.
    fn configuration_fingerprint(&self) -> Sha256Digest;

    /// Returns the hard complete-request wall-clock ceiling.
    ///
    /// The duration must be a nonzero whole number of milliseconds so the
    /// provider timeout and durable database authorization are identical.
    fn maximum_mint_duration(&self) -> Duration;

    /// Performs exactly one provider mint attempt.
    async fn mint_once(
        &self,
        request: &RepositoryCredentialRequest,
    ) -> GithubInstallationTokenMintOutcome;
}

/// Live App broker pinned to one exact scope-specific authority configuration.
///
/// The issuer fingerprint is always derived from the injected live broker. The
/// configuration fingerprint must come from the same converged authority plan
/// that authorized the repository scope; it is never inferred from an
/// installation ID or mutable current manifest.
pub struct PinnedGithubRuntimeAuthorityMintBroker {
    broker: Arc<GithubAppCredentialBroker>,
    github_app_id: GithubServerServiceAppId,
    github_app_client_id: GithubServerServiceAppClientId,
    github_app_jwt_issuer_kind: GithubServerServiceJwtIssuer,
    configuration_fingerprint: Sha256Digest,
}

impl PinnedGithubRuntimeAuthorityMintBroker {
    /// Binds a live App broker to its exact converged authority configuration.
    ///
    /// # Errors
    ///
    /// Rejects a live signer whose JWT issuer does not exactly match the
    /// supplied App issuer descriptor.
    pub fn new(
        broker: Arc<GithubAppCredentialBroker>,
        github_app_id: GithubServerServiceAppId,
        github_app_client_id: GithubServerServiceAppClientId,
        github_app_jwt_issuer_kind: GithubServerServiceJwtIssuer,
        configuration_fingerprint: Sha256Digest,
    ) -> Result<Self, PinnedGithubRuntimeAuthorityMintBrokerError> {
        let expected_issuer = match github_app_jwt_issuer_kind {
            GithubServerServiceJwtIssuer::AppClientId => github_app_client_id.as_str().to_owned(),
            GithubServerServiceJwtIssuer::AppId => github_app_id.get().to_string(),
        };
        if broker.app_jwt_issuer_value() != expected_issuer {
            return Err(PinnedGithubRuntimeAuthorityMintBrokerError);
        }
        Ok(Self {
            broker,
            github_app_id,
            github_app_client_id,
            github_app_jwt_issuer_kind,
            configuration_fingerprint,
        })
    }
}

/// A live App broker does not match its exact durable issuer descriptor.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
#[error("GitHub runtime-authority mint broker issuer is inconsistent")]
pub struct PinnedGithubRuntimeAuthorityMintBrokerError;

impl fmt::Debug for PinnedGithubRuntimeAuthorityMintBroker {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PinnedGithubRuntimeAuthorityMintBroker")
            .field("installation_id", &self.broker.mint_installation_id())
            .field("github_app_id", &self.github_app_id)
            .field(
                "github_app_jwt_issuer_kind",
                &self.github_app_jwt_issuer_kind,
            )
            .field("app_key_spki_sha256", &self.broker.app_key_spki_sha256())
            .field("configuration_fingerprint", &self.configuration_fingerprint)
            .finish_non_exhaustive()
    }
}

#[async_trait]
impl GithubRuntimeAuthorityMintBroker for PinnedGithubRuntimeAuthorityMintBroker {
    fn installation_id(&self) -> u64 {
        self.broker.mint_installation_id()
    }

    fn github_app_id(&self) -> GithubServerServiceAppId {
        self.github_app_id
    }

    fn github_app_client_id(&self) -> &GithubServerServiceAppClientId {
        &self.github_app_client_id
    }

    fn github_app_jwt_issuer_kind(&self) -> GithubServerServiceJwtIssuer {
        self.github_app_jwt_issuer_kind
    }

    fn github_app_jwt_issuer_value(&self) -> &str {
        self.broker.app_jwt_issuer_value()
    }

    fn app_key_spki_sha256(&self) -> Sha256Digest {
        self.broker.app_key_spki_sha256()
    }

    fn configuration_fingerprint(&self) -> Sha256Digest {
        self.configuration_fingerprint
    }

    fn maximum_mint_duration(&self) -> Duration {
        self.broker.mint_request_timeout()
    }

    async fn mint_once(
        &self,
        request: &RepositoryCredentialRequest,
    ) -> GithubInstallationTokenMintOutcome {
        self.broker.mint_once(request).await
    }
}

/// Trusted wall-clock source for durable coordinator observations.
pub trait GithubRuntimeAuthorityCoordinatorClock: fmt::Debug + Send + Sync {
    /// Returns whole milliseconds since the Unix epoch.
    fn now(&self) -> UnixMillis;
}

/// An exact encrypted commit retained after an ambiguous repository result.
///
/// The value owns no plaintext. It keeps the same timestamp, metadata,
/// wrapping key ciphertext, nonce, and payload ciphertext available for an
/// exact replay, and its diagnostics remain redacted.
#[must_use = "an ambiguous protected commit must be retained and replayed"]
pub struct PendingGithubRuntimeAuthorityCommit {
    commit: CommitGithubRuntimeAuthority,
}

impl PendingGithubRuntimeAuthorityCommit {
    /// Replays the byte-identical protected commit without minting again.
    ///
    /// A failure leaves `self` intact so the exact request remains available
    /// for another replay or controlled process supervision.
    ///
    /// # Errors
    ///
    /// Returns a sanitized error when the repository does not confirm the
    /// commit. No database or protected-content diagnostic is retained.
    pub async fn replay(
        &self,
        repository: &dyn GithubRuntimeAuthorityRepository,
    ) -> Result<GithubRuntimeAuthorityReceipt, PendingGithubRuntimeAuthorityCommitError> {
        repository
            .commit_github_runtime_authority(&self.commit)
            .await
            .map_err(|_| PendingGithubRuntimeAuthorityCommitError)
    }

    /// Returns the immutable authority key without exposing protected bytes.
    #[must_use]
    pub const fn key(&self) -> automata_ci_store::GithubRuntimeAuthorityKey {
        self.commit.protected().metadata().identity().key()
    }
}

impl fmt::Debug for PendingGithubRuntimeAuthorityCommit {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PendingGithubRuntimeAuthorityCommit")
            .field("key", &self.key())
            .field("disposition", &self.commit.disposition())
            .field("committed_at", &self.commit.committed_at())
            .field("protected", &"[PROTECTED]")
            .finish()
    }
}

/// A byte-identical protected commit replay was not confirmed.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
#[error("GitHub runtime-authority protected commit was not confirmed")]
pub struct PendingGithubRuntimeAuthorityCommitError;

/// Construction failure for the bounded in-process commit supervisor.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum GithubRuntimeAuthorityCommitSupervisorError {
    /// The maximum number of protected candidates was zero or excessive.
    #[error("GitHub runtime-authority commit supervision capacity is invalid")]
    InvalidCapacity,
    /// The exact replay interval was zero or excessive.
    #[error("GitHub runtime-authority commit supervision retry interval is invalid")]
    InvalidRetryInterval,
}

/// Bounded in-process custody for a known protected commit candidate.
///
/// A reservation is acquired before any provider mint. If the authoritative
/// commit has an ambiguous result, the supervisor moves the candidate into an
/// independent runtime task that replays exactly the same protected request
/// until `PostgreSQL` confirms it. Only the Store's locked database-time
/// transition may decide that the fixed safe-erasure horizon has passed.
/// Request cancellation therefore cannot discard a known candidate. Process
/// failure still cannot recover a provider response that never reached any
/// durable write; the durable `minting` row remains the truthful restart
/// evidence and must reconcile to `indeterminate` without another mint.
pub struct GithubRuntimeAuthorityCommitSupervisor {
    repository: Arc<dyn GithubRuntimeAuthorityRepository>,
    retry_interval: Duration,
    protected_custody: SupervisedCustody<PendingGithubRuntimeAuthorityCommit>,
    unprotected_custody: SupervisedCustody<UnprotectedGithubRuntimeAuthorityCandidate>,
}

impl GithubRuntimeAuthorityCommitSupervisor {
    /// Constructs a supervisor with a hard in-memory candidate bound.
    ///
    /// # Errors
    ///
    /// Rejects zero or excessive capacity and retry intervals outside
    /// `1ms..=60s`.
    pub fn new(
        repository: Arc<dyn GithubRuntimeAuthorityRepository>,
        runtime: Handle,
        capacity: usize,
        retry_interval: Duration,
    ) -> Result<Self, GithubRuntimeAuthorityCommitSupervisorError> {
        if capacity == 0 || capacity > MAX_SUPERVISED_PENDING_COMMITS {
            return Err(GithubRuntimeAuthorityCommitSupervisorError::InvalidCapacity);
        }
        if retry_interval.is_zero() || retry_interval > MAX_PENDING_COMMIT_RETRY_DELAY {
            return Err(GithubRuntimeAuthorityCommitSupervisorError::InvalidRetryInterval);
        }
        let protected_custody = SupervisedCustody::new(runtime, capacity);
        let unprotected_custody = protected_custody.linked(capacity);
        Ok(Self {
            repository,
            retry_interval,
            protected_custody,
            unprotected_custody,
        })
    }

    pub(crate) fn try_reserve(&self) -> Option<GithubRuntimeAuthorityCommitReservation> {
        self.redrive_retained();
        self.protected_custody.try_reserve()
    }

    pub(crate) fn supervise(
        &self,
        reservation: GithubRuntimeAuthorityCommitReservation,
        pending: PendingGithubRuntimeAuthorityCommit,
    ) -> oneshot::Receiver<GithubRuntimeAuthorityReceipt> {
        let custody = self.protected_custody.retain(reservation, pending);

        let (result_sender, result_receiver) = oneshot::channel();
        let started = self.start_protected_driver(&custody, Some(result_sender));
        assert!(started, "new protected custody starts one driver");
        result_receiver
    }

    fn start_protected_driver(
        &self,
        custody: &Arc<Entry<PendingGithubRuntimeAuthorityCommit>>,
        result_sender: Option<oneshot::Sender<GithubRuntimeAuthorityReceipt>>,
    ) -> bool {
        let repository = Arc::clone(&self.repository);
        let retry_interval = self.retry_interval;
        self.protected_custody.start_driver(
            custody,
            move |custody| async move {
                loop {
                    match custody.value().replay(repository.as_ref()).await {
                        Ok(receipt) => break receipt,
                        Err(_) => tokio::time::sleep(retry_interval).await,
                    }
                }
            },
            move |receipt| {
                if let Some(result_sender) = result_sender {
                    let _ = result_sender.send(receipt);
                }
            },
        )
    }

    fn retain_unprotected(
        &self,
        reservation: GithubRuntimeAuthorityCommitReservation,
        custody: UnprotectedGithubRuntimeAuthorityCandidate,
    ) {
        let custody = self.unprotected_custody.retain(reservation, custody);

        let started = self.start_unprotected_driver(&custody);
        assert!(started, "new unprotected custody starts one driver");
    }

    fn start_unprotected_driver(
        &self,
        custody: &Arc<Entry<UnprotectedGithubRuntimeAuthorityCandidate>>,
    ) -> bool {
        let repository = Arc::clone(&self.repository);
        let retry_interval = self.retry_interval;
        self.unprotected_custody.start_driver(
            custody,
            move |custody| async move {
                let request = AuthenticateGithubRuntimeAuthorityUnprotectedErasure::new(
                    &custody.value().claim,
                );
                let expected_key = custody.value().claim.identity().key();
                let earliest_erasure = custody.value().claim.identity().conservative_expiry();
                loop {
                    if let Ok(Some(receipt)) = repository
                        .authenticate_github_runtime_authority_unprotected_erasure(request.clone())
                        .await
                        && receipt.key() == expected_key
                        && receipt.state() == GithubRuntimeAuthorityState::Revoked
                        && receipt.updated_at() >= earliest_erasure
                        && receipt.terminal_reason()
                            == Some(
                                GithubRuntimeAuthorityTerminalReason::IndeterminateAuthorityExpired,
                            )
                    {
                        break;
                    }
                    tokio::time::sleep(retry_interval).await;
                }
            },
            |()| {},
        )
    }

    fn redrive_retained(&self) {
        for custody in self.protected_custody.retained() {
            let _ = self.start_protected_driver(&custody, None);
        }
        for custody in self.unprotected_custody.retained() {
            let _ = self.start_unprotected_driver(&custody);
        }
    }

    #[cfg(test)]
    fn abort_protected_task(&self) -> bool {
        self.protected_custody
            .retained()
            .first()
            .is_some_and(|custody| custody.abort_driver())
    }

    #[cfg(test)]
    fn abort_unprotected_task(&self) -> bool {
        self.unprotected_custody
            .retained()
            .first()
            .is_some_and(|custody| custody.abort_driver())
    }

    /// Returns the number of protected or unprotected candidates under custody.
    #[must_use]
    pub fn pending_count(&self) -> usize {
        self.protected_custody.pending()
    }

    /// Closes admission for new provider-mint candidates during shutdown.
    /// Already-supervised candidates retain their permits and custody.
    pub fn close(&self) {
        self.protected_custody.close();
    }

    /// Waits until every supervised protected commit is durably confirmed.
    /// Process wall time can never authorize loss of pending custody.
    pub async fn wait_for_idle(&self) {
        self.protected_custody
            .wait_for_idle(|| self.redrive_retained())
            .await;
    }

    /// Waits up to `timeout` for all supervised protected commits to confirm.
    ///
    /// Returns `true` when custody drained completely.
    pub async fn drain(&self, timeout: Duration) -> bool {
        tokio::time::timeout(timeout, self.wait_for_idle())
            .await
            .is_ok()
    }
}

impl fmt::Debug for GithubRuntimeAuthorityCommitSupervisor {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GithubRuntimeAuthorityCommitSupervisor")
            .field("repository", &"[AUTHORITY REPOSITORY]")
            .field("retry_interval", &self.retry_interval)
            .field("outstanding", &self.protected_custody.outstanding())
            .field("available_capacity", &self.protected_custody.available())
            .field("pending", &self.pending_count())
            .field(
                "protected_custody",
                &self.protected_custody.retained_count(),
            )
            .field(
                "unprotected_custody",
                &self.unprotected_custody.retained_count(),
            )
            .finish_non_exhaustive()
    }
}

pub(crate) type GithubRuntimeAuthorityCommitReservation = Reservation;

/// Result of one bounded coordinator pass.
#[must_use]
#[derive(Debug)]
pub enum GithubRuntimeAuthorityCoordinationOutcome {
    /// Durable state already prevents another mint or is not yet retryable.
    Existing(GithubRuntimeAuthorityInspection),
    /// Another live worker owns the claim, or a racing transition won.
    ClaimUnavailable,
    /// The exact claim had already crossed the irreversible boundary.
    AlreadyStarted(GithubRuntimeAuthorityReceipt),
    /// The provider outcome was durably mapped to its truthful state.
    Transitioned(GithubRuntimeAuthorityReceipt),
}

/// Sanitized coordinator failure that never contains token or provider text.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum GithubRuntimeAuthorityCoordinatorError {
    /// A durable repository operation failed before a candidate commit existed.
    #[error("GitHub runtime-authority repository operation failed")]
    Repository,
    /// Exact least-authority resolution was unavailable or inconsistent.
    #[error("GitHub runtime-authority request resolution failed")]
    Resolution,
    /// No currently authorized exact request exists for the identity.
    #[error("GitHub runtime-authority request is not authorized")]
    Unauthorized,
    /// Returned resolution evidence did not match the requested identity.
    #[error("GitHub runtime-authority resolution identity mismatched")]
    ResolutionIdentityMismatch,
    /// The injected broker serves a different App installation.
    #[error("GitHub runtime-authority broker identity mismatched")]
    BrokerIdentityMismatch,
    /// Bounded protected-candidate custody is currently full.
    #[error("GitHub runtime-authority commit supervision is full")]
    SupervisionCapacity,
    /// Randomness or key wrapping failed before the provider mint boundary.
    #[error("GitHub runtime-authority envelope preparation failed")]
    EnvelopePreparation,
    /// A recovered candidate contradicted the protected-custody contract and
    /// remains retained under bounded fail-stop supervision.
    #[error("GitHub runtime-authority candidate protection failed")]
    CandidateProtection,
    /// The immutable request or trusted observation time was invalid.
    #[error("GitHub runtime-authority coordination time is invalid")]
    InvalidTime,
    /// The remaining request window cannot contain the broker's hard timeout.
    #[error("GitHub runtime-authority mint window is exhausted")]
    MintWindowExhausted,
}

/// Production single-winner GitHub runtime-authority mint coordinator.
pub struct GithubRuntimeAuthorityMintCoordinator {
    repository: Arc<dyn GithubRuntimeAuthorityRepository>,
    resolver: Arc<dyn GithubRuntimeAuthorityRequestResolver>,
    broker: Arc<dyn GithubRuntimeAuthorityMintBroker>,
    envelopes: Arc<EnvelopeCodec>,
    clock: Arc<dyn GithubRuntimeAuthorityCoordinatorClock>,
    worker: GithubRuntimeAuthorityWorkerId,
    supervisor: Arc<GithubRuntimeAuthorityCommitSupervisor>,
}

impl GithubRuntimeAuthorityMintCoordinator {
    /// Constructs a coordinator from exact injected authority boundaries.
    #[must_use]
    pub fn new(
        repository: Arc<dyn GithubRuntimeAuthorityRepository>,
        resolver: Arc<dyn GithubRuntimeAuthorityRequestResolver>,
        broker: Arc<dyn GithubRuntimeAuthorityMintBroker>,
        envelopes: Arc<EnvelopeCodec>,
        clock: Arc<dyn GithubRuntimeAuthorityCoordinatorClock>,
        worker: GithubRuntimeAuthorityWorkerId,
        supervisor: Arc<GithubRuntimeAuthorityCommitSupervisor>,
    ) -> Self {
        Self {
            repository,
            resolver,
            broker,
            envelopes,
            clock,
            worker,
            supervisor,
        }
    }

    /// Performs at most one exact provider mint under durable single-winner custody.
    ///
    /// Inspection prevents calls after ready, revoke-pending, minting,
    /// indeterminate, quarantined, or terminal state. Randomness and provider
    /// key wrapping complete after the claim but before `begin`; only a newly
    /// committed `Started` transition permits `mint_once`.
    ///
    /// # Errors
    ///
    /// Returns only closed, sanitized pre-candidate failures. Every uniquely
    /// recovered candidate transfers to independent bounded custody before its
    /// first Store commit is polled, so cancellation can drop only the waiter.
    pub async fn coordinate_once(
        &self,
        identity: automata_ci_store::GithubRuntimeAuthorityIdentity,
    ) -> Result<GithubRuntimeAuthorityCoordinationOutcome, GithubRuntimeAuthorityCoordinatorError>
    {
        if !broker_matches_identity(self.broker.as_ref(), &identity) {
            return Err(GithubRuntimeAuthorityCoordinatorError::BrokerIdentityMismatch);
        }
        let observed_at = self.observation_at_least(identity.requested_at());
        let inspection = self.inspect(identity.clone(), observed_at).await?;
        if let Some(inspection) = inspection {
            let state = inspection.receipt().state();
            let retry_due = state == GithubRuntimeAuthorityState::MintRetryPending
                && inspection
                    .next_action_at()
                    .is_some_and(|retry_at| retry_at <= observed_at);
            if state != GithubRuntimeAuthorityState::Claimed && !retry_due {
                return Ok(GithubRuntimeAuthorityCoordinationOutcome::Existing(
                    inspection,
                ));
            }
        }

        let reservation = self
            .supervisor
            .try_reserve()
            .ok_or(GithubRuntimeAuthorityCoordinatorError::SupervisionCapacity)?;

        let claim_expires_at = claim_expiry(&identity, observed_at)?;
        let claim = ClaimGithubRuntimeAuthorityMint::new(
            identity.clone(),
            self.worker,
            observed_at,
            claim_expires_at,
        )
        .map_err(|_| GithubRuntimeAuthorityCoordinatorError::InvalidTime)?;
        let Some(claim) = self
            .repository
            .claim_github_runtime_authority_mint(claim)
            .await
            .map_err(|_| GithubRuntimeAuthorityCoordinatorError::Repository)?
        else {
            return self.claim_unavailable(identity).await;
        };

        let resolved = self
            .resolver
            .resolve_github_runtime_authority_request(claim.identity())
            .await
            .map_err(|_| GithubRuntimeAuthorityCoordinatorError::Resolution)?
            .ok_or(GithubRuntimeAuthorityCoordinatorError::Unauthorized)?;
        if resolved.identity() != claim.identity() {
            return Err(GithubRuntimeAuthorityCoordinatorError::ResolutionIdentityMismatch);
        }
        if !broker_matches_identity(self.broker.as_ref(), claim.identity()) {
            return Err(GithubRuntimeAuthorityCoordinatorError::BrokerIdentityMismatch);
        }

        let wrapping_context = claim
            .identity()
            .wrapping_encryption_context()
            .map_err(|_| GithubRuntimeAuthorityCoordinatorError::InvalidTime)?;
        let prepared = self
            .envelopes
            .prepare(&wrapping_context)
            .await
            .map_err(|_| GithubRuntimeAuthorityCoordinatorError::EnvelopePreparation)?;

        let begin_at = self.observation_at_least(claim.claimed_at());
        let provider_request_millis = ensure_mint_window(
            claim.identity(),
            begin_at,
            self.broker.maximum_mint_duration(),
        )?;
        let begin =
            BeginGithubRuntimeAuthorityMint::new(claim.clone(), begin_at, provider_request_millis)
                .map_err(|_| GithubRuntimeAuthorityCoordinatorError::InvalidTime)?;
        match self
            .repository
            .begin_github_runtime_authority_mint(begin)
            .await
            .map_err(|_| GithubRuntimeAuthorityCoordinatorError::Repository)?
        {
            BeginGithubRuntimeAuthorityMintOutcome::AlreadyStarted(receipt) => {
                return Ok(GithubRuntimeAuthorityCoordinationOutcome::AlreadyStarted(
                    receipt,
                ));
            }
            BeginGithubRuntimeAuthorityMintOutcome::Started(_) => {}
        }

        let outcome = self.broker.mint_once(resolved.request()).await;
        self.persist_mint_outcome(
            claim,
            prepared,
            resolved.request(),
            outcome,
            begin_at,
            reservation,
        )
        .await
    }

    async fn inspect(
        &self,
        identity: automata_ci_store::GithubRuntimeAuthorityIdentity,
        observed_at: UnixMillis,
    ) -> Result<Option<GithubRuntimeAuthorityInspection>, GithubRuntimeAuthorityCoordinatorError>
    {
        let request = InspectGithubRuntimeAuthority::new(identity, observed_at)
            .map_err(|_| GithubRuntimeAuthorityCoordinatorError::InvalidTime)?;
        self.repository
            .inspect_github_runtime_authority(request)
            .await
            .map_err(|_| GithubRuntimeAuthorityCoordinatorError::Repository)
    }

    async fn claim_unavailable(
        &self,
        identity: automata_ci_store::GithubRuntimeAuthorityIdentity,
    ) -> Result<GithubRuntimeAuthorityCoordinationOutcome, GithubRuntimeAuthorityCoordinatorError>
    {
        let observed_at = self.observation_at_least(identity.requested_at());
        Ok(self.inspect(identity, observed_at).await?.map_or(
            GithubRuntimeAuthorityCoordinationOutcome::ClaimUnavailable,
            GithubRuntimeAuthorityCoordinationOutcome::Existing,
        ))
    }

    async fn persist_mint_outcome(
        &self,
        claim: ClaimedGithubRuntimeAuthorityMint,
        prepared: automata_ci_key_management::PreparedEnvelope,
        expected_request: &RepositoryCredentialRequest,
        outcome: GithubInstallationTokenMintOutcome,
        observed_at: UnixMillis,
        reservation: GithubRuntimeAuthorityCommitReservation,
    ) -> Result<GithubRuntimeAuthorityCoordinationOutcome, GithubRuntimeAuthorityCoordinatorError>
    {
        match outcome {
            GithubInstallationTokenMintOutcome::Ready(ready) => {
                let provider_expires_at = provider_expiry_millis(ready.provider_expires_at());
                let provenance = ready.provenance();
                let deliverable = ready.request() == expected_request
                    && provenance.provider().as_str() == "github"
                    && provenance.subject().as_str()
                        == claim
                            .identity()
                            .provider_installation_id()
                            .get()
                            .to_string()
                    && provider_expiry_millis(ready.issued_at())
                        <= claim.identity().request_deadline()
                    && observed_at < claim.identity().request_deadline();
                let commit = protect_candidate(
                    &claim,
                    prepared,
                    ready.into_revocation_candidate(),
                    Some(provider_expires_at),
                    deliverable,
                    observed_at,
                );
                self.commit_or_retain_candidate(commit, reservation).await
            }
            GithubInstallationTokenMintOutcome::RevokePending(revoke) => {
                let provider_expires_at = revoke.provider_expires_at().and_then(|expires_at| {
                    let expires_at = provider_expiry_millis(expires_at);
                    (expires_at > claim.identity().requested_at()).then_some(expires_at)
                });
                let commit = protect_candidate(
                    &claim,
                    prepared,
                    revoke.into_candidate(),
                    provider_expires_at,
                    false,
                    observed_at,
                );
                self.commit_or_retain_candidate(commit, reservation).await
            }
            GithubInstallationTokenMintOutcome::Indeterminate(_) => {
                drop(prepared);
                let request = MarkGithubRuntimeAuthorityIndeterminate::new(&claim, observed_at)
                    .map_err(|_| GithubRuntimeAuthorityCoordinatorError::InvalidTime)?;
                let receipt = self
                    .repository
                    .mark_github_runtime_authority_indeterminate(request)
                    .await
                    .map_err(|_| GithubRuntimeAuthorityCoordinatorError::Repository)?;
                Ok(GithubRuntimeAuthorityCoordinationOutcome::Transitioned(
                    receipt,
                ))
            }
            GithubInstallationTokenMintOutcome::Rejected(error) => {
                drop(prepared);
                self.persist_definitive_rejection(&claim, error, observed_at)
                    .await
            }
        }
    }

    async fn persist_definitive_rejection(
        &self,
        claim: &ClaimedGithubRuntimeAuthorityMint,
        error: CredentialError,
        observed_at: UnixMillis,
    ) -> Result<GithubRuntimeAuthorityCoordinationOutcome, GithubRuntimeAuthorityCoordinatorError>
    {
        let failure = GithubRuntimeAuthorityMintFailure::new(mint_failure_kind(error.kind()))
            .map_err(|_| GithubRuntimeAuthorityCoordinatorError::Repository)?;
        let receipt = if matches!(
            error.kind(),
            CredentialErrorKind::RateLimited | CredentialErrorKind::Unavailable
        ) {
            let retry_at = retry_at(claim, error, observed_at)?;
            let request =
                RetryGithubRuntimeAuthorityMint::new(claim, failure, observed_at, retry_at)
                    .map_err(|_| GithubRuntimeAuthorityCoordinatorError::InvalidTime)?;
            self.repository
                .retry_github_runtime_authority_mint(request)
                .await
                .map_err(|_| GithubRuntimeAuthorityCoordinatorError::Repository)?
        } else {
            let request = RejectGithubRuntimeAuthorityMint::new(claim, failure, observed_at)
                .map_err(|_| GithubRuntimeAuthorityCoordinatorError::InvalidTime)?;
            self.repository
                .reject_github_runtime_authority_mint(request)
                .await
                .map_err(|_| GithubRuntimeAuthorityCoordinatorError::Repository)?
        };
        Ok(GithubRuntimeAuthorityCoordinationOutcome::Transitioned(
            receipt,
        ))
    }

    async fn commit_candidate(
        &self,
        commit: CommitGithubRuntimeAuthority,
        reservation: GithubRuntimeAuthorityCommitReservation,
    ) -> Result<GithubRuntimeAuthorityCoordinationOutcome, GithubRuntimeAuthorityCoordinatorError>
    {
        let receipt = self
            .supervisor
            .supervise(reservation, PendingGithubRuntimeAuthorityCommit { commit })
            .await
            .map_err(|_| GithubRuntimeAuthorityCoordinatorError::Repository)?;
        Ok(GithubRuntimeAuthorityCoordinationOutcome::Transitioned(
            receipt,
        ))
    }

    async fn commit_or_retain_candidate(
        &self,
        candidate: Result<CommitGithubRuntimeAuthority, UnprotectedGithubRuntimeAuthorityCandidate>,
        reservation: GithubRuntimeAuthorityCommitReservation,
    ) -> Result<GithubRuntimeAuthorityCoordinationOutcome, GithubRuntimeAuthorityCoordinatorError>
    {
        match candidate {
            Ok(commit) => self.commit_candidate(commit, reservation).await,
            Err(custody) => {
                self.supervisor.retain_unprotected(reservation, custody);
                Err(GithubRuntimeAuthorityCoordinatorError::CandidateProtection)
            }
        }
    }

    fn observation_at_least(&self, lower_bound: UnixMillis) -> UnixMillis {
        self.clock.now().max(lower_bound)
    }
}

impl fmt::Debug for GithubRuntimeAuthorityMintCoordinator {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GithubRuntimeAuthorityMintCoordinator")
            .field("repository", &"[AUTHORITY REPOSITORY]")
            .field("resolver", &"[LEAST-AUTHORITY RESOLVER]")
            .field("broker", &self.broker)
            .field("envelopes", &self.envelopes)
            .field("clock", &self.clock)
            .field("worker", &self.worker)
            .field("supervisor", &self.supervisor)
            .finish()
    }
}

struct InstallationTokenFrame {
    plaintext: SecretBytes,
    size_bytes: u64,
    digest: Sha256Digest,
}

impl InstallationTokenFrame {
    fn new(candidate: &GithubInstallationTokenRevocationCandidate) -> Option<Self> {
        let token = candidate.secret().expose_secret().as_bytes();
        let token_length = u32::try_from(token.len()).ok()?;
        let mut encoded = Vec::with_capacity(
            INSTALLATION_TOKEN_FRAME_DOMAIN.len() + size_of::<u32>() + token.len(),
        );
        encoded.extend_from_slice(INSTALLATION_TOKEN_FRAME_DOMAIN);
        encoded.extend_from_slice(&token_length.to_be_bytes());
        encoded.extend_from_slice(token);
        let size_bytes = u64::try_from(encoded.len()).ok()?;
        let digest = Sha256Digest::from_bytes(Sha256::digest(&encoded).into());
        let plaintext = SecretBytes::new(encoded).ok()?;
        Some(Self {
            plaintext,
            size_bytes,
            digest,
        })
    }
}

struct UnprotectedGithubRuntimeAuthorityCandidate {
    claim: Box<ClaimedGithubRuntimeAuthorityMint>,
    _candidate: GithubInstallationTokenRevocationCandidate,
    _prepared: Option<automata_ci_key_management::PreparedEnvelope>,
}

fn protect_candidate(
    claim: &ClaimedGithubRuntimeAuthorityMint,
    prepared: automata_ci_key_management::PreparedEnvelope,
    candidate: GithubInstallationTokenRevocationCandidate,
    provider_expires_at: Option<UnixMillis>,
    deliverable: bool,
    committed_at: UnixMillis,
) -> Result<CommitGithubRuntimeAuthority, UnprotectedGithubRuntimeAuthorityCandidate> {
    let Some(frame) = InstallationTokenFrame::new(&candidate) else {
        return Err(UnprotectedGithubRuntimeAuthorityCandidate {
            claim: Box::new(claim.clone()),
            _candidate: candidate,
            _prepared: Some(prepared),
        });
    };
    let (metadata, deliverable) = match GithubRuntimeAuthorityEnvelopeMetadata::new(
        claim.identity().clone(),
        provider_expires_at,
        frame.size_bytes,
        frame.digest,
    ) {
        Ok(metadata) => (metadata, deliverable),
        Err(_) => match GithubRuntimeAuthorityEnvelopeMetadata::new(
            claim.identity().clone(),
            None,
            frame.size_bytes,
            frame.digest,
        ) {
            Ok(metadata) => (metadata, false),
            Err(_) => {
                return Err(UnprotectedGithubRuntimeAuthorityCandidate {
                    claim: Box::new(claim.clone()),
                    _candidate: candidate,
                    _prepared: Some(prepared),
                });
            }
        },
    };
    let Ok(payload_context) = metadata.encryption_context() else {
        return Err(UnprotectedGithubRuntimeAuthorityCandidate {
            claim: Box::new(claim.clone()),
            _candidate: candidate,
            _prepared: Some(prepared),
        });
    };
    let envelope = prepared.seal_prepared(&payload_context, frame.plaintext);
    let Ok(protected) = ProtectedGithubRuntimeAuthority::new(metadata, envelope) else {
        return Err(UnprotectedGithubRuntimeAuthorityCandidate {
            claim: Box::new(claim.clone()),
            _candidate: candidate,
            _prepared: None,
        });
    };
    let commit = if deliverable {
        CommitGithubRuntimeAuthority::deliverable(claim, protected, committed_at)
    } else {
        CommitGithubRuntimeAuthority::revoke_only(claim, protected, committed_at)
    };
    match commit {
        Ok(commit) => {
            drop(candidate);
            Ok(commit)
        }
        Err(_) => Err(UnprotectedGithubRuntimeAuthorityCandidate {
            claim: Box::new(claim.clone()),
            _candidate: candidate,
            _prepared: None,
        }),
    }
}

fn broker_matches_identity(
    broker: &dyn GithubRuntimeAuthorityMintBroker,
    identity: &automata_ci_store::GithubRuntimeAuthorityIdentity,
) -> bool {
    broker.installation_id() == identity.provider_installation_id().get()
        && broker.github_app_id() == identity.github_app_id()
        && broker.github_app_client_id() == identity.github_app_client_id()
        && broker.github_app_jwt_issuer_kind() == identity.github_app_jwt_issuer_kind()
        && broker.github_app_jwt_issuer_value() == identity.github_app_jwt_issuer_value()
        && broker.app_key_spki_sha256() == identity.app_key_spki_sha256()
        && broker.configuration_fingerprint() == identity.configuration_fingerprint()
}

fn claim_expiry(
    identity: &automata_ci_store::GithubRuntimeAuthorityIdentity,
    observed_at: UnixMillis,
) -> Result<UnixMillis, GithubRuntimeAuthorityCoordinatorError> {
    if observed_at >= identity.request_deadline() {
        return Err(GithubRuntimeAuthorityCoordinatorError::MintWindowExhausted);
    }
    let maximum = observed_at
        .get()
        .checked_add(MAX_GITHUB_AUTHORITY_MINT_CLAIM_MILLIS)
        .ok_or(GithubRuntimeAuthorityCoordinatorError::InvalidTime)?;
    Ok(UnixMillis::new(
        maximum.min(identity.request_deadline().get()),
    ))
}

fn ensure_mint_window(
    identity: &automata_ci_store::GithubRuntimeAuthorityIdentity,
    begin_at: UnixMillis,
    maximum_duration: Duration,
) -> Result<i64, GithubRuntimeAuthorityCoordinatorError> {
    let duration = whole_milliseconds(maximum_duration)
        .and_then(|duration| i64::try_from(duration).ok())
        .filter(|duration| *duration > 0)
        .ok_or(GithubRuntimeAuthorityCoordinatorError::MintWindowExhausted)?;
    let completes_by = begin_at
        .get()
        .checked_add(duration)
        .ok_or(GithubRuntimeAuthorityCoordinatorError::InvalidTime)?;
    if completes_by > identity.request_deadline().get() {
        return Err(GithubRuntimeAuthorityCoordinatorError::MintWindowExhausted);
    }
    Ok(duration)
}

fn provider_expiry_millis(expiry: automata_ci_auth::time::UnixTimestamp) -> UnixMillis {
    let milliseconds = expiry
        .as_seconds()
        .checked_mul(1_000)
        .and_then(|value| i64::try_from(value).ok())
        .expect("validated GitHub RFC3339 expiration fits Unix milliseconds");
    UnixMillis::new(milliseconds)
}

fn retry_at(
    claim: &ClaimedGithubRuntimeAuthorityMint,
    error: CredentialError,
    observed_at: UnixMillis,
) -> Result<UnixMillis, GithubRuntimeAuthorityCoordinatorError> {
    let requested_backoff = error
        .retry_after_seconds()
        .and_then(|seconds| seconds.checked_mul(1_000))
        .and_then(|milliseconds| i64::try_from(milliseconds).ok())
        .unwrap_or(DEFAULT_MINT_RETRY_BACKOFF_MILLIS)
        .clamp(1, MAX_GITHUB_AUTHORITY_MINT_RETRY_BACKOFF_MILLIS);
    let requested_at = observed_at
        .get()
        .checked_add(requested_backoff)
        .ok_or(GithubRuntimeAuthorityCoordinatorError::InvalidTime)?;
    let latest = claim
        .identity()
        .conservative_expiry()
        .get()
        .checked_sub(1)
        .ok_or(GithubRuntimeAuthorityCoordinatorError::InvalidTime)?;
    let retry_at = requested_at.min(latest);
    if retry_at <= observed_at.get() {
        return Err(GithubRuntimeAuthorityCoordinatorError::InvalidTime);
    }
    Ok(UnixMillis::new(retry_at))
}

const fn mint_failure_kind(kind: CredentialErrorKind) -> &'static str {
    match kind {
        CredentialErrorKind::UnsupportedProvider => "unsupported_provider",
        CredentialErrorKind::InvalidRequest => "invalid_request",
        CredentialErrorKind::Unauthorized => "provider_unauthorized",
        CredentialErrorKind::Forbidden => "provider_forbidden",
        CredentialErrorKind::NotFound => "provider_not_found",
        CredentialErrorKind::RateLimited => "provider_rate_limited",
        CredentialErrorKind::Unavailable => "provider_unavailable",
        CredentialErrorKind::InvalidResponse => "invalid_response",
        CredentialErrorKind::RepositoryMismatch => "repository_mismatch",
        CredentialErrorKind::PermissionMismatch => "permission_mismatch",
        CredentialErrorKind::Expired => "insufficient_validity",
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{
        Mutex,
        atomic::{AtomicBool, AtomicI64, AtomicU64, AtomicUsize, Ordering},
    };

    use automata_ci_auth::{secret::SecretString, time::UnixTimestamp};
    use automata_ci_core::{
        AttemptId, FencingToken, JobId, JobIrVersion, LeaseId, RunId, RunnerId, RunnerSessionId,
    };
    use automata_ci_key_management::{
        EncryptedEnvelope, KeyEncryptionContext, KeyEncryptionError, KeyEncryptionProvider, KeyId,
        KeyPurpose, WrappedDataKey,
    };
    use automata_ci_provider::ProviderConnectionId;
    use automata_ci_scm::RepositoryId as ScmRepositoryId;
    use automata_ci_scm::credential::{
        CredentialProvenance, MinimumValidity, PermissionLevel, PermissionName, PermissionSet,
        ProviderResourceId, RepositoryScope,
    };
    use automata_ci_store::{
        ClaimGithubRuntimeAuthorityRevocation, ClaimedGithubRuntimeAuthorityRevocation,
        ConfirmGithubRuntimeAuthorityRevocation, DeferGithubRuntimeAuthorityRevocation,
        GithubInstallationId, GithubRepositoryId, GithubRepositoryName,
        GithubRuntimeAuthorityActivationSelectionTail, GithubRuntimeAuthorityClaimFence,
        GithubRuntimeAuthorityCommitDisposition, GithubRuntimeAuthorityCorruptionKind,
        GithubRuntimeAuthorityIdentity, GithubRuntimeAuthorityMaterializationSelectionTail,
        GithubRuntimeAuthorityNamespace, GithubRuntimeAuthorityPreparationSelectionTail,
        GithubRuntimeAuthorityReconciliationReport, GithubRuntimeAuthorityStoreError,
        GithubRuntimeAuthorityTerminalReason, LoadGithubRuntimeAuthority,
        LogicalActivationGeneration, LogicalActivationPreparationGeneration,
        LogicalActivationWorkerId, LogicalMaterializationGeneration,
        LogicalMaterializationWorkerId, LogicalWorkSelectionId, QuarantineGithubRuntimeAuthority,
        ReadyGithubRuntimeAuthority, ReconcileGithubRuntimeAuthorities, RepositoryId,
        RetryGithubRuntimeAuthorityRevocation, RunnerGeneration, SessionEpoch, StableRunnerSlot,
        TenantScope,
    };
    use uuid::Uuid;

    use crate::{
        GithubInstallationTokenIndeterminate, GithubInstallationTokenIndeterminateReason,
        GithubInstallationTokenRevokePending, GithubReadyInstallationToken,
    };

    use super::*;

    const TOKEN: &str = "ghs_exact-test-token_123";
    const REQUESTED_AT: i64 = 1_010_000;
    const REQUEST_DEADLINE: i64 = 1_120_000;
    const PROVIDER_EXPIRES_AT_SECONDS: u64 = 4_620;

    fn selection_tails() -> (
        GithubRuntimeAuthorityPreparationSelectionTail,
        GithubRuntimeAuthorityActivationSelectionTail,
        GithubRuntimeAuthorityMaterializationSelectionTail,
    ) {
        let activation_owner =
            LogicalActivationWorkerId::from_uuid(Uuid::from_u128(100)).expect("activation owner");
        (
            GithubRuntimeAuthorityPreparationSelectionTail::new(
                LogicalWorkSelectionId::from_uuid(Uuid::from_u128(101))
                    .expect("preparation selection"),
                activation_owner,
                LogicalActivationPreparationGeneration::new(1).expect("preparation generation"),
                Sha256Digest::from_bytes([31; 32]),
                UnixMillis::new(1_000_000),
                UnixMillis::new(1_010_000),
            )
            .expect("preparation tail"),
            GithubRuntimeAuthorityActivationSelectionTail::new(
                LogicalWorkSelectionId::from_uuid(Uuid::from_u128(102))
                    .expect("activation selection"),
                activation_owner,
                LogicalActivationGeneration::new(2).expect("activation generation"),
                Sha256Digest::from_bytes([32; 32]),
                UnixMillis::new(1_000_000),
                UnixMillis::new(1_010_000),
            )
            .expect("activation tail"),
            GithubRuntimeAuthorityMaterializationSelectionTail::new(
                LogicalWorkSelectionId::from_uuid(Uuid::from_u128(103))
                    .expect("materialization selection"),
                LogicalMaterializationWorkerId::from_uuid(Uuid::from_u128(104))
                    .expect("materialization owner"),
                LogicalMaterializationGeneration::new(3).expect("materialization generation"),
                Sha256Digest::from_bytes([33; 32]),
                UnixMillis::new(1_000_000),
                UnixMillis::new(1_010_000),
            )
            .expect("materialization tail"),
        )
    }

    fn identity() -> GithubRuntimeAuthorityIdentity {
        let (preparation_tail, activation_tail, materialization_tail) = selection_tails();
        GithubRuntimeAuthorityIdentity::new(
            TenantScope::from_authenticated_tenant_id("tenant-a").expect("tenant"),
            AttemptId::from_uuid(Uuid::from_u128(1)),
            FencingToken::new(7).expect("attempt fence"),
            LeaseId::from_uuid(Uuid::from_u128(2)),
            UnixMillis::new(1_000_000),
            UnixMillis::new(1_200_000),
            RunId::from_uuid(Uuid::from_u128(3)),
            JobId::from_uuid(Uuid::from_u128(4)),
            RunnerId::from_uuid(Uuid::from_u128(5)),
            RunnerSessionId::from_uuid(Uuid::from_u128(6)),
            SessionEpoch::new(8).expect("session epoch"),
            RunnerGeneration::new(9).expect("runner generation"),
            StableRunnerSlot::new(1).expect("runner slot"),
            JobIrVersion::current(),
            1_024,
            Sha256Digest::from_bytes([10; 32]),
            RepositoryId::from_uuid(Uuid::from_u128(11)),
            ProviderConnectionId::from_uuid(Uuid::from_u128(16)).expect("provider connection"),
            GithubInstallationId::new(17).expect("provider installation"),
            GithubServerServiceAppId::new(18).expect("App ID"),
            GithubServerServiceAppClientId::new("Iv1.automata-runtime").expect("App client ID"),
            GithubServerServiceJwtIssuer::AppClientId,
            GithubRepositoryId::new(12).expect("GitHub repository ID"),
            GithubRepositoryName::new("automata-ci/automata").expect("repository name"),
            GithubRuntimeAuthorityNamespace::new("github.actions.runtime")
                .expect("authority namespace"),
            Sha256Digest::from_bytes([10; 32]),
            Sha256Digest::from_bytes([13; 32]),
            Sha256Digest::from_bytes([15; 32]),
            preparation_tail,
            activation_tail,
            materialization_tail,
            UnixMillis::new(REQUESTED_AT),
            UnixMillis::new(REQUEST_DEADLINE),
        )
        .expect("runtime authority identity")
    }

    fn credential_request(
        identity: &GithubRuntimeAuthorityIdentity,
    ) -> RepositoryCredentialRequest {
        RepositoryCredentialRequest::new(
            github_runtime_authority_workload_identity(identity),
            RepositoryScope::new(
                ScmProviderId::new("github").expect("provider"),
                ScmRepositoryId::new(identity.github_repository_name().as_str())
                    .expect("repository"),
                ProviderResourceId::new(identity.github_repository_id().get().to_string())
                    .expect("provider repository ID"),
            ),
            PermissionSet::new([(
                PermissionName::new("contents").expect("permission"),
                PermissionLevel::Read,
            )])
            .expect("permissions"),
            MinimumValidity::default(),
        )
    }

    #[derive(Debug)]
    struct IncrementingClock(Arc<AtomicI64>);

    impl IncrementingClock {
        fn new(value: i64) -> Self {
            Self(Arc::new(AtomicI64::new(value)))
        }
    }

    impl GithubRuntimeAuthorityCoordinatorClock for IncrementingClock {
        fn now(&self) -> UnixMillis {
            UnixMillis::new(self.0.fetch_add(1_000, Ordering::SeqCst))
        }
    }

    #[derive(Debug)]
    struct FixedCoordinatorClock(UnixMillis);

    impl GithubRuntimeAuthorityCoordinatorClock for FixedCoordinatorClock {
        fn now(&self) -> UnixMillis {
            self.0
        }
    }

    struct FakeResolver {
        calls: AtomicUsize,
        request: RepositoryCredentialRequest,
        identity_override: Mutex<Option<GithubRuntimeAuthorityIdentity>>,
        missing: bool,
    }

    impl FakeResolver {
        fn exact(identity: &GithubRuntimeAuthorityIdentity) -> Self {
            Self {
                calls: AtomicUsize::new(0),
                request: credential_request(identity),
                identity_override: Mutex::new(None),
                missing: false,
            }
        }
    }

    #[async_trait]
    impl GithubRuntimeAuthorityRequestResolver for FakeResolver {
        async fn resolve_github_runtime_authority_request(
            &self,
            identity: &GithubRuntimeAuthorityIdentity,
        ) -> Result<
            Option<ResolvedGithubRuntimeAuthorityRequest>,
            GithubRuntimeAuthorityResolutionError,
        > {
            self.calls.fetch_add(1, Ordering::SeqCst);
            if self.missing {
                return Ok(None);
            }
            let attested = self
                .identity_override
                .lock()
                .expect("resolver lock")
                .clone()
                .unwrap_or_else(|| identity.clone());
            Ok(Some(
                ResolvedGithubRuntimeAuthorityRequest::new(attested, self.request.clone())
                    .expect("fake exact resolution"),
            ))
        }
    }

    #[derive(Clone, Copy, Debug)]
    enum FakeBrokerMode {
        Ready,
        ReadyWrongRequest,
        ReadyLate,
        RevokePendingKnown,
        RevokePendingUnknown,
        RevokePendingExpired,
        Indeterminate,
        Rejected(CredentialErrorKind),
    }

    struct FakeBroker {
        mode: FakeBrokerMode,
        installation_id: AtomicU64,
        github_app_id: AtomicU64,
        rotated_app_client_id: AtomicBool,
        app_id_jwt_issuer: AtomicBool,
        rotated_jwt_issuer_value: AtomicBool,
        issuer_fingerprint: Mutex<Sha256Digest>,
        configuration_fingerprint: Mutex<Sha256Digest>,
        post_mint_clock_jump: Mutex<Option<Arc<AtomicI64>>>,
        maximum_mint_duration_micros: AtomicU64,
        calls: AtomicUsize,
    }

    impl FakeBroker {
        fn new(mode: FakeBrokerMode) -> Self {
            Self {
                mode,
                installation_id: AtomicU64::new(17),
                github_app_id: AtomicU64::new(18),
                rotated_app_client_id: AtomicBool::new(false),
                app_id_jwt_issuer: AtomicBool::new(false),
                rotated_jwt_issuer_value: AtomicBool::new(false),
                issuer_fingerprint: Mutex::new(Sha256Digest::from_bytes([13; 32])),
                configuration_fingerprint: Mutex::new(Sha256Digest::from_bytes([15; 32])),
                post_mint_clock_jump: Mutex::new(None),
                maximum_mint_duration_micros: AtomicU64::new(1_000_000),
                calls: AtomicUsize::new(0),
            }
        }

        fn jump_clock_after_mint(&self, clock: Arc<AtomicI64>) {
            *self
                .post_mint_clock_jump
                .lock()
                .expect("post-mint clock lock") = Some(clock);
        }

        fn candidate() -> GithubInstallationTokenRevocationCandidate {
            GithubInstallationTokenRevocationCandidate::new(
                SecretString::new(TOKEN).expect("token"),
            )
        }
    }

    impl fmt::Debug for FakeBroker {
        fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str("FakeBroker([REDACTED])")
        }
    }

    #[async_trait]
    impl GithubRuntimeAuthorityMintBroker for FakeBroker {
        fn installation_id(&self) -> u64 {
            self.installation_id.load(Ordering::SeqCst)
        }

        fn github_app_id(&self) -> GithubServerServiceAppId {
            GithubServerServiceAppId::new(self.github_app_id.load(Ordering::SeqCst))
                .expect("App ID")
        }

        fn github_app_client_id(&self) -> &GithubServerServiceAppClientId {
            static CURRENT: std::sync::OnceLock<GithubServerServiceAppClientId> =
                std::sync::OnceLock::new();
            static ROTATED: std::sync::OnceLock<GithubServerServiceAppClientId> =
                std::sync::OnceLock::new();
            if self.rotated_app_client_id.load(Ordering::SeqCst) {
                ROTATED.get_or_init(|| {
                    GithubServerServiceAppClientId::new("Iv1.rotated-runtime")
                        .expect("rotated App client ID")
                })
            } else {
                CURRENT.get_or_init(|| {
                    GithubServerServiceAppClientId::new("Iv1.automata-runtime")
                        .expect("App client ID")
                })
            }
        }

        fn github_app_jwt_issuer_kind(&self) -> GithubServerServiceJwtIssuer {
            if self.app_id_jwt_issuer.load(Ordering::SeqCst) {
                GithubServerServiceJwtIssuer::AppId
            } else {
                GithubServerServiceJwtIssuer::AppClientId
            }
        }

        fn github_app_jwt_issuer_value(&self) -> &str {
            if self.rotated_jwt_issuer_value.load(Ordering::SeqCst) {
                "Iv1.rotated-runtime"
            } else {
                "Iv1.automata-runtime"
            }
        }

        fn app_key_spki_sha256(&self) -> Sha256Digest {
            *self.issuer_fingerprint.lock().expect("issuer lock")
        }

        fn configuration_fingerprint(&self) -> Sha256Digest {
            *self
                .configuration_fingerprint
                .lock()
                .expect("configuration lock")
        }

        fn maximum_mint_duration(&self) -> Duration {
            Duration::from_micros(self.maximum_mint_duration_micros.load(Ordering::SeqCst))
        }

        async fn mint_once(
            &self,
            request: &RepositoryCredentialRequest,
        ) -> GithubInstallationTokenMintOutcome {
            self.calls.fetch_add(1, Ordering::SeqCst);
            let expires_at = UnixTimestamp::from_seconds(PROVIDER_EXPIRES_AT_SECONDS);
            let conservative_expires_at =
                UnixTimestamp::from_seconds(PROVIDER_EXPIRES_AT_SECONDS - 60);
            let outcome = match self.mode {
                FakeBrokerMode::Ready
                | FakeBrokerMode::ReadyWrongRequest
                | FakeBrokerMode::ReadyLate => {
                    let returned_request = if matches!(self.mode, FakeBrokerMode::ReadyWrongRequest)
                    {
                        RepositoryCredentialRequest::new(
                            WorkloadIdentity::new("wrong-workload").expect("wrong workload"),
                            request.repository().clone(),
                            request.permissions().clone(),
                            request.minimum_validity(),
                        )
                    } else {
                        request.clone()
                    };
                    let issued_at = if matches!(self.mode, FakeBrokerMode::ReadyLate) {
                        UnixTimestamp::from_seconds(1_200)
                    } else {
                        UnixTimestamp::from_seconds(1_020)
                    };
                    GithubInstallationTokenMintOutcome::Ready(GithubReadyInstallationToken::new(
                        Self::candidate(),
                        returned_request,
                        issued_at,
                        expires_at,
                        conservative_expires_at,
                        CredentialProvenance::new(
                            ScmProviderId::new("github").expect("provider"),
                            ProviderResourceId::new("app-issuer").expect("issuer"),
                            ProviderResourceId::new("17").expect("installation"),
                        ),
                    ))
                }
                FakeBrokerMode::RevokePendingKnown => {
                    GithubInstallationTokenMintOutcome::RevokePending(
                        GithubInstallationTokenRevokePending::new(
                            Self::candidate(),
                            CredentialError::new(CredentialErrorKind::PermissionMismatch),
                            Some(expires_at),
                            Some(conservative_expires_at),
                        ),
                    )
                }
                FakeBrokerMode::RevokePendingUnknown => {
                    GithubInstallationTokenMintOutcome::RevokePending(
                        GithubInstallationTokenRevokePending::new(
                            Self::candidate(),
                            CredentialError::new(CredentialErrorKind::InvalidResponse),
                            None,
                            None,
                        ),
                    )
                }
                FakeBrokerMode::RevokePendingExpired => {
                    GithubInstallationTokenMintOutcome::RevokePending(
                        GithubInstallationTokenRevokePending::new(
                            Self::candidate(),
                            CredentialError::new(CredentialErrorKind::Expired),
                            Some(UnixTimestamp::from_seconds(1)),
                            None,
                        ),
                    )
                }
                FakeBrokerMode::Indeterminate => GithubInstallationTokenMintOutcome::Indeterminate(
                    GithubInstallationTokenIndeterminate::new(
                        GithubInstallationTokenIndeterminateReason::Transport,
                    ),
                ),
                FakeBrokerMode::Rejected(kind) => {
                    GithubInstallationTokenMintOutcome::Rejected(CredentialError::new(kind))
                }
            };
            if let Some(clock) = self
                .post_mint_clock_jump
                .lock()
                .expect("post-mint clock lock")
                .as_ref()
            {
                clock.store(i64::MAX - 1, Ordering::SeqCst);
            }
            outcome
        }
    }

    struct FakeKeyProvider {
        fail_wrap: bool,
        wrap_calls: AtomicUsize,
        wrapping_contexts: Mutex<Vec<Vec<u8>>>,
        post_wrap_database_clock_jump: Mutex<Option<(Arc<AtomicI64>, i64)>>,
    }

    impl FakeKeyProvider {
        fn new(fail_wrap: bool) -> Self {
            Self {
                fail_wrap,
                wrap_calls: AtomicUsize::new(0),
                wrapping_contexts: Mutex::new(Vec::new()),
                post_wrap_database_clock_jump: Mutex::new(None),
            }
        }

        fn jump_database_clock_after_wrap(&self, clock: Arc<AtomicI64>, value: i64) {
            *self
                .post_wrap_database_clock_jump
                .lock()
                .expect("post-wrap database-clock lock") = Some((clock, value));
        }
    }

    impl fmt::Debug for FakeKeyProvider {
        fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str("FakeKeyProvider([REDACTED])")
        }
    }

    #[async_trait]
    impl KeyEncryptionProvider for FakeKeyProvider {
        async fn wrap_data_key(
            &self,
            plaintext_key: &SecretBytes,
            context: &KeyEncryptionContext,
        ) -> Result<WrappedDataKey, KeyEncryptionError> {
            self.wrap_calls.fetch_add(1, Ordering::SeqCst);
            self.wrapping_contexts
                .lock()
                .expect("context lock")
                .push(context.canonical_authenticated_bytes());
            if self.fail_wrap {
                return Err(KeyEncryptionError::Unavailable);
            }
            let context_digest = Sha256::digest(context.canonical_authenticated_bytes());
            let mut wrapped = Vec::with_capacity(context_digest.len() + plaintext_key.len());
            wrapped.extend_from_slice(&context_digest);
            wrapped.extend_from_slice(plaintext_key.expose_secret());
            if let Some((clock, value)) = self
                .post_wrap_database_clock_jump
                .lock()
                .expect("post-wrap database-clock lock")
                .as_ref()
            {
                clock.store(*value, Ordering::SeqCst);
            }
            WrappedDataKey::new(KeyId::new("fake-kms-v1").expect("key ID"), wrapped)
                .map_err(|_| KeyEncryptionError::InvalidCiphertext)
        }

        async fn unwrap_data_key(
            &self,
            wrapped_key: &WrappedDataKey,
            context: &KeyEncryptionContext,
        ) -> Result<SecretBytes, KeyEncryptionError> {
            let wrapped = wrapped_key.ciphertext();
            let expected_context = Sha256::digest(context.canonical_authenticated_bytes());
            if wrapped.len() != expected_context.len() + 32
                || wrapped[..expected_context.len()] != expected_context[..]
            {
                return Err(KeyEncryptionError::AuthenticationFailed);
            }
            SecretBytes::new(wrapped[expected_context.len()..].to_vec())
                .map_err(|_| KeyEncryptionError::InvalidDataKey)
        }
    }

    #[derive(Clone, Eq, PartialEq)]
    struct CommitSnapshot {
        disposition: GithubRuntimeAuthorityCommitDisposition,
        committed_at: UnixMillis,
        metadata: GithubRuntimeAuthorityEnvelopeMetadata,
        key_id: KeyId,
        wrapped_data_key: Vec<u8>,
        nonce: [u8; automata_ci_key_management::ENVELOPE_NONCE_BYTES],
        ciphertext: Vec<u8>,
    }

    impl CommitSnapshot {
        fn capture(commit: &CommitGithubRuntimeAuthority) -> Self {
            let envelope = commit.protected().envelope();
            Self {
                disposition: commit.disposition(),
                committed_at: commit.committed_at(),
                metadata: commit.protected().metadata().clone(),
                key_id: envelope.wrapping_key_id().clone(),
                wrapped_data_key: envelope.wrapped_data_key().ciphertext().to_vec(),
                nonce: *envelope.nonce(),
                ciphertext: envelope.ciphertext().to_vec(),
            }
        }

        fn envelope(&self) -> EncryptedEnvelope {
            EncryptedEnvelope::from_parts(
                automata_ci_key_management::ENVELOPE_SCHEMA_V1,
                WrappedDataKey::new(self.key_id.clone(), self.wrapped_data_key.clone())
                    .expect("wrapped data key"),
                self.nonce,
                self.ciphertext.clone(),
            )
            .expect("captured envelope")
        }
    }

    #[derive(Default)]
    struct FakeStoreState {
        identity: Option<GithubRuntimeAuthorityIdentity>,
        claim: Option<ClaimedGithubRuntimeAuthorityMint>,
        state: Option<GithubRuntimeAuthorityState>,
        begin_calls: usize,
        begin_provider_request_millis: Vec<i64>,
        commit_failures: usize,
        begin_ambiguous_once: bool,
        force_already_started: bool,
        unprotected_erasure_authenticated: bool,
        unprotected_erasure_calls: usize,
        commits: Vec<CommitSnapshot>,
    }

    #[derive(Default)]
    struct FakeStore {
        inner: Mutex<FakeStoreState>,
        commit_gate: Option<Arc<CommitGate>>,
        unprotected_erasure_gate: Option<Arc<CommitGate>>,
        begin_database_clock: Option<Arc<AtomicI64>>,
    }

    struct CommitGate {
        entered: tokio::sync::Semaphore,
        release: tokio::sync::Semaphore,
    }

    impl Default for CommitGate {
        fn default() -> Self {
            Self {
                entered: tokio::sync::Semaphore::new(0),
                release: tokio::sync::Semaphore::new(0),
            }
        }
    }

    impl CommitGate {
        async fn wait_until_entered(&self) {
            self.entered
                .acquire()
                .await
                .expect("commit-entry semaphore")
                .forget();
        }

        fn release(&self) {
            self.release.add_permits(1);
        }
    }

    impl FakeStore {
        fn with_minting_claim() -> (Self, ClaimedGithubRuntimeAuthorityMint) {
            let identity = identity();
            let claim = ClaimedGithubRuntimeAuthorityMint::from_repository_parts(
                identity.clone(),
                GithubRuntimeAuthorityWorkerId::from_uuid(Uuid::from_u128(90)).expect("worker"),
                GithubRuntimeAuthorityClaimFence::new(1).expect("claim fence"),
                1,
                UnixMillis::new(REQUESTED_AT),
                UnixMillis::new(REQUESTED_AT + 10_000),
            )
            .expect("claim");
            let store = Self::default();
            {
                let mut state = store.inner.lock().expect("store lock");
                state.identity = Some(identity);
                state.claim = Some(claim.clone());
                state.state = Some(GithubRuntimeAuthorityState::Minting);
            }
            (store, claim)
        }

        fn authenticate_unprotected_erasure(&self) {
            self.inner
                .lock()
                .expect("store lock")
                .unprotected_erasure_authenticated = true;
        }

        fn unprotected_erasure_calls(&self) -> usize {
            self.inner
                .lock()
                .expect("store lock")
                .unprotected_erasure_calls
        }

        fn with_commit_failure() -> Self {
            let store = Self::default();
            store.inner.lock().expect("store lock").commit_failures = 1;
            store
        }

        fn with_ambiguous_begin() -> Self {
            let store = Self::default();
            store.inner.lock().expect("store lock").begin_ambiguous_once = true;
            store
        }

        fn with_begin_database_clock(clock: Arc<AtomicI64>) -> Self {
            Self {
                begin_database_clock: Some(clock),
                ..Self::default()
            }
        }

        fn with_already_started() -> Self {
            let store = Self::default();
            store
                .inner
                .lock()
                .expect("store lock")
                .force_already_started = true;
            store
        }

        fn with_gated_commit() -> (Self, Arc<CommitGate>) {
            let gate = Arc::new(CommitGate::default());
            (
                Self {
                    inner: Mutex::new(FakeStoreState::default()),
                    commit_gate: Some(gate.clone()),
                    unprotected_erasure_gate: None,
                    begin_database_clock: None,
                },
                gate,
            )
        }

        fn with_gated_unprotected_erasure()
        -> (Self, ClaimedGithubRuntimeAuthorityMint, Arc<CommitGate>) {
            let (mut store, claim) = Self::with_minting_claim();
            let gate = Arc::new(CommitGate::default());
            store.unprotected_erasure_gate = Some(gate.clone());
            (store, claim, gate)
        }

        fn receipt(
            state: &FakeStoreState,
            lifecycle: GithubRuntimeAuthorityState,
            updated_at: UnixMillis,
        ) -> GithubRuntimeAuthorityReceipt {
            let identity = state.identity.as_ref().expect("stored identity");
            let terminal_reason = match lifecycle {
                GithubRuntimeAuthorityState::Rejected => {
                    Some(GithubRuntimeAuthorityTerminalReason::ProviderMintRejected)
                }
                GithubRuntimeAuthorityState::Revoked => {
                    Some(GithubRuntimeAuthorityTerminalReason::ProviderRevocationConfirmed)
                }
                _ => None,
            };
            GithubRuntimeAuthorityReceipt::from_repository_parts(
                identity.key(),
                lifecycle,
                updated_at,
                terminal_reason,
            )
            .expect("receipt")
        }

        fn begin_calls(&self) -> usize {
            self.inner.lock().expect("store lock").begin_calls
        }

        fn begin_provider_request_millis(&self) -> Vec<i64> {
            self.inner
                .lock()
                .expect("store lock")
                .begin_provider_request_millis
                .clone()
        }

        fn snapshots(&self) -> Vec<CommitSnapshot> {
            self.inner.lock().expect("store lock").commits.clone()
        }

        fn state(&self) -> Option<GithubRuntimeAuthorityState> {
            self.inner.lock().expect("store lock").state
        }
    }

    #[async_trait]
    impl GithubRuntimeAuthorityRepository for FakeStore {
        async fn inspect_github_runtime_authority(
            &self,
            _request: InspectGithubRuntimeAuthority,
        ) -> Result<Option<GithubRuntimeAuthorityInspection>, GithubRuntimeAuthorityStoreError>
        {
            Ok(None)
        }

        async fn claim_github_runtime_authority_mint(
            &self,
            request: ClaimGithubRuntimeAuthorityMint,
        ) -> Result<Option<ClaimedGithubRuntimeAuthorityMint>, GithubRuntimeAuthorityStoreError>
        {
            let mut state = self.inner.lock().expect("store lock");
            if state.state.is_none() {
                let claim = ClaimedGithubRuntimeAuthorityMint::from_repository_parts(
                    request.identity().clone(),
                    request.owner(),
                    GithubRuntimeAuthorityClaimFence::new(1).expect("claim fence"),
                    1,
                    request.observed_at(),
                    request.expires_at(),
                )
                .expect("claim");
                state.identity = Some(request.identity().clone());
                state.claim = Some(claim.clone());
                state.state = Some(GithubRuntimeAuthorityState::Claimed);
                return Ok(Some(claim));
            }
            if state.state == Some(GithubRuntimeAuthorityState::Claimed) {
                return Ok(state.claim.clone());
            }
            Ok(None)
        }

        async fn begin_github_runtime_authority_mint(
            &self,
            request: BeginGithubRuntimeAuthorityMint,
        ) -> Result<BeginGithubRuntimeAuthorityMintOutcome, GithubRuntimeAuthorityStoreError>
        {
            let mut state = self.inner.lock().expect("store lock");
            state.begin_calls += 1;
            state
                .begin_provider_request_millis
                .push(request.provider_request_millis());
            if let Some(database_clock) = &self.begin_database_clock {
                let database_now = database_clock.load(Ordering::SeqCst);
                let latest_completion = request
                    .claim()
                    .expires_at()
                    .get()
                    .min(request.claim().identity().request_deadline().get());
                if database_now
                    .checked_add(request.provider_request_millis())
                    .is_none_or(|completes_at| completes_at > latest_completion)
                {
                    return Err(GithubRuntimeAuthorityStoreError::MintClaimRejected);
                }
            }
            state.state = Some(GithubRuntimeAuthorityState::Minting);
            let receipt = Self::receipt(
                &state,
                GithubRuntimeAuthorityState::Minting,
                request.observed_at(),
            );
            if state.begin_ambiguous_once {
                state.begin_ambiguous_once = false;
                return Err(GithubRuntimeAuthorityStoreError::operation(
                    std::io::Error::other("ambiguous begin"),
                ));
            }
            if state.force_already_started {
                return Ok(BeginGithubRuntimeAuthorityMintOutcome::AlreadyStarted(
                    receipt,
                ));
            }
            Ok(BeginGithubRuntimeAuthorityMintOutcome::Started(receipt))
        }

        async fn authenticate_github_runtime_authority_unprotected_erasure(
            &self,
            request: AuthenticateGithubRuntimeAuthorityUnprotectedErasure,
        ) -> Result<Option<GithubRuntimeAuthorityReceipt>, GithubRuntimeAuthorityStoreError>
        {
            {
                let mut state = self.inner.lock().expect("store lock");
                state.unprotected_erasure_calls += 1;
            }
            if let Some(gate) = &self.unprotected_erasure_gate {
                gate.entered.add_permits(1);
                gate.release
                    .acquire()
                    .await
                    .map_err(GithubRuntimeAuthorityStoreError::operation)?
                    .forget();
            }
            let mut state = self.inner.lock().expect("store lock");
            if state.claim.as_ref() != Some(request.claim())
                || !matches!(
                    state.state,
                    Some(
                        GithubRuntimeAuthorityState::Minting
                            | GithubRuntimeAuthorityState::Indeterminate
                            | GithubRuntimeAuthorityState::Revoked
                    )
                )
            {
                return Err(GithubRuntimeAuthorityStoreError::CorruptData);
            }
            if !state.unprotected_erasure_authenticated {
                return Ok(None);
            }
            state.state = Some(GithubRuntimeAuthorityState::Revoked);
            let identity = state.identity.as_ref().expect("stored identity");
            Ok(Some(
                GithubRuntimeAuthorityReceipt::from_repository_parts(
                    identity.key(),
                    GithubRuntimeAuthorityState::Revoked,
                    identity.conservative_expiry(),
                    Some(GithubRuntimeAuthorityTerminalReason::IndeterminateAuthorityExpired),
                )
                .expect("terminal erasure receipt"),
            ))
        }

        async fn mark_github_runtime_authority_indeterminate(
            &self,
            request: MarkGithubRuntimeAuthorityIndeterminate,
        ) -> Result<GithubRuntimeAuthorityReceipt, GithubRuntimeAuthorityStoreError> {
            let mut state = self.inner.lock().expect("store lock");
            state.state = Some(GithubRuntimeAuthorityState::Indeterminate);
            Ok(Self::receipt(
                &state,
                GithubRuntimeAuthorityState::Indeterminate,
                request.observed_at(),
            ))
        }

        async fn retry_github_runtime_authority_mint(
            &self,
            request: RetryGithubRuntimeAuthorityMint,
        ) -> Result<GithubRuntimeAuthorityReceipt, GithubRuntimeAuthorityStoreError> {
            let mut state = self.inner.lock().expect("store lock");
            state.state = Some(GithubRuntimeAuthorityState::MintRetryPending);
            Ok(Self::receipt(
                &state,
                GithubRuntimeAuthorityState::MintRetryPending,
                request.observed_at(),
            ))
        }

        async fn reject_github_runtime_authority_mint(
            &self,
            request: RejectGithubRuntimeAuthorityMint,
        ) -> Result<GithubRuntimeAuthorityReceipt, GithubRuntimeAuthorityStoreError> {
            let mut state = self.inner.lock().expect("store lock");
            state.state = Some(GithubRuntimeAuthorityState::Rejected);
            Ok(Self::receipt(
                &state,
                GithubRuntimeAuthorityState::Rejected,
                request.observed_at(),
            ))
        }

        async fn commit_github_runtime_authority(
            &self,
            request: &CommitGithubRuntimeAuthority,
        ) -> Result<GithubRuntimeAuthorityReceipt, GithubRuntimeAuthorityStoreError> {
            if let Some(gate) = &self.commit_gate {
                gate.entered.add_permits(1);
                gate.release
                    .acquire()
                    .await
                    .expect("commit-release semaphore")
                    .forget();
            }
            let mut state = self.inner.lock().expect("store lock");
            state.commits.push(CommitSnapshot::capture(request));
            if state.commit_failures > 0 {
                state.commit_failures -= 1;
                return Err(GithubRuntimeAuthorityStoreError::operation(
                    std::io::Error::other("ambiguous commit"),
                ));
            }
            let lifecycle = match request.disposition() {
                GithubRuntimeAuthorityCommitDisposition::Deliverable => {
                    GithubRuntimeAuthorityState::Ready
                }
                GithubRuntimeAuthorityCommitDisposition::RevokeOnly => {
                    GithubRuntimeAuthorityState::RevokePending
                }
            };
            state.state = Some(lifecycle);
            Ok(Self::receipt(&state, lifecycle, request.committed_at()))
        }

        async fn load_ready_github_runtime_authority(
            &self,
            _request: LoadGithubRuntimeAuthority,
        ) -> Result<Option<ReadyGithubRuntimeAuthority>, GithubRuntimeAuthorityStoreError> {
            Ok(None)
        }

        async fn quarantine_github_runtime_authority(
            &self,
            _request: QuarantineGithubRuntimeAuthority,
        ) -> Result<GithubRuntimeAuthorityReceipt, GithubRuntimeAuthorityStoreError> {
            Err(GithubRuntimeAuthorityStoreError::QuarantineRejected)
        }

        async fn reconcile_github_runtime_authorities(
            &self,
            _request: ReconcileGithubRuntimeAuthorities,
        ) -> Result<GithubRuntimeAuthorityReconciliationReport, GithubRuntimeAuthorityStoreError>
        {
            Err(GithubRuntimeAuthorityStoreError::MintClaimRejected)
        }

        async fn claim_github_runtime_authority_revocation(
            &self,
            _request: ClaimGithubRuntimeAuthorityRevocation,
        ) -> Result<Option<ClaimedGithubRuntimeAuthorityRevocation>, GithubRuntimeAuthorityStoreError>
        {
            Ok(None)
        }

        async fn revalidate_github_runtime_authority_revocation(
            &self,
            _request: automata_ci_store::RevalidateGithubRuntimeAuthorityRevocation,
        ) -> Result<
            Option<automata_ci_store::RevalidatedGithubRuntimeAuthorityRevocation>,
            GithubRuntimeAuthorityStoreError,
        > {
            unreachable!("revocation is outside mint coordination")
        }

        async fn retry_github_runtime_authority_revocation(
            &self,
            _request: RetryGithubRuntimeAuthorityRevocation,
        ) -> Result<GithubRuntimeAuthorityReceipt, GithubRuntimeAuthorityStoreError> {
            Err(GithubRuntimeAuthorityStoreError::RevocationClaimRejected)
        }

        async fn defer_github_runtime_authority_revocation(
            &self,
            _request: DeferGithubRuntimeAuthorityRevocation,
        ) -> Result<GithubRuntimeAuthorityReceipt, GithubRuntimeAuthorityStoreError> {
            Err(GithubRuntimeAuthorityStoreError::RevocationClaimRejected)
        }

        async fn confirm_github_runtime_authority_revocation(
            &self,
            _request: ConfirmGithubRuntimeAuthorityRevocation,
        ) -> Result<GithubRuntimeAuthorityReceipt, GithubRuntimeAuthorityStoreError> {
            Err(GithubRuntimeAuthorityStoreError::RevocationClaimRejected)
        }
    }

    struct Harness {
        identity: GithubRuntimeAuthorityIdentity,
        store: Arc<FakeStore>,
        broker: Arc<FakeBroker>,
        keys: Arc<FakeKeyProvider>,
        codec: Arc<EnvelopeCodec>,
        coordinator: GithubRuntimeAuthorityMintCoordinator,
        supervisor: Arc<GithubRuntimeAuthorityCommitSupervisor>,
    }

    impl Harness {
        fn new(mode: FakeBrokerMode, store: FakeStore, fail_wrap: bool) -> Self {
            Self::with_clock(
                mode,
                store,
                fail_wrap,
                Arc::new(IncrementingClock::new(REQUESTED_AT)),
            )
        }

        fn with_clock(
            mode: FakeBrokerMode,
            store: FakeStore,
            fail_wrap: bool,
            coordinator_clock: Arc<dyn GithubRuntimeAuthorityCoordinatorClock>,
        ) -> Self {
            let identity = identity();
            let store = Arc::new(store);
            let resolver = Arc::new(FakeResolver::exact(&identity));
            let broker = Arc::new(FakeBroker::new(mode));
            let keys = Arc::new(FakeKeyProvider::new(fail_wrap));
            let codec = Arc::new(EnvelopeCodec::new(keys.clone()));
            let supervisor = Arc::new(
                GithubRuntimeAuthorityCommitSupervisor::new(
                    store.clone(),
                    Handle::current(),
                    1,
                    Duration::from_millis(1),
                )
                .expect("supervisor"),
            );
            let coordinator = GithubRuntimeAuthorityMintCoordinator::new(
                store.clone(),
                resolver.clone(),
                broker.clone(),
                codec.clone(),
                coordinator_clock,
                GithubRuntimeAuthorityWorkerId::from_uuid(Uuid::from_u128(90)).expect("worker"),
                supervisor.clone(),
            );
            Self {
                identity,
                store,
                broker,
                keys,
                codec,
                coordinator,
                supervisor,
            }
        }

        async fn run(
            &self,
        ) -> Result<GithubRuntimeAuthorityCoordinationOutcome, GithubRuntimeAuthorityCoordinatorError>
        {
            self.coordinator
                .coordinate_once(self.identity.clone())
                .await
        }

        async fn open_snapshot(&self, snapshot: &CommitSnapshot) -> SecretBytes {
            self.codec
                .open_with_contexts(
                    &self
                        .identity
                        .wrapping_encryption_context()
                        .expect("wrapping context"),
                    &snapshot
                        .metadata
                        .encryption_context()
                        .expect("payload context"),
                    &snapshot.envelope(),
                )
                .await
                .expect("open protected frame")
        }
    }

    #[tokio::test]
    async fn kms_outage_happens_before_begin_and_provider_mint() {
        let harness = Harness::new(FakeBrokerMode::Ready, FakeStore::default(), true);

        assert_eq!(
            harness.run().await.unwrap_err(),
            GithubRuntimeAuthorityCoordinatorError::EnvelopePreparation
        );
        assert_eq!(harness.keys.wrap_calls.load(Ordering::SeqCst), 1);
        assert_eq!(harness.store.begin_calls(), 0);
        assert_eq!(harness.broker.calls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn slow_kms_with_frozen_process_clock_is_rejected_by_database_before_provider_mint() {
        let database_clock = Arc::new(AtomicI64::new(REQUESTED_AT));
        let harness = Harness::with_clock(
            FakeBrokerMode::Ready,
            FakeStore::with_begin_database_clock(database_clock.clone()),
            false,
            Arc::new(FixedCoordinatorClock(UnixMillis::new(REQUESTED_AT))),
        );
        harness
            .keys
            .jump_database_clock_after_wrap(database_clock, REQUEST_DEADLINE - 500);

        assert_eq!(
            harness.run().await.unwrap_err(),
            GithubRuntimeAuthorityCoordinatorError::Repository
        );
        assert_eq!(harness.keys.wrap_calls.load(Ordering::SeqCst), 1);
        assert_eq!(harness.store.begin_calls(), 1);
        assert_eq!(harness.store.begin_provider_request_millis(), [1_000]);
        assert_eq!(
            harness.store.state(),
            Some(GithubRuntimeAuthorityState::Claimed)
        );
        assert_eq!(harness.broker.calls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn fractional_millisecond_provider_window_never_reaches_begin_or_provider() {
        let harness = Harness::with_clock(
            FakeBrokerMode::Ready,
            FakeStore::default(),
            false,
            Arc::new(FixedCoordinatorClock(UnixMillis::new(REQUESTED_AT))),
        );
        harness
            .broker
            .maximum_mint_duration_micros
            .store(1_500, Ordering::SeqCst);

        assert_eq!(
            harness.run().await.unwrap_err(),
            GithubRuntimeAuthorityCoordinatorError::MintWindowExhausted
        );
        assert_eq!(harness.keys.wrap_calls.load(Ordering::SeqCst), 1);
        assert_eq!(harness.store.begin_calls(), 0);
        assert!(harness.store.begin_provider_request_millis().is_empty());
        assert_eq!(harness.broker.calls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn wrong_installation_broker_fails_before_kms_begin_or_mint() {
        let harness = Harness::new(FakeBrokerMode::Ready, FakeStore::default(), false);
        harness.broker.installation_id.store(18, Ordering::SeqCst);

        assert_eq!(
            harness.run().await.unwrap_err(),
            GithubRuntimeAuthorityCoordinatorError::BrokerIdentityMismatch
        );
        assert_eq!(harness.keys.wrap_calls.load(Ordering::SeqCst), 0);
        assert_eq!(harness.store.begin_calls(), 0);
        assert_eq!(harness.broker.calls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn every_app_and_jwt_issuer_rotation_fails_before_kms_begin_or_mint() {
        for rotation in 0..4 {
            let harness = Harness::new(FakeBrokerMode::Ready, FakeStore::default(), false);
            match rotation {
                0 => harness.broker.github_app_id.store(19, Ordering::SeqCst),
                1 => harness
                    .broker
                    .rotated_app_client_id
                    .store(true, Ordering::SeqCst),
                2 => harness
                    .broker
                    .app_id_jwt_issuer
                    .store(true, Ordering::SeqCst),
                3 => harness
                    .broker
                    .rotated_jwt_issuer_value
                    .store(true, Ordering::SeqCst),
                _ => unreachable!("closed issuer-rotation matrix"),
            }

            assert_eq!(
                harness.run().await.unwrap_err(),
                GithubRuntimeAuthorityCoordinatorError::BrokerIdentityMismatch
            );
            assert_eq!(harness.store.state(), None);
            assert_eq!(harness.keys.wrap_calls.load(Ordering::SeqCst), 0);
            assert_eq!(harness.store.begin_calls(), 0);
            assert_eq!(harness.broker.calls.load(Ordering::SeqCst), 0);
        }
    }

    #[tokio::test]
    async fn successor_app_key_cannot_mint_historical_pinned_identity() {
        let harness = Harness::new(FakeBrokerMode::Ready, FakeStore::default(), false);
        *harness
            .broker
            .issuer_fingerprint
            .lock()
            .expect("issuer lock") = Sha256Digest::from_bytes([99; 32]);

        assert_eq!(
            harness.run().await.unwrap_err(),
            GithubRuntimeAuthorityCoordinatorError::BrokerIdentityMismatch
        );
        assert_eq!(harness.store.state(), None);
        assert_eq!(harness.keys.wrap_calls.load(Ordering::SeqCst), 0);
        assert_eq!(harness.store.begin_calls(), 0);
        assert_eq!(harness.broker.calls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn successor_configuration_cannot_mint_historical_pinned_identity() {
        let harness = Harness::new(FakeBrokerMode::Ready, FakeStore::default(), false);
        *harness
            .broker
            .configuration_fingerprint
            .lock()
            .expect("configuration lock") = Sha256Digest::from_bytes([98; 32]);

        assert_eq!(
            harness.run().await.unwrap_err(),
            GithubRuntimeAuthorityCoordinatorError::BrokerIdentityMismatch
        );
        assert_eq!(harness.store.state(), None);
        assert_eq!(harness.keys.wrap_calls.load(Ordering::SeqCst), 0);
        assert_eq!(harness.store.begin_calls(), 0);
        assert_eq!(harness.broker.calls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn ready_commit_uses_exact_wrapping_payload_context_and_binary_frame() {
        let harness = Harness::new(FakeBrokerMode::Ready, FakeStore::default(), false);

        let outcome = harness.run().await.expect("coordinate");
        let GithubRuntimeAuthorityCoordinationOutcome::Transitioned(receipt) = outcome else {
            panic!("expected durable transition");
        };
        assert_eq!(receipt.state(), GithubRuntimeAuthorityState::Ready);
        assert_eq!(harness.broker.calls.load(Ordering::SeqCst), 1);

        let contexts = harness
            .keys
            .wrapping_contexts
            .lock()
            .expect("context lock")
            .clone();
        assert_eq!(
            contexts,
            [harness
                .identity
                .wrapping_encryption_context()
                .expect("wrapping context")
                .canonical_authenticated_bytes()]
        );

        let snapshots = harness.store.snapshots();
        assert_eq!(snapshots.len(), 1);
        let snapshot = &snapshots[0];
        assert_eq!(
            snapshot.disposition,
            GithubRuntimeAuthorityCommitDisposition::Deliverable
        );
        let plaintext = harness.open_snapshot(snapshot).await;
        let mut expected = Vec::from(INSTALLATION_TOKEN_FRAME_DOMAIN);
        expected.extend_from_slice(
            &u32::try_from(TOKEN.len())
                .expect("token length")
                .to_be_bytes(),
        );
        expected.extend_from_slice(TOKEN.as_bytes());
        assert_eq!(plaintext.expose_secret(), expected);
        assert_eq!(
            snapshot.metadata.plaintext_digest(),
            Sha256Digest::from_bytes(Sha256::digest(expected).into())
        );
        let wrong_wrapping_context = KeyEncryptionContext::new(
            "tenant-b",
            KeyPurpose::new("control-plane/github-runtime-authority-wrapping:v3").expect("purpose"),
            "wrong-authority",
        )
        .expect("wrong context");
        assert!(
            harness
                .codec
                .open_with_contexts(
                    &wrong_wrapping_context,
                    &snapshot
                        .metadata
                        .encryption_context()
                        .expect("payload context"),
                    &snapshot.envelope(),
                )
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn known_unknown_and_expired_revoke_candidates_commit_only_for_revocation() {
        for mode in [
            FakeBrokerMode::RevokePendingKnown,
            FakeBrokerMode::RevokePendingUnknown,
            FakeBrokerMode::RevokePendingExpired,
        ] {
            let harness = Harness::new(mode, FakeStore::default(), false);
            let outcome = harness.run().await.expect("coordinate");
            let GithubRuntimeAuthorityCoordinationOutcome::Transitioned(receipt) = outcome else {
                panic!("expected durable transition");
            };
            assert_eq!(receipt.state(), GithubRuntimeAuthorityState::RevokePending);
            assert_eq!(
                harness.store.snapshots()[0].disposition,
                GithubRuntimeAuthorityCommitDisposition::RevokeOnly
            );
        }
    }

    #[tokio::test]
    async fn late_or_request_mismatched_ready_candidate_is_revoke_only() {
        for mode in [FakeBrokerMode::ReadyWrongRequest, FakeBrokerMode::ReadyLate] {
            let harness = Harness::new(mode, FakeStore::default(), false);
            let outcome = harness.run().await.expect("coordinate");
            let GithubRuntimeAuthorityCoordinationOutcome::Transitioned(receipt) = outcome else {
                panic!("expected durable transition");
            };
            assert_eq!(receipt.state(), GithubRuntimeAuthorityState::RevokePending);
            assert_eq!(
                harness.store.snapshots()[0].disposition,
                GithubRuntimeAuthorityCommitDisposition::RevokeOnly
            );
        }
    }

    #[tokio::test]
    async fn indeterminate_state_blocks_every_repeated_mint() {
        let harness = Harness::new(FakeBrokerMode::Indeterminate, FakeStore::default(), false);

        let first = harness.run().await.expect("first pass");
        let GithubRuntimeAuthorityCoordinationOutcome::Transitioned(receipt) = first else {
            panic!("expected indeterminate transition");
        };
        assert_eq!(receipt.state(), GithubRuntimeAuthorityState::Indeterminate);
        assert!(matches!(
            harness.run().await.expect("repeat"),
            GithubRuntimeAuthorityCoordinationOutcome::ClaimUnavailable
        ));
        assert_eq!(harness.broker.calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn rejected_outcomes_retry_only_the_transient_no_token_classes() {
        let transient = Harness::new(
            FakeBrokerMode::Rejected(CredentialErrorKind::RateLimited),
            FakeStore::default(),
            false,
        );
        let outcome = transient.run().await.expect("transient rejection");
        let GithubRuntimeAuthorityCoordinationOutcome::Transitioned(receipt) = outcome else {
            panic!("expected retry transition");
        };
        assert_eq!(
            receipt.state(),
            GithubRuntimeAuthorityState::MintRetryPending
        );

        let terminal = Harness::new(
            FakeBrokerMode::Rejected(CredentialErrorKind::InvalidRequest),
            FakeStore::default(),
            false,
        );
        let outcome = terminal.run().await.expect("terminal rejection");
        let GithubRuntimeAuthorityCoordinationOutcome::Transitioned(receipt) = outcome else {
            panic!("expected rejection transition");
        };
        assert_eq!(receipt.state(), GithubRuntimeAuthorityState::Rejected);
    }

    #[tokio::test]
    async fn ambiguous_commit_replays_under_custody_without_reminting() {
        let harness = Harness::new(
            FakeBrokerMode::Ready,
            FakeStore::with_commit_failure(),
            false,
        );

        let outcome = harness.run().await.expect("coordinate");
        let GithubRuntimeAuthorityCoordinationOutcome::Transitioned(receipt) = outcome else {
            panic!("expected supervised transition");
        };
        assert_eq!(receipt.state(), GithubRuntimeAuthorityState::Ready);
        let commits = harness.store.snapshots();
        assert_eq!(commits.len(), 2);
        assert!(commits[0] == commits[1]);
        assert_eq!(harness.broker.calls.load(Ordering::SeqCst), 1);
        assert!(
            !commits[0]
                .ciphertext
                .windows(TOKEN.len())
                .any(|window| window == TOKEN.as_bytes())
        );
        let plaintext = harness.open_snapshot(&commits[0]).await;
        assert!(plaintext.expose_secret().ends_with(TOKEN.as_bytes()));
    }

    #[tokio::test]
    async fn forward_process_clock_jump_cannot_discard_a_pending_commit() {
        let harness = Harness::new(
            FakeBrokerMode::Ready,
            FakeStore::with_commit_failure(),
            false,
        );
        let outcome = harness.run().await.expect("coordinate");
        let GithubRuntimeAuthorityCoordinationOutcome::Transitioned(receipt) = outcome else {
            panic!("expected supervised transition");
        };
        assert_eq!(receipt.state(), GithubRuntimeAuthorityState::Ready);
        let commits = harness.store.snapshots();
        assert_eq!(commits.len(), 2);
        assert!(commits[0] == commits[1]);
        assert_eq!(harness.broker.calls.load(Ordering::SeqCst), 1);
        assert_eq!(harness.supervisor.pending_count(), 0);
    }

    #[tokio::test]
    async fn post_provider_forward_clock_jump_cannot_drop_a_recovered_candidate() {
        let coordinator_time = Arc::new(AtomicI64::new(REQUESTED_AT));
        let coordinator_clock: Arc<dyn GithubRuntimeAuthorityCoordinatorClock> =
            Arc::new(IncrementingClock(coordinator_time.clone()));
        let harness = Harness::with_clock(
            FakeBrokerMode::Ready,
            FakeStore::default(),
            false,
            coordinator_clock,
        );
        harness
            .broker
            .jump_clock_after_mint(coordinator_time.clone());

        let outcome = harness.run().await.expect("coordinate");
        let GithubRuntimeAuthorityCoordinationOutcome::Transitioned(receipt) = outcome else {
            panic!("expected supervised transition");
        };
        assert_eq!(receipt.state(), GithubRuntimeAuthorityState::Ready);
        assert_eq!(coordinator_time.load(Ordering::SeqCst), i64::MAX - 1);
        assert_eq!(harness.store.snapshots().len(), 1);
        assert_eq!(harness.broker.calls.load(Ordering::SeqCst), 1);
        assert_eq!(harness.supervisor.pending_count(), 0);
    }

    #[tokio::test]
    async fn cancellation_at_first_commit_poll_drops_only_the_waiter() {
        let (store, gate) = FakeStore::with_gated_commit();
        let harness = Arc::new(Harness::new(FakeBrokerMode::Ready, store, false));
        let request = {
            let harness = harness.clone();
            tokio::spawn(async move { harness.run().await })
        };

        gate.wait_until_entered().await;
        assert_eq!(harness.supervisor.pending_count(), 1);
        assert_eq!(
            harness.store.state(),
            Some(GithubRuntimeAuthorityState::Minting)
        );
        assert_eq!(harness.broker.calls.load(Ordering::SeqCst), 1);
        request.abort();
        assert!(
            request
                .await
                .expect_err("request was cancelled")
                .is_cancelled()
        );

        gate.release();
        tokio::time::timeout(Duration::from_secs(1), async {
            harness.supervisor.wait_for_idle().await;
        })
        .await
        .expect("independent commit custody drained");
        assert_eq!(
            harness.store.state(),
            Some(GithubRuntimeAuthorityState::Ready)
        );
        assert_eq!(harness.store.snapshots().len(), 1);
        assert_eq!(harness.broker.calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn protected_watchdog_task_loss_retains_custody_and_never_false_drains() {
        let (store, gate) = FakeStore::with_gated_commit();
        let harness = Arc::new(Harness::new(FakeBrokerMode::Ready, store, false));
        let request = tokio::spawn({
            let harness = Arc::clone(&harness);
            async move { harness.run().await }
        });

        gate.wait_until_entered().await;
        assert!(
            harness.supervisor.abort_protected_task(),
            "protected watchdog exists"
        );
        assert_eq!(
            request.await.expect("coordinator task").unwrap_err(),
            GithubRuntimeAuthorityCoordinatorError::Repository
        );
        assert_eq!(harness.supervisor.pending_count(), 1);
        assert!(!harness.supervisor.drain(Duration::from_millis(5)).await);
        assert!(
            harness.supervisor.try_reserve().is_none(),
            "lost-task protected custody retains its bounded permit"
        );
        gate.wait_until_entered().await;
        let hammer_started = tokio_util::sync::CancellationToken::new();
        let stop_hammer = tokio_util::sync::CancellationToken::new();
        let hammer = tokio::spawn({
            let supervisor = Arc::clone(&harness.supervisor);
            let hammer_started = hammer_started.clone();
            let stop_hammer = stop_hammer.clone();
            async move {
                hammer_started.cancel();
                while !stop_hammer.is_cancelled() {
                    supervisor.redrive_retained();
                    tokio::task::yield_now().await;
                }
            }
        });
        hammer_started.cancelled().await;
        gate.release();
        assert!(harness.supervisor.drain(Duration::from_secs(1)).await);
        stop_hammer.cancel();
        hammer.await.expect("protected redrive hammer");
        assert_eq!(harness.supervisor.pending_count(), 0);
        assert_eq!(
            harness.store.state(),
            Some(GithubRuntimeAuthorityState::Ready)
        );
        assert_eq!(harness.broker.calls.load(Ordering::SeqCst), 1);
        assert!(harness.supervisor.try_reserve().is_some());
        for _ in 0..32 {
            harness.supervisor.redrive_retained();
            tokio::task::yield_now().await;
        }
        assert_eq!(harness.store.snapshots().len(), 1);
    }

    #[tokio::test]
    async fn removed_protected_custody_rejects_its_exact_stale_driver() {
        let (store, gate) = FakeStore::with_gated_commit();
        let harness = Arc::new(Harness::new(FakeBrokerMode::Ready, store, false));
        let request = tokio::spawn({
            let harness = Arc::clone(&harness);
            async move { harness.run().await }
        });

        gate.wait_until_entered().await;
        let stale_custody = harness
            .supervisor
            .protected_custody
            .retained()
            .first()
            .cloned()
            .expect("protected custody retained before confirmation");
        gate.release();
        let outcome = request
            .await
            .expect("coordinator task")
            .expect("protected commit");
        assert!(matches!(
            outcome,
            GithubRuntimeAuthorityCoordinationOutcome::Transitioned(_)
        ));
        tokio::time::timeout(Duration::from_secs(1), async {
            while !stale_custody.is_removed() || stale_custody.is_driver_active() {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("protected custody removed with no active driver");

        let confirmed_calls = harness.store.snapshots().len();
        assert!(
            !harness
                .supervisor
                .start_protected_driver(&stale_custody, None)
        );
        tokio::task::yield_now().await;
        assert_eq!(harness.store.snapshots().len(), confirmed_calls);
        assert_eq!(harness.broker.calls.load(Ordering::SeqCst), 1);
        assert!(!harness.supervisor.drain(Duration::from_millis(5)).await);

        drop(stale_custody);
        assert!(harness.supervisor.drain(Duration::from_secs(1)).await);
        assert!(harness.supervisor.try_reserve().is_some());
    }

    #[tokio::test]
    async fn unprotected_candidate_releases_custody_at_its_authenticated_horizon() {
        let (repository, claim) = FakeStore::with_minting_claim();
        let repository = Arc::new(repository);
        let repository_port: Arc<dyn GithubRuntimeAuthorityRepository> = repository.clone();
        let supervisor = Arc::new(
            GithubRuntimeAuthorityCommitSupervisor::new(
                repository_port,
                Handle::current(),
                1,
                Duration::from_millis(1),
            )
            .expect("supervisor"),
        );
        let reservation = supervisor.try_reserve().expect("initial capacity");
        supervisor.retain_unprotected(
            reservation,
            UnprotectedGithubRuntimeAuthorityCandidate {
                claim: Box::new(claim),
                _candidate: FakeBroker::candidate(),
                _prepared: None,
            },
        );

        assert!(
            !supervisor.drain(Duration::from_millis(5)).await,
            "custody must remain held before the authenticated horizon"
        );
        repository.authenticate_unprotected_erasure();
        assert!(supervisor.drain(Duration::from_secs(1)).await);
        assert_eq!(supervisor.pending_count(), 0);
        assert!(
            supervisor.try_reserve().is_some(),
            "the bounded permit must be reusable after authenticated erasure"
        );
    }

    #[tokio::test]
    async fn unprotected_watchdog_task_loss_retains_custody_and_never_false_drains() {
        let (repository, claim, gate) = FakeStore::with_gated_unprotected_erasure();
        let repository = Arc::new(repository);
        let repository_port: Arc<dyn GithubRuntimeAuthorityRepository> = repository.clone();
        let supervisor = Arc::new(
            GithubRuntimeAuthorityCommitSupervisor::new(
                repository_port,
                Handle::current(),
                1,
                Duration::from_millis(1),
            )
            .expect("supervisor"),
        );
        let reservation = supervisor.try_reserve().expect("initial capacity");
        supervisor.retain_unprotected(
            reservation,
            UnprotectedGithubRuntimeAuthorityCandidate {
                claim: Box::new(claim),
                _candidate: FakeBroker::candidate(),
                _prepared: None,
            },
        );

        gate.wait_until_entered().await;
        assert_eq!(repository.unprotected_erasure_calls(), 1);
        assert!(
            supervisor.abort_unprotected_task(),
            "unprotected watchdog exists"
        );
        assert_eq!(supervisor.pending_count(), 1);
        assert!(!supervisor.drain(Duration::from_millis(5)).await);
        assert!(
            supervisor.try_reserve().is_none(),
            "lost-task unprotected custody retains its bounded permit"
        );
        gate.wait_until_entered().await;
        assert_eq!(repository.unprotected_erasure_calls(), 2);
        repository.authenticate_unprotected_erasure();
        let hammer_started = tokio_util::sync::CancellationToken::new();
        let stop_hammer = tokio_util::sync::CancellationToken::new();
        let hammer = tokio::spawn({
            let supervisor = Arc::clone(&supervisor);
            let hammer_started = hammer_started.clone();
            let stop_hammer = stop_hammer.clone();
            async move {
                hammer_started.cancel();
                while !stop_hammer.is_cancelled() {
                    supervisor.redrive_retained();
                    tokio::task::yield_now().await;
                }
            }
        });
        hammer_started.cancelled().await;
        gate.release();
        assert!(supervisor.drain(Duration::from_secs(1)).await);
        stop_hammer.cancel();
        hammer.await.expect("unprotected redrive hammer");
        assert_eq!(supervisor.pending_count(), 0);
        assert!(supervisor.try_reserve().is_some());
        for _ in 0..32 {
            supervisor.redrive_retained();
            tokio::task::yield_now().await;
        }
        assert_eq!(repository.unprotected_erasure_calls(), 2);
    }

    #[tokio::test]
    async fn removed_unprotected_custody_rejects_its_exact_stale_driver() {
        let (repository, claim, gate) = FakeStore::with_gated_unprotected_erasure();
        let repository = Arc::new(repository);
        let repository_port: Arc<dyn GithubRuntimeAuthorityRepository> = repository.clone();
        let supervisor = Arc::new(
            GithubRuntimeAuthorityCommitSupervisor::new(
                repository_port,
                Handle::current(),
                1,
                Duration::from_millis(1),
            )
            .expect("supervisor"),
        );
        let reservation = supervisor.try_reserve().expect("initial capacity");
        supervisor.retain_unprotected(
            reservation,
            UnprotectedGithubRuntimeAuthorityCandidate {
                claim: Box::new(claim),
                _candidate: FakeBroker::candidate(),
                _prepared: None,
            },
        );

        gate.wait_until_entered().await;
        let stale_custody = supervisor
            .unprotected_custody
            .retained()
            .first()
            .cloned()
            .expect("unprotected custody retained before erasure confirmation");
        repository.authenticate_unprotected_erasure();
        gate.release();
        tokio::time::timeout(Duration::from_secs(1), async {
            while !stale_custody.is_removed() || stale_custody.is_driver_active() {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("unprotected custody removed with no active driver");

        let confirmed_calls = repository.unprotected_erasure_calls();
        assert!(!supervisor.start_unprotected_driver(&stale_custody));
        tokio::task::yield_now().await;
        assert_eq!(repository.unprotected_erasure_calls(), confirmed_calls);
        assert!(!supervisor.drain(Duration::from_millis(5)).await);

        drop(stale_custody);
        assert!(supervisor.drain(Duration::from_secs(1)).await);
        assert!(supervisor.try_reserve().is_some());
    }

    #[tokio::test]
    async fn supervisor_limits_are_closed_and_bounded() {
        let repository: Arc<dyn GithubRuntimeAuthorityRepository> = Arc::new(FakeStore::default());
        for (capacity, retry_interval, expected) in [
            (
                0,
                Duration::from_millis(1),
                GithubRuntimeAuthorityCommitSupervisorError::InvalidCapacity,
            ),
            (
                MAX_SUPERVISED_PENDING_COMMITS + 1,
                Duration::from_millis(1),
                GithubRuntimeAuthorityCommitSupervisorError::InvalidCapacity,
            ),
            (
                1,
                Duration::ZERO,
                GithubRuntimeAuthorityCommitSupervisorError::InvalidRetryInterval,
            ),
            (
                1,
                MAX_PENDING_COMMIT_RETRY_DELAY + Duration::from_millis(1),
                GithubRuntimeAuthorityCommitSupervisorError::InvalidRetryInterval,
            ),
        ] {
            assert_eq!(
                GithubRuntimeAuthorityCommitSupervisor::new(
                    repository.clone(),
                    Handle::current(),
                    capacity,
                    retry_interval,
                )
                .unwrap_err(),
                expected
            );
        }
    }

    #[tokio::test]
    async fn ambiguous_begin_and_already_started_never_call_the_provider() {
        let ambiguous = Harness::new(
            FakeBrokerMode::Ready,
            FakeStore::with_ambiguous_begin(),
            false,
        );
        assert_eq!(
            ambiguous.run().await.unwrap_err(),
            GithubRuntimeAuthorityCoordinatorError::Repository
        );
        assert!(matches!(
            ambiguous.run().await.expect("repeat after ambiguity"),
            GithubRuntimeAuthorityCoordinationOutcome::ClaimUnavailable
        ));
        assert_eq!(ambiguous.broker.calls.load(Ordering::SeqCst), 0);

        let already = Harness::new(
            FakeBrokerMode::Ready,
            FakeStore::with_already_started(),
            false,
        );
        assert!(matches!(
            already.run().await.expect("already started"),
            GithubRuntimeAuthorityCoordinationOutcome::AlreadyStarted(_)
        ));
        assert_eq!(already.broker.calls.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn resolution_and_all_diagnostics_are_exact_and_redacted() {
        let identity = identity();
        let mut wrong_request = credential_request(&identity);
        let wrong_identity = GithubRuntimeAuthorityIdentity::new(
            identity.tenant().clone(),
            identity.key().attempt_id(),
            identity.key().fencing_token(),
            identity.lease_id(),
            identity.lease_issued_at(),
            identity.lease_expires_at(),
            identity.run_id(),
            identity.job_id(),
            identity.runner_id(),
            identity.runner_session_id(),
            identity.runner_session_epoch(),
            identity.runner_generation(),
            identity.runner_slot(),
            identity.job_ir_version(),
            identity.job_ir_size_bytes(),
            identity.job_ir_digest(),
            identity.repository_id(),
            identity.provider_connection_id(),
            identity.provider_installation_id(),
            identity.github_app_id(),
            identity.github_app_client_id().clone(),
            identity.github_app_jwt_issuer_kind(),
            GithubRepositoryId::new(99).expect("other repository"),
            GithubRepositoryName::new("automata-ci/other").expect("other name"),
            identity.namespace().clone(),
            identity.policy_digest(),
            identity.app_key_spki_sha256(),
            identity.configuration_fingerprint(),
            identity.preparation_selection_tail(),
            identity.activation_selection_tail(),
            identity.materialization_selection_tail(),
            identity.requested_at(),
            identity.request_deadline(),
        )
        .expect("wrong identity");
        assert_eq!(
            ResolvedGithubRuntimeAuthorityRequest::new(wrong_identity, wrong_request.clone()),
            Err(GithubRuntimeAuthorityResolutionValueError)
        );

        wrong_request = RepositoryCredentialRequest::new(
            github_runtime_authority_workload_identity(&identity),
            RepositoryScope::new(
                ScmProviderId::new("gitlab").expect("other provider"),
                ScmRepositoryId::new("automata-ci/automata").expect("repository"),
                ProviderResourceId::new("12").expect("ID"),
            ),
            wrong_request.permissions().clone(),
            wrong_request.minimum_validity(),
        );
        assert_eq!(
            ResolvedGithubRuntimeAuthorityRequest::new(identity, wrong_request),
            Err(GithubRuntimeAuthorityResolutionValueError)
        );

        for rendered in [
            format!("{:?}", FakeBroker::new(FakeBrokerMode::Ready)),
            format!("{:?}", FakeKeyProvider::new(false)),
            format!("{:?}", GithubRuntimeAuthorityCoordinatorError::Repository),
            format!("{:?}", GithubRuntimeAuthorityResolutionError::Unavailable),
            format!(
                "{:?}",
                GithubRuntimeAuthorityCorruptionKind::EnvelopeAuthenticationFailed
            ),
        ] {
            assert!(!rendered.contains(TOKEN));
        }
    }
}
