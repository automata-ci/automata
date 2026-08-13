//! Production lifecycle core for durable GitHub server-service credentials.

use std::{collections::BTreeMap, fmt, sync::Arc, time::Duration};

use async_trait::async_trait;
use automata_ci_auth::{secret::SecretString, time::UnixTimestamp};
use automata_ci_core::UnixMillis;
use automata_ci_credential::{
    CredentialError, CredentialErrorKind, MinimumValidity, PermissionLevel, PermissionName,
    PermissionSet, ProviderResourceId, RepositoryCredentialRequest, RepositoryScope,
    WorkloadIdentity,
};
use automata_ci_key_management::{
    EnvelopeCodec, EnvelopeError, KeyEncryptionError, PreparedEnvelope, SecretBytes,
};
use automata_ci_scm::{RepositoryId as ScmRepositoryId, ScmProviderId};
use automata_ci_store::{
    AcquireGithubServerServiceHandoff, BeginGithubServerServiceMint,
    BeginGithubServerServiceMintOutcome, ClaimNextGithubServerServiceMaintenance,
    ClaimedGithubServerServiceMint, ClaimedGithubServerServiceRevocation,
    FinishGithubServerServiceMint, FinishGithubServerServiceRevocation,
    GithubServerServiceAuthorityIdentity, GithubServerServiceAuthorityRepository,
    GithubServerServiceAuthoritySelector, GithubServerServiceConsumerClaim,
    GithubServerServiceCredentialHandoff, GithubServerServiceFailureKind,
    GithubServerServiceHandoffId, GithubServerServiceIssuanceKey,
    GithubServerServiceIssuanceReceipt, GithubServerServiceMaintenanceOutcome,
    GithubServerServiceMintStart, GithubServerServiceScope, GithubServerServiceStoreError,
    GithubServerServiceWorkerId, MAX_GITHUB_SERVICE_MINT_RETRY_MILLIS,
    MAX_GITHUB_SERVICE_REVOKE_CLAIM_MILLIS, MAX_GITHUB_SERVICE_REVOKE_RETRY_MILLIS,
    MIN_GITHUB_SERVICE_READY_USE_MILLIS, ProtectedGithubServerServiceCredential,
    QuarantineGithubServerServiceCredential, ReleaseGithubServerServiceHandoff, Sha256Digest,
    TenantScope,
};
use sha2::{Digest as _, Sha256};
use thiserror::Error;

use crate::{
    GithubAppCredentialBroker, GithubInstallationTokenIndeterminateReason,
    GithubInstallationTokenMintOutcome, GithubInstallationTokenRevocationCandidate,
    GithubInstallationTokenRevocationFailureKind, GithubInstallationTokenRevocationOutcome,
    config::whole_milliseconds,
};

const SERVER_SERVICE_TOKEN_FRAME_DOMAIN: &[u8] =
    b"automata-ci/github-server-service-installation-token/v1\0";
const DEFAULT_MINT_RETRY_MILLIS: i64 = 1_000;
const DEFAULT_REVOKE_RETRY_MILLIS: i64 = 1_000;

/// Maximum exact installation brokers admitted by one product router.
pub const MAX_GITHUB_SERVER_SERVICE_INSTALLATION_BROKERS: usize = 256;

/// Canonical non-secret workload subject for one immutable service authority.
///
/// # Panics
///
/// Panics only if a fixed ASCII prefix plus one SHA-256 digest no longer fits
/// the provider-neutral workload identity bound.
#[must_use]
pub fn github_server_service_workload_identity(
    identity: &GithubServerServiceAuthorityIdentity,
) -> WorkloadIdentity {
    WorkloadIdentity::new(format!(
        "automata-ci/github-server-service/v1/{}",
        identity.identity_digest()
    ))
    .expect("a fixed prefix and SHA-256 digest fit the workload identity boundary")
}

/// Builds the sole provider-neutral request authorized by an immutable scope.
///
/// The request binds the complete identity digest, numeric and named
/// repository, exact fixed permission map, and the Store's minimum replacement
/// horizon. It contains no public-repository or anonymous-source mode.
///
/// # Errors
///
/// Returns a sanitized invariant error only if a validated durable identity
/// cannot be represented by the provider-neutral model.
pub fn github_server_service_credential_request(
    identity: &GithubServerServiceAuthorityIdentity,
) -> Result<RepositoryCredentialRequest, GithubServerServiceResolutionValueError> {
    let permission = match identity.scope() {
        GithubServerServiceScope::ChecksWrite => ("checks", PermissionLevel::Write),
        GithubServerServiceScope::PrivateRepositorySourceRead => {
            ("contents", PermissionLevel::Read)
        }
    };
    let permissions = PermissionSet::new([(
        PermissionName::new(permission.0).map_err(|_| GithubServerServiceResolutionValueError)?,
        permission.1,
    )])
    .map_err(|_| GithubServerServiceResolutionValueError)?;
    let repository = RepositoryScope::new(
        ScmProviderId::new("github").map_err(|_| GithubServerServiceResolutionValueError)?,
        ScmRepositoryId::new(identity.github_repository_name().as_str())
            .map_err(|_| GithubServerServiceResolutionValueError)?,
        ProviderResourceId::new(identity.github_repository_id().get().to_string())
            .map_err(|_| GithubServerServiceResolutionValueError)?,
    );
    let minimum_validity = MinimumValidity::from_seconds(
        u64::try_from(MIN_GITHUB_SERVICE_READY_USE_MILLIS / 1_000)
            .map_err(|_| GithubServerServiceResolutionValueError)?,
    )
    .map_err(|_| GithubServerServiceResolutionValueError)?;
    Ok(RepositoryCredentialRequest::new(
        github_server_service_workload_identity(identity),
        repository,
        permissions,
        minimum_validity,
    ))
}

/// One exact request returned after authoritative configuration revalidation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResolvedGithubServerServiceCredentialRequest {
    identity: GithubServerServiceAuthorityIdentity,
    request: RepositoryCredentialRequest,
}

impl ResolvedGithubServerServiceCredentialRequest {
    /// Cross-binds a resolver result to every canonical request field.
    ///
    /// # Errors
    ///
    /// Rejects any changed identity, repository, scope, permissions, workload,
    /// or minimum validity. There is no default installation or token fallback.
    pub fn new(
        identity: GithubServerServiceAuthorityIdentity,
        request: RepositoryCredentialRequest,
    ) -> Result<Self, GithubServerServiceResolutionValueError> {
        if request != github_server_service_credential_request(&identity)? {
            return Err(GithubServerServiceResolutionValueError);
        }
        Ok(Self { identity, request })
    }

    /// Returns the complete immutable identity revalidated by the resolver.
    #[must_use]
    pub const fn identity(&self) -> &GithubServerServiceAuthorityIdentity {
        &self.identity
    }

    /// Returns the exact provider-neutral mint request.
    #[must_use]
    pub const fn request(&self) -> &RepositoryCredentialRequest {
        &self.request
    }
}

/// A resolved request was not the canonical request for its immutable scope.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
#[error("GitHub server-service credential resolution is inconsistent")]
pub struct GithubServerServiceResolutionValueError;

/// Sanitized authoritative request-resolution failure.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum GithubServerServiceResolutionError {
    /// Exact configuration is temporarily unavailable.
    #[error("GitHub server-service credential resolution is unavailable")]
    Unavailable,
    /// Authoritative configuration is internally inconsistent.
    #[error("GitHub server-service credential resolution is inconsistent")]
    Inconsistent,
}

/// Revalidates one immutable descriptor against current product configuration.
#[async_trait]
pub trait GithubServerServiceCredentialRequestResolver: Send + Sync {
    /// Resolves the sole request still authorized for `identity`.
    async fn resolve_github_server_service_credential_request(
        &self,
        identity: &GithubServerServiceAuthorityIdentity,
    ) -> Result<
        Option<ResolvedGithubServerServiceCredentialRequest>,
        GithubServerServiceResolutionError,
    >;
}

/// Exact bounded provider boundary for mint and revocation.
///
/// A composite implementation may route by the immutable installation ID. It
/// must never select a default broker when the exact installation is absent.
#[async_trait]
pub trait GithubServerServiceCredentialBroker: fmt::Debug + Send + Sync {
    /// Returns the hard request bound for one exact installation, or `None`.
    fn maximum_request_duration(&self, installation_id: u64) -> Option<Duration>;

    /// Performs exactly one installation-token mint attempt.
    async fn mint_once(
        &self,
        installation_id: u64,
        request: &RepositoryCredentialRequest,
    ) -> GithubInstallationTokenMintOutcome;

    /// Performs exactly one revocation attempt while retaining caller custody.
    async fn revoke(
        &self,
        installation_id: u64,
        candidate: &GithubInstallationTokenRevocationCandidate,
    ) -> GithubInstallationTokenRevocationOutcome;
}

#[async_trait]
impl GithubServerServiceCredentialBroker for GithubAppCredentialBroker {
    fn maximum_request_duration(&self, installation_id: u64) -> Option<Duration> {
        (self.mint_installation_id() == installation_id).then(|| self.mint_request_timeout())
    }

    async fn mint_once(
        &self,
        installation_id: u64,
        request: &RepositoryCredentialRequest,
    ) -> GithubInstallationTokenMintOutcome {
        if self.mint_installation_id() != installation_id {
            return GithubInstallationTokenMintOutcome::Rejected(CredentialError::new(
                CredentialErrorKind::InvalidRequest,
            ));
        }
        GithubAppCredentialBroker::mint_once(self, request).await
    }

    async fn revoke(
        &self,
        installation_id: u64,
        candidate: &GithubInstallationTokenRevocationCandidate,
    ) -> GithubInstallationTokenRevocationOutcome {
        if self.mint_installation_id() != installation_id {
            return GithubInstallationTokenRevocationOutcome::Unconfirmed(
                crate::GithubInstallationTokenRevocationFailure::new(
                    GithubInstallationTokenRevocationFailureKind::InvalidResponse,
                ),
            );
        }
        GithubAppCredentialBroker::revoke(self, candidate).await
    }
}

/// Invalid exact installation-router configuration.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum GithubServerServiceInstallationRouterError {
    /// At least one exact installation broker is required.
    #[error("GitHub server-service installation router is empty")]
    Empty,
    /// The router exceeds the product's bounded repository count.
    #[error("GitHub server-service installation router is too large")]
    TooMany,
    /// A zero installation identity is never valid.
    #[error("GitHub server-service installation router contains an invalid ID")]
    InvalidInstallationId,
    /// Two entries selected the same installation identity.
    #[error("GitHub server-service installation router contains a duplicate ID")]
    DuplicateInstallationId,
    /// An entry's broker does not serve its declared exact installation.
    #[error("GitHub server-service installation router entry mismatched its broker")]
    BrokerMismatch,
}

/// Bounded no-default broker router for one App's exact installations.
pub struct GithubServerServiceInstallationRouter {
    brokers: BTreeMap<u64, Arc<dyn GithubServerServiceCredentialBroker>>,
}

impl GithubServerServiceInstallationRouter {
    /// Builds a bounded exact router.
    ///
    /// Each tuple explicitly declares the installation selected by its broker.
    /// Nested routers are permitted only when they also report that exact ID.
    ///
    /// # Errors
    ///
    /// Rejects empty, oversized, zero, duplicate, or broker-mismatched maps.
    pub fn new(
        entries: impl IntoIterator<Item = (u64, Arc<dyn GithubServerServiceCredentialBroker>)>,
    ) -> Result<Self, GithubServerServiceInstallationRouterError> {
        let mut brokers = BTreeMap::new();
        for (installation_id, broker) in entries {
            if installation_id == 0 {
                return Err(GithubServerServiceInstallationRouterError::InvalidInstallationId);
            }
            if brokers.len() >= MAX_GITHUB_SERVER_SERVICE_INSTALLATION_BROKERS {
                return Err(GithubServerServiceInstallationRouterError::TooMany);
            }
            if broker
                .maximum_request_duration(installation_id)
                .and_then(exact_request_millis)
                .is_none()
            {
                return Err(GithubServerServiceInstallationRouterError::BrokerMismatch);
            }
            if brokers.insert(installation_id, broker).is_some() {
                return Err(GithubServerServiceInstallationRouterError::DuplicateInstallationId);
            }
        }
        if brokers.is_empty() {
            return Err(GithubServerServiceInstallationRouterError::Empty);
        }
        Ok(Self { brokers })
    }

    /// Returns the number of exact installation routes.
    #[must_use]
    pub fn len(&self) -> usize {
        self.brokers.len()
    }

    /// Reports whether the router has no routes.
    ///
    /// Values returned by [`Self::new`] are always non-empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.brokers.is_empty()
    }
}

impl fmt::Debug for GithubServerServiceInstallationRouter {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GithubServerServiceInstallationRouter")
            .field("installation_ids", &self.brokers.keys().collect::<Vec<_>>())
            .field("brokers", &"[EXACT INSTALLATION BROKERS]")
            .finish()
    }
}

#[async_trait]
impl GithubServerServiceCredentialBroker for GithubServerServiceInstallationRouter {
    fn maximum_request_duration(&self, installation_id: u64) -> Option<Duration> {
        self.brokers
            .get(&installation_id)
            .and_then(|broker| broker.maximum_request_duration(installation_id))
    }

    async fn mint_once(
        &self,
        installation_id: u64,
        request: &RepositoryCredentialRequest,
    ) -> GithubInstallationTokenMintOutcome {
        let Some(broker) = self.brokers.get(&installation_id) else {
            return GithubInstallationTokenMintOutcome::Rejected(CredentialError::new(
                CredentialErrorKind::InvalidRequest,
            ));
        };
        broker.mint_once(installation_id, request).await
    }

    async fn revoke(
        &self,
        installation_id: u64,
        candidate: &GithubInstallationTokenRevocationCandidate,
    ) -> GithubInstallationTokenRevocationOutcome {
        let Some(broker) = self.brokers.get(&installation_id) else {
            return GithubInstallationTokenRevocationOutcome::Unconfirmed(
                crate::GithubInstallationTokenRevocationFailure::new(
                    GithubInstallationTokenRevocationFailureKind::InvalidResponse,
                ),
            );
        };
        broker.revoke(installation_id, candidate).await
    }
}

/// Trusted wall-clock source used for non-regressing lifecycle observations.
pub trait GithubServerServiceCoordinatorClock: fmt::Debug + Send + Sync {
    /// Returns whole milliseconds since the Unix epoch.
    fn now(&self) -> UnixMillis;
}

/// Operating-system clock for a production server-service coordinator.
#[derive(Clone, Copy, Debug, Default)]
pub struct SystemGithubServerServiceCoordinatorClock;

impl GithubServerServiceCoordinatorClock for SystemGithubServerServiceCoordinatorClock {
    fn now(&self) -> UnixMillis {
        let milliseconds = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |duration| duration.as_millis());
        UnixMillis::new(i64::try_from(milliseconds).unwrap_or(i64::MAX))
    }
}

/// Value-free evidence returned by the irreversible Store mint cutoff.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GithubServerServiceMintCutoffEvidence {
    receipt: GithubServerServiceIssuanceReceipt,
    claim_expires_at: UnixMillis,
    request_deadline: UnixMillis,
    started_at: UnixMillis,
}

impl GithubServerServiceMintCutoffEvidence {
    fn from_store(value: &GithubServerServiceMintStart) -> Self {
        Self {
            receipt: value.receipt(),
            claim_expires_at: value.claim_expires_at(),
            request_deadline: value.request_deadline(),
            started_at: value.started_at(),
        }
    }

    /// Returns the durable minting receipt.
    #[must_use]
    pub const fn receipt(&self) -> GithubServerServiceIssuanceReceipt {
        self.receipt
    }
    /// Returns the exclusive claim deadline.
    #[must_use]
    pub const fn claim_expires_at(&self) -> UnixMillis {
        self.claim_expires_at
    }
    /// Returns the exclusive provider deadline.
    #[must_use]
    pub const fn request_deadline(&self) -> UnixMillis {
        self.request_deadline
    }
    /// Returns the durable irreversible cutoff time.
    #[must_use]
    pub const fn started_at(&self) -> UnixMillis {
        self.started_at
    }
}

/// Exact result of attempting the irreversible Store mint cutoff.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum GithubServerServiceMintCutoffOutcome {
    /// This worker committed the cutoff and alone may poll one provider future.
    Started(GithubServerServiceMintCutoffEvidence),
    /// The cutoff already existed; provider I/O must never be repeated.
    AlreadyStarted(GithubServerServiceMintCutoffEvidence),
}

/// Narrow durable port consumed by the credential lifecycle core.
///
/// Every implementation must preserve the exact Store server-service
/// credential semantics. The
/// blanket implementation delegates directly to
/// [`GithubServerServiceAuthorityRepository`]; the narrower port also permits
/// deterministic provider-boundary tests without constructing Store-private
/// rehydration values.
#[async_trait]
pub trait GithubServerServiceCredentialRepository: Send + Sync {
    /// Claims or reduces at most one due tenant maintenance row.
    async fn claim_next_github_server_service_maintenance(
        &self,
        request: ClaimNextGithubServerServiceMaintenance,
    ) -> Result<Option<GithubServerServiceMaintenanceOutcome>, GithubServerServiceStoreError>;
    /// Persists the irreversible provider-mint cutoff.
    async fn begin_github_server_service_mint(
        &self,
        request: BeginGithubServerServiceMint,
    ) -> Result<GithubServerServiceMintCutoffOutcome, GithubServerServiceStoreError>;
    /// Commits one closed provider mint result.
    async fn finish_github_server_service_mint(
        &self,
        request: &FinishGithubServerServiceMint,
    ) -> Result<GithubServerServiceIssuanceReceipt, GithubServerServiceStoreError>;
    /// Commits one closed provider revocation result.
    async fn finish_github_server_service_revocation(
        &self,
        request: FinishGithubServerServiceRevocation,
    ) -> Result<GithubServerServiceIssuanceReceipt, GithubServerServiceStoreError>;
    /// Acquires one exact action-bound protected handoff.
    async fn acquire_github_server_service_handoff(
        &self,
        request: AcquireGithubServerServiceHandoff,
    ) -> Result<GithubServerServiceCredentialHandoff, GithubServerServiceStoreError>;
    /// Exactly releases one handoff.
    async fn release_github_server_service_handoff(
        &self,
        request: ReleaseGithubServerServiceHandoff,
    ) -> Result<(), GithubServerServiceStoreError>;
    /// Quarantines corrupt current custody by exact AAD evidence.
    async fn quarantine_github_server_service_credential(
        &self,
        request: QuarantineGithubServerServiceCredential,
    ) -> Result<GithubServerServiceIssuanceReceipt, GithubServerServiceStoreError>;
}

#[async_trait]
impl<T> GithubServerServiceCredentialRepository for T
where
    T: GithubServerServiceAuthorityRepository + Send + Sync + ?Sized,
{
    async fn claim_next_github_server_service_maintenance(
        &self,
        request: ClaimNextGithubServerServiceMaintenance,
    ) -> Result<Option<GithubServerServiceMaintenanceOutcome>, GithubServerServiceStoreError> {
        GithubServerServiceAuthorityRepository::claim_next_github_server_service_maintenance(
            self, request,
        )
        .await
    }

    async fn begin_github_server_service_mint(
        &self,
        request: BeginGithubServerServiceMint,
    ) -> Result<GithubServerServiceMintCutoffOutcome, GithubServerServiceStoreError> {
        let outcome =
            GithubServerServiceAuthorityRepository::begin_github_server_service_mint(self, request)
                .await?;
        Ok(match outcome {
            BeginGithubServerServiceMintOutcome::Started(value) => {
                GithubServerServiceMintCutoffOutcome::Started(
                    GithubServerServiceMintCutoffEvidence::from_store(&value),
                )
            }
            BeginGithubServerServiceMintOutcome::AlreadyStarted(value) => {
                GithubServerServiceMintCutoffOutcome::AlreadyStarted(
                    GithubServerServiceMintCutoffEvidence::from_store(&value),
                )
            }
        })
    }

    async fn finish_github_server_service_mint(
        &self,
        request: &FinishGithubServerServiceMint,
    ) -> Result<GithubServerServiceIssuanceReceipt, GithubServerServiceStoreError> {
        GithubServerServiceAuthorityRepository::finish_github_server_service_mint(self, request)
            .await
    }

    async fn finish_github_server_service_revocation(
        &self,
        request: FinishGithubServerServiceRevocation,
    ) -> Result<GithubServerServiceIssuanceReceipt, GithubServerServiceStoreError> {
        GithubServerServiceAuthorityRepository::finish_github_server_service_revocation(
            self, request,
        )
        .await
    }

    async fn acquire_github_server_service_handoff(
        &self,
        request: AcquireGithubServerServiceHandoff,
    ) -> Result<GithubServerServiceCredentialHandoff, GithubServerServiceStoreError> {
        GithubServerServiceAuthorityRepository::acquire_github_server_service_handoff(self, request)
            .await
    }

    async fn release_github_server_service_handoff(
        &self,
        request: ReleaseGithubServerServiceHandoff,
    ) -> Result<(), GithubServerServiceStoreError> {
        GithubServerServiceAuthorityRepository::release_github_server_service_handoff(self, request)
            .await
    }

    async fn quarantine_github_server_service_credential(
        &self,
        request: QuarantineGithubServerServiceCredential,
    ) -> Result<GithubServerServiceIssuanceReceipt, GithubServerServiceStoreError> {
        GithubServerServiceAuthorityRepository::quarantine_github_server_service_credential(
            self, request,
        )
        .await
    }
}

/// Sanitized coordinator failure before a closed durable result is available.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum GithubServerServiceCoordinatorError {
    /// Durable authority access failed.
    #[error("GitHub server-service credential repository is unavailable")]
    Repository,
    /// Exact request resolution failed.
    #[error("GitHub server-service credential resolution failed")]
    Resolution,
    /// No current product configuration authorizes the immutable descriptor.
    #[error("GitHub server-service credential is not authorized")]
    Unauthorized,
    /// Resolver evidence did not equal the claimed immutable descriptor.
    #[error("GitHub server-service credential resolution identity mismatched")]
    ResolutionIdentityMismatch,
    /// No exact broker serves the descriptor's installation.
    #[error("GitHub server-service credential broker identity mismatched")]
    BrokerIdentityMismatch,
    /// Key wrapping could not be prepared before the mint cutoff.
    #[error("GitHub server-service credential envelope preparation failed")]
    EnvelopePreparation,
    /// A trusted timestamp or protected result was internally inconsistent.
    #[error("GitHub server-service credential lifecycle is inconsistent")]
    Inconsistent,
}

/// A closed mint result retained for byte-identical durable replay.
#[must_use = "a closed protected mint result must be committed or retained"]
pub struct PendingGithubServerServiceMintCommit {
    request: FinishGithubServerServiceMint,
}

impl PendingGithubServerServiceMintCommit {
    /// Replays the exact closed result without another provider mint.
    ///
    /// # Errors
    ///
    /// Returns the Store's sanitized error when the exact commit is not
    /// confirmed. `self` remains available for another byte-identical replay.
    pub async fn replay(
        &self,
        repository: &dyn GithubServerServiceCredentialRepository,
    ) -> Result<GithubServerServiceIssuanceReceipt, GithubServerServiceStoreError> {
        repository
            .finish_github_server_service_mint(&self.request)
            .await
    }

    /// Returns the immutable issuance key without exposing protected bytes.
    #[must_use]
    pub fn key(&self) -> GithubServerServiceIssuanceKey {
        finish_mint_claim(&self.request).key()
    }
}

impl fmt::Debug for PendingGithubServerServiceMintCommit {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PendingGithubServerServiceMintCommit")
            .field("key", &self.key())
            .field("result", &finish_mint_disposition(&self.request))
            .field("protected", &"[PROTECTED]")
            .finish()
    }
}

/// A closed revocation result retained for exact durable replay.
#[must_use = "a closed revocation result must be committed or retained"]
pub struct PendingGithubServerServiceRevocationCommit {
    request: FinishGithubServerServiceRevocation,
}

impl PendingGithubServerServiceRevocationCommit {
    /// Replays the exact revocation result without another provider request.
    ///
    /// # Errors
    ///
    /// Returns the Store's sanitized error when the exact result is not
    /// confirmed. `self` remains available for another replay.
    pub async fn replay(
        &self,
        repository: &dyn GithubServerServiceCredentialRepository,
    ) -> Result<GithubServerServiceIssuanceReceipt, GithubServerServiceStoreError> {
        repository
            .finish_github_server_service_revocation(self.request.clone())
            .await
    }
}

impl fmt::Debug for PendingGithubServerServiceRevocationCommit {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PendingGithubServerServiceRevocationCommit")
            .field("request", &self.request)
            .finish()
    }
}

/// Result of one bounded maintenance step.
#[derive(Debug)]
pub enum GithubServerServiceCoordinationOutcome {
    /// No tenant maintenance row was due.
    Idle,
    /// Store atomically reduced a stale row without provider I/O.
    Reduced {
        /// Exact immutable authority selector.
        selector: GithubServerServiceAuthoritySelector,
        /// Value-free durable result.
        receipt: GithubServerServiceIssuanceReceipt,
    },
    /// A mint cutoff already existed and no provider call was repeated.
    MintAlreadyStarted(GithubServerServiceIssuanceReceipt),
    /// This worker committed the cutoff, but the final live window closed
    /// before the provider future's first poll. Store reconciliation owns it.
    MintStartedWindowExhausted(GithubServerServiceIssuanceReceipt),
    /// The exact provider result is ready for its first supervised Store poll.
    MintCommitPending(Box<PendingGithubServerServiceMintCommit>),
    /// The exact revocation result is ready for its first supervised Store poll.
    RevocationCommitPending(Box<PendingGithubServerServiceRevocationCommit>),
}

/// Generic coordinator for Checks and private-source credentials.
pub struct GithubServerServiceCredentialCoordinator {
    repository: Arc<dyn GithubServerServiceCredentialRepository>,
    resolver: Arc<dyn GithubServerServiceCredentialRequestResolver>,
    broker: Arc<dyn GithubServerServiceCredentialBroker>,
    envelopes: Arc<EnvelopeCodec>,
    clock: Arc<dyn GithubServerServiceCoordinatorClock>,
    worker: GithubServerServiceWorkerId,
}

impl GithubServerServiceCredentialCoordinator {
    /// Constructs a coordinator from explicit durable and provider boundaries.
    #[must_use]
    pub fn new(
        repository: Arc<dyn GithubServerServiceCredentialRepository>,
        resolver: Arc<dyn GithubServerServiceCredentialRequestResolver>,
        broker: Arc<dyn GithubServerServiceCredentialBroker>,
        envelopes: Arc<EnvelopeCodec>,
        clock: Arc<dyn GithubServerServiceCoordinatorClock>,
        worker: GithubServerServiceWorkerId,
    ) -> Self {
        Self {
            repository,
            resolver,
            broker,
            envelopes,
            clock,
            worker,
        }
    }

    /// Claims and processes at most one due tenant maintenance row.
    ///
    /// # Errors
    ///
    /// Returns a sanitized repository, resolution, broker, envelope, or
    /// invariant failure before a closed durable result is available.
    pub async fn coordinate_next(
        &self,
        tenant: TenantScope,
    ) -> Result<GithubServerServiceCoordinationOutcome, GithubServerServiceCoordinatorError> {
        let observed_at = self.clock.now();
        let claim_expires_at = checked_add(observed_at, MAX_GITHUB_SERVICE_REVOKE_CLAIM_MILLIS)?;
        let request = ClaimNextGithubServerServiceMaintenance::new(
            tenant,
            self.worker,
            observed_at,
            claim_expires_at,
        )
        .map_err(|_| GithubServerServiceCoordinatorError::Inconsistent)?;
        let Some(outcome) = self
            .repository
            .claim_next_github_server_service_maintenance(request)
            .await
            .map_err(|_| GithubServerServiceCoordinatorError::Repository)?
        else {
            return Ok(GithubServerServiceCoordinationOutcome::Idle);
        };
        self.coordinate_maintenance(outcome).await
    }

    /// Processes one already claimed atomic maintenance result.
    ///
    /// # Errors
    ///
    /// Returns a sanitized resolution, broker, envelope, repository, or
    /// invariant failure before a closed durable result is available.
    pub async fn coordinate_maintenance(
        &self,
        outcome: GithubServerServiceMaintenanceOutcome,
    ) -> Result<GithubServerServiceCoordinationOutcome, GithubServerServiceCoordinatorError> {
        match outcome {
            GithubServerServiceMaintenanceOutcome::Mint(claimed) => {
                self.coordinate_claimed_mint(*claimed).await
            }
            GithubServerServiceMaintenanceOutcome::Revocation(claimed) => {
                self.coordinate_claimed_revocation(*claimed).await
            }
            GithubServerServiceMaintenanceOutcome::Reduced { selector, receipt } => {
                Ok(GithubServerServiceCoordinationOutcome::Reduced { selector, receipt })
            }
        }
    }

    /// Processes one exact initial, refresh, or retry mint claim.
    ///
    /// # Errors
    ///
    /// Returns a sanitized pre-candidate failure. A closed provider outcome is
    /// committed or returned as protected replayable pending custody.
    pub async fn coordinate_claimed_mint(
        &self,
        claimed: ClaimedGithubServerServiceMint,
    ) -> Result<GithubServerServiceCoordinationOutcome, GithubServerServiceCoordinatorError> {
        let resolved = self
            .resolver
            .resolve_github_server_service_credential_request(claimed.identity())
            .await
            .map_err(|_| GithubServerServiceCoordinatorError::Resolution)?
            .ok_or(GithubServerServiceCoordinatorError::Unauthorized)?;
        if resolved.identity() != claimed.identity() {
            return Err(GithubServerServiceCoordinatorError::ResolutionIdentityMismatch);
        }
        let installation_id = claimed.identity().installation_id().get();
        let Some(maximum_request_duration) = self.broker.maximum_request_duration(installation_id)
        else {
            return Err(GithubServerServiceCoordinatorError::BrokerIdentityMismatch);
        };

        // The wrapping call is intentionally before the irreversible Store
        // cutoff. No provider future exists yet.
        let wrapping_context = claimed
            .identity()
            .wrapping_encryption_context(claimed.receipt().key().generation())
            .map_err(|_| GithubServerServiceCoordinatorError::Inconsistent)?;
        let prepared = self
            .envelopes
            .prepare(&wrapping_context)
            .await
            .map_err(|_| GithubServerServiceCoordinatorError::EnvelopePreparation)?;

        let begin_at = self.clock.now().max(claimed.claimed_at());
        if !request_fits_live_window(
            begin_at,
            claimed.claim_expires_at(),
            claimed.receipt().request_deadline(),
            maximum_request_duration,
        ) {
            return Err(GithubServerServiceCoordinatorError::Inconsistent);
        }
        let begin = BeginGithubServerServiceMint::new(&claimed, begin_at)
            .map_err(|_| GithubServerServiceCoordinatorError::Inconsistent)?;
        let started = match self
            .repository
            .begin_github_server_service_mint(begin)
            .await
            .map_err(|_| GithubServerServiceCoordinatorError::Repository)?
        {
            GithubServerServiceMintCutoffOutcome::AlreadyStarted(started) => {
                return Ok(GithubServerServiceCoordinationOutcome::MintAlreadyStarted(
                    started.receipt(),
                ));
            }
            GithubServerServiceMintCutoffOutcome::Started(started) => started,
        };

        // This is the final non-regressing deadline check immediately before
        // `.await` first polls the provider future.
        let provider_poll_at = self.clock.now().max(started.started_at());
        if !request_fits_live_window(
            provider_poll_at,
            started.claim_expires_at(),
            started.request_deadline(),
            maximum_request_duration,
        ) {
            return Ok(
                GithubServerServiceCoordinationOutcome::MintStartedWindowExhausted(
                    started.receipt(),
                ),
            );
        }
        let outcome = self
            .broker
            .mint_once(installation_id, resolved.request())
            .await;
        let observed_at = self.clock.now().max(provider_poll_at);
        let request =
            map_mint_outcome(&claimed, prepared, resolved.request(), outcome, observed_at)?;
        Ok(GithubServerServiceCoordinationOutcome::MintCommitPending(
            Box::new(PendingGithubServerServiceMintCommit { request }),
        ))
    }

    async fn coordinate_claimed_revocation(
        &self,
        claimed: ClaimedGithubServerServiceRevocation,
    ) -> Result<GithubServerServiceCoordinationOutcome, GithubServerServiceCoordinatorError> {
        let installation_id = claimed.identity().installation_id().get();
        let Some(maximum_request_duration) = self.broker.maximum_request_duration(installation_id)
        else {
            return Err(GithubServerServiceCoordinatorError::BrokerIdentityMismatch);
        };
        let observed_at = self.clock.now().max(claimed.claimed_at());
        let wrapping_context = claimed
            .identity()
            .wrapping_encryption_context(claimed.receipt().key().generation())
            .map_err(|_| GithubServerServiceCoordinatorError::Inconsistent)?;
        let payload_context = claimed
            .protected()
            .metadata()
            .encryption_context()
            .map_err(|_| GithubServerServiceCoordinatorError::Inconsistent)?;
        let plaintext = match self
            .envelopes
            .open_with_contexts(
                &wrapping_context,
                &payload_context,
                claimed.protected().envelope(),
            )
            .await
        {
            Ok(plaintext) => plaintext,
            Err(EnvelopeError::KeyEncryption(KeyEncryptionError::Unavailable)) => {
                return Ok(retain_revocation_result(revocation_retry(
                    &claimed,
                    "key_management_unavailable",
                    observed_at,
                    None,
                )?));
            }
            Err(_) => {
                let request = FinishGithubServerServiceRevocation::quarantined(
                    claimed.claim().clone(),
                    failure("credential_envelope_corrupt")?,
                    observed_at,
                )
                .map_err(|_| GithubServerServiceCoordinatorError::Inconsistent)?;
                return Ok(retain_revocation_result(request));
            }
        };
        let Ok(candidate) = decode_token_frame(&plaintext, claimed.protected().metadata()) else {
            let request = FinishGithubServerServiceRevocation::quarantined(
                claimed.claim().clone(),
                failure("credential_frame_corrupt")?,
                observed_at,
            )
            .map_err(|_| GithubServerServiceCoordinatorError::Inconsistent)?;
            return Ok(retain_revocation_result(request));
        };
        let request = if request_fits_live_window(
            observed_at,
            claimed.claim_expires_at(),
            claimed.receipt().safe_erase_after(),
            maximum_request_duration,
        ) {
            match self.broker.revoke(installation_id, &candidate).await {
                GithubInstallationTokenRevocationOutcome::Confirmed => {
                    FinishGithubServerServiceRevocation::confirmed(
                        claimed.claim().clone(),
                        self.clock.now().max(observed_at),
                    )
                    .map_err(|_| GithubServerServiceCoordinatorError::Inconsistent)?
                }
                GithubInstallationTokenRevocationOutcome::Unconfirmed(unconfirmed) => {
                    revocation_retry(
                        &claimed,
                        revocation_failure_kind(unconfirmed.kind()),
                        self.clock.now().max(observed_at),
                        unconfirmed.retry_after_seconds(),
                    )?
                }
            }
        } else {
            revocation_retry(&claimed, "revocation_window_exhausted", observed_at, None)?
        };
        drop(candidate);
        Ok(retain_revocation_result(request))
    }
}

fn retain_revocation_result(
    request: FinishGithubServerServiceRevocation,
) -> GithubServerServiceCoordinationOutcome {
    GithubServerServiceCoordinationOutcome::RevocationCommitPending(Box::new(
        PendingGithubServerServiceRevocationCommit { request },
    ))
}

impl fmt::Debug for GithubServerServiceCredentialCoordinator {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GithubServerServiceCredentialCoordinator")
            .field("repository", &"[AUTHORITY REPOSITORY]")
            .field("resolver", &"[EXACT REQUEST RESOLVER]")
            .field("broker", &self.broker)
            .field("envelopes", &self.envelopes)
            .field("clock", &self.clock)
            .field("worker", &self.worker)
            .finish()
    }
}

/// Exact non-secret binding carried with a decrypted handoff credential.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GithubServerServiceHandoffBinding {
    selector: GithubServerServiceAuthoritySelector,
    handoff_id: GithubServerServiceHandoffId,
    consumer: GithubServerServiceConsumerClaim,
    key: GithubServerServiceIssuanceKey,
    required_through: UnixMillis,
    usable_until: UnixMillis,
    granted_at: UnixMillis,
    acquired_at: UnixMillis,
}

impl GithubServerServiceHandoffBinding {
    /// Returns the immutable authority selector.
    #[must_use]
    pub const fn selector(&self) -> &GithubServerServiceAuthoritySelector {
        &self.selector
    }
    /// Returns the durable natural-key winner's handoff ID.
    #[must_use]
    pub const fn handoff_id(&self) -> GithubServerServiceHandoffId {
        self.handoff_id
    }
    /// Returns the exact consumer, action, fence, and revision claim.
    #[must_use]
    pub const fn consumer(&self) -> GithubServerServiceConsumerClaim {
        self.consumer
    }
    /// Returns the exact protected issuance generation.
    #[must_use]
    pub const fn key(&self) -> GithubServerServiceIssuanceKey {
        self.key
    }
    /// Returns the exclusive provider-use horizon requested by the consumer.
    #[must_use]
    pub const fn required_through(&self) -> UnixMillis {
        self.required_through
    }
    /// Returns the exclusive conservative provider-use expiry.
    #[must_use]
    pub const fn usable_until(&self) -> UnixMillis {
        self.usable_until
    }
    /// Returns when the original natural-key handoff was granted.
    #[must_use]
    pub const fn granted_at(&self) -> UnixMillis {
        self.granted_at
    }
    /// Returns this acquisition or replay observation.
    #[must_use]
    pub const fn acquired_at(&self) -> UnixMillis {
        self.acquired_at
    }
}

/// Move-only, zeroizing credential plus its exact handoff binding.
#[must_use = "the credential handoff must be used and exactly released"]
pub struct GithubServerServiceCredential {
    candidate: GithubInstallationTokenRevocationCandidate,
    binding: GithubServerServiceHandoffBinding,
}

impl GithubServerServiceCredential {
    /// Borrows the bearer value only at the provider adapter boundary.
    #[must_use]
    pub const fn secret(&self) -> &SecretString {
        self.candidate.secret()
    }

    /// Returns the exact non-secret handoff binding.
    #[must_use]
    pub const fn binding(&self) -> &GithubServerServiceHandoffBinding {
        &self.binding
    }

    /// Transfers the zeroizing bearer and exact release binding to an adapter.
    ///
    /// The caller becomes responsible for retaining the binding through the
    /// last provider future and issuing an exact release afterward. Splitting
    /// the values does not make early release safe.
    #[must_use = "transferred bearer custody and its release binding must both be retained"]
    pub fn into_secret_and_binding(self) -> (SecretString, GithubServerServiceHandoffBinding) {
        (self.candidate.into_secret(), self.binding)
    }
}

impl fmt::Debug for GithubServerServiceCredential {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GithubServerServiceCredential")
            .field("credential", &"[REDACTED]")
            .field("binding", &self.binding)
            .finish_non_exhaustive()
    }
}

/// Sanitized handoff issuance failure.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum GithubServerServiceHandoffError {
    /// Durable handoff access failed.
    #[error("GitHub server-service handoff repository is unavailable")]
    Repository,
    /// Key management is temporarily unavailable; custody was not quarantined.
    #[error("GitHub server-service handoff key management is unavailable")]
    Unavailable,
    /// Returned handoff evidence did not match the exact request.
    #[error("GitHub server-service handoff binding is inconsistent")]
    Inconsistent,
    /// Protected current custody was corrupt and has been quarantined.
    #[error("GitHub server-service handoff credential is corrupt")]
    Corrupt,
    /// Exact corruption cleanup needs Store replay after an uncertain response.
    #[error("GitHub server-service handoff corruption cleanup is pending")]
    CorruptCleanupPending(Box<PendingGithubServerServiceCorruptionCleanup>),
}

/// Exact quarantine and handoff release retained after uncertain cleanup.
#[must_use = "uncertain corruption cleanup must be replayed"]
#[derive(Clone, Eq, PartialEq)]
pub struct PendingGithubServerServiceCorruptionCleanup {
    quarantine: QuarantineGithubServerServiceCredential,
    release: ReleaseGithubServerServiceHandoff,
}

impl PendingGithubServerServiceCorruptionCleanup {
    /// Replays the exact quarantine before the exact handoff release.
    ///
    /// Both Store requests are idempotent. Replaying quarantine first is safe
    /// whether the uncertain response came from quarantine or from release.
    ///
    /// # Errors
    ///
    /// Returns the Store's sanitized error unless both mutations are confirmed.
    pub async fn replay(
        &self,
        repository: &dyn GithubServerServiceCredentialRepository,
    ) -> Result<(), GithubServerServiceStoreError> {
        repository
            .quarantine_github_server_service_credential(self.quarantine.clone())
            .await?;
        repository
            .release_github_server_service_handoff(self.release.clone())
            .await
    }
}

impl fmt::Debug for PendingGithubServerServiceCorruptionCleanup {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PendingGithubServerServiceCorruptionCleanup")
            .finish_non_exhaustive()
    }
}

/// An exact release retained after an unconfirmed Store response.
#[must_use = "an unconfirmed release must be replayed"]
#[derive(Clone, Debug)]
pub struct PendingGithubServerServiceHandoffRelease {
    request: ReleaseGithubServerServiceHandoff,
}

impl PendingGithubServerServiceHandoffRelease {
    /// Replays the exact release timestamp and binding.
    ///
    /// # Errors
    ///
    /// Returns the Store's sanitized error when exact release is not confirmed.
    pub async fn replay(
        &self,
        repository: &dyn GithubServerServiceCredentialRepository,
    ) -> Result<(), GithubServerServiceStoreError> {
        repository
            .release_github_server_service_handoff(self.request.clone())
            .await
    }
}

/// Result of consuming and releasing one decrypted credential.
#[derive(Debug)]
pub enum GithubServerServiceHandoffReleaseOutcome {
    /// Store confirmed the exact release.
    Released,
    /// The bearer was dropped, but exact release evidence needs Store replay.
    Pending(PendingGithubServerServiceHandoffRelease),
}

/// Opens and releases exact action-bound credential handoffs.
pub struct GithubServerServiceCredentialIssuer {
    repository: Arc<dyn GithubServerServiceCredentialRepository>,
    envelopes: Arc<EnvelopeCodec>,
    clock: Arc<dyn GithubServerServiceCoordinatorClock>,
}

impl GithubServerServiceCredentialIssuer {
    /// Constructs an issuer from durable custody and envelope boundaries.
    #[must_use]
    pub fn new(
        repository: Arc<dyn GithubServerServiceCredentialRepository>,
        envelopes: Arc<EnvelopeCodec>,
        clock: Arc<dyn GithubServerServiceCoordinatorClock>,
    ) -> Self {
        Self {
            repository,
            envelopes,
            clock,
        }
    }

    /// Acquires, authenticates, and opens one exact consumer handoff.
    ///
    /// A lost response may be retried with a fresh proposed UUID. Store returns
    /// the original natural-key winner, which is carried in the binding.
    ///
    /// # Errors
    ///
    /// Returns a sanitized repository, key-management, binding, or corruption
    /// failure. Authenticated corruption is quarantined before return.
    pub async fn acquire(
        &self,
        request: AcquireGithubServerServiceHandoff,
    ) -> Result<GithubServerServiceCredential, GithubServerServiceHandoffError> {
        let requested_selector = request.selector().clone();
        let requested_consumer = request.consumer();
        let requested_through = request.required_through();
        let requested_at = request.observed_at();
        let handoff = self
            .repository
            .acquire_github_server_service_handoff(request)
            .await
            .map_err(|_| GithubServerServiceHandoffError::Repository)?;
        if GithubServerServiceAuthoritySelector::from_identity(handoff.identity())
            != requested_selector
            || handoff.consumer() != requested_consumer
            || handoff.required_through() != requested_through
            || handoff.acquired_at() != requested_at
        {
            return Err(GithubServerServiceHandoffError::Inconsistent);
        }
        self.open_handoff(requested_selector, handoff).await
    }

    async fn open_handoff(
        &self,
        selector: GithubServerServiceAuthoritySelector,
        handoff: GithubServerServiceCredentialHandoff,
    ) -> Result<GithubServerServiceCredential, GithubServerServiceHandoffError> {
        let metadata = handoff.protected().metadata();
        let wrapping_context = handoff
            .identity()
            .wrapping_encryption_context(metadata.generation())
            .map_err(|_| GithubServerServiceHandoffError::Inconsistent)?;
        let payload_context = metadata
            .encryption_context()
            .map_err(|_| GithubServerServiceHandoffError::Inconsistent)?;
        let plaintext = match self
            .envelopes
            .open_with_contexts(
                &wrapping_context,
                &payload_context,
                handoff.protected().envelope(),
            )
            .await
        {
            Ok(plaintext) => plaintext,
            Err(EnvelopeError::KeyEncryption(KeyEncryptionError::Unavailable)) => {
                return Err(GithubServerServiceHandoffError::Unavailable);
            }
            Err(_) => {
                return self
                    .quarantine_corrupt(selector, &handoff, "credential_envelope_corrupt")
                    .await;
            }
        };
        let Ok(candidate) = decode_token_frame(&plaintext, metadata) else {
            return self
                .quarantine_corrupt(selector, &handoff, "credential_frame_corrupt")
                .await;
        };
        let binding = GithubServerServiceHandoffBinding {
            selector,
            handoff_id: handoff.handoff_id(),
            consumer: handoff.consumer(),
            key: handoff.receipt().key(),
            required_through: handoff.required_through(),
            usable_until: handoff
                .receipt()
                .usable_until()
                .expect("a validated handoff always has known provider expiry"),
            granted_at: handoff.granted_at(),
            acquired_at: handoff.acquired_at(),
        };
        Ok(GithubServerServiceCredential { candidate, binding })
    }

    async fn quarantine_corrupt(
        &self,
        selector: GithubServerServiceAuthoritySelector,
        handoff: &GithubServerServiceCredentialHandoff,
        kind: &'static str,
    ) -> Result<GithubServerServiceCredential, GithubServerServiceHandoffError> {
        let observed_at = self.clock.now().max(handoff.acquired_at());
        let quarantine = QuarantineGithubServerServiceCredential::new(
            selector.clone(),
            handoff.receipt().key(),
            handoff.protected().metadata().aad_digest(),
            failure(kind).map_err(|_| GithubServerServiceHandoffError::Inconsistent)?,
            observed_at,
        )
        .map_err(|_| GithubServerServiceHandoffError::Inconsistent)?;
        let release = ReleaseGithubServerServiceHandoff::new(
            selector,
            handoff.handoff_id(),
            handoff.consumer(),
            observed_at,
        )
        .map_err(|_| GithubServerServiceHandoffError::Inconsistent)?;
        let cleanup = PendingGithubServerServiceCorruptionCleanup {
            quarantine,
            release,
        };
        match cleanup.replay(self.repository.as_ref()).await {
            Ok(()) => Err(GithubServerServiceHandoffError::Corrupt),
            Err(_) => Err(GithubServerServiceHandoffError::CorruptCleanupPending(
                Box::new(cleanup),
            )),
        }
    }

    /// Consumes the bearer and exactly releases its durable handoff.
    ///
    /// # Errors
    ///
    /// Returns only when the exact release request cannot be constructed.
    /// Store uncertainty is returned as replayable pending release evidence.
    pub async fn release(
        &self,
        credential: GithubServerServiceCredential,
    ) -> Result<GithubServerServiceHandoffReleaseOutcome, GithubServerServiceHandoffError> {
        let GithubServerServiceCredential { candidate, binding } = credential;
        drop(candidate);
        self.release_binding(binding).await
    }

    /// Releases a transferred binding after its final provider future ends.
    ///
    /// This method contains no bearer value. The caller must first drop the
    /// separately transferred [`SecretString`] and must not call this method
    /// while any request still borrows or owns that credential.
    ///
    /// # Errors
    ///
    /// Returns only when the exact release request cannot be constructed.
    /// Store uncertainty is returned as replayable pending release evidence.
    pub async fn release_binding(
        &self,
        binding: GithubServerServiceHandoffBinding,
    ) -> Result<GithubServerServiceHandoffReleaseOutcome, GithubServerServiceHandoffError> {
        let pending = self.prepare_release_binding(binding)?;
        match pending.replay(self.repository.as_ref()).await {
            Ok(()) => Ok(GithubServerServiceHandoffReleaseOutcome::Released),
            Err(_) => Ok(GithubServerServiceHandoffReleaseOutcome::Pending(pending)),
        }
    }

    /// Freezes an exact release request before its first Store poll.
    ///
    /// Replaying the returned value never resamples the coordinator clock or
    /// changes any binding field.
    ///
    /// # Errors
    ///
    /// Returns only when the exact release request cannot be constructed.
    pub fn prepare_release_binding(
        &self,
        binding: GithubServerServiceHandoffBinding,
    ) -> Result<PendingGithubServerServiceHandoffRelease, GithubServerServiceHandoffError> {
        let released_at = self.clock.now().max(binding.acquired_at);
        let request = ReleaseGithubServerServiceHandoff::new(
            binding.selector,
            binding.handoff_id,
            binding.consumer,
            released_at,
        )
        .map_err(|_| GithubServerServiceHandoffError::Inconsistent)?;
        Ok(PendingGithubServerServiceHandoffRelease { request })
    }
}

impl fmt::Debug for GithubServerServiceCredentialIssuer {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GithubServerServiceCredentialIssuer")
            .field("repository", &"[AUTHORITY REPOSITORY]")
            .field("envelopes", &self.envelopes)
            .field("clock", &self.clock)
            .finish()
    }
}

struct ServerServiceTokenFrame {
    plaintext: SecretBytes,
    size_bytes: u64,
    digest: Sha256Digest,
}

impl ServerServiceTokenFrame {
    fn new(candidate: &GithubInstallationTokenRevocationCandidate) -> Self {
        let token = candidate.secret().expose_secret().as_bytes();
        let token_length =
            u32::try_from(token.len()).expect("validated GitHub token is u32-bounded");
        let mut encoded = Vec::with_capacity(
            SERVER_SERVICE_TOKEN_FRAME_DOMAIN.len() + size_of::<u32>() + token.len(),
        );
        encoded.extend_from_slice(SERVER_SERVICE_TOKEN_FRAME_DOMAIN);
        encoded.extend_from_slice(&token_length.to_be_bytes());
        encoded.extend_from_slice(token);
        let size_bytes = u64::try_from(encoded.len()).expect("bounded token frame fits u64");
        let digest = Sha256Digest::from_bytes(Sha256::digest(&encoded).into());
        let plaintext =
            SecretBytes::new(encoded).expect("a validated token frame fits SecretBytes");
        Self {
            plaintext,
            size_bytes,
            digest,
        }
    }
}

fn map_mint_outcome(
    claimed: &ClaimedGithubServerServiceMint,
    prepared: PreparedEnvelope,
    expected_request: &RepositoryCredentialRequest,
    outcome: GithubInstallationTokenMintOutcome,
    observed_at: UnixMillis,
) -> Result<FinishGithubServerServiceMint, GithubServerServiceCoordinatorError> {
    match outcome {
        GithubInstallationTokenMintOutcome::Ready(ready) => {
            let provider_expires_at = timestamp_millis(ready.provider_expires_at());
            let exact = ready.request() == expected_request
                && ready.provenance().provider().as_str() == "github"
                && ready.provenance().subject().as_str()
                    == claimed.identity().installation_id().get().to_string()
                && timestamp_millis(ready.issued_at())
                    .is_some_and(|issued_at| issued_at <= claimed.receipt().request_deadline())
                && observed_at < claimed.receipt().request_deadline();
            protect_mint_candidate(
                claimed,
                prepared,
                ready.into_revocation_candidate(),
                provider_expires_at,
                exact,
                observed_at,
            )
        }
        GithubInstallationTokenMintOutcome::RevokePending(revoke) => {
            let provider_expires_at = revoke.provider_expires_at().and_then(timestamp_millis);
            protect_mint_candidate(
                claimed,
                prepared,
                revoke.into_candidate(),
                provider_expires_at,
                false,
                observed_at,
            )
        }
        GithubInstallationTokenMintOutcome::Indeterminate(indeterminate) => {
            drop(prepared);
            FinishGithubServerServiceMint::indeterminate(
                claimed.claim().clone(),
                failure(indeterminate_failure_kind(indeterminate.reason()))?,
                observed_at,
            )
            .map_err(|_| GithubServerServiceCoordinatorError::Inconsistent)
        }
        GithubInstallationTokenMintOutcome::Rejected(error) => {
            drop(prepared);
            map_rejected_mint(claimed, error, observed_at)
        }
    }
}

fn protect_mint_candidate(
    claimed: &ClaimedGithubServerServiceMint,
    prepared: PreparedEnvelope,
    candidate: GithubInstallationTokenRevocationCandidate,
    provider_expires_at: Option<UnixMillis>,
    deliverable: bool,
    committed_at: UnixMillis,
) -> Result<FinishGithubServerServiceMint, GithubServerServiceCoordinatorError> {
    let frame = ServerServiceTokenFrame::new(&candidate);
    let metadata = provider_expires_at
        .and_then(|provider_expires_at| {
            automata_ci_store::GithubServerServiceEnvelopeMetadata::new(
                claimed.identity().clone(),
                claimed.receipt().key().generation(),
                claimed.receipt().requested_at(),
                claimed.receipt().request_deadline(),
                provider_expires_at,
                frame.size_bytes,
                frame.digest,
            )
            .ok()
        })
        .or_else(|| {
            automata_ci_store::GithubServerServiceEnvelopeMetadata::unknown_provider_expiry(
                claimed.identity().clone(),
                claimed.receipt().key().generation(),
                claimed.receipt().requested_at(),
                claimed.receipt().request_deadline(),
                frame.size_bytes,
                frame.digest,
            )
            .ok()
        })
        .ok_or(GithubServerServiceCoordinatorError::Inconsistent)?;
    let payload_context = metadata
        .encryption_context()
        .map_err(|_| GithubServerServiceCoordinatorError::Inconsistent)?;
    let envelope = prepared.seal_prepared(&payload_context, frame.plaintext);
    drop(candidate);
    let protected = ProtectedGithubServerServiceCredential::new(metadata, envelope)
        .map_err(|_| GithubServerServiceCoordinatorError::Inconsistent)?;
    let ready_horizon = committed_at
        .get()
        .checked_add(MIN_GITHUB_SERVICE_READY_USE_MILLIS)
        .map(UnixMillis::new);
    let may_be_ready = deliverable
        && ready_horizon.is_some_and(|required| {
            protected
                .metadata()
                .usable_until()
                .is_some_and(|usable| usable >= required)
        });
    if may_be_ready {
        FinishGithubServerServiceMint::ready(claimed.claim().clone(), protected, committed_at)
            .map_err(|_| GithubServerServiceCoordinatorError::Inconsistent)
    } else {
        FinishGithubServerServiceMint::issued_revoke_only(
            claimed.claim().clone(),
            protected,
            committed_at,
        )
        .map_err(|_| GithubServerServiceCoordinatorError::Inconsistent)
    }
}

fn map_rejected_mint(
    claimed: &ClaimedGithubServerServiceMint,
    error: CredentialError,
    observed_at: UnixMillis,
) -> Result<FinishGithubServerServiceMint, GithubServerServiceCoordinatorError> {
    let failure_kind = failure(mint_failure_kind(error.kind()))?;
    if matches!(
        error.kind(),
        CredentialErrorKind::RateLimited | CredentialErrorKind::Unavailable
    ) {
        let requested = error
            .retry_after_seconds()
            .and_then(|seconds| seconds.checked_mul(1_000))
            .and_then(|value| i64::try_from(value).ok())
            .unwrap_or(DEFAULT_MINT_RETRY_MILLIS)
            .clamp(1, MAX_GITHUB_SERVICE_MINT_RETRY_MILLIS);
        if let Some(retry_at) =
            bounded_retry_at(observed_at, requested, claimed.receipt().request_deadline())
        {
            return FinishGithubServerServiceMint::retry(
                claimed.claim().clone(),
                failure_kind,
                observed_at,
                retry_at,
            )
            .map_err(|_| GithubServerServiceCoordinatorError::Inconsistent);
        }
    }
    FinishGithubServerServiceMint::rejected(claimed.claim().clone(), failure_kind, observed_at)
        .map_err(|_| GithubServerServiceCoordinatorError::Inconsistent)
}

fn revocation_retry(
    claimed: &ClaimedGithubServerServiceRevocation,
    kind: &'static str,
    observed_at: UnixMillis,
    retry_after_seconds: Option<u64>,
) -> Result<FinishGithubServerServiceRevocation, GithubServerServiceCoordinatorError> {
    let requested = retry_after_seconds
        .and_then(|seconds| seconds.checked_mul(1_000))
        .and_then(|value| i64::try_from(value).ok())
        .unwrap_or(DEFAULT_REVOKE_RETRY_MILLIS)
        .clamp(1, MAX_GITHUB_SERVICE_REVOKE_RETRY_MILLIS);
    let retry_at = bounded_retry_at(observed_at, requested, claimed.receipt().safe_erase_after())
        .or_else(|| observed_at.get().checked_add(1).map(UnixMillis::new))
        .ok_or(GithubServerServiceCoordinatorError::Inconsistent)?;
    FinishGithubServerServiceRevocation::retry(
        claimed.claim().clone(),
        failure(kind)?,
        observed_at,
        retry_at,
    )
    .map_err(|_| GithubServerServiceCoordinatorError::Inconsistent)
}

fn decode_token_frame(
    plaintext: &SecretBytes,
    metadata: &automata_ci_store::GithubServerServiceEnvelopeMetadata,
) -> Result<GithubInstallationTokenRevocationCandidate, ()> {
    let bytes = plaintext.expose_secret();
    if u64::try_from(bytes.len()).ok() != Some(metadata.plaintext_size_bytes())
        || Sha256Digest::from_bytes(Sha256::digest(bytes).into()) != metadata.plaintext_digest()
        || !bytes.starts_with(SERVER_SERVICE_TOKEN_FRAME_DOMAIN)
    {
        return Err(());
    }
    let length_start = SERVER_SERVICE_TOKEN_FRAME_DOMAIN.len();
    let length_end = length_start.checked_add(size_of::<u32>()).ok_or(())?;
    let length: [u8; size_of::<u32>()] = bytes
        .get(length_start..length_end)
        .ok_or(())?
        .try_into()
        .map_err(|_| ())?;
    let token_length = usize::try_from(u32::from_be_bytes(length)).map_err(|_| ())?;
    let token = bytes.get(length_end..).ok_or(())?;
    if token.len() != token_length || token.is_empty() || !token.iter().all(u8::is_ascii_graphic) {
        return Err(());
    }
    let token = String::from_utf8(token.to_vec()).map_err(|_| ())?;
    let secret = SecretString::new(token).map_err(|_| ())?;
    GithubInstallationTokenRevocationCandidate::from_protected_secret(secret).map_err(|_| ())
}

fn request_fits_live_window(
    observed_at: UnixMillis,
    claim_expires_at: UnixMillis,
    request_deadline: UnixMillis,
    maximum_duration: Duration,
) -> bool {
    exact_request_millis(maximum_duration)
        .and_then(|duration| observed_at.get().checked_add(duration))
        .is_some_and(|completion| {
            observed_at < claim_expires_at
                && observed_at < request_deadline
                && completion <= claim_expires_at.get()
                && completion <= request_deadline.get()
        })
}

fn exact_request_millis(duration: Duration) -> Option<i64> {
    whole_milliseconds(duration)
        .and_then(|milliseconds| i64::try_from(milliseconds).ok())
        .filter(|milliseconds| *milliseconds > 0)
}

fn bounded_retry_at(
    observed_at: UnixMillis,
    requested_delay: i64,
    exclusive_horizon: UnixMillis,
) -> Option<UnixMillis> {
    let requested = observed_at.get().checked_add(requested_delay)?;
    let latest = exclusive_horizon.get().checked_sub(1)?;
    let retry_at = requested.min(latest);
    (retry_at > observed_at.get()).then(|| UnixMillis::new(retry_at))
}

fn checked_add(
    value: UnixMillis,
    increment: i64,
) -> Result<UnixMillis, GithubServerServiceCoordinatorError> {
    value
        .get()
        .checked_add(increment)
        .map(UnixMillis::new)
        .ok_or(GithubServerServiceCoordinatorError::Inconsistent)
}

fn timestamp_millis(value: UnixTimestamp) -> Option<UnixMillis> {
    value
        .as_seconds()
        .checked_mul(1_000)
        .and_then(|value| i64::try_from(value).ok())
        .map(UnixMillis::new)
}

fn failure(
    kind: &'static str,
) -> Result<GithubServerServiceFailureKind, GithubServerServiceCoordinatorError> {
    GithubServerServiceFailureKind::new(kind)
        .map_err(|_| GithubServerServiceCoordinatorError::Inconsistent)
}

fn finish_mint_claim(
    request: &FinishGithubServerServiceMint,
) -> &automata_ci_store::GithubServerServiceClaim {
    match request {
        FinishGithubServerServiceMint::Ready { claim, .. }
        | FinishGithubServerServiceMint::RevokeOnly { claim, .. }
        | FinishGithubServerServiceMint::Retry { claim, .. }
        | FinishGithubServerServiceMint::Indeterminate { claim, .. }
        | FinishGithubServerServiceMint::Rejected { claim, .. } => claim,
    }
}

fn finish_mint_disposition(request: &FinishGithubServerServiceMint) -> &'static str {
    match request {
        FinishGithubServerServiceMint::Ready { .. } => "ready",
        FinishGithubServerServiceMint::RevokeOnly { .. } => "revoke_only",
        FinishGithubServerServiceMint::Retry { .. } => "retry",
        FinishGithubServerServiceMint::Indeterminate { .. } => "indeterminate",
        FinishGithubServerServiceMint::Rejected { .. } => "rejected",
    }
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

const fn indeterminate_failure_kind(
    reason: GithubInstallationTokenIndeterminateReason,
) -> &'static str {
    match reason {
        GithubInstallationTokenIndeterminateReason::Transport => "mint_transport_indeterminate",
        GithubInstallationTokenIndeterminateReason::ProviderUnavailable => {
            "mint_provider_indeterminate"
        }
        GithubInstallationTokenIndeterminateReason::ResponseTooLarge => "mint_response_too_large",
        GithubInstallationTokenIndeterminateReason::TruncatedResponse => "mint_response_truncated",
        GithubInstallationTokenIndeterminateReason::MalformedResponse => "mint_response_malformed",
        GithubInstallationTokenIndeterminateReason::MissingToken => "mint_token_missing",
        GithubInstallationTokenIndeterminateReason::AmbiguousToken => "mint_token_ambiguous",
        GithubInstallationTokenIndeterminateReason::UnexpectedStatus => "mint_status_indeterminate",
    }
}

const fn revocation_failure_kind(
    kind: GithubInstallationTokenRevocationFailureKind,
) -> &'static str {
    match kind {
        GithubInstallationTokenRevocationFailureKind::Unauthorized => "revocation_unauthorized",
        GithubInstallationTokenRevocationFailureKind::RateLimited => "revocation_rate_limited",
        GithubInstallationTokenRevocationFailureKind::Retryable => "revocation_unavailable",
        GithubInstallationTokenRevocationFailureKind::InvalidResponse => {
            "revocation_invalid_response"
        }
    }
}

#[cfg(test)]
#[path = "server_service_authority_tests.rs"]
mod tests;
