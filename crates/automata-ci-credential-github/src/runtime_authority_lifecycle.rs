//! Bounded reconciliation and revocation for protected GitHub job authority.

use std::{
    collections::BTreeMap,
    fmt,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    time::Duration,
};

use automata_ci_auth::secret::SecretString;
use automata_ci_core::UnixMillis;
use automata_ci_key_management::{
    EnvelopeCodec, EnvelopeError, KeyEncryptionContext, KeyEncryptionError, SecretBytes,
};
use automata_ci_store::{
    ClaimGithubRuntimeAuthorityRevocation, ClaimedGithubRuntimeAuthorityRevocation,
    ConfirmGithubRuntimeAuthorityRevocation, DeferGithubRuntimeAuthorityRevocation,
    GithubRuntimeAuthorityCorruptionKind, GithubRuntimeAuthorityIdentity,
    GithubRuntimeAuthorityKey, GithubRuntimeAuthorityReceipt,
    GithubRuntimeAuthorityReconciliationReport, GithubRuntimeAuthorityRepository,
    GithubRuntimeAuthorityRevocationFailure, GithubRuntimeAuthorityWorkerId,
    GithubServerServiceAppClientId, GithubServerServiceAppId, GithubServerServiceJwtIssuer,
    MAX_GITHUB_AUTHORITY_RECONCILE_BATCH, MAX_GITHUB_AUTHORITY_REVOKE_BACKOFF_MILLIS,
    MAX_GITHUB_AUTHORITY_REVOKE_CLAIM_MILLIS, QuarantineGithubRuntimeAuthority,
    ReconcileGithubRuntimeAuthorities, RetryGithubRuntimeAuthorityRevocation,
    RevalidateGithubRuntimeAuthorityRevocation, Sha256Digest,
};
use sha2::{Digest as _, Sha256};
use thiserror::Error;
use tokio::{
    runtime::Handle,
    sync::{OwnedSemaphorePermit, oneshot},
};
use tokio_util::sync::CancellationToken;

use crate::{
    GithubAppCredentialBroker, GithubInstallationTokenRevocationCandidate,
    GithubInstallationTokenRevocationFailureKind, GithubInstallationTokenRevocationOutcome,
    GithubRuntimeAuthorityCoordinatorClock, config::whole_milliseconds,
};

const INSTALLATION_TOKEN_FRAME_DOMAIN: &[u8] = b"automata-ci/github-installation-token/v1\0";
const DEFAULT_REVOKE_RETRY_MILLIS: i64 = 1_000;
const MAX_PENDING_LIFECYCLE_COMMITS: usize = 1_024;
const MAX_PENDING_RETRY_DELAY: Duration = Duration::from_mins(1);
const MAX_GITHUB_RUNTIME_AUTHORITY_LIFECYCLE_BROKERS: usize = 256;

/// Exact provider boundary for protected job-authority revocation.
///
/// Implementations must select a route only when the immutable installation,
/// live App-key SPKI fingerprint, and scope-specific configuration fingerprint
/// all match `identity`. There is no default installation or configuration.
#[async_trait::async_trait]
pub trait GithubRuntimeAuthorityLifecycleBroker: fmt::Debug + Send + Sync {
    /// Returns the hard request bound for the exact attested identity, or
    /// `None` when no byte-identical live route exists. A returned duration
    /// must be a nonzero whole number of milliseconds so provider and durable
    /// database bounds are byte-for-byte equivalent.
    fn maximum_request_duration(
        &self,
        identity: &GithubRuntimeAuthorityIdentity,
    ) -> Option<Duration>;

    /// Performs exactly one revocation attempt through the exact attested
    /// route while the caller retains candidate custody.
    async fn revoke(
        &self,
        identity: &GithubRuntimeAuthorityIdentity,
        candidate: &GithubInstallationTokenRevocationCandidate,
    ) -> GithubInstallationTokenRevocationOutcome;
}

/// Invalid pinned lifecycle-broker configuration.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum GithubRuntimeAuthorityLifecycleBrokerRouterError {
    /// At least one exact installation route is required.
    #[error("GitHub runtime-authority lifecycle broker router is empty")]
    Empty,
    /// The route count exceeds the product's bounded installation count.
    #[error("GitHub runtime-authority lifecycle broker router is too large")]
    TooMany,
    /// Two routes selected the same installation identity.
    #[error("GitHub runtime-authority lifecycle broker router contains a duplicate installation")]
    DuplicateInstallation,
    /// The injected live signer does not use the pinned App JWT issuer value.
    #[error("GitHub runtime-authority lifecycle broker issuer is inconsistent")]
    InconsistentIssuer,
}

struct GithubRuntimeAuthorityLifecycleBrokerRoute {
    broker: Arc<GithubAppCredentialBroker>,
    github_app_id: GithubServerServiceAppId,
    github_app_client_id: GithubServerServiceAppClientId,
    github_app_jwt_issuer_kind: GithubServerServiceJwtIssuer,
    configuration_fingerprint: Sha256Digest,
}

/// Bounded no-default router for exactly pinned job-authority revocation.
///
/// Each route derives its installation and issuer/SPKI fingerprint from the
/// injected live App broker. The caller supplies only the configuration digest
/// produced by the same converged authority plan that admitted the job.
pub struct GithubRuntimeAuthorityLifecycleBrokerRouter {
    routes: BTreeMap<u64, GithubRuntimeAuthorityLifecycleBrokerRoute>,
}

impl GithubRuntimeAuthorityLifecycleBrokerRouter {
    /// Builds an immutable exact router from live App brokers and configuration
    /// fingerprints.
    ///
    /// # Errors
    ///
    /// Rejects an empty, oversized, or duplicate-installation route set.
    pub fn new(
        entries: impl IntoIterator<
            Item = (
                Arc<GithubAppCredentialBroker>,
                GithubServerServiceAppId,
                GithubServerServiceAppClientId,
                GithubServerServiceJwtIssuer,
                Sha256Digest,
            ),
        >,
    ) -> Result<Self, GithubRuntimeAuthorityLifecycleBrokerRouterError> {
        let mut routes = BTreeMap::new();
        for (
            broker,
            github_app_id,
            github_app_client_id,
            github_app_jwt_issuer_kind,
            configuration_fingerprint,
        ) in entries
        {
            if routes.len() >= MAX_GITHUB_RUNTIME_AUTHORITY_LIFECYCLE_BROKERS {
                return Err(GithubRuntimeAuthorityLifecycleBrokerRouterError::TooMany);
            }
            let expected_issuer = match github_app_jwt_issuer_kind {
                GithubServerServiceJwtIssuer::AppClientId => {
                    github_app_client_id.as_str().to_owned()
                }
                GithubServerServiceJwtIssuer::AppId => github_app_id.get().to_string(),
            };
            if broker.app_jwt_issuer_value() != expected_issuer {
                return Err(GithubRuntimeAuthorityLifecycleBrokerRouterError::InconsistentIssuer);
            }
            let installation_id = broker.mint_installation_id();
            let route = GithubRuntimeAuthorityLifecycleBrokerRoute {
                broker,
                github_app_id,
                github_app_client_id,
                github_app_jwt_issuer_kind,
                configuration_fingerprint,
            };
            if routes.insert(installation_id, route).is_some() {
                return Err(
                    GithubRuntimeAuthorityLifecycleBrokerRouterError::DuplicateInstallation,
                );
            }
        }
        if routes.is_empty() {
            return Err(GithubRuntimeAuthorityLifecycleBrokerRouterError::Empty);
        }
        Ok(Self { routes })
    }

    fn exact_route(
        &self,
        identity: &GithubRuntimeAuthorityIdentity,
    ) -> Option<&GithubRuntimeAuthorityLifecycleBrokerRoute> {
        self.routes
            .get(&identity.provider_installation_id().get())
            .filter(|route| {
                route.github_app_id == identity.github_app_id()
                    && route.github_app_client_id == *identity.github_app_client_id()
                    && route.github_app_jwt_issuer_kind == identity.github_app_jwt_issuer_kind()
                    && route.broker.app_jwt_issuer_value() == identity.github_app_jwt_issuer_value()
                    && route.broker.app_key_spki_sha256() == identity.app_key_spki_sha256()
                    && route.configuration_fingerprint == identity.configuration_fingerprint()
            })
    }
}

impl fmt::Debug for GithubRuntimeAuthorityLifecycleBrokerRouter {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GithubRuntimeAuthorityLifecycleBrokerRouter")
            .field("installation_ids", &self.routes.keys().collect::<Vec<_>>())
            .field("routes", &"[PINNED APP BROKERS]")
            .finish()
    }
}

#[async_trait::async_trait]
impl GithubRuntimeAuthorityLifecycleBroker for GithubRuntimeAuthorityLifecycleBrokerRouter {
    fn maximum_request_duration(
        &self,
        identity: &GithubRuntimeAuthorityIdentity,
    ) -> Option<Duration> {
        self.exact_route(identity)
            .map(|route| route.broker.mint_request_timeout())
    }

    async fn revoke(
        &self,
        identity: &GithubRuntimeAuthorityIdentity,
        candidate: &GithubInstallationTokenRevocationCandidate,
    ) -> GithubInstallationTokenRevocationOutcome {
        let Some(route) = self.exact_route(identity) else {
            return GithubInstallationTokenRevocationOutcome::Unconfirmed(
                crate::GithubInstallationTokenRevocationFailure::new(
                    GithubInstallationTokenRevocationFailureKind::InvalidResponse,
                ),
            );
        };
        route.broker.revoke(candidate).await
    }
}

/// An exact closed lifecycle mutation retained after an ambiguous Store result.
#[must_use = "an ambiguous lifecycle mutation must remain supervised"]
pub struct PendingGithubRuntimeAuthorityLifecycleCommit {
    mutation: LifecycleMutation,
}

impl PendingGithubRuntimeAuthorityLifecycleCommit {
    /// Replays the exact mutation without decrypting or calling the provider.
    ///
    /// # Errors
    ///
    /// Returns a sanitized error unless Store confirms the byte-identical
    /// lifecycle mutation.
    pub async fn replay(
        &self,
        repository: &dyn GithubRuntimeAuthorityRepository,
    ) -> Result<GithubRuntimeAuthorityReceipt, PendingGithubRuntimeAuthorityLifecycleCommitError>
    {
        let result = match &self.mutation {
            LifecycleMutation::Retry(request) => {
                repository
                    .retry_github_runtime_authority_revocation(request.clone())
                    .await
            }
            LifecycleMutation::Defer(request) => {
                repository
                    .defer_github_runtime_authority_revocation(request.clone())
                    .await
            }
            LifecycleMutation::Confirm(request) => {
                repository
                    .confirm_github_runtime_authority_revocation(*request)
                    .await
            }
            LifecycleMutation::Quarantine(request) => {
                repository
                    .quarantine_github_runtime_authority(*request)
                    .await
            }
        };
        result.map_err(|_| PendingGithubRuntimeAuthorityLifecycleCommitError)
    }

    /// Returns the exact authority key without exposing protected material.
    #[must_use]
    pub const fn key(&self) -> GithubRuntimeAuthorityKey {
        self.mutation.key()
    }
}

impl fmt::Debug for PendingGithubRuntimeAuthorityLifecycleCommit {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PendingGithubRuntimeAuthorityLifecycleCommit")
            .field("key", &self.key())
            .field("mutation", &self.mutation.kind())
            .finish()
    }
}

/// An exact lifecycle mutation was not durably confirmed.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
#[error("GitHub runtime-authority lifecycle commit was not confirmed")]
pub struct PendingGithubRuntimeAuthorityLifecycleCommitError;

#[derive(Clone, Eq, PartialEq)]
enum LifecycleMutation {
    Retry(RetryGithubRuntimeAuthorityRevocation),
    Defer(DeferGithubRuntimeAuthorityRevocation),
    Confirm(ConfirmGithubRuntimeAuthorityRevocation),
    Quarantine(QuarantineGithubRuntimeAuthority),
}

impl LifecycleMutation {
    const fn key(&self) -> GithubRuntimeAuthorityKey {
        match self {
            Self::Retry(request) => request.key(),
            Self::Defer(request) => request.key(),
            Self::Confirm(request) => request.key(),
            Self::Quarantine(request) => request.key(),
        }
    }

    const fn kind(&self) -> &'static str {
        match self {
            Self::Retry(_) => "retry",
            Self::Defer(_) => "defer",
            Self::Confirm(_) => "confirm",
            Self::Quarantine(_) => "quarantine",
        }
    }
}

/// Invalid bounded lifecycle-supervisor configuration.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum GithubRuntimeAuthorityLifecycleSupervisorError {
    /// Pending mutation capacity is zero or excessive.
    #[error("GitHub runtime-authority lifecycle supervision capacity is invalid")]
    InvalidCapacity,
    /// Exact replay interval is zero or excessive.
    #[error("GitHub runtime-authority lifecycle replay interval is invalid")]
    InvalidRetryInterval,
}

/// Bounded independent custody for exact post-provider lifecycle mutations.
pub struct GithubRuntimeAuthorityLifecycleSupervisor {
    repository: Arc<dyn GithubRuntimeAuthorityRepository>,
    runtime: Handle,
    retry_interval: Duration,
    permits: Arc<tokio::sync::Semaphore>,
    outstanding: Arc<AtomicUsize>,
    pending: Arc<AtomicUsize>,
    drained: Arc<tokio::sync::Notify>,
    custody: Arc<Mutex<Vec<Arc<SupervisedLifecycleCommit>>>>,
}

impl GithubRuntimeAuthorityLifecycleSupervisor {
    /// Constructs a supervisor with a hard pending-mutation bound.
    ///
    /// # Errors
    ///
    /// Rejects capacity outside `1..=1024` or a replay interval outside
    /// `1ms..=60s`.
    pub fn new(
        repository: Arc<dyn GithubRuntimeAuthorityRepository>,
        runtime: Handle,
        capacity: usize,
        retry_interval: Duration,
    ) -> Result<Self, GithubRuntimeAuthorityLifecycleSupervisorError> {
        if capacity == 0 || capacity > MAX_PENDING_LIFECYCLE_COMMITS {
            return Err(GithubRuntimeAuthorityLifecycleSupervisorError::InvalidCapacity);
        }
        if retry_interval.is_zero() || retry_interval > MAX_PENDING_RETRY_DELAY {
            return Err(GithubRuntimeAuthorityLifecycleSupervisorError::InvalidRetryInterval);
        }
        Ok(Self {
            repository,
            runtime,
            retry_interval,
            permits: Arc::new(tokio::sync::Semaphore::new(capacity)),
            outstanding: Arc::new(AtomicUsize::new(0)),
            pending: Arc::new(AtomicUsize::new(0)),
            drained: Arc::new(tokio::sync::Notify::new()),
            custody: Arc::new(Mutex::new(Vec::with_capacity(capacity))),
        })
    }

    fn try_reserve(&self) -> Option<LifecycleCommitReservation> {
        self.redrive_retained();
        self.outstanding.fetch_add(1, Ordering::AcqRel);
        let Ok(permit) = Arc::clone(&self.permits).try_acquire_owned() else {
            self.outstanding.fetch_sub(1, Ordering::AcqRel);
            self.drained.notify_waiters();
            return None;
        };
        Some(LifecycleCommitReservation {
            _permit: permit,
            outstanding: Arc::clone(&self.outstanding),
            drained: Arc::clone(&self.drained),
        })
    }

    fn supervise(
        &self,
        reservation: LifecycleCommitReservation,
        pending_commit: PendingGithubRuntimeAuthorityLifecycleCommit,
    ) -> oneshot::Receiver<GithubRuntimeAuthorityReceipt> {
        let custody = Arc::new(SupervisedLifecycleCommit {
            _reservation: reservation,
            _pending_observation: LifecyclePendingObservation::new(
                Arc::clone(&self.pending),
                Arc::clone(&self.drained),
            ),
            pending: pending_commit,
            task_abort: Mutex::new(None),
            driver_active: Arc::new(AtomicBool::new(false)),
            removed: AtomicBool::new(false),
        });
        self.custody
            .lock()
            .expect("runtime-authority lifecycle custody lock")
            .push(Arc::clone(&custody));

        let (result_sender, result_receiver) = oneshot::channel();
        let started = self.start_driver(&custody, Some(result_sender));
        assert!(started, "new lifecycle custody starts one driver");
        result_receiver
    }

    fn start_driver(
        &self,
        custody: &Arc<SupervisedLifecycleCommit>,
        result_sender: Option<oneshot::Sender<GithubRuntimeAuthorityReceipt>>,
    ) -> bool {
        if custody.removed.load(Ordering::Acquire) {
            return false;
        }
        if custody
            .driver_active
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return false;
        }
        if custody.removed.load(Ordering::Acquire) {
            custody.driver_active.store(false, Ordering::Release);
            self.drained.notify_waiters();
            return false;
        }
        let repository = Arc::clone(&self.repository);
        let retained = Arc::clone(&self.custody);
        let task_custody = Arc::clone(custody);
        let retry_interval = self.retry_interval;
        let driver_active = LifecycleDriverObservation {
            active: Arc::clone(&custody.driver_active),
            drained: Arc::clone(&self.drained),
        };
        let task = self.runtime.spawn(async move {
            let _driver_active = driver_active;
            let receipt = loop {
                match task_custody.pending.replay(repository.as_ref()).await {
                    Ok(receipt) => break receipt,
                    Err(_) => tokio::time::sleep(retry_interval).await,
                }
            };
            task_custody.removed.store(true, Ordering::Release);
            drop(take_lifecycle_custody(&retained, &task_custody));
            drop(task_custody);
            if let Some(result_sender) = result_sender {
                let _ = result_sender.send(receipt);
            }
        });
        *custody
            .task_abort
            .lock()
            .expect("runtime-authority lifecycle task lock") = Some(task.abort_handle());
        true
    }

    fn redrive_retained(&self) {
        let custody = self
            .custody
            .lock()
            .expect("runtime-authority lifecycle custody lock")
            .clone();
        for custody in custody {
            let _ = self.start_driver(&custody, None);
        }
    }

    #[cfg(test)]
    fn abort_pending_task(&self) -> bool {
        let custody = self
            .custody
            .lock()
            .expect("runtime-authority lifecycle custody lock")
            .first()
            .cloned();
        let Some(custody) = custody else {
            return false;
        };
        let task = custody
            .task_abort
            .lock()
            .expect("runtime-authority lifecycle task lock")
            .clone();
        task.is_some_and(|task| {
            task.abort();
            true
        })
    }

    /// Returns the number of exact lifecycle mutations under independent custody.
    #[must_use]
    pub fn pending_count(&self) -> usize {
        self.pending.load(Ordering::Acquire)
    }

    /// Closes admission for new provider-side lifecycle work during shutdown.
    /// Already-supervised mutations retain their permits and custody.
    pub fn close(&self) {
        self.permits.close();
    }

    /// Waits until every supervised lifecycle mutation commits. Process wall
    /// time can never authorize loss of pending custody.
    pub async fn wait_for_idle(&self) {
        loop {
            let notified = self.drained.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            self.redrive_retained();
            if self.outstanding.load(Ordering::Acquire) == 0 {
                return;
            }
            notified.await;
        }
    }

    /// Waits up to `timeout` for all currently supervised mutations to commit.
    ///
    /// Returns `true` when custody drained completely.
    pub async fn drain(&self, timeout: Duration) -> bool {
        tokio::time::timeout(timeout, self.wait_for_idle())
            .await
            .is_ok()
    }
}

impl fmt::Debug for GithubRuntimeAuthorityLifecycleSupervisor {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GithubRuntimeAuthorityLifecycleSupervisor")
            .field("repository", &"[AUTHORITY REPOSITORY]")
            .field("retry_interval", &self.retry_interval)
            .field("outstanding", &self.outstanding.load(Ordering::Acquire))
            .field("pending", &self.pending_count())
            .field("available_capacity", &self.permits.available_permits())
            .field(
                "retained_custody",
                &self
                    .custody
                    .lock()
                    .expect("runtime-authority lifecycle custody lock")
                    .len(),
            )
            .finish_non_exhaustive()
    }
}

struct SupervisedLifecycleCommit {
    _reservation: LifecycleCommitReservation,
    _pending_observation: LifecyclePendingObservation,
    pending: PendingGithubRuntimeAuthorityLifecycleCommit,
    task_abort: Mutex<Option<tokio::task::AbortHandle>>,
    driver_active: Arc<AtomicBool>,
    removed: AtomicBool,
}

struct LifecycleDriverObservation {
    active: Arc<AtomicBool>,
    drained: Arc<tokio::sync::Notify>,
}

impl Drop for LifecycleDriverObservation {
    fn drop(&mut self) {
        self.active.store(false, Ordering::Release);
        self.drained.notify_waiters();
    }
}

fn take_lifecycle_custody(
    retained: &Mutex<Vec<Arc<SupervisedLifecycleCommit>>>,
    target: &Arc<SupervisedLifecycleCommit>,
) -> Option<Arc<SupervisedLifecycleCommit>> {
    let mut retained = retained
        .lock()
        .expect("runtime-authority lifecycle custody lock");
    let position = retained
        .iter()
        .position(|entry| Arc::ptr_eq(entry, target))?;
    Some(retained.swap_remove(position))
}

struct LifecycleCommitReservation {
    _permit: OwnedSemaphorePermit,
    outstanding: Arc<AtomicUsize>,
    drained: Arc<tokio::sync::Notify>,
}

impl Drop for LifecycleCommitReservation {
    fn drop(&mut self) {
        self.outstanding.fetch_sub(1, Ordering::AcqRel);
        self.drained.notify_waiters();
    }
}

struct LifecyclePendingObservation {
    count: Arc<AtomicUsize>,
    drained: Arc<tokio::sync::Notify>,
}

impl LifecyclePendingObservation {
    fn new(count: Arc<AtomicUsize>, drained: Arc<tokio::sync::Notify>) -> Self {
        count.fetch_add(1, Ordering::AcqRel);
        Self { count, drained }
    }
}

impl Drop for LifecyclePendingObservation {
    fn drop(&mut self) {
        self.count.fetch_sub(1, Ordering::AcqRel);
        self.drained.notify_waiters();
    }
}

/// Result of one bounded reconcile-and-revoke maintenance step.
#[derive(Debug)]
pub struct GithubRuntimeAuthorityLifecycleOutcome {
    reconciliation: GithubRuntimeAuthorityReconciliationReport,
    revocation: GithubRuntimeAuthorityRevocationOutcome,
}

impl GithubRuntimeAuthorityLifecycleOutcome {
    /// Returns deterministic Store-only recovery reductions from this pass.
    #[must_use]
    pub const fn reconciliation(&self) -> GithubRuntimeAuthorityReconciliationReport {
        self.reconciliation
    }

    /// Returns the optional protected-token revocation result.
    #[must_use]
    pub const fn revocation(&self) -> GithubRuntimeAuthorityRevocationOutcome {
        self.revocation
    }
}

/// Closed revocation disposition for one maintenance pass.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GithubRuntimeAuthorityRevocationOutcome {
    /// No protected revocation was currently eligible.
    Idle,
    /// An exact lifecycle mutation committed durably.
    Committed(GithubRuntimeAuthorityKey),
}

/// Sanitized lifecycle coordinator failure.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum GithubRuntimeAuthorityLifecycleError {
    /// Durable reconciliation, claim, or pre-provider mutation failed.
    #[error("GitHub runtime-authority lifecycle repository operation failed")]
    Repository,
    /// Bounded pending-mutation custody is currently full.
    #[error("GitHub runtime-authority lifecycle supervision is full")]
    SupervisionCapacity,
    /// Protected metadata, frame, time, or broker configuration is inconsistent.
    #[error("GitHub runtime-authority lifecycle evidence is inconsistent")]
    Inconsistent,
}

/// Production reconcile-and-revoke coordinator for job-scoped GitHub authority.
pub struct GithubRuntimeAuthorityLifecycleCoordinator {
    repository: Arc<dyn GithubRuntimeAuthorityRepository>,
    broker: Arc<dyn GithubRuntimeAuthorityLifecycleBroker>,
    envelopes: Arc<EnvelopeCodec>,
    clock: Arc<dyn GithubRuntimeAuthorityCoordinatorClock>,
    worker: GithubRuntimeAuthorityWorkerId,
    supervisor: Arc<GithubRuntimeAuthorityLifecycleSupervisor>,
}

impl GithubRuntimeAuthorityLifecycleCoordinator {
    /// Constructs a coordinator using one no-default exact installation route.
    #[must_use]
    pub fn new(
        repository: Arc<dyn GithubRuntimeAuthorityRepository>,
        broker: Arc<dyn GithubRuntimeAuthorityLifecycleBroker>,
        envelopes: Arc<EnvelopeCodec>,
        clock: Arc<dyn GithubRuntimeAuthorityCoordinatorClock>,
        worker: GithubRuntimeAuthorityWorkerId,
        supervisor: Arc<GithubRuntimeAuthorityLifecycleSupervisor>,
    ) -> Self {
        Self {
            repository,
            broker,
            envelopes,
            clock,
            worker,
            supervisor,
        }
    }

    /// Applies one bounded reconciliation batch and at most one provider revoke.
    ///
    /// # Errors
    ///
    /// Returns a sanitized error for unavailable durable state, exhausted
    /// supervision capacity, or inconsistent protected lifecycle evidence.
    pub async fn coordinate_once(
        &self,
    ) -> Result<GithubRuntimeAuthorityLifecycleOutcome, GithubRuntimeAuthorityLifecycleError> {
        let stop = CancellationToken::new();
        self.coordinate_once_until_stopped(&stop)
            .await?
            .ok_or(GithubRuntimeAuthorityLifecycleError::Repository)
    }

    /// Applies one bounded pass while observing shutdown at custody-safe boundaries.
    ///
    /// A stop that arrives before provider work prevents a new provider call. A
    /// stop during an already-started provider call is observed only after that
    /// call returns and its exact lifecycle mutation has moved into independent
    /// supervision. `None` therefore never abandons provider-result custody.
    ///
    /// # Errors
    ///
    /// Returns the same sanitized failures as [`Self::coordinate_once`].
    pub async fn coordinate_once_until_stopped(
        &self,
        stop: &CancellationToken,
    ) -> Result<Option<GithubRuntimeAuthorityLifecycleOutcome>, GithubRuntimeAuthorityLifecycleError>
    {
        if stop.is_cancelled() {
            return Ok(None);
        }
        let observed_at = self.clock.now();
        let reconcile = ReconcileGithubRuntimeAuthorities::new(
            observed_at,
            MAX_GITHUB_AUTHORITY_RECONCILE_BATCH,
        )
        .map_err(|_| GithubRuntimeAuthorityLifecycleError::Inconsistent)?;
        let reconciliation = self
            .repository
            .reconcile_github_runtime_authorities(reconcile)
            .await
            .map_err(|_| GithubRuntimeAuthorityLifecycleError::Repository)?;
        if stop.is_cancelled() {
            return Ok(None);
        }

        let Some(reservation) = self.supervisor.try_reserve() else {
            if stop.is_cancelled() {
                return Ok(None);
            }
            return Err(GithubRuntimeAuthorityLifecycleError::SupervisionCapacity);
        };
        let claim_expires_at = observed_at
            .get()
            .checked_add(MAX_GITHUB_AUTHORITY_REVOKE_CLAIM_MILLIS)
            .map(UnixMillis::new)
            .ok_or(GithubRuntimeAuthorityLifecycleError::Inconsistent)?;
        let claim =
            ClaimGithubRuntimeAuthorityRevocation::new(self.worker, observed_at, claim_expires_at)
                .map_err(|_| GithubRuntimeAuthorityLifecycleError::Inconsistent)?;
        let Some(claimed) = self
            .repository
            .claim_github_runtime_authority_revocation(claim)
            .await
            .map_err(|_| GithubRuntimeAuthorityLifecycleError::Repository)?
        else {
            drop(reservation);
            return Ok(Some(GithubRuntimeAuthorityLifecycleOutcome {
                reconciliation,
                revocation: GithubRuntimeAuthorityRevocationOutcome::Idle,
            }));
        };
        let mutation = self
            .revocation_mutation_until_stopped(&claimed, stop)
            .await?;
        let key = mutation.key();
        let completion = self.supervisor.supervise(
            reservation,
            PendingGithubRuntimeAuthorityLifecycleCommit { mutation },
        );
        tokio::select! {
            biased;
            result = completion => {
                result.map_err(|_| GithubRuntimeAuthorityLifecycleError::Repository)?;
                Ok(Some(GithubRuntimeAuthorityLifecycleOutcome {
                    reconciliation,
                    revocation: GithubRuntimeAuthorityRevocationOutcome::Committed(key),
                }))
            }
            () = stop.cancelled() => Ok(None),
        }
    }

    #[cfg(test)]
    async fn revocation_mutation(
        &self,
        claimed: &ClaimedGithubRuntimeAuthorityRevocation,
    ) -> Result<LifecycleMutation, GithubRuntimeAuthorityLifecycleError> {
        let stop = CancellationToken::new();
        self.revocation_mutation_until_stopped(claimed, &stop).await
    }

    async fn revocation_mutation_until_stopped(
        &self,
        claimed: &ClaimedGithubRuntimeAuthorityRevocation,
        stop: &CancellationToken,
    ) -> Result<LifecycleMutation, GithubRuntimeAuthorityLifecycleError> {
        let observed_at = self.clock.now().max(claimed.claimed_at());
        if stop.is_cancelled() {
            return defer_mutation(claimed, "shutdown_before_provider", observed_at);
        }
        let identity = claimed.protected().metadata().identity();
        let Some(maximum_duration) = self.broker.maximum_request_duration(identity) else {
            return defer_mutation(claimed, "installation_route_unavailable", observed_at);
        };
        let metadata = claimed.protected().metadata();
        let (wrapping_context, payload_context) = revocation_encryption_contexts(metadata)?;
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
                return retry_mutation(claimed, "key_management_unavailable", observed_at, None);
            }
            Err(error) => {
                let request = QuarantineGithubRuntimeAuthority::new(
                    claimed.protected(),
                    envelope_corruption(error),
                    observed_at,
                )
                .map_err(|_| GithubRuntimeAuthorityLifecycleError::Inconsistent)?;
                return Ok(LifecycleMutation::Quarantine(request));
            }
        };
        let Ok(candidate) = decode_installation_token_frame(&plaintext, metadata) else {
            let request = QuarantineGithubRuntimeAuthority::new(
                claimed.protected(),
                GithubRuntimeAuthorityCorruptionKind::InvalidEnvelope,
                observed_at,
            )
            .map_err(|_| GithubRuntimeAuthorityLifecycleError::Inconsistent)?;
            return Ok(LifecycleMutation::Quarantine(request));
        };
        drop(plaintext);
        if stop.is_cancelled() {
            drop(candidate);
            return defer_mutation(claimed, "shutdown_before_provider", observed_at);
        }
        let provider_request_millis = exact_provider_request_millis(maximum_duration)?;
        let revalidation =
            RevalidateGithubRuntimeAuthorityRevocation::new(claimed, provider_request_millis)
                .map_err(|_| GithubRuntimeAuthorityLifecycleError::Inconsistent)?;
        let Some(revalidated) = self
            .repository
            .revalidate_github_runtime_authority_revocation(revalidation)
            .await
            .map_err(|_| GithubRuntimeAuthorityLifecycleError::Repository)?
        else {
            drop(candidate);
            return Err(GithubRuntimeAuthorityLifecycleError::Inconsistent);
        };
        let observed_at = revalidated.observed_at();
        if !revalidated.provider_call_authorized() {
            drop(candidate);
            return defer_mutation(claimed, "revocation_window_exhausted", observed_at);
        }
        if stop.is_cancelled() {
            drop(candidate);
            return defer_mutation(claimed, "shutdown_before_provider", observed_at);
        }
        let outcome = self.broker.revoke(identity, &candidate).await;
        drop(candidate);
        match outcome {
            GithubInstallationTokenRevocationOutcome::Confirmed => {
                ConfirmGithubRuntimeAuthorityRevocation::provider_no_content(claimed, observed_at)
                    .map(LifecycleMutation::Confirm)
                    .map_err(|_| GithubRuntimeAuthorityLifecycleError::Inconsistent)
            }
            GithubInstallationTokenRevocationOutcome::Unconfirmed(failure) => {
                if failure.is_retryable() {
                    retry_mutation(
                        claimed,
                        revocation_failure_kind(failure.kind()),
                        observed_at,
                        failure.retry_after_seconds(),
                    )
                } else {
                    defer_mutation(
                        claimed,
                        revocation_failure_kind(failure.kind()),
                        observed_at,
                    )
                }
            }
        }
    }
}

impl fmt::Debug for GithubRuntimeAuthorityLifecycleCoordinator {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GithubRuntimeAuthorityLifecycleCoordinator")
            .field("repository", &"[AUTHORITY REPOSITORY]")
            .field("broker", &self.broker)
            .field("envelopes", &self.envelopes)
            .field("clock", &self.clock)
            .field("worker", &self.worker)
            .field("supervisor", &self.supervisor)
            .finish()
    }
}

fn exact_provider_request_millis(
    maximum_duration: Duration,
) -> Result<i64, GithubRuntimeAuthorityLifecycleError> {
    whole_milliseconds(maximum_duration)
        .and_then(|duration| i64::try_from(duration).ok())
        .filter(|duration| *duration > 0)
        .ok_or(GithubRuntimeAuthorityLifecycleError::Inconsistent)
}

fn revocation_encryption_contexts(
    metadata: &automata_ci_store::GithubRuntimeAuthorityEnvelopeMetadata,
) -> Result<(KeyEncryptionContext, KeyEncryptionContext), GithubRuntimeAuthorityLifecycleError> {
    let wrapping = metadata
        .identity()
        .wrapping_encryption_context()
        .map_err(|_| GithubRuntimeAuthorityLifecycleError::Inconsistent)?;
    let payload = metadata
        .encryption_context()
        .map_err(|_| GithubRuntimeAuthorityLifecycleError::Inconsistent)?;
    Ok((wrapping, payload))
}

fn retry_mutation(
    claimed: &ClaimedGithubRuntimeAuthorityRevocation,
    kind: &'static str,
    observed_at: UnixMillis,
    retry_after_seconds: Option<u64>,
) -> Result<LifecycleMutation, GithubRuntimeAuthorityLifecycleError> {
    let requested_delay = retry_after_seconds
        .and_then(|seconds| seconds.checked_mul(1_000))
        .and_then(|milliseconds| i64::try_from(milliseconds).ok())
        .unwrap_or(DEFAULT_REVOKE_RETRY_MILLIS)
        .clamp(1, MAX_GITHUB_AUTHORITY_REVOKE_BACKOFF_MILLIS);
    let Some(retry_at) = bounded_retry_at(
        observed_at,
        requested_delay,
        claimed.protected().metadata().safe_erase_after(),
    ) else {
        return defer_mutation(claimed, kind, observed_at);
    };
    let failure = GithubRuntimeAuthorityRevocationFailure::new(kind)
        .map_err(|_| GithubRuntimeAuthorityLifecycleError::Inconsistent)?;
    RetryGithubRuntimeAuthorityRevocation::new(claimed, failure, observed_at, retry_at)
        .map(LifecycleMutation::Retry)
        .map_err(|_| GithubRuntimeAuthorityLifecycleError::Inconsistent)
}

fn defer_mutation(
    claimed: &ClaimedGithubRuntimeAuthorityRevocation,
    kind: &'static str,
    observed_at: UnixMillis,
) -> Result<LifecycleMutation, GithubRuntimeAuthorityLifecycleError> {
    let failure = GithubRuntimeAuthorityRevocationFailure::new(kind)
        .map_err(|_| GithubRuntimeAuthorityLifecycleError::Inconsistent)?;
    DeferGithubRuntimeAuthorityRevocation::new(claimed, failure, observed_at)
        .map(LifecycleMutation::Defer)
        .map_err(|_| GithubRuntimeAuthorityLifecycleError::Inconsistent)
}

fn decode_installation_token_frame(
    plaintext: &SecretBytes,
    metadata: &automata_ci_store::GithubRuntimeAuthorityEnvelopeMetadata,
) -> Result<GithubInstallationTokenRevocationCandidate, ()> {
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
    if token.len() != token_length || token.is_empty() || !token.iter().all(u8::is_ascii_graphic) {
        return Err(());
    }
    let secret =
        SecretString::new(String::from_utf8(token.to_vec()).map_err(|_| ())?).map_err(|_| ())?;
    GithubInstallationTokenRevocationCandidate::from_protected_secret(secret).map_err(|_| ())
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
            unreachable!("key-management unavailability is handled before classification")
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{
        Mutex,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    };

    use async_trait::async_trait;
    use automata_ci_core::{
        AttemptId, FencingToken, JobId, JobIrVersion, LeaseId, RunId, RunnerId, RunnerSessionId,
    };
    use automata_ci_key_management::{
        KeyEncryptionContext, KeyEncryptionProvider, KeyId, LocalAes256GcmKeyring,
        LocalKeyMaterial, WrappedDataKey,
    };
    use automata_ci_store::{
        AuthenticateGithubRuntimeAuthorityUnprotectedErasure, BeginGithubRuntimeAuthorityMint,
        BeginGithubRuntimeAuthorityMintOutcome, ClaimGithubRuntimeAuthorityMint,
        ClaimGithubRuntimeAuthorityRevocation, ClaimedGithubRuntimeAuthorityMint,
        ClaimedGithubRuntimeAuthorityRevocation, CommitGithubRuntimeAuthority,
        ConfirmGithubRuntimeAuthorityRevocation, DeferGithubRuntimeAuthorityRevocation,
        GithubRepositoryId, GithubRepositoryName, GithubRuntimeAuthorityActivationSelectionTail,
        GithubRuntimeAuthorityClaimFence, GithubRuntimeAuthorityEnvelopeMetadata,
        GithubRuntimeAuthorityIdentity, GithubRuntimeAuthorityInspection,
        GithubRuntimeAuthorityMaterializationSelectionTail, GithubRuntimeAuthorityNamespace,
        GithubRuntimeAuthorityPreparationSelectionTail, GithubRuntimeAuthorityReceipt,
        GithubRuntimeAuthorityReconciliationReport, GithubRuntimeAuthorityState,
        GithubRuntimeAuthorityStoreError, GithubRuntimeAuthorityTerminalReason,
        InspectGithubRuntimeAuthority, LoadGithubRuntimeAuthority, LogicalActivationGeneration,
        LogicalActivationPreparationGeneration, LogicalActivationWorkerId,
        LogicalMaterializationGeneration, LogicalMaterializationWorkerId, LogicalWorkSelectionId,
        MarkGithubRuntimeAuthorityIndeterminate, ProtectedGithubRuntimeAuthority,
        ProviderConnectionId, ProviderInstallationId, QuarantineGithubRuntimeAuthority,
        ReadyGithubRuntimeAuthority, ReconcileGithubRuntimeAuthorities,
        RejectGithubRuntimeAuthorityMint, RepositoryId, RetryGithubRuntimeAuthorityMint,
        RetryGithubRuntimeAuthorityRevocation, RevalidatedGithubRuntimeAuthorityRevocation,
        RunnerGeneration, SessionEpoch, StableRunnerSlot, TenantScope,
    };

    use super::*;
    use crate::GithubInstallationTokenRevocationOutcome;

    #[tokio::test]
    async fn idle_pass_reconciles_once_and_never_calls_a_provider_route() {
        let repository = Arc::new(IdleRepository::default());
        let repository_port: Arc<dyn GithubRuntimeAuthorityRepository> = repository.clone();
        let clock: Arc<dyn GithubRuntimeAuthorityCoordinatorClock> =
            Arc::new(FixedClock(UnixMillis::new(1_000)));
        let supervisor = Arc::new(
            GithubRuntimeAuthorityLifecycleSupervisor::new(
                repository_port.clone(),
                tokio::runtime::Handle::current(),
                2,
                Duration::from_millis(1),
            )
            .expect("supervisor"),
        );
        let broker = Arc::new(NoCallBroker::default());
        let coordinator = GithubRuntimeAuthorityLifecycleCoordinator::new(
            repository_port,
            broker.clone(),
            Arc::new(EnvelopeCodec::new(Arc::new(UnavailableKeys))),
            clock,
            GithubRuntimeAuthorityWorkerId::from_uuid(uuid::Uuid::new_v4()).expect("worker"),
            supervisor.clone(),
        );

        let outcome = coordinator.coordinate_once().await.expect("idle pass");
        assert_eq!(outcome.reconciliation().total(), 0);
        assert_eq!(
            outcome.revocation(),
            GithubRuntimeAuthorityRevocationOutcome::Idle
        );
        assert_eq!(repository.reconciliations.load(Ordering::SeqCst), 1);
        assert_eq!(repository.revocation_claims.load(Ordering::SeqCst), 1);
        assert_eq!(broker.calls.load(Ordering::SeqCst), 0);
        supervisor.close();
        supervisor.wait_for_idle().await;
    }

    #[tokio::test]
    async fn stopped_pass_starts_no_reconciliation_claim_or_provider_work() {
        let repository = Arc::new(IdleRepository::default());
        let repository_port: Arc<dyn GithubRuntimeAuthorityRepository> = repository.clone();
        let clock: Arc<dyn GithubRuntimeAuthorityCoordinatorClock> =
            Arc::new(FixedClock(UnixMillis::new(1_000)));
        let supervisor = Arc::new(
            GithubRuntimeAuthorityLifecycleSupervisor::new(
                repository_port.clone(),
                tokio::runtime::Handle::current(),
                1,
                Duration::from_millis(1),
            )
            .expect("supervisor"),
        );
        let broker = Arc::new(NoCallBroker::default());
        let coordinator = GithubRuntimeAuthorityLifecycleCoordinator::new(
            repository_port,
            broker.clone(),
            Arc::new(EnvelopeCodec::new(Arc::new(UnavailableKeys))),
            clock,
            GithubRuntimeAuthorityWorkerId::from_uuid(uuid::Uuid::new_v4()).expect("worker"),
            supervisor.clone(),
        );
        let stop = CancellationToken::new();
        stop.cancel();

        assert!(
            coordinator
                .coordinate_once_until_stopped(&stop)
                .await
                .expect("stopped pass")
                .is_none()
        );
        assert_eq!(repository.reconciliations.load(Ordering::SeqCst), 0);
        assert_eq!(repository.revocation_claims.load(Ordering::SeqCst), 0);
        assert_eq!(broker.calls.load(Ordering::SeqCst), 0);
        assert_eq!(supervisor.pending_count(), 0);
        assert!(supervisor.drain(Duration::from_millis(10)).await);
    }

    #[tokio::test]
    async fn stop_after_provider_handoff_keeps_exact_mutation_and_reuses_permit() {
        let codec = lifecycle_test_codec();
        let claim = lifecycle_test_claim(codec.as_ref()).await;
        let repository = Arc::new(IdleRepository {
            revalidation_observed_at: Some(UnixMillis::new(1_200)),
            revocation_claim: Mutex::new(Some(claim)),
            ..IdleRepository::default()
        });
        let repository_port: Arc<dyn GithubRuntimeAuthorityRepository> = repository.clone();
        let broker = Arc::new(RevalidationBroker::default());
        let clock: Arc<dyn GithubRuntimeAuthorityCoordinatorClock> =
            Arc::new(FixedClock(UnixMillis::new(1_200)));
        let supervisor = Arc::new(
            GithubRuntimeAuthorityLifecycleSupervisor::new(
                repository_port.clone(),
                tokio::runtime::Handle::current(),
                1,
                Duration::from_millis(1),
            )
            .expect("supervisor"),
        );
        let coordinator = Arc::new(GithubRuntimeAuthorityLifecycleCoordinator::new(
            repository_port,
            broker.clone(),
            codec,
            clock,
            GithubRuntimeAuthorityWorkerId::from_uuid(uuid::Uuid::new_v4()).expect("worker"),
            supervisor.clone(),
        ));
        let stop = CancellationToken::new();
        let pass = tokio::spawn({
            let coordinator = coordinator.clone();
            let stop = stop.clone();
            async move { coordinator.coordinate_once_until_stopped(&stop).await }
        });

        tokio::time::timeout(Duration::from_secs(1), async {
            while repository.commit_attempts.load(Ordering::SeqCst) == 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("exact post-provider mutation reached independent custody");
        assert_eq!(broker.revocations.load(Ordering::SeqCst), 1);
        stop.cancel();
        assert!(
            pass.await
                .expect("pass task")
                .expect("stopped pass")
                .is_none()
        );
        assert_eq!(supervisor.pending_count(), 1);
        assert!(!supervisor.drain(Duration::from_millis(5)).await);

        repository.commit_confirmed.store(true, Ordering::SeqCst);
        assert!(supervisor.drain(Duration::from_secs(1)).await);
        assert_eq!(supervisor.pending_count(), 0);
        assert!(
            supervisor.try_reserve().is_some(),
            "the bounded permit is reusable after exact replay"
        );
    }

    #[tokio::test]
    async fn lifecycle_watchdog_task_loss_retains_custody_and_never_false_drains() {
        let codec = lifecycle_test_codec();
        let claim = lifecycle_test_claim(codec.as_ref()).await;
        let repository = Arc::new(IdleRepository {
            revalidation_observed_at: Some(UnixMillis::new(1_200)),
            revocation_claim: Mutex::new(Some(claim)),
            ..IdleRepository::default()
        });
        let repository_port: Arc<dyn GithubRuntimeAuthorityRepository> = repository.clone();
        let broker = Arc::new(RevalidationBroker::default());
        let supervisor = Arc::new(
            GithubRuntimeAuthorityLifecycleSupervisor::new(
                repository_port.clone(),
                tokio::runtime::Handle::current(),
                1,
                Duration::from_millis(1),
            )
            .expect("supervisor"),
        );
        let coordinator = Arc::new(GithubRuntimeAuthorityLifecycleCoordinator::new(
            repository_port,
            broker.clone(),
            codec,
            Arc::new(FixedClock(UnixMillis::new(1_200))),
            GithubRuntimeAuthorityWorkerId::from_uuid(uuid::Uuid::from_u128(94)).expect("worker"),
            Arc::clone(&supervisor),
        ));
        let stop = CancellationToken::new();
        let pass = tokio::spawn({
            let coordinator = Arc::clone(&coordinator);
            async move { coordinator.coordinate_once_until_stopped(&stop).await }
        });

        tokio::time::timeout(Duration::from_secs(1), async {
            while repository.commit_attempts.load(Ordering::SeqCst) == 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("lifecycle watchdog attempted the exact mutation");
        assert!(supervisor.abort_pending_task(), "lifecycle watchdog exists");
        assert_eq!(
            pass.await.expect("maintenance pass").unwrap_err(),
            GithubRuntimeAuthorityLifecycleError::Repository
        );
        assert_eq!(supervisor.pending_count(), 1);
        assert!(!supervisor.drain(Duration::from_millis(5)).await);
        assert!(
            supervisor.try_reserve().is_none(),
            "lost-task lifecycle custody retains its bounded permit"
        );
        repository.commit_confirmed.store(true, Ordering::SeqCst);
        assert!(supervisor.drain(Duration::from_secs(1)).await);
        assert_eq!(supervisor.pending_count(), 0);
        assert!(repository.commit_attempts.load(Ordering::SeqCst) >= 2);
        assert_eq!(broker.revocations.load(Ordering::SeqCst), 1);
        assert!(supervisor.try_reserve().is_some());
        let confirmed_attempts = repository.commit_attempts.load(Ordering::SeqCst);
        for _ in 0..32 {
            supervisor.redrive_retained();
            tokio::task::yield_now().await;
        }
        assert_eq!(
            repository.commit_attempts.load(Ordering::SeqCst),
            confirmed_attempts,
            "removed lifecycle custody must never restart after confirmation"
        );
    }

    #[tokio::test]
    async fn removed_lifecycle_custody_rejects_its_exact_stale_driver() {
        let codec = lifecycle_test_codec();
        let claim = lifecycle_test_claim(codec.as_ref()).await;
        let mutation = LifecycleMutation::Confirm(
            ConfirmGithubRuntimeAuthorityRevocation::provider_no_content(
                &claim,
                claim.claimed_at(),
            )
            .expect("confirm mutation"),
        );
        let expected = mutation.clone();
        let gate = Arc::new(LifecycleMutationGate::default());
        let repository = Arc::new(IdleRepository {
            mutation_gate: Some(Arc::clone(&gate)),
            ..IdleRepository::default()
        });
        let repository_port: Arc<dyn GithubRuntimeAuthorityRepository> = repository.clone();
        let supervisor = Arc::new(
            GithubRuntimeAuthorityLifecycleSupervisor::new(
                repository_port,
                Handle::current(),
                1,
                Duration::from_millis(1),
            )
            .expect("supervisor"),
        );
        let reservation = supervisor.try_reserve().expect("initial capacity");
        let result = supervisor.supervise(
            reservation,
            PendingGithubRuntimeAuthorityLifecycleCommit { mutation },
        );

        gate.wait_until_entered().await;
        repository.assert_exact_mutation_attempts(&expected, 1);
        let stale_custody = supervisor
            .custody
            .lock()
            .expect("runtime-authority lifecycle custody lock")
            .first()
            .cloned()
            .expect("lifecycle custody retained before confirmation");
        gate.release();
        result.await.expect("confirmed lifecycle mutation");
        tokio::time::timeout(Duration::from_secs(1), async {
            while !stale_custody.removed.load(Ordering::Acquire)
                || stale_custody.driver_active.load(Ordering::Acquire)
            {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("lifecycle custody removed with no active driver");

        assert!(!supervisor.start_driver(&stale_custody, None));
        tokio::task::yield_now().await;
        repository.assert_exact_mutation_attempts(&expected, 1);
        assert!(!supervisor.drain(Duration::from_millis(5)).await);

        drop(stale_custody);
        assert!(supervisor.drain(Duration::from_secs(1)).await);
        assert!(supervisor.try_reserve().is_some());
    }

    #[tokio::test]
    async fn every_lifecycle_mutation_shape_replays_its_exact_store_operation() {
        let codec = lifecycle_test_codec();
        let claim = lifecycle_test_claim(codec.as_ref()).await;
        let observed_at = claim.claimed_at();
        let mutations = [
            retry_mutation(&claim, "shape_retry", observed_at, None).expect("retry mutation"),
            defer_mutation(&claim, "shape_defer", observed_at).expect("defer mutation"),
            LifecycleMutation::Confirm(
                ConfirmGithubRuntimeAuthorityRevocation::provider_no_content(&claim, observed_at)
                    .expect("confirm mutation"),
            ),
            LifecycleMutation::Quarantine(
                QuarantineGithubRuntimeAuthority::new(
                    claim.protected(),
                    GithubRuntimeAuthorityCorruptionKind::InvalidEnvelope,
                    observed_at,
                )
                .expect("quarantine mutation"),
            ),
        ];
        for mutation in mutations {
            let expected = mutation.clone();
            let gate = Arc::new(LifecycleMutationGate::default());
            let repository = Arc::new(IdleRepository {
                mutation_gate: Some(Arc::clone(&gate)),
                ..IdleRepository::default()
            });
            let repository_port: Arc<dyn GithubRuntimeAuthorityRepository> = repository.clone();
            let supervisor = Arc::new(
                GithubRuntimeAuthorityLifecycleSupervisor::new(
                    repository_port,
                    Handle::current(),
                    1,
                    Duration::from_millis(1),
                )
                .expect("supervisor"),
            );
            let reservation = supervisor.try_reserve().expect("initial capacity");
            let result = supervisor.supervise(
                reservation,
                PendingGithubRuntimeAuthorityLifecycleCommit { mutation },
            );

            gate.wait_until_entered().await;
            repository.assert_exact_mutation_attempts(&expected, 1);
            assert!(supervisor.abort_pending_task(), "lifecycle driver exists");
            assert!(result.await.is_err(), "aborted driver drops its observer");
            assert_eq!(supervisor.pending_count(), 1);
            assert!(!supervisor.drain(Duration::from_millis(5)).await);
            assert!(
                supervisor.try_reserve().is_none(),
                "retained lifecycle mutation keeps capacity reserved"
            );

            gate.wait_until_entered().await;
            repository.assert_exact_mutation_attempts(&expected, 2);
            let hammer_started = CancellationToken::new();
            let stop_hammer = CancellationToken::new();
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
            hammer.await.expect("lifecycle redrive hammer");
            assert_eq!(supervisor.pending_count(), 0);
            assert!(supervisor.try_reserve().is_some());

            for _ in 0..32 {
                supervisor.redrive_retained();
                tokio::task::yield_now().await;
            }
            repository.assert_exact_mutation_attempts(&expected, 2);
        }
    }

    #[tokio::test]
    async fn closed_supervisor_rejects_new_lifecycle_work_and_drains() {
        let repository: Arc<dyn GithubRuntimeAuthorityRepository> =
            Arc::new(IdleRepository::default());
        let supervisor = GithubRuntimeAuthorityLifecycleSupervisor::new(
            repository,
            tokio::runtime::Handle::current(),
            1,
            Duration::from_millis(1),
        )
        .expect("supervisor");
        supervisor.close();
        assert!(supervisor.try_reserve().is_none());
        assert!(supervisor.drain(Duration::from_millis(10)).await);
    }

    #[tokio::test]
    async fn stale_post_decrypt_revalidation_never_calls_provider() {
        let repository = Arc::new(IdleRepository::default());
        let repository_port: Arc<dyn GithubRuntimeAuthorityRepository> = repository.clone();
        let broker = Arc::new(RevalidationBroker::default());
        let clock: Arc<dyn GithubRuntimeAuthorityCoordinatorClock> =
            Arc::new(FixedClock(UnixMillis::new(1_200)));
        let codec = lifecycle_test_codec();
        let supervisor = Arc::new(
            GithubRuntimeAuthorityLifecycleSupervisor::new(
                repository_port.clone(),
                tokio::runtime::Handle::current(),
                1,
                Duration::from_millis(1),
            )
            .expect("supervisor"),
        );
        let coordinator = GithubRuntimeAuthorityLifecycleCoordinator::new(
            repository_port,
            broker.clone(),
            codec.clone(),
            clock,
            GithubRuntimeAuthorityWorkerId::from_uuid(uuid::Uuid::from_u128(90)).expect("worker"),
            supervisor,
        );
        let claim = lifecycle_test_claim(codec.as_ref()).await;

        assert!(matches!(
            coordinator.revocation_mutation(&claim).await,
            Err(GithubRuntimeAuthorityLifecycleError::Inconsistent)
        ));
        assert_eq!(repository.revalidations.load(Ordering::SeqCst), 1);
        assert_eq!(broker.route_checks.load(Ordering::SeqCst), 1);
        assert_eq!(broker.revocations.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn insufficient_store_window_defers_without_calling_provider() {
        let repository = Arc::new(IdleRepository {
            revalidation_observed_at: Some(UnixMillis::new(1_990)),
            ..IdleRepository::default()
        });
        let repository_port: Arc<dyn GithubRuntimeAuthorityRepository> = repository.clone();
        let broker = Arc::new(RevalidationBroker::default());
        let clock: Arc<dyn GithubRuntimeAuthorityCoordinatorClock> =
            Arc::new(FixedClock(UnixMillis::new(1_200)));
        let codec = lifecycle_test_codec();
        let supervisor = Arc::new(
            GithubRuntimeAuthorityLifecycleSupervisor::new(
                repository_port.clone(),
                tokio::runtime::Handle::current(),
                1,
                Duration::from_millis(1),
            )
            .expect("supervisor"),
        );
        let coordinator = GithubRuntimeAuthorityLifecycleCoordinator::new(
            repository_port,
            broker.clone(),
            codec.clone(),
            clock,
            GithubRuntimeAuthorityWorkerId::from_uuid(uuid::Uuid::from_u128(92)).expect("worker"),
            supervisor,
        );
        let claim = lifecycle_test_claim(codec.as_ref()).await;

        let Ok(LifecycleMutation::Defer(defer)) = coordinator.revocation_mutation(&claim).await
        else {
            panic!("an insufficient Store-issued window must defer exact custody");
        };
        assert_eq!(defer.failure().as_str(), "revocation_window_exhausted");
        assert_eq!(defer.observed_at(), UnixMillis::new(1_990));
        assert_eq!(repository.revalidations.load(Ordering::SeqCst), 1);
        assert_eq!(broker.route_checks.load(Ordering::SeqCst), 1);
        assert_eq!(broker.revocations.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn fractional_millisecond_provider_window_never_revalidates_or_calls_provider() {
        let repository = Arc::new(IdleRepository::default());
        let repository_port: Arc<dyn GithubRuntimeAuthorityRepository> = repository.clone();
        let broker = Arc::new(RevalidationBroker::default());
        broker.fractional_duration.store(true, Ordering::SeqCst);
        let codec = lifecycle_test_codec();
        let supervisor = Arc::new(
            GithubRuntimeAuthorityLifecycleSupervisor::new(
                repository_port.clone(),
                tokio::runtime::Handle::current(),
                1,
                Duration::from_millis(1),
            )
            .expect("supervisor"),
        );
        let coordinator = GithubRuntimeAuthorityLifecycleCoordinator::new(
            repository_port,
            broker.clone(),
            codec.clone(),
            Arc::new(FixedClock(UnixMillis::new(1_200))),
            GithubRuntimeAuthorityWorkerId::from_uuid(uuid::Uuid::from_u128(93)).expect("worker"),
            supervisor,
        );
        let claim = lifecycle_test_claim(codec.as_ref()).await;

        assert!(matches!(
            coordinator.revocation_mutation(&claim).await,
            Err(GithubRuntimeAuthorityLifecycleError::Inconsistent)
        ));
        assert_eq!(broker.route_checks.load(Ordering::SeqCst), 1);
        assert_eq!(repository.revalidations.load(Ordering::SeqCst), 0);
        assert_eq!(broker.revocations.load(Ordering::SeqCst), 0);
    }

    #[derive(Debug)]
    struct FixedClock(UnixMillis);

    impl GithubRuntimeAuthorityCoordinatorClock for FixedClock {
        fn now(&self) -> UnixMillis {
            self.0
        }
    }

    fn lifecycle_test_identity() -> GithubRuntimeAuthorityIdentity {
        let job_ir_digest = Sha256Digest::from_bytes([10; 32]);
        let activation_owner = LogicalActivationWorkerId::from_uuid(uuid::Uuid::from_u128(100))
            .expect("activation owner");
        let preparation_tail = GithubRuntimeAuthorityPreparationSelectionTail::new(
            LogicalWorkSelectionId::from_uuid(uuid::Uuid::from_u128(101))
                .expect("preparation selection"),
            activation_owner,
            LogicalActivationPreparationGeneration::new(1).expect("preparation generation"),
            Sha256Digest::from_bytes([31; 32]),
            UnixMillis::new(900),
            UnixMillis::new(10_900),
        )
        .expect("preparation tail");
        let activation_tail = GithubRuntimeAuthorityActivationSelectionTail::new(
            LogicalWorkSelectionId::from_uuid(uuid::Uuid::from_u128(102))
                .expect("activation selection"),
            activation_owner,
            LogicalActivationGeneration::new(2).expect("activation generation"),
            Sha256Digest::from_bytes([32; 32]),
            UnixMillis::new(900),
            UnixMillis::new(10_900),
        )
        .expect("activation tail");
        let materialization_tail = GithubRuntimeAuthorityMaterializationSelectionTail::new(
            LogicalWorkSelectionId::from_uuid(uuid::Uuid::from_u128(103))
                .expect("materialization selection"),
            LogicalMaterializationWorkerId::from_uuid(uuid::Uuid::from_u128(104))
                .expect("materialization owner"),
            LogicalMaterializationGeneration::new(3).expect("materialization generation"),
            Sha256Digest::from_bytes([33; 32]),
            UnixMillis::new(900),
            UnixMillis::new(10_900),
        )
        .expect("materialization tail");
        GithubRuntimeAuthorityIdentity::new(
            TenantScope::from_authenticated_tenant_id("tenant-a").expect("tenant"),
            AttemptId::from_uuid(uuid::Uuid::from_u128(1)),
            FencingToken::new(7).expect("attempt fence"),
            LeaseId::from_uuid(uuid::Uuid::from_u128(2)),
            UnixMillis::new(900),
            UnixMillis::new(180_000),
            RunId::from_uuid(uuid::Uuid::from_u128(3)),
            JobId::from_uuid(uuid::Uuid::from_u128(4)),
            RunnerId::from_uuid(uuid::Uuid::from_u128(5)),
            RunnerSessionId::from_uuid(uuid::Uuid::from_u128(6)),
            SessionEpoch::new(8).expect("session epoch"),
            RunnerGeneration::new(9).expect("runner generation"),
            StableRunnerSlot::new(1).expect("runner slot"),
            JobIrVersion::current(),
            1_024,
            job_ir_digest,
            RepositoryId::from_uuid(uuid::Uuid::from_u128(11)),
            ProviderConnectionId::from_uuid(uuid::Uuid::from_u128(16))
                .expect("provider connection"),
            ProviderInstallationId::new(17).expect("provider installation"),
            GithubServerServiceAppId::new(18).expect("App ID"),
            GithubServerServiceAppClientId::new("Iv1.automata-runtime").expect("App client ID"),
            GithubServerServiceJwtIssuer::AppClientId,
            GithubRepositoryId::new(12).expect("GitHub repository ID"),
            GithubRepositoryName::new("automata-ci/automata").expect("repository name"),
            GithubRuntimeAuthorityNamespace::new("github.actions.runtime")
                .expect("authority namespace"),
            job_ir_digest,
            Sha256Digest::from_bytes([13; 32]),
            Sha256Digest::from_bytes([15; 32]),
            preparation_tail,
            activation_tail,
            materialization_tail,
            UnixMillis::new(1_000),
            UnixMillis::new(120_000),
        )
        .expect("runtime-authority identity")
    }

    fn lifecycle_test_codec() -> Arc<EnvelopeCodec> {
        let material = LocalKeyMaterial::new(
            KeyId::new("github-lifecycle-test-v1").expect("key ID"),
            SecretBytes::new(vec![0x42; 32]).expect("key material"),
        )
        .expect("local key material");
        let keys = LocalAes256GcmKeyring::new(material, Vec::new(), Vec::<KeyId>::new())
            .expect("local keyring");
        Arc::new(EnvelopeCodec::new(Arc::new(keys)))
    }

    async fn lifecycle_test_claim(
        codec: &EnvelopeCodec,
    ) -> ClaimedGithubRuntimeAuthorityRevocation {
        let identity = lifecycle_test_identity();
        let token = b"ghs_exact-lifecycle-token";
        let mut frame = Vec::from(INSTALLATION_TOKEN_FRAME_DOMAIN);
        frame.extend_from_slice(
            &u32::try_from(token.len())
                .expect("token length")
                .to_be_bytes(),
        );
        frame.extend_from_slice(token);
        let metadata = GithubRuntimeAuthorityEnvelopeMetadata::new(
            identity.clone(),
            None,
            u64::try_from(frame.len()).expect("frame length"),
            Sha256Digest::from_bytes(Sha256::digest(&frame).into()),
        )
        .expect("metadata");
        let wrapping_context = identity
            .wrapping_encryption_context()
            .expect("wrapping context");
        let payload_context = metadata.encryption_context().expect("payload context");
        let envelope = codec
            .prepare(&wrapping_context)
            .await
            .expect("prepared envelope")
            .seal_prepared(
                &payload_context,
                SecretBytes::new(frame).expect("protected frame"),
            );
        let protected =
            ProtectedGithubRuntimeAuthority::new(metadata, envelope).expect("protected authority");
        ClaimedGithubRuntimeAuthorityRevocation::from_repository_parts(
            protected,
            GithubRuntimeAuthorityWorkerId::from_uuid(uuid::Uuid::from_u128(91)).expect("worker"),
            GithubRuntimeAuthorityClaimFence::new(1).expect("claim fence"),
            1,
            UnixMillis::new(1_100),
            UnixMillis::new(2_000),
        )
        .expect("revocation claim")
    }

    #[derive(Default)]
    struct IdleRepository {
        reconciliations: AtomicUsize,
        revocation_claims: AtomicUsize,
        revalidations: AtomicUsize,
        revalidation_observed_at: Option<UnixMillis>,
        revocation_claim: Mutex<Option<ClaimedGithubRuntimeAuthorityRevocation>>,
        commit_confirmed: AtomicBool,
        commit_attempts: AtomicUsize,
        mutation_shapes: Mutex<Vec<&'static str>>,
        mutation_gate: Option<Arc<LifecycleMutationGate>>,
        retry_requests: Mutex<Vec<RetryGithubRuntimeAuthorityRevocation>>,
        defer_requests: Mutex<Vec<DeferGithubRuntimeAuthorityRevocation>>,
        confirm_requests: Mutex<Vec<ConfirmGithubRuntimeAuthorityRevocation>>,
        quarantine_requests: Mutex<Vec<QuarantineGithubRuntimeAuthority>>,
    }

    struct LifecycleMutationGate {
        entered: tokio::sync::Semaphore,
        release: tokio::sync::Semaphore,
    }

    impl Default for LifecycleMutationGate {
        fn default() -> Self {
            Self {
                entered: tokio::sync::Semaphore::new(0),
                release: tokio::sync::Semaphore::new(0),
            }
        }
    }

    impl LifecycleMutationGate {
        async fn enter(&self) {
            self.entered.add_permits(1);
            self.release
                .acquire()
                .await
                .expect("lifecycle mutation release semaphore")
                .forget();
        }

        async fn wait_until_entered(&self) {
            self.entered
                .acquire()
                .await
                .expect("lifecycle mutation entry semaphore")
                .forget();
        }

        fn release(&self) {
            self.release.add_permits(1);
        }
    }

    impl IdleRepository {
        fn mutation_receipt(
            key: GithubRuntimeAuthorityKey,
            observed_at: UnixMillis,
        ) -> Result<GithubRuntimeAuthorityReceipt, GithubRuntimeAuthorityStoreError> {
            GithubRuntimeAuthorityReceipt::from_repository_parts(
                key,
                GithubRuntimeAuthorityState::Revoked,
                observed_at,
                Some(GithubRuntimeAuthorityTerminalReason::ProviderRevocationConfirmed),
            )
            .map_err(|_| GithubRuntimeAuthorityStoreError::CorruptData)
        }

        fn assert_exact_mutation_attempts(&self, expected: &LifecycleMutation, count: usize) {
            match expected {
                LifecycleMutation::Retry(expected) => {
                    let requests = self.retry_requests.lock().expect("retry request lock");
                    assert_eq!(requests.len(), count);
                    assert!(requests.iter().all(|request| request == expected));
                }
                LifecycleMutation::Defer(expected) => {
                    let requests = self.defer_requests.lock().expect("defer request lock");
                    assert_eq!(requests.len(), count);
                    assert!(requests.iter().all(|request| request == expected));
                }
                LifecycleMutation::Confirm(expected) => {
                    let requests = self.confirm_requests.lock().expect("confirm request lock");
                    assert_eq!(requests.len(), count);
                    assert!(requests.iter().all(|request| request == expected));
                }
                LifecycleMutation::Quarantine(expected) => {
                    let requests = self
                        .quarantine_requests
                        .lock()
                        .expect("quarantine request lock");
                    assert_eq!(requests.len(), count);
                    assert!(requests.iter().all(|request| request == expected));
                }
            }
        }
    }

    #[async_trait]
    impl GithubRuntimeAuthorityRepository for IdleRepository {
        async fn inspect_github_runtime_authority(
            &self,
            _request: InspectGithubRuntimeAuthority,
        ) -> Result<Option<GithubRuntimeAuthorityInspection>, GithubRuntimeAuthorityStoreError>
        {
            unreachable!("mint inspection is outside lifecycle maintenance")
        }

        async fn claim_github_runtime_authority_mint(
            &self,
            _request: ClaimGithubRuntimeAuthorityMint,
        ) -> Result<Option<ClaimedGithubRuntimeAuthorityMint>, GithubRuntimeAuthorityStoreError>
        {
            unreachable!("mint claim is outside lifecycle maintenance")
        }

        async fn begin_github_runtime_authority_mint(
            &self,
            _request: BeginGithubRuntimeAuthorityMint,
        ) -> Result<BeginGithubRuntimeAuthorityMintOutcome, GithubRuntimeAuthorityStoreError>
        {
            unreachable!("mint begin is outside lifecycle maintenance")
        }

        async fn authenticate_github_runtime_authority_unprotected_erasure(
            &self,
            _request: AuthenticateGithubRuntimeAuthorityUnprotectedErasure,
        ) -> Result<Option<GithubRuntimeAuthorityReceipt>, GithubRuntimeAuthorityStoreError>
        {
            unreachable!("unprotected erasure is outside lifecycle maintenance")
        }

        async fn mark_github_runtime_authority_indeterminate(
            &self,
            _request: MarkGithubRuntimeAuthorityIndeterminate,
        ) -> Result<GithubRuntimeAuthorityReceipt, GithubRuntimeAuthorityStoreError> {
            unreachable!("mint reduction is outside this idle path")
        }

        async fn retry_github_runtime_authority_mint(
            &self,
            _request: RetryGithubRuntimeAuthorityMint,
        ) -> Result<GithubRuntimeAuthorityReceipt, GithubRuntimeAuthorityStoreError> {
            unreachable!("mint retry is outside lifecycle maintenance")
        }

        async fn reject_github_runtime_authority_mint(
            &self,
            _request: RejectGithubRuntimeAuthorityMint,
        ) -> Result<GithubRuntimeAuthorityReceipt, GithubRuntimeAuthorityStoreError> {
            unreachable!("mint rejection is outside lifecycle maintenance")
        }

        async fn commit_github_runtime_authority(
            &self,
            _request: &CommitGithubRuntimeAuthority,
        ) -> Result<GithubRuntimeAuthorityReceipt, GithubRuntimeAuthorityStoreError> {
            unreachable!("mint commit is outside lifecycle maintenance")
        }

        async fn load_ready_github_runtime_authority(
            &self,
            _request: LoadGithubRuntimeAuthority,
        ) -> Result<Option<ReadyGithubRuntimeAuthority>, GithubRuntimeAuthorityStoreError> {
            unreachable!("ready load is outside lifecycle maintenance")
        }

        async fn quarantine_github_runtime_authority(
            &self,
            request: QuarantineGithubRuntimeAuthority,
        ) -> Result<GithubRuntimeAuthorityReceipt, GithubRuntimeAuthorityStoreError> {
            self.mutation_shapes
                .lock()
                .expect("mutation-shape lock")
                .push("quarantine");
            self.quarantine_requests
                .lock()
                .expect("quarantine request lock")
                .push(request);
            if let Some(gate) = &self.mutation_gate {
                gate.enter().await;
                return Self::mutation_receipt(request.key(), request.observed_at());
            }
            Err(GithubRuntimeAuthorityStoreError::operation(
                std::io::Error::other("scripted quarantine uncertainty"),
            ))
        }

        async fn reconcile_github_runtime_authorities(
            &self,
            request: ReconcileGithubRuntimeAuthorities,
        ) -> Result<GithubRuntimeAuthorityReconciliationReport, GithubRuntimeAuthorityStoreError>
        {
            assert_eq!(request.batch_size(), MAX_GITHUB_AUTHORITY_RECONCILE_BATCH);
            self.reconciliations.fetch_add(1, Ordering::SeqCst);
            Ok(GithubRuntimeAuthorityReconciliationReport::default())
        }

        async fn claim_github_runtime_authority_revocation(
            &self,
            _request: ClaimGithubRuntimeAuthorityRevocation,
        ) -> Result<Option<ClaimedGithubRuntimeAuthorityRevocation>, GithubRuntimeAuthorityStoreError>
        {
            self.revocation_claims.fetch_add(1, Ordering::SeqCst);
            Ok(self
                .revocation_claim
                .lock()
                .expect("revocation claim lock")
                .take())
        }

        async fn revalidate_github_runtime_authority_revocation(
            &self,
            request: RevalidateGithubRuntimeAuthorityRevocation,
        ) -> Result<
            Option<RevalidatedGithubRuntimeAuthorityRevocation>,
            GithubRuntimeAuthorityStoreError,
        > {
            self.revalidations.fetch_add(1, Ordering::SeqCst);
            let Some(observed_at) = self.revalidation_observed_at else {
                return Ok(None);
            };
            let provider_call_authorized = observed_at
                .get()
                .checked_add(request.provider_request_millis())
                .is_some_and(|completion| {
                    completion <= request.expires_at().get()
                        && completion < request.safe_erase_after().get()
                });
            Ok(Some(
                RevalidatedGithubRuntimeAuthorityRevocation::from_repository_parts(
                    request,
                    observed_at,
                    provider_call_authorized,
                )
                .expect("consistent fake Store decision"),
            ))
        }

        async fn retry_github_runtime_authority_revocation(
            &self,
            request: RetryGithubRuntimeAuthorityRevocation,
        ) -> Result<GithubRuntimeAuthorityReceipt, GithubRuntimeAuthorityStoreError> {
            self.mutation_shapes
                .lock()
                .expect("mutation-shape lock")
                .push("retry");
            self.retry_requests
                .lock()
                .expect("retry request lock")
                .push(request.clone());
            if let Some(gate) = &self.mutation_gate {
                gate.enter().await;
                return Self::mutation_receipt(request.key(), request.observed_at());
            }
            Err(GithubRuntimeAuthorityStoreError::operation(
                std::io::Error::other("scripted retry uncertainty"),
            ))
        }

        async fn defer_github_runtime_authority_revocation(
            &self,
            request: DeferGithubRuntimeAuthorityRevocation,
        ) -> Result<GithubRuntimeAuthorityReceipt, GithubRuntimeAuthorityStoreError> {
            self.mutation_shapes
                .lock()
                .expect("mutation-shape lock")
                .push("defer");
            self.defer_requests
                .lock()
                .expect("defer request lock")
                .push(request.clone());
            if let Some(gate) = &self.mutation_gate {
                gate.enter().await;
                return Self::mutation_receipt(request.key(), request.observed_at());
            }
            Err(GithubRuntimeAuthorityStoreError::operation(
                std::io::Error::other("scripted defer uncertainty"),
            ))
        }

        async fn confirm_github_runtime_authority_revocation(
            &self,
            request: ConfirmGithubRuntimeAuthorityRevocation,
        ) -> Result<GithubRuntimeAuthorityReceipt, GithubRuntimeAuthorityStoreError> {
            self.mutation_shapes
                .lock()
                .expect("mutation-shape lock")
                .push("confirm");
            self.commit_attempts.fetch_add(1, Ordering::SeqCst);
            self.confirm_requests
                .lock()
                .expect("confirm request lock")
                .push(request);
            if let Some(gate) = &self.mutation_gate {
                gate.enter().await;
                return Self::mutation_receipt(request.key(), request.confirmed_at());
            }
            if !self.commit_confirmed.load(Ordering::SeqCst) {
                return Err(GithubRuntimeAuthorityStoreError::operation(
                    std::io::Error::other("ambiguous confirmation"),
                ));
            }
            GithubRuntimeAuthorityReceipt::from_repository_parts(
                request.key(),
                GithubRuntimeAuthorityState::Revoked,
                request.confirmed_at(),
                Some(GithubRuntimeAuthorityTerminalReason::ProviderRevocationConfirmed),
            )
            .map_err(|_| GithubRuntimeAuthorityStoreError::CorruptData)
        }
    }

    #[derive(Default)]
    struct NoCallBroker {
        calls: AtomicUsize,
    }

    impl fmt::Debug for NoCallBroker {
        fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str("NoCallBroker([NO ROUTES])")
        }
    }

    #[async_trait]
    impl GithubRuntimeAuthorityLifecycleBroker for NoCallBroker {
        fn maximum_request_duration(
            &self,
            _identity: &GithubRuntimeAuthorityIdentity,
        ) -> Option<Duration> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            None
        }

        async fn revoke(
            &self,
            _identity: &GithubRuntimeAuthorityIdentity,
            _candidate: &GithubInstallationTokenRevocationCandidate,
        ) -> GithubInstallationTokenRevocationOutcome {
            self.calls.fetch_add(1, Ordering::SeqCst);
            unreachable!("idle maintenance has no revocation claim")
        }
    }

    #[derive(Default)]
    struct RevalidationBroker {
        route_checks: AtomicUsize,
        revocations: AtomicUsize,
        fractional_duration: AtomicBool,
    }

    impl fmt::Debug for RevalidationBroker {
        fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str("RevalidationBroker([REDACTED])")
        }
    }

    #[async_trait]
    impl GithubRuntimeAuthorityLifecycleBroker for RevalidationBroker {
        fn maximum_request_duration(
            &self,
            _identity: &GithubRuntimeAuthorityIdentity,
        ) -> Option<Duration> {
            self.route_checks.fetch_add(1, Ordering::SeqCst);
            if self.fractional_duration.load(Ordering::SeqCst) {
                Some(Duration::from_micros(1_500))
            } else {
                Some(Duration::from_millis(25))
            }
        }

        async fn revoke(
            &self,
            _identity: &GithubRuntimeAuthorityIdentity,
            _candidate: &GithubInstallationTokenRevocationCandidate,
        ) -> GithubInstallationTokenRevocationOutcome {
            self.revocations.fetch_add(1, Ordering::SeqCst);
            GithubInstallationTokenRevocationOutcome::Confirmed
        }
    }

    struct UnavailableKeys;

    impl fmt::Debug for UnavailableKeys {
        fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str("UnavailableKeys([REDACTED])")
        }
    }

    #[async_trait]
    impl KeyEncryptionProvider for UnavailableKeys {
        async fn wrap_data_key(
            &self,
            _plaintext_key: &SecretBytes,
            _context: &KeyEncryptionContext,
        ) -> Result<WrappedDataKey, KeyEncryptionError> {
            Err(KeyEncryptionError::Unavailable)
        }

        async fn unwrap_data_key(
            &self,
            _wrapped_key: &WrappedDataKey,
            _context: &KeyEncryptionContext,
        ) -> Result<SecretBytes, KeyEncryptionError> {
            Err(KeyEncryptionError::Unavailable)
        }
    }
}
