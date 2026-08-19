//! Product adapters for exact GitHub server-service credential handoffs.

use std::{
    collections::BTreeMap,
    fmt,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    time::Duration,
};

use async_trait::async_trait;
use automata_ci_auth::secret::SecretString;
use automata_ci_core::UnixMillis;
use automata_ci_credential_github::{
    GithubServerServiceCoordinatorClock, GithubServerServiceCredentialIssuer,
    GithubServerServiceCredentialRepository, GithubServerServiceCredentialRequestResolver,
    GithubServerServiceHandoffBinding, GithubServerServiceHandoffError,
    GithubServerServiceResolutionError, PendingGithubServerServiceCorruptionCleanup,
    PendingGithubServerServiceHandoffRelease, github_server_service_credential_request,
};
use automata_ci_github_delivery::GithubServerServiceCredentialRelease;
use automata_ci_provider::{
    ControlCredential, ControlCredentialFuture, ControlCredentialProvider,
    ControlCredentialProviderError, ControlCredentialRelease, ControlCredentialReleaseFuture,
    ControlCredentialRequest, ControlCredentialRevocation, ControlCredentialStrategy,
    ProviderControlOperation, ProviderCredentialGeneration,
};
use automata_ci_provider_github::GithubConnectionPolicy;
use automata_ci_secret::SecretValue;
use automata_ci_store::{
    AcquireGithubServerServiceHandoff, GithubServerServiceAction, GithubServerServiceAuthorityId,
    GithubServerServiceAuthorityIdentity, GithubServerServiceAuthorityRepository,
    GithubServerServiceAuthoritySelector, GithubServerServiceAuthorityState,
    GithubServerServiceClaimFence, GithubServerServiceConsumerClaim, GithubServerServiceConsumerId,
    GithubServerServiceHandoffId, GithubServerServiceIssuanceKey, GithubServerServiceRevision,
    GithubServerServiceScope, GithubServerServiceStoreError, GithubServerServiceWorkerId,
    TenantScope,
};
use thiserror::Error;
use tokio::{
    runtime::Handle,
    sync::{OwnedSemaphorePermit, Semaphore, oneshot},
};
use uuid::Uuid;

use super::GithubProviderCredentialRequestResolver;

/// Maximum live or release-pending handoffs supervised by one adapter set.
pub const MAX_GITHUB_PROVIDER_SUPERVISED_RELEASES: usize = 4_096;

const MAX_RELEASE_RETRY_INTERVAL: Duration = Duration::from_mins(1);

/// Invalid product credential-adapter configuration.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum GithubProviderCredentialAdapterConfigurationError {
    /// No authority was supplied, too many were supplied, or an identity was duplicated.
    #[error("the GitHub provider credential authority registry is invalid")]
    InvalidAuthorityRegistry,
    /// Release supervision capacity is zero or excessive.
    #[error("the GitHub provider credential release capacity is invalid")]
    InvalidReleaseCapacity,
    /// The exact release retry interval is zero or excessive.
    #[error("the GitHub provider credential release retry interval is invalid")]
    InvalidReleaseRetryInterval,
}

/// Bounded independent custody for live and ambiguously released handoffs.
///
/// A permit is reserved before Store can grant a handoff. Once the final
/// provider future ends, the move-only release capability transfers the exact
/// binding into this supervisor. An uncertain first release retains its exact
/// request in the bounded supervisor registry and replays it without mutation
/// until Store confirms it. Crossing the immutable handoff horizon is recorded
/// but never authorizes dropping custody. Watchdog task loss therefore remains
/// non-drained and observable.
pub struct GithubProviderCredentialReleaseSupervisor {
    clock: Arc<dyn GithubServerServiceCoordinatorClock>,
    runtime: Handle,
    retry_interval: Duration,
    permits: Arc<Semaphore>,
    capacity: usize,
    pending: Arc<AtomicUsize>,
    expired_unconfirmed: Arc<AtomicUsize>,
    custody: Arc<Mutex<Vec<Arc<SupervisedHandoffRelease>>>>,
    drained: Arc<tokio::sync::Notify>,
}

impl GithubProviderCredentialReleaseSupervisor {
    /// Constructs one hard-bounded exact-release supervisor.
    ///
    /// # Errors
    ///
    /// Rejects capacity outside `1..=4096` and retry intervals outside
    /// `1ms..=60s`.
    pub fn new(
        clock: Arc<dyn GithubServerServiceCoordinatorClock>,
        runtime: Handle,
        capacity: usize,
        retry_interval: Duration,
    ) -> Result<Self, GithubProviderCredentialAdapterConfigurationError> {
        if capacity == 0 || capacity > MAX_GITHUB_PROVIDER_SUPERVISED_RELEASES {
            return Err(GithubProviderCredentialAdapterConfigurationError::InvalidReleaseCapacity);
        }
        if retry_interval.is_zero() || retry_interval > MAX_RELEASE_RETRY_INTERVAL {
            return Err(
                GithubProviderCredentialAdapterConfigurationError::InvalidReleaseRetryInterval,
            );
        }
        Ok(Self {
            clock,
            runtime,
            retry_interval,
            permits: Arc::new(Semaphore::new(capacity)),
            capacity,
            pending: Arc::new(AtomicUsize::new(0)),
            expired_unconfirmed: Arc::new(AtomicUsize::new(0)),
            custody: Arc::new(Mutex::new(Vec::with_capacity(capacity))),
            drained: Arc::new(tokio::sync::Notify::new()),
        })
    }

    /// Returns the hard live-plus-pending handoff capacity.
    #[must_use]
    pub const fn capacity(&self) -> usize {
        self.capacity
    }

    /// Returns currently unreserved handoff slots.
    #[must_use]
    pub fn available_capacity(&self) -> usize {
        self.permits.available_permits()
    }

    /// Returns exact releases currently awaiting Store confirmation.
    #[must_use]
    pub fn pending_release_count(&self) -> usize {
        self.pending.load(Ordering::Acquire)
    }

    /// Returns unconfirmed releases that crossed their immutable use horizon.
    #[must_use]
    pub fn expired_unconfirmed_release_count(&self) -> usize {
        self.expired_unconfirmed.load(Ordering::Acquire)
    }

    /// Waits until every reserved live or release-pending handoff has left the supervisor.
    ///
    /// Product shutdown must first stop every Checks publisher and repository-source
    /// delivery worker, so no new reservation can race this drain. A caller may
    /// impose its own shutdown deadline; abandoning this future cannot erase
    /// the authoritative durable handoff or extend its immutable horizon.
    pub async fn wait_for_idle(&self) {
        let permit_count = u32::try_from(self.capacity).unwrap_or(u32::MAX);
        loop {
            let notified = self.drained.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            self.redrive_retained();
            let permits = Arc::clone(&self.permits).acquire_many_owned(permit_count);
            tokio::pin!(permits);
            tokio::select! {
                permits = &mut permits => {
                    if let Ok(permits) = permits {
                        drop(permits);
                    }
                    return;
                }
                () = &mut notified => {}
            }
        }
    }

    /// Waits up to `timeout` for all live or release-pending handoffs to end.
    ///
    /// Returns `true` only when every capacity permit was recovered.
    pub async fn drain(&self, timeout: Duration) -> bool {
        tokio::time::timeout(timeout, self.wait_for_idle())
            .await
            .is_ok()
    }

    fn try_reserve(&self) -> Option<GithubProviderCredentialReleaseReservation> {
        self.redrive_retained();
        Arc::clone(&self.permits)
            .try_acquire_owned()
            .ok()
            .map(|permit| GithubProviderCredentialReleaseReservation { _permit: permit })
    }

    fn supervise(
        &self,
        reservation: GithubProviderCredentialReleaseReservation,
        operation: Box<dyn GithubProviderExactHandoffRelease>,
        required_through: UnixMillis,
    ) -> oneshot::Receiver<()> {
        let (initial_attempt_sender, initial_attempt_receiver) = oneshot::channel();
        let pending = operation.freeze();
        drop(operation);
        self.pending.fetch_add(1, Ordering::AcqRel);
        let custody = Arc::new(SupervisedHandoffRelease {
            _reservation: reservation,
            _pending_observation: PendingReleaseObservation {
                count: Arc::clone(&self.pending),
            },
            pending,
            task_abort: Mutex::new(None),
            driver_active: Arc::new(AtomicBool::new(false)),
            required_through,
            expiry_observed: AtomicBool::new(false),
            removed: AtomicBool::new(false),
        });
        self.custody
            .lock()
            .expect("provider credential release custody lock")
            .push(Arc::clone(&custody));

        let started = self.start_driver(&custody, Some(initial_attempt_sender));
        assert!(started, "new release custody starts one driver");
        initial_attempt_receiver
    }

    fn start_driver(
        &self,
        custody: &Arc<SupervisedHandoffRelease>,
        initial_attempt_sender: Option<oneshot::Sender<()>>,
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
        let clock = Arc::clone(&self.clock);
        let retained = Arc::clone(&self.custody);
        let task_custody = Arc::clone(custody);
        let expired_count = Arc::clone(&self.expired_unconfirmed);
        let retry_interval = self.retry_interval;
        let driver_active = ReleaseDriverObservation {
            active: Arc::clone(&custody.driver_active),
            drained: Arc::clone(&self.drained),
        };
        let task = self.runtime.spawn(async move {
            let _driver_active = driver_active;
            let mut initial_attempt_sender = initial_attempt_sender;
            loop {
                if task_custody.pending.replay().await {
                    if let Some(initial_attempt_sender) = initial_attempt_sender.take() {
                        let _ = initial_attempt_sender.send(());
                    }
                    break;
                }
                if let Some(initial_attempt_sender) = initial_attempt_sender.take() {
                    let _ = initial_attempt_sender.send(());
                }
                if clock.now() >= task_custody.required_through
                    && !task_custody.expiry_observed.swap(true, Ordering::AcqRel)
                {
                    expired_count.fetch_add(1, Ordering::AcqRel);
                }
                tokio::time::sleep(retry_interval).await;
            }
            if task_custody.expiry_observed.swap(false, Ordering::AcqRel) {
                expired_count.fetch_sub(1, Ordering::AcqRel);
            }
            task_custody.removed.store(true, Ordering::Release);
            drop(take_release_custody(&retained, &task_custody));
            drop(task_custody);
        });
        *custody
            .task_abort
            .lock()
            .expect("provider credential release task lock") = Some(task.abort_handle());
        true
    }

    fn redrive_retained(&self) {
        let custody = self
            .custody
            .lock()
            .expect("provider credential release custody lock")
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
            .expect("provider credential release custody lock")
            .first()
            .cloned();
        let Some(custody) = custody else {
            return false;
        };
        let task = custody
            .task_abort
            .lock()
            .expect("provider credential release task lock")
            .clone();
        task.is_some_and(|task| {
            task.abort();
            true
        })
    }
}

impl fmt::Debug for GithubProviderCredentialReleaseSupervisor {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GithubProviderCredentialReleaseSupervisor")
            .field("clock", &self.clock)
            .field("retry_interval", &self.retry_interval)
            .field("capacity", &self.capacity)
            .field("available_capacity", &self.available_capacity())
            .field("pending_release_count", &self.pending_release_count())
            .field(
                "expired_unconfirmed_release_count",
                &self.expired_unconfirmed_release_count(),
            )
            .field(
                "retained_custody",
                &self
                    .custody
                    .lock()
                    .expect("provider credential release custody lock")
                    .len(),
            )
            .finish_non_exhaustive()
    }
}

struct SupervisedHandoffRelease {
    _reservation: GithubProviderCredentialReleaseReservation,
    _pending_observation: PendingReleaseObservation,
    pending: Arc<dyn GithubProviderPendingHandoffRelease>,
    task_abort: Mutex<Option<tokio::task::AbortHandle>>,
    driver_active: Arc<AtomicBool>,
    required_through: UnixMillis,
    expiry_observed: AtomicBool,
    removed: AtomicBool,
}

struct ReleaseDriverObservation {
    active: Arc<AtomicBool>,
    drained: Arc<tokio::sync::Notify>,
}

impl Drop for ReleaseDriverObservation {
    fn drop(&mut self) {
        self.active.store(false, Ordering::Release);
        self.drained.notify_waiters();
    }
}

fn take_release_custody(
    retained: &Mutex<Vec<Arc<SupervisedHandoffRelease>>>,
    target: &Arc<SupervisedHandoffRelease>,
) -> Option<Arc<SupervisedHandoffRelease>> {
    let mut retained = retained
        .lock()
        .expect("provider credential release custody lock");
    let position = retained
        .iter()
        .position(|entry| Arc::ptr_eq(entry, target))?;
    Some(retained.swap_remove(position))
}

struct GithubProviderCredentialReleaseReservation {
    _permit: OwnedSemaphorePermit,
}

struct PendingReleaseObservation {
    count: Arc<AtomicUsize>,
}

impl Drop for PendingReleaseObservation {
    fn drop(&mut self) {
        self.count.fetch_sub(1, Ordering::AcqRel);
    }
}

#[async_trait]
trait GithubProviderPendingHandoffRelease: fmt::Debug + Send + Sync {
    async fn replay(&self) -> bool;
}

trait GithubProviderExactHandoffRelease: fmt::Debug + Send + Sync {
    fn freeze(&self) -> Arc<dyn GithubProviderPendingHandoffRelease>;
}

struct IssuerHandoffRelease {
    issuer: Arc<GithubServerServiceCredentialIssuer>,
    repository: Arc<dyn GithubServerServiceCredentialRepository>,
    binding: GithubServerServiceHandoffBinding,
}

impl GithubProviderExactHandoffRelease for IssuerHandoffRelease {
    fn freeze(&self) -> Arc<dyn GithubProviderPendingHandoffRelease> {
        // Production bindings are privately constructed from a validated durable
        // handoff. Core clamps the sampled clock to that nonnegative acquisition
        // timestamp, so ReleaseGithubServerServiceHandoff cannot reject it.
        let pending = self
            .issuer
            .prepare_release_binding(self.binding.clone())
            .expect("a validated handoff binding always forms an exact release");
        Arc::new(CorePendingHandoffRelease {
            repository: Arc::clone(&self.repository),
            pending,
        })
    }
}

impl fmt::Debug for IssuerHandoffRelease {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("IssuerHandoffRelease")
            .field("issuer", &self.issuer)
            .field("repository", &"[AUTHORITY REPOSITORY]")
            .field("binding", &"[EXACT RELEASE BINDING]")
            .finish()
    }
}

struct CorePendingHandoffRelease {
    repository: Arc<dyn GithubServerServiceCredentialRepository>,
    pending: PendingGithubServerServiceHandoffRelease,
}

struct CorePendingCorruptionCleanup {
    repository: Arc<dyn GithubServerServiceCredentialRepository>,
    pending: PendingGithubServerServiceCorruptionCleanup,
}

#[async_trait]
impl GithubProviderPendingHandoffRelease for CorePendingCorruptionCleanup {
    async fn replay(&self) -> bool {
        self.pending.replay(self.repository.as_ref()).await.is_ok()
    }
}

impl fmt::Debug for CorePendingCorruptionCleanup {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CorePendingCorruptionCleanup")
            .field("repository", &"[AUTHORITY REPOSITORY]")
            .field("pending", &"[EXACT PENDING CLEANUP]")
            .finish()
    }
}

struct RetainedPendingRelease {
    pending: Arc<dyn GithubProviderPendingHandoffRelease>,
}

impl GithubProviderExactHandoffRelease for RetainedPendingRelease {
    fn freeze(&self) -> Arc<dyn GithubProviderPendingHandoffRelease> {
        Arc::clone(&self.pending)
    }
}

impl fmt::Debug for RetainedPendingRelease {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RetainedPendingRelease")
            .field("pending", &"[EXACT PENDING CLEANUP]")
            .finish()
    }
}

#[async_trait]
impl GithubProviderPendingHandoffRelease for CorePendingHandoffRelease {
    async fn replay(&self) -> bool {
        self.pending.replay(self.repository.as_ref()).await.is_ok()
    }
}

impl fmt::Debug for CorePendingHandoffRelease {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CorePendingHandoffRelease")
            .field("repository", &"[AUTHORITY REPOSITORY]")
            .field("pending", &"[EXACT PENDING RELEASE]")
            .finish()
    }
}

struct SupervisedCredentialRelease {
    supervisor: Arc<GithubProviderCredentialReleaseSupervisor>,
    reservation: Option<GithubProviderCredentialReleaseReservation>,
    operation: Option<Box<dyn GithubProviderExactHandoffRelease>>,
    required_through: UnixMillis,
    drop_release_armed: Arc<AtomicBool>,
}

impl SupervisedCredentialRelease {
    fn start(&mut self) -> Option<oneshot::Receiver<()>> {
        let reservation = self.reservation.take()?;
        let operation = self.operation.take()?;
        Some(
            self.supervisor
                .supervise(reservation, operation, self.required_through),
        )
    }
}

#[async_trait]
impl GithubServerServiceCredentialRelease for SupervisedCredentialRelease {
    async fn release(mut self: Box<Self>) {
        if let Some(initial_attempt) = self.start() {
            drop(initial_attempt.await);
        }
    }
}

impl Drop for SupervisedCredentialRelease {
    fn drop(&mut self) {
        if self.drop_release_armed.load(Ordering::Acquire) {
            drop(self.start());
        }
    }
}

impl fmt::Debug for SupervisedCredentialRelease {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SupervisedCredentialRelease")
            .field("supervisor", &self.supervisor)
            .field("reservation", &self.reservation.is_some())
            .field("operation", &"[EXACT RELEASE OPERATION]")
            .field("required_through", &self.required_through)
            .field(
                "drop_release_armed",
                &self.drop_release_armed.load(Ordering::Acquire),
            )
            .finish()
    }
}

struct GithubProviderCredentialHandoff {
    selector: GithubServerServiceAuthoritySelector,
    consumer: GithubServerServiceConsumerClaim,
    key: GithubServerServiceIssuanceKey,
    required_through: UnixMillis,
    acquired_at: UnixMillis,
    usable_until: UnixMillis,
    token: SecretString,
    release: Box<dyn GithubServerServiceCredentialRelease>,
    drop_release_arm: Option<Arc<AtomicBool>>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum GithubProviderCredentialHandoffError {
    Unavailable,
    Rejected,
    Inconsistent,
}

#[async_trait]
trait GithubProviderCredentialHandoffIssuer: fmt::Debug + Send + Sync {
    async fn acquire(
        &self,
        request: AcquireGithubServerServiceHandoff,
    ) -> Result<GithubProviderCredentialHandoff, GithubProviderCredentialHandoffError>;
}

struct ExactCredentialHandoffIssuer {
    issuer: Arc<GithubServerServiceCredentialIssuer>,
    repository: Arc<dyn GithubServerServiceCredentialRepository>,
    releases: Arc<GithubProviderCredentialReleaseSupervisor>,
}

#[async_trait]
impl GithubProviderCredentialHandoffIssuer for ExactCredentialHandoffIssuer {
    async fn acquire(
        &self,
        request: AcquireGithubServerServiceHandoff,
    ) -> Result<GithubProviderCredentialHandoff, GithubProviderCredentialHandoffError> {
        let reservation = self
            .releases
            .try_reserve()
            .ok_or(GithubProviderCredentialHandoffError::Unavailable)?;
        let credential = match self.issuer.acquire(request).await {
            Ok(credential) => credential,
            Err(GithubServerServiceHandoffError::CorruptCleanupPending(pending)) => {
                drop(self.releases.supervise(
                    reservation,
                    Box::new(RetainedPendingRelease {
                        pending: Arc::new(CorePendingCorruptionCleanup {
                            repository: Arc::clone(&self.repository),
                            pending: *pending,
                        }),
                    }),
                    UnixMillis::new(i64::MAX),
                ));
                return Err(GithubProviderCredentialHandoffError::Inconsistent);
            }
            Err(error) => return Err(map_handoff_error(&error)),
        };
        let binding = credential.binding();
        let selector = binding.selector().clone();
        let consumer = binding.consumer();
        let key = binding.key();
        let binding_required_through = binding.required_through();
        let acquired_at = binding.acquired_at();
        let usable_until = binding.usable_until();
        let (token, binding) = credential.into_secret_and_binding();
        let drop_release_arm = Arc::new(AtomicBool::new(false));
        let release = SupervisedCredentialRelease {
            supervisor: Arc::clone(&self.releases),
            reservation: Some(reservation),
            operation: Some(Box::new(IssuerHandoffRelease {
                issuer: Arc::clone(&self.issuer),
                repository: Arc::clone(&self.repository),
                binding,
            })),
            required_through: binding_required_through,
            drop_release_armed: Arc::clone(&drop_release_arm),
        };
        Ok(GithubProviderCredentialHandoff {
            selector,
            consumer,
            key,
            required_through: binding_required_through,
            acquired_at,
            usable_until,
            token,
            release: Box::new(release),
            drop_release_arm: Some(drop_release_arm),
        })
    }
}

impl fmt::Debug for ExactCredentialHandoffIssuer {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ExactCredentialHandoffIssuer")
            .field("issuer", &self.issuer)
            .field("repository", &"[AUTHORITY REPOSITORY]")
            .field("releases", &self.releases)
            .finish()
    }
}

fn map_handoff_error(
    error: &GithubServerServiceHandoffError,
) -> GithubProviderCredentialHandoffError {
    match error {
        GithubServerServiceHandoffError::Repository
        | GithubServerServiceHandoffError::Unavailable => {
            GithubProviderCredentialHandoffError::Unavailable
        }
        GithubServerServiceHandoffError::Inconsistent
        | GithubServerServiceHandoffError::Corrupt
        | GithubServerServiceHandoffError::CorruptCleanupPending(_) => {
            GithubProviderCredentialHandoffError::Inconsistent
        }
    }
}

/// Exact authority registry plus delivery-provider adapters for one product replica.
///
/// Every REST-backed repository operation uses a scoped GitHub App installation
/// credential. Exact public archives bypass REST and therefore do not acquire a
/// token unless workflow evaluation later requests changed-file evidence.
pub struct GithubProviderCredentialAdapters {
    handoffs: Arc<dyn GithubProviderCredentialHandoffIssuer>,
    observation_clock: Option<Arc<dyn GithubServerServiceCoordinatorClock>>,
    authorities:
        Arc<BTreeMap<GithubServerServiceAuthorityId, GithubServerServiceAuthorityIdentity>>,
    durable_authorities: Option<DurableGithubProviderAuthorityResolver>,
}

#[derive(Clone)]
struct DurableGithubProviderAuthorityResolver {
    repository: Arc<dyn GithubProviderAuthorityLookup>,
    routes: GithubProviderCredentialRequestResolver,
}

#[async_trait]
trait GithubProviderAuthorityLookup: fmt::Debug + Send + Sync {
    async fn inspect(
        &self,
        selector: &GithubServerServiceAuthoritySelector,
    ) -> Result<
        automata_ci_store::GithubServerServiceAuthorityDescriptor,
        GithubServerServiceStoreError,
    >;
}

struct StoreGithubProviderAuthorityLookup {
    repository: Arc<dyn GithubServerServiceAuthorityRepository>,
}

#[async_trait]
impl GithubProviderAuthorityLookup for StoreGithubProviderAuthorityLookup {
    async fn inspect(
        &self,
        selector: &GithubServerServiceAuthoritySelector,
    ) -> Result<
        automata_ci_store::GithubServerServiceAuthorityDescriptor,
        GithubServerServiceStoreError,
    > {
        self.repository
            .inspect_github_server_service_authority(selector.tenant(), selector.authority_id())
            .await
    }
}

impl fmt::Debug for StoreGithubProviderAuthorityLookup {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("StoreGithubProviderAuthorityLookup")
            .field("repository", &"[AUTHORITY REPOSITORY]")
            .finish()
    }
}

impl GithubProviderCredentialAdapters {
    /// Constructs product adapters from a bootstrap-projected exact authority set.
    ///
    /// Both repository ports must be views of the same durable credential
    /// implementation used by the issuer. The authority view revalidates exact
    /// current and historical descriptors before any handoff attempt; the
    /// credential view is retained inside redacted pending-release replay
    /// evidence.
    ///
    /// # Errors
    ///
    /// Rejects an empty, excessive, duplicate, or ambiguously routed authority set.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        issuer: &Arc<GithubServerServiceCredentialIssuer>,
        repository: &Arc<dyn GithubServerServiceCredentialRepository>,
        authority_repository: Arc<dyn GithubServerServiceAuthorityRepository>,
        releases: &Arc<GithubProviderCredentialReleaseSupervisor>,
        authorities: &[GithubServerServiceAuthorityIdentity],
        routes: GithubProviderCredentialRequestResolver,
        observation_clock: Arc<dyn GithubServerServiceCoordinatorClock>,
    ) -> Result<Self, GithubProviderCredentialAdapterConfigurationError> {
        let handoffs = Arc::new(ExactCredentialHandoffIssuer {
            issuer: Arc::clone(issuer),
            repository: Arc::clone(repository),
            releases: Arc::clone(releases),
        });
        let mut adapters = Self::with_handoffs(handoffs, authorities)?;
        adapters.observation_clock = Some(observation_clock);
        adapters.durable_authorities = Some(DurableGithubProviderAuthorityResolver {
            repository: Arc::new(StoreGithubProviderAuthorityLookup {
                repository: authority_repository,
            }),
            routes,
        });
        Ok(adapters)
    }

    fn with_handoffs(
        handoffs: Arc<dyn GithubProviderCredentialHandoffIssuer>,
        authorities: &[GithubServerServiceAuthorityIdentity],
    ) -> Result<Self, GithubProviderCredentialAdapterConfigurationError> {
        let maximum_authorities = 3 * super::MAX_GITHUB_PROVIDER_REPOSITORIES;
        if authorities.is_empty() || authorities.len() > maximum_authorities {
            return Err(
                GithubProviderCredentialAdapterConfigurationError::InvalidAuthorityRegistry,
            );
        }
        let mut exact = BTreeMap::new();
        for identity in authorities {
            if exact
                .values()
                .any(|existing: &GithubServerServiceAuthorityIdentity| {
                    existing.tenant() == identity.tenant()
                        && existing.connection_id() == identity.connection_id()
                        && existing.repository_id() == identity.repository_id()
                        && existing.scope() == identity.scope()
                })
                || exact
                    .insert(identity.authority_id(), identity.clone())
                    .is_some()
            {
                return Err(
                    GithubProviderCredentialAdapterConfigurationError::InvalidAuthorityRegistry,
                );
            }
        }
        Ok(Self {
            handoffs,
            observation_clock: None,
            authorities: Arc::new(exact),
            durable_authorities: None,
        })
    }

    async fn authority(
        &self,
        selector: &GithubServerServiceAuthoritySelector,
        scope: GithubServerServiceScope,
    ) -> Result<GithubServerServiceAuthorityIdentity, GithubProviderCredentialHandoffError> {
        let identity = if let Some(durable) = &self.durable_authorities {
            let descriptor = durable
                .repository
                .inspect(selector)
                .await
                .map_err(|error| map_authority_resolution_store_error(&error))?;
            if descriptor.state() != GithubServerServiceAuthorityState::Active
                || GithubServerServiceAuthoritySelector::from_identity(descriptor.identity())
                    != *selector
            {
                return Err(GithubProviderCredentialHandoffError::Rejected);
            }
            match durable
                .routes
                .resolve_github_server_service_credential_request(descriptor.identity())
                .await
                .map_err(map_authority_resolution_error)?
            {
                Some(resolved) => resolved.identity().clone(),
                None => return Err(GithubProviderCredentialHandoffError::Rejected),
            }
        } else {
            self.authorities
                .get(&selector.authority_id())
                .cloned()
                .ok_or(GithubProviderCredentialHandoffError::Rejected)?
        };
        if identity.scope() != scope
            || GithubServerServiceAuthoritySelector::from_identity(&identity) != *selector
        {
            return Err(GithubProviderCredentialHandoffError::Rejected);
        }
        Ok(identity)
    }

    async fn control_authority(
        &self,
        request: &ControlCredentialRequest,
        scope: GithubServerServiceScope,
    ) -> Result<GithubServerServiceAuthoritySelector, GithubProviderCredentialHandoffError> {
        let connection = request.connection();
        let policy = GithubConnectionPolicy::decode(connection.configuration().adapter_policy())
            .map_err(|_| GithubProviderCredentialHandoffError::Rejected)?;
        let tenant = TenantScope::from_authenticated_tenant_id(
            connection.configuration().workspace_id().to_string(),
        )
        .map_err(|_| GithubProviderCredentialHandoffError::Inconsistent)?;
        let github_repository_id = request
            .repository()
            .external_id()
            .as_str()
            .parse::<u64>()
            .ok()
            .filter(|value| *value != 0)
            .ok_or(GithubProviderCredentialHandoffError::Rejected)?;
        let mut candidates = self.authorities.values().filter(|authority| {
            authority.scope() == scope
                && authority.tenant() == &tenant
                && authority.connection_id() == request.connection_id()
                && authority.github_repository_id().get() == github_repository_id
                && authority.installation_id().get() == policy.installation_id().get()
        });
        let candidate = candidates
            .next()
            .filter(|_| candidates.next().is_none())
            .ok_or(GithubProviderCredentialHandoffError::Rejected)?;
        let selector = GithubServerServiceAuthoritySelector::from_identity(candidate);
        let authority = self.authority(&selector, scope).await?;
        let canonical = github_server_service_credential_request(&authority)
            .map_err(|_| GithubProviderCredentialHandoffError::Inconsistent)?;
        if canonical.repository().repository() != policy.repository()
            || authority.github_repository_id().get() != github_repository_id
        {
            return Err(GithubProviderCredentialHandoffError::Rejected);
        }
        Ok(selector)
    }

    async fn acquire_control(
        &self,
        request: &ControlCredentialRequest,
    ) -> Result<ControlCredential, ControlCredentialProviderError> {
        let mut operations = request.operations().iter();
        let operation = operations
            .next()
            .filter(|_| operations.next().is_none())
            .ok_or(ControlCredentialProviderError::Unsupported)?;
        let action =
            common_control_action(operation).ok_or(ControlCredentialProviderError::Unsupported)?;
        let selector = self
            .control_authority(request, action.required_scope())
            .await
            .map_err(common_control_handoff_error)?;
        let consumer = common_control_consumer(request, action)?;
        let observed_at = self
            .observation_clock
            .as_ref()
            .ok_or(ControlCredentialProviderError::InvalidResponse)?
            .now()
            .max(request.requested_at());
        let required_through = request
            .requested_at()
            .get()
            .checked_add(request.minimum_validity_millis().cast_signed())
            .map(UnixMillis::new)
            .ok_or(ControlCredentialProviderError::InvalidResponse)?;
        if observed_at >= required_through || required_through < request.claim().expires_at() {
            return Err(ControlCredentialProviderError::InvalidResponse);
        }
        let handoff_request =
            acquire_request(selector.clone(), consumer, observed_at, required_through)
                .map_err(common_control_handoff_error)?;
        let handoff = self
            .handoffs
            .acquire(handoff_request)
            .await
            .map_err(common_control_handoff_error)?;
        if handoff.selector != selector
            || handoff.consumer != consumer
            || handoff.key.authority_id() != selector.authority_id()
            || handoff.required_through != required_through
            || handoff.acquired_at != observed_at
            || handoff.usable_until <= required_through
        {
            release_invalid_handoff(handoff).await;
            return Err(ControlCredentialProviderError::InvalidResponse);
        }
        let drop_release_arm = handoff.drop_release_arm.clone();
        let Ok(generation) = ProviderCredentialGeneration::new(handoff.key.generation().get())
        else {
            release_invalid_handoff(handoff).await;
            return Err(ControlCredentialProviderError::InvalidResponse);
        };
        let Ok(value) = SecretValue::new(handoff.token.into_secret_bytes()) else {
            handoff.release.release().await;
            return Err(ControlCredentialProviderError::InvalidResponse);
        };
        arm_drop_release(drop_release_arm);
        ControlCredential::new(
            request,
            request.operations().clone(),
            ControlCredentialStrategy::Minted,
            generation,
            value,
            handoff.acquired_at,
            Some(handoff.usable_until),
            ControlCredentialRevocation::Explicit,
            Box::new(CommonControlCredentialRelease {
                inner: handoff.release,
            }),
        )
        .map_err(|_| ControlCredentialProviderError::InvalidResponse)
    }
}

fn map_authority_resolution_store_error(
    error: &GithubServerServiceStoreError,
) -> GithubProviderCredentialHandoffError {
    match error {
        GithubServerServiceStoreError::Operation(_) => {
            GithubProviderCredentialHandoffError::Unavailable
        }
        GithubServerServiceStoreError::NotFound => GithubProviderCredentialHandoffError::Rejected,
        GithubServerServiceStoreError::CorruptData
        | GithubServerServiceStoreError::IdentityConflict
        | GithubServerServiceStoreError::ClaimRejected
        | GithubServerServiceStoreError::HandoffRejected
        | GithubServerServiceStoreError::FenceExhausted
        | GithubServerServiceStoreError::HandoffStillLive => {
            GithubProviderCredentialHandoffError::Inconsistent
        }
    }
}

fn map_authority_resolution_error(
    error: GithubServerServiceResolutionError,
) -> GithubProviderCredentialHandoffError {
    match error {
        GithubServerServiceResolutionError::Unavailable => {
            GithubProviderCredentialHandoffError::Unavailable
        }
        GithubServerServiceResolutionError::Inconsistent => {
            GithubProviderCredentialHandoffError::Inconsistent
        }
    }
}

impl fmt::Debug for GithubProviderCredentialAdapters {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GithubProviderCredentialAdapters")
            .field("handoffs", &self.handoffs)
            .field("observation_clock", &self.observation_clock.is_some())
            .field("authority_count", &self.authorities.len())
            .field("durable_authorities", &self.durable_authorities.is_some())
            .finish()
    }
}

struct CommonControlCredentialRelease {
    inner: Box<dyn GithubServerServiceCredentialRelease>,
}

impl ControlCredentialRelease for CommonControlCredentialRelease {
    fn release(self: Box<Self>) -> ControlCredentialReleaseFuture {
        Box::pin(async move {
            self.inner.release().await;
        })
    }
}

impl fmt::Debug for CommonControlCredentialRelease {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CommonControlCredentialRelease")
            .field("inner", &"[exact supervised release]")
            .finish()
    }
}

impl ControlCredentialProvider for GithubProviderCredentialAdapters {
    fn acquire<'a>(&'a self, request: &'a ControlCredentialRequest) -> ControlCredentialFuture<'a> {
        Box::pin(self.acquire_control(request))
    }
}

fn acquire_request(
    selector: GithubServerServiceAuthoritySelector,
    consumer: GithubServerServiceConsumerClaim,
    observed_at: UnixMillis,
    required_through: UnixMillis,
) -> Result<AcquireGithubServerServiceHandoff, GithubProviderCredentialHandoffError> {
    let handoff_id = GithubServerServiceHandoffId::from_uuid(Uuid::new_v4())
        .map_err(|_| GithubProviderCredentialHandoffError::Inconsistent)?;
    AcquireGithubServerServiceHandoff::new(
        selector,
        handoff_id,
        consumer,
        observed_at,
        required_through,
    )
    .map_err(|_| GithubProviderCredentialHandoffError::Inconsistent)
}

async fn release_invalid_handoff(handoff: GithubProviderCredentialHandoff) {
    drop(handoff.token);
    handoff.release.release().await;
}

fn arm_drop_release(arm: Option<Arc<AtomicBool>>) {
    if let Some(arm) = arm {
        arm.store(true, Ordering::Release);
    }
}

fn common_control_consumer(
    request: &ControlCredentialRequest,
    action: GithubServerServiceAction,
) -> Result<GithubServerServiceConsumerClaim, ControlCredentialProviderError> {
    let claim = request.claim();
    let consumer_id = GithubServerServiceConsumerId::from_uuid(claim.credential_id().as_uuid())
        .map_err(|_| ControlCredentialProviderError::InvalidResponse)?;
    let owner = GithubServerServiceWorkerId::from_uuid(claim.worker_id().as_uuid())
        .map_err(|_| ControlCredentialProviderError::InvalidResponse)?;
    let fence = GithubServerServiceClaimFence::new(claim.fence())
        .map_err(|_| ControlCredentialProviderError::InvalidResponse)?;
    let revision = GithubServerServiceRevision::new(claim.revision())
        .map_err(|_| ControlCredentialProviderError::InvalidResponse)?;
    Ok(GithubServerServiceConsumerClaim::new(
        consumer_id,
        owner,
        fence,
        action,
        revision,
    ))
}

const fn common_control_action(
    operation: ProviderControlOperation,
) -> Option<GithubServerServiceAction> {
    match operation {
        ProviderControlOperation::RepositoryRead => {
            Some(GithubServerServiceAction::FetchRepositoryRevision)
        }
        ProviderControlOperation::CommitChangedFilesRead => {
            Some(GithubServerServiceAction::FetchRepositoryChangedFiles)
        }
        ProviderControlOperation::MergeRequestChangedFilesRead => {
            Some(GithubServerServiceAction::FetchPullRequestFiles)
        }
        ProviderControlOperation::ResultResolve => {
            Some(GithubServerServiceAction::EnsureCheckSuite)
        }
        ProviderControlOperation::ResultCreate => Some(GithubServerServiceAction::CreateCheckRun),
        ProviderControlOperation::ResultReconcile => {
            Some(GithubServerServiceAction::ReconcileCheckRun)
        }
        ProviderControlOperation::ResultRead | ProviderControlOperation::ResultWrite => {
            Some(GithubServerServiceAction::PublishCheckRun)
        }
        ProviderControlOperation::WorkflowPermissionRead => {
            Some(GithubServerServiceAction::ObserveWorkflowPermissionDefaults)
        }
        _ => None,
    }
}

const fn common_control_handoff_error(
    error: GithubProviderCredentialHandoffError,
) -> ControlCredentialProviderError {
    match error {
        GithubProviderCredentialHandoffError::Unavailable => {
            ControlCredentialProviderError::Unavailable
        }
        GithubProviderCredentialHandoffError::Rejected => ControlCredentialProviderError::Forbidden,
        GithubProviderCredentialHandoffError::Inconsistent => {
            ControlCredentialProviderError::InvalidResponse
        }
    }
}

#[cfg(test)]
#[path = "github_provider_credentials_tests.rs"]
mod tests;
