//! Product adapters for exact GitHub server-service credential handoffs.

use std::{
    collections::BTreeMap,
    fmt,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    time::{Duration, Instant},
};

use async_trait::async_trait;
use automata_ci_auth::github::GithubEndpointError;
use automata_ci_auth::secret::SecretString;
use automata_ci_core::UnixMillis;
use automata_ci_credential_github::{
    GithubServerServiceCoordinatorClock, GithubServerServiceCredentialIssuer,
    GithubServerServiceCredentialRepository, GithubServerServiceCredentialRequestResolver,
    GithubServerServiceHandoffBinding, GithubServerServiceHandoffError,
    GithubServerServiceResolutionError, PendingGithubServerServiceCorruptionCleanup,
    PendingGithubServerServiceHandoffRelease, github_server_service_credential_request,
};
use automata_ci_github_delivery::{
    GithubChecksCredentialProvider, GithubChecksCredentialProviderError,
    GithubChecksCredentialRequest, GithubChecksServerServiceCredential,
    GithubDeliveryRepositoryAction, GithubDeliverySourceCredential,
    GithubDeliverySourceCredentialBinding, GithubDeliverySourceCredentialProvider,
    GithubDeliverySourceCredentialProviderError, GithubDeliverySourceCredentialRequest,
    GithubResultCredential, GithubResultCredentialProvider, GithubResultCredentialProviderError,
    GithubResultCredentialRelease, GithubResultCredentialRequest, GithubResultOperation,
    GithubScheduleSourceCredential, GithubScheduleSourceCredentialProvider,
    GithubScheduleSourceCredentialProviderError, GithubScheduleSourceCredentialRequest,
    GithubServerServiceCredentialRelease, GithubTriggerCredential,
    GithubTriggerCredentialOperation, GithubTriggerCredentialProvider,
    GithubTriggerCredentialProviderError, GithubTriggerCredentialRelease,
    GithubTriggerCredentialRequest,
};
use automata_ci_provider_github::{
    GithubHttpEndpoint, GithubWorkflowPermissionDefaults, GithubWorkflowPermissionDefaultsRequest,
};
use automata_ci_store::{
    AcquireGithubServerServiceHandoff, GithubCheckSubjectIdentity, GithubProviderManifest,
    GithubServerServiceAction, GithubServerServiceAuthorityId,
    GithubServerServiceAuthorityIdentity, GithubServerServiceAuthorityRepository,
    GithubServerServiceAuthoritySelector, GithubServerServiceAuthorityState,
    GithubServerServiceClaimFence, GithubServerServiceConsumerClaim, GithubServerServiceConsumerId,
    GithubServerServiceHandoffId, GithubServerServiceIssuanceKey, GithubServerServiceRevision,
    GithubServerServiceScope, GithubServerServiceStoreError, GithubServerServiceWorkerId,
    GithubWorkflowPermissionDefaultsObservationRepository,
    GithubWorkflowPermissionObservationCandidate, ProviderDeliveryIdentity,
    ProviderRepositoryOwnerId, ReconcileGithubWorkflowPermissionHandoff,
    ReleaseGithubServerServiceHandoff, TenantScope, WorkflowDispatchSourceClaim,
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

/// Sanitized workflow-permission observation failure.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum GithubWorkflowPermissionObservationError {
    /// Provider or credential infrastructure is temporarily unavailable.
    #[error("the GitHub workflow-permission observation is unavailable")]
    Unavailable,
    /// The authority, repository, or provider authorization was rejected.
    #[error("the GitHub workflow-permission observation was rejected")]
    Rejected,
    /// Exact binding or provider response evidence was inconsistent.
    #[error("the GitHub workflow-permission observation was inconsistent")]
    Inconsistent,
}

/// Sanitized repository-source credential failure for a manual dispatch.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub(crate) enum GithubWorkflowDispatchSourceCredentialError {
    /// Credential or provider infrastructure is temporarily unavailable.
    #[error("workflow dispatch source credential is unavailable")]
    Unavailable,
    /// The exact claim, manifest, or authority was rejected.
    #[error("workflow dispatch source credential was rejected")]
    Rejected,
    /// Durable credential evidence was contradictory.
    #[error("workflow dispatch source credential was inconsistent")]
    Inconsistent,
}

/// Move-only `contents:read` handoff for one exact manual-dispatch claim.
#[must_use = "the workflow dispatch credential must be used and exactly released"]
pub(crate) struct GithubWorkflowDispatchSourceCredential {
    selector: GithubServerServiceAuthoritySelector,
    consumer: GithubServerServiceConsumerClaim,
    repository: automata_ci_scm::RepositoryId,
    required_through: UnixMillis,
    token: SecretString,
    release: Box<dyn GithubServerServiceCredentialRelease>,
}

impl fmt::Debug for GithubWorkflowDispatchSourceCredential {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GithubWorkflowDispatchSourceCredential")
            .field("selector", &self.selector)
            .field("consumer", &self.consumer)
            .field("repository", &self.repository)
            .field("required_through", &self.required_through)
            .field("token", &"[REDACTED]")
            .finish_non_exhaustive()
    }
}

impl GithubWorkflowDispatchSourceCredential {
    pub(crate) const fn token(&self) -> &SecretString {
        &self.token
    }

    pub(crate) fn matches(
        &self,
        claim: &WorkflowDispatchSourceClaim,
        manifest: &GithubProviderManifest,
    ) -> bool {
        claim.repository_contents_authority() == &self.selector
            && claim.credential_consumer() == self.consumer
            && self.repository.as_str() == manifest.github_repository_name().as_str()
            && self.required_through > claim.expires_at()
    }

    pub(crate) async fn release(self) {
        let Self { token, release, .. } = self;
        drop(token);
        release.release().await;
    }
}

/// Provider result plus the sole exact release operation retained for atomic finalization.
pub struct GithubWorkflowPermissionObservationAttempt {
    defaults: GithubWorkflowPermissionDefaults,
    provider_observed_at: UnixMillis,
    handoff_generation: automata_ci_store::GithubServerServiceGeneration,
    release: Option<PendingGithubServerServiceHandoffRelease>,
    release_reservation: Option<GithubProviderCredentialReleaseReservation>,
    releases: Arc<GithubProviderCredentialReleaseSupervisor>,
    repository: Arc<dyn GithubServerServiceCredentialRepository>,
    required_through: UnixMillis,
}

impl fmt::Debug for GithubWorkflowPermissionObservationAttempt {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GithubWorkflowPermissionObservationAttempt")
            .field("defaults", &self.defaults)
            .field("provider_observed_at", &self.provider_observed_at)
            .field("handoff_generation", &self.handoff_generation)
            .field("release", &"[EXACT RELEASE]")
            .field("release_reservation", &"[RESERVED]")
            .field("releases", &"[RELEASE SUPERVISOR]")
            .field("repository", &"[CREDENTIAL REPOSITORY]")
            .field("required_through", &self.required_through)
            .finish()
    }
}

impl GithubWorkflowPermissionObservationAttempt {
    #[must_use]
    pub const fn defaults(&self) -> &GithubWorkflowPermissionDefaults {
        &self.defaults
    }

    #[must_use]
    pub const fn provider_observed_at(&self) -> UnixMillis {
        self.provider_observed_at
    }

    #[must_use]
    pub const fn handoff_generation(&self) -> automata_ci_store::GithubServerServiceGeneration {
        self.handoff_generation
    }

    #[must_use]
    pub const fn release_request(&self) -> &ReleaseGithubServerServiceHandoff {
        self.release
            .as_ref()
            .expect("an observation attempt remains armed until finalization")
            .request()
    }

    /// Disarms exact-release fallback after Store durably finalized the attempt.
    pub fn confirm_finalized(mut self) {
        drop(self.release.take());
        drop(self.release_reservation.take());
    }

    fn supervise_release(&mut self) {
        let (Some(release), Some(reservation)) =
            (self.release.take(), self.release_reservation.take())
        else {
            return;
        };
        drop(self.releases.supervise(
            reservation,
            Box::new(RetainedPendingRelease {
                pending: Arc::new(CorePendingHandoffRelease {
                    repository: Arc::clone(&self.repository),
                    pending: release,
                }),
            }),
            self.required_through,
        ));
    }
}

impl Drop for GithubWorkflowPermissionObservationAttempt {
    fn drop(&mut self) {
        self.supervise_release();
    }
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

    async fn reserve_until(
        &self,
        deadline: Instant,
    ) -> Option<GithubProviderCredentialReleaseReservation> {
        self.redrive_retained();
        let remaining = deadline.checked_duration_since(Instant::now())?;
        tokio::time::timeout(remaining, Arc::clone(&self.permits).acquire_owned())
            .await
            .ok()?
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

/// Ambiguity custody for an acquire whose Store commit may outlive its response.
struct WorkflowPermissionAcquireCustody {
    observation_repository: Arc<dyn GithubWorkflowPermissionDefaultsObservationRepository>,
    releases: Arc<GithubProviderCredentialReleaseSupervisor>,
    reconciliation: Option<ReconcileGithubWorkflowPermissionHandoff>,
    reservation: Option<GithubProviderCredentialReleaseReservation>,
    required_through: UnixMillis,
}

impl WorkflowPermissionAcquireCustody {
    fn new(
        observation_repository: Arc<dyn GithubWorkflowPermissionDefaultsObservationRepository>,
        releases: Arc<GithubProviderCredentialReleaseSupervisor>,
        reconciliation: ReconcileGithubWorkflowPermissionHandoff,
        reservation: GithubProviderCredentialReleaseReservation,
    ) -> Self {
        let required_through = reconciliation.required_through();
        Self {
            observation_repository,
            releases,
            reconciliation: Some(reconciliation),
            reservation: Some(reservation),
            required_through,
        }
    }

    fn confirm_acquired(
        &mut self,
    ) -> Result<GithubProviderCredentialReleaseReservation, GithubWorkflowPermissionObservationError>
    {
        drop(self.reconciliation.take());
        self.reservation
            .take()
            .ok_or(GithubWorkflowPermissionObservationError::Inconsistent)
    }
}

impl Drop for WorkflowPermissionAcquireCustody {
    fn drop(&mut self) {
        let (Some(reconciliation), Some(reservation)) =
            (self.reconciliation.take(), self.reservation.take())
        else {
            return;
        };
        drop(self.releases.supervise(
            reservation,
            Box::new(AmbiguousObservationRelease {
                repository: Arc::clone(&self.observation_repository),
                reconciliation,
            }),
            self.required_through,
        ));
    }
}

impl fmt::Debug for WorkflowPermissionAcquireCustody {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("WorkflowPermissionAcquireCustody")
            .field("observation_repository", &"[OBSERVATION REPOSITORY]")
            .field("releases", &self.releases)
            .field(
                "reconciliation",
                &self.reconciliation.as_ref().map(|_| "[EXACT CLOSURE]"),
            )
            .field(
                "reservation",
                &self.reservation.as_ref().map(|_| "[RESERVED]"),
            )
            .field("required_through", &self.required_through)
            .finish()
    }
}

struct AmbiguousObservationRelease {
    repository: Arc<dyn GithubWorkflowPermissionDefaultsObservationRepository>,
    reconciliation: ReconcileGithubWorkflowPermissionHandoff,
}

impl GithubProviderExactHandoffRelease for AmbiguousObservationRelease {
    fn freeze(&self) -> Arc<dyn GithubProviderPendingHandoffRelease> {
        Arc::new(PendingAmbiguousObservationRelease {
            repository: Arc::clone(&self.repository),
            reconciliation: self.reconciliation.clone(),
        })
    }
}

impl fmt::Debug for AmbiguousObservationRelease {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AmbiguousObservationRelease")
            .field("repository", &"[OBSERVATION REPOSITORY]")
            .field("reconciliation", &"[EXACT CLOSURE]")
            .finish()
    }
}

struct PendingAmbiguousObservationRelease {
    repository: Arc<dyn GithubWorkflowPermissionDefaultsObservationRepository>,
    reconciliation: ReconcileGithubWorkflowPermissionHandoff,
}

#[async_trait]
impl GithubProviderPendingHandoffRelease for PendingAmbiguousObservationRelease {
    async fn replay(&self) -> bool {
        self.repository
            .reconcile_github_workflow_permission_handoff(self.reconciliation.clone())
            .await
            .is_ok()
    }
}

impl fmt::Debug for PendingAmbiguousObservationRelease {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PendingAmbiguousObservationRelease")
            .field("repository", &"[OBSERVATION REPOSITORY]")
            .field("reconciliation", &"[EXACT CLOSURE]")
            .finish()
    }
}

/// Cancellation-safe custody for one workflow-permission observation handoff.
///
/// The binding and a pre-reserved supervisor slot remain live across provider
/// I/O. Dropping the future at any await point freezes and supervises the exact
/// release; a successful caller instead converts this guard into the release
/// request carried by the atomic Store finalization.
struct WorkflowPermissionHandoffCustody {
    issuer: Arc<GithubServerServiceCredentialIssuer>,
    repository: Arc<dyn GithubServerServiceCredentialRepository>,
    releases: Arc<GithubProviderCredentialReleaseSupervisor>,
    binding: Option<GithubServerServiceHandoffBinding>,
    reservation: Option<GithubProviderCredentialReleaseReservation>,
    required_through: UnixMillis,
}

impl WorkflowPermissionHandoffCustody {
    fn new(
        issuer: Arc<GithubServerServiceCredentialIssuer>,
        repository: Arc<dyn GithubServerServiceCredentialRepository>,
        releases: Arc<GithubProviderCredentialReleaseSupervisor>,
        binding: GithubServerServiceHandoffBinding,
        reservation: GithubProviderCredentialReleaseReservation,
        required_through: UnixMillis,
    ) -> Self {
        Self {
            issuer,
            repository,
            releases,
            binding: Some(binding),
            reservation: Some(reservation),
            required_through,
        }
    }

    fn freeze_at(
        &mut self,
        not_before: UnixMillis,
    ) -> Result<
        (
            PendingGithubServerServiceHandoffRelease,
            GithubProviderCredentialReleaseReservation,
        ),
        GithubWorkflowPermissionObservationError,
    > {
        let binding = self
            .binding
            .as_ref()
            .ok_or(GithubWorkflowPermissionObservationError::Inconsistent)?;
        let pending = self
            .issuer
            .prepare_release_binding_at(binding.clone(), not_before)
            .map_err(|_| GithubWorkflowPermissionObservationError::Inconsistent)?;
        drop(self.binding.take());
        let reservation = self
            .reservation
            .take()
            .ok_or(GithubWorkflowPermissionObservationError::Inconsistent)?;
        Ok((pending, reservation))
    }

    fn supervise_pending(&mut self) {
        let Some(binding) = self.binding.as_ref() else {
            return;
        };
        let Ok(pending) = self.issuer.prepare_release_binding(binding.clone()) else {
            return;
        };
        drop(self.binding.take());
        let Some(reservation) = self.reservation.take() else {
            return;
        };
        drop(self.releases.supervise(
            reservation,
            Box::new(RetainedPendingRelease {
                pending: Arc::new(CorePendingHandoffRelease {
                    repository: Arc::clone(&self.repository),
                    pending,
                }),
            }),
            self.required_through,
        ));
    }
}

impl Drop for WorkflowPermissionHandoffCustody {
    fn drop(&mut self) {
        self.supervise_pending();
    }
}

impl fmt::Debug for WorkflowPermissionHandoffCustody {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("WorkflowPermissionHandoffCustody")
            .field("issuer", &self.issuer)
            .field("repository", &"[AUTHORITY REPOSITORY]")
            .field("releases", &self.releases)
            .field("binding", &self.binding.as_ref().map(|_| "[EXACT BINDING]"))
            .field(
                "reservation",
                &self.reservation.as_ref().map(|_| "[RESERVED]"),
            )
            .field("required_through", &self.required_through)
            .finish()
    }
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
    handoff_id: GithubServerServiceHandoffId,
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
        let handoff_id = binding.handoff_id();
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
            handoff_id,
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
    workflow_permission_issuer: Option<Arc<GithubServerServiceCredentialIssuer>>,
    workflow_permission_repository: Option<Arc<dyn GithubServerServiceCredentialRepository>>,
    workflow_permission_observations:
        Option<Arc<dyn GithubWorkflowPermissionDefaultsObservationRepository>>,
    releases: Option<Arc<GithubProviderCredentialReleaseSupervisor>>,
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
        issuer: Arc<GithubServerServiceCredentialIssuer>,
        repository: Arc<dyn GithubServerServiceCredentialRepository>,
        authority_repository: Arc<dyn GithubServerServiceAuthorityRepository>,
        observation_repository: Arc<dyn GithubWorkflowPermissionDefaultsObservationRepository>,
        releases: Arc<GithubProviderCredentialReleaseSupervisor>,
        authorities: &[GithubServerServiceAuthorityIdentity],
        routes: GithubProviderCredentialRequestResolver,
        observation_clock: Arc<dyn GithubServerServiceCoordinatorClock>,
    ) -> Result<Self, GithubProviderCredentialAdapterConfigurationError> {
        let handoffs = Arc::new(ExactCredentialHandoffIssuer {
            issuer: issuer.clone(),
            repository: repository.clone(),
            releases: releases.clone(),
        });
        let mut adapters = Self::with_handoffs(handoffs, authorities)?;
        adapters.workflow_permission_issuer = Some(issuer);
        adapters.workflow_permission_repository = Some(repository);
        adapters.workflow_permission_observations = Some(observation_repository);
        adapters.releases = Some(releases);
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
            workflow_permission_issuer: None,
            workflow_permission_repository: None,
            workflow_permission_observations: None,
            releases: None,
            observation_clock: None,
            authorities: Arc::new(exact),
            durable_authorities: None,
        })
    }

    #[cfg(test)]
    fn with_durable_handoffs(
        handoffs: Arc<dyn GithubProviderCredentialHandoffIssuer>,
        authorities: &[GithubServerServiceAuthorityIdentity],
        repository: Arc<dyn GithubProviderAuthorityLookup>,
        routes: GithubProviderCredentialRequestResolver,
    ) -> Result<Self, GithubProviderCredentialAdapterConfigurationError> {
        let mut adapters = Self::with_handoffs(handoffs, authorities)?;
        adapters.durable_authorities =
            Some(DurableGithubProviderAuthorityResolver { repository, routes });
        Ok(adapters)
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

    async fn operation_authority(
        &self,
        context: &automata_ci_provider_delivery::ProviderRuntimeContext,
        external_repository_id: &automata_ci_provider::ExternalRepositoryId,
        installation_id: u64,
        app_id: automata_ci_provider_github::GithubCheckAppId,
        repository: &automata_ci_scm::RepositoryId,
        scope: GithubServerServiceScope,
    ) -> Result<
        (
            GithubServerServiceAuthoritySelector,
            automata_ci_scm::RepositoryId,
        ),
        GithubProviderCredentialHandoffError,
    > {
        let tenant = TenantScope::from_authenticated_tenant_id(
            context
                .connection()
                .configuration()
                .workspace_id()
                .to_string(),
        )
        .map_err(|_| GithubProviderCredentialHandoffError::Inconsistent)?;
        let github_repository_id = external_repository_id
            .as_str()
            .parse::<u64>()
            .ok()
            .filter(|value| *value != 0)
            .ok_or(GithubProviderCredentialHandoffError::Inconsistent)?;
        let mut candidates = self.authorities.values().filter(|authority| {
            authority.scope() == scope
                && authority.tenant() == &tenant
                && authority.connection_id() == context.connection().connection_id()
                && authority.installation_id().get() == installation_id
                && authority.github_app_id().get() == app_id.get()
                && authority.github_repository_id().get() == github_repository_id
        });
        let candidate = candidates
            .next()
            .filter(|_| candidates.next().is_none())
            .ok_or(GithubProviderCredentialHandoffError::Rejected)?;
        let selector = GithubServerServiceAuthoritySelector::from_identity(candidate);
        let authority = self.authority(&selector, scope).await?;
        let canonical_request = github_server_service_credential_request(&authority)
            .map_err(|_| GithubProviderCredentialHandoffError::Inconsistent)?;
        if canonical_request.repository().repository() != repository
            || authority.github_repository_id().get() != github_repository_id
        {
            return Err(GithubProviderCredentialHandoffError::Rejected);
        }
        Ok((
            selector,
            canonical_request.repository().repository().clone(),
        ))
    }

    async fn acquire_checks(
        &self,
        context: ChecksCredentialContext,
    ) -> Result<GithubChecksServerServiceCredential, GithubChecksCredentialProviderError> {
        let authority = self
            .authority(&context.selector, GithubServerServiceScope::ChecksWrite)
            .await
            .map_err(checks_handoff_error)?;
        if !checks_identity_matches(&authority, &context.identity)
            || context.consumer.action().required_scope() != GithubServerServiceScope::ChecksWrite
        {
            return Err(GithubChecksCredentialProviderError::Rejected);
        }
        let request = acquire_request(
            context.selector.clone(),
            context.consumer,
            context.observed_at,
            context.required_through,
        )
        .map_err(checks_handoff_error)?;
        let handoff = self
            .handoffs
            .acquire(request)
            .await
            .map_err(checks_handoff_error)?;
        if !handoff_matches(&handoff, &context) {
            release_invalid_handoff(handoff).await;
            return Err(GithubChecksCredentialProviderError::InvariantViolation);
        }
        let Ok(canonical_request) = github_server_service_credential_request(&authority) else {
            release_invalid_handoff(handoff).await;
            return Err(GithubChecksCredentialProviderError::InvariantViolation);
        };
        let repository = canonical_request.repository().repository().clone();
        let drop_release_arm = handoff.drop_release_arm.clone();
        let credential = GithubChecksServerServiceCredential::new(
            handoff.selector,
            handoff.handoff_id,
            handoff.consumer,
            handoff.required_through,
            handoff.acquired_at,
            context.identity.tenant().clone(),
            context.identity.repository_id(),
            context.identity.connection_id(),
            context.identity.installation_id(),
            context.identity.github_repository_id(),
            context.identity.app_id(),
            repository,
            handoff.token,
            handoff.usable_until,
            handoff.release,
        );
        match credential {
            Ok(credential) => {
                arm_drop_release(drop_release_arm);
                Ok(credential)
            }
            Err(_) => Err(GithubChecksCredentialProviderError::InvariantViolation),
        }
    }

    async fn acquire_common_result(
        &self,
        request: GithubResultCredentialRequest<'_>,
    ) -> Result<GithubResultCredential, GithubResultCredentialProviderError> {
        let (selector, repository) = self
            .operation_authority(
                request.context(),
                request.claimed().subject().repository().external_id(),
                request.installation_id(),
                request.app_id(),
                request.repository(),
                GithubServerServiceScope::ChecksWrite,
            )
            .await
            .map_err(common_result_handoff_error)?;
        let consumer = common_result_consumer(&request)?;
        let observed_at = self
            .observation_clock
            .as_ref()
            .ok_or(GithubResultCredentialProviderError::InvariantViolation)?
            .now();
        let handoff_request = acquire_request(
            selector.clone(),
            consumer,
            observed_at,
            request.required_through(),
        )
        .map_err(common_result_handoff_error)?;
        let handoff = self
            .handoffs
            .acquire(handoff_request)
            .await
            .map_err(common_result_handoff_error)?;
        if handoff.selector != selector
            || handoff.consumer != consumer
            || handoff.key.authority_id() != selector.authority_id()
            || handoff.required_through != request.required_through()
            || handoff.acquired_at != observed_at
            || handoff.usable_until <= request.required_through()
        {
            release_invalid_handoff(handoff).await;
            return Err(GithubResultCredentialProviderError::InvariantViolation);
        }
        let drop_release_arm = handoff.drop_release_arm.clone();
        let credential = GithubResultCredential::new(
            request.context().connection().connection_id(),
            request.context().connection().revision(),
            request
                .claimed()
                .subject()
                .repository()
                .external_id()
                .clone(),
            request.claim(),
            request.operation(),
            request.app_id(),
            request.installation_id(),
            repository,
            handoff.token,
            request.required_through(),
            handoff.usable_until,
            Box::new(CommonResultCredentialRelease {
                inner: handoff.release,
            }),
        )
        .map_err(|_| GithubResultCredentialProviderError::InvariantViolation)?;
        arm_drop_release(drop_release_arm);
        Ok(credential)
    }

    async fn acquire_common_trigger(
        &self,
        request: GithubTriggerCredentialRequest<'_>,
    ) -> Result<GithubTriggerCredential, GithubTriggerCredentialProviderError> {
        let action = common_trigger_action(request.operation());
        let (selector, repository) = self
            .operation_authority(
                request.context(),
                request
                    .context()
                    .connection()
                    .configuration()
                    .repository()
                    .external_id(),
                request.installation_id(),
                request.app_id(),
                request.repository(),
                action.required_scope(),
            )
            .await
            .map_err(common_trigger_handoff_error)?;
        let consumer = common_trigger_consumer(&request)?;
        let observed_at = self
            .observation_clock
            .as_ref()
            .ok_or(GithubTriggerCredentialProviderError::InvariantViolation)?
            .now();
        let handoff_request = acquire_request(
            selector.clone(),
            consumer,
            observed_at,
            request.required_through(),
        )
        .map_err(common_trigger_handoff_error)?;
        let handoff = self
            .handoffs
            .acquire(handoff_request)
            .await
            .map_err(common_trigger_handoff_error)?;
        if handoff.selector != selector
            || handoff.consumer != consumer
            || handoff.key.authority_id() != selector.authority_id()
            || handoff.required_through != request.required_through()
            || handoff.acquired_at != observed_at
            || handoff.usable_until <= request.required_through()
        {
            release_invalid_handoff(handoff).await;
            return Err(GithubTriggerCredentialProviderError::InvariantViolation);
        }
        let drop_release_arm = handoff.drop_release_arm.clone();
        let credential = GithubTriggerCredential::new(
            request.context().connection().revision(),
            request
                .context()
                .connection()
                .configuration()
                .repository()
                .external_id()
                .clone(),
            request.fence(),
            request.operation(),
            request.app_id(),
            request.installation_id(),
            repository,
            handoff.token,
            request.required_through(),
            handoff.usable_until,
            Box::new(CommonTriggerCredentialRelease {
                inner: handoff.release,
            }),
        )
        .map_err(|_| GithubTriggerCredentialProviderError::InvariantViolation)?;
        arm_drop_release(drop_release_arm);
        Ok(credential)
    }

    async fn acquire_source(
        &self,
        context: SourceCredentialContext,
    ) -> Result<GithubDeliverySourceCredential, GithubDeliverySourceCredentialProviderError> {
        let action = repository_action(context.action);
        let authority = self
            .authority(&context.selector, action.required_scope())
            .await
            .map_err(source_handoff_error)?;
        if !repository_identity_matches(&authority, &context.identity)
            || context.consumer.action() != action
        {
            return Err(GithubDeliverySourceCredentialProviderError::Rejected);
        }
        let request = acquire_request(
            context.selector.clone(),
            context.consumer,
            context.observed_at,
            context.required_through,
        )
        .map_err(source_handoff_error)?;
        let handoff = self
            .handoffs
            .acquire(request)
            .await
            .map_err(source_handoff_error)?;
        if !repository_handoff_matches(&handoff, &context) {
            release_invalid_handoff(handoff).await;
            return Err(GithubDeliverySourceCredentialProviderError::InvariantViolation);
        }
        let Ok(canonical_request) = github_server_service_credential_request(&authority) else {
            release_invalid_handoff(handoff).await;
            return Err(GithubDeliverySourceCredentialProviderError::InvariantViolation);
        };
        let repository = canonical_request.repository().repository().clone();
        let Ok(binding) = GithubDeliverySourceCredentialBinding::new(
            context.identity,
            context.repository_owner_id,
            repository,
            handoff.selector.clone(),
            handoff.handoff_id,
            handoff.consumer,
            handoff.required_through,
        ) else {
            release_invalid_handoff(handoff).await;
            return Err(GithubDeliverySourceCredentialProviderError::InvariantViolation);
        };
        let drop_release_arm = handoff.drop_release_arm.clone();
        let credential = GithubDeliverySourceCredential::new(
            binding,
            handoff.acquired_at,
            handoff.token,
            handoff.usable_until,
            handoff.release,
        );
        match credential {
            Ok(credential) => {
                arm_drop_release(drop_release_arm);
                Ok(credential)
            }
            Err(_) => Err(GithubDeliverySourceCredentialProviderError::InvariantViolation),
        }
    }

    async fn acquire_schedule_source(
        &self,
        request: GithubScheduleSourceCredentialRequest<'_>,
    ) -> Result<GithubScheduleSourceCredential, GithubScheduleSourceCredentialProviderError> {
        let authority = self
            .authority(
                request.authority_selector(),
                GithubServerServiceScope::RepositoryContentsRead,
            )
            .await
            .map_err(schedule_source_handoff_error)?;
        if !schedule_identity_matches(&authority, request.manifest()) {
            return Err(GithubScheduleSourceCredentialProviderError::Rejected);
        }
        let consumer = request
            .consumer_claim()
            .map_err(|_| GithubScheduleSourceCredentialProviderError::InvariantViolation)?;
        let handoff_request = acquire_request(
            request.authority_selector().clone(),
            consumer,
            request.observed_at(),
            request.required_through(),
        )
        .map_err(schedule_source_handoff_error)?;
        let handoff = self
            .handoffs
            .acquire(handoff_request)
            .await
            .map_err(schedule_source_handoff_error)?;
        if !schedule_handoff_matches(&handoff, &request, consumer) {
            release_invalid_handoff(handoff).await;
            return Err(GithubScheduleSourceCredentialProviderError::InvariantViolation);
        }
        let Ok(canonical_request) = github_server_service_credential_request(&authority) else {
            release_invalid_handoff(handoff).await;
            return Err(GithubScheduleSourceCredentialProviderError::InvariantViolation);
        };
        let repository = canonical_request.repository().repository().clone();
        let drop_release_arm = handoff.drop_release_arm.clone();
        let credential = GithubScheduleSourceCredential::new(
            &request,
            repository,
            handoff.selector,
            handoff.consumer,
            handoff.token,
            handoff.release,
        );
        match credential {
            Ok(credential) => {
                arm_drop_release(drop_release_arm);
                Ok(credential)
            }
            Err(_) => Err(GithubScheduleSourceCredentialProviderError::InvariantViolation),
        }
    }

    /// Acquires one exact repository handoff for a live manual-dispatch claim.
    pub(crate) async fn acquire_workflow_dispatch_source(
        &self,
        claim: &WorkflowDispatchSourceClaim,
        manifest: &GithubProviderManifest,
        observed_at: UnixMillis,
    ) -> Result<GithubWorkflowDispatchSourceCredential, GithubWorkflowDispatchSourceCredentialError>
    {
        let selector = claim.repository_contents_authority();
        if manifest.tenant() != claim.tenant()
            || manifest.repository_id() != claim.repository_id()
            || manifest.connection_id() != claim.connection_id()
            || manifest.revision() != claim.manifest_revision()
            || manifest.digest() != claim.manifest_digest()
        {
            return Err(GithubWorkflowDispatchSourceCredentialError::Rejected);
        }
        let authority = self
            .authority(selector, GithubServerServiceScope::RepositoryContentsRead)
            .await
            .map_err(workflow_dispatch_source_handoff_error)?;
        if !schedule_identity_matches(&authority, manifest) {
            return Err(GithubWorkflowDispatchSourceCredentialError::Rejected);
        }
        let consumer = claim.credential_consumer();
        if consumer.action() != GithubServerServiceAction::ResolveWorkflowDispatchSource {
            return Err(GithubWorkflowDispatchSourceCredentialError::Inconsistent);
        }
        let required_through = claim
            .expires_at()
            .get()
            .checked_add(consumer.action().provider_tail_millis())
            .map(UnixMillis::new)
            .ok_or(GithubWorkflowDispatchSourceCredentialError::Inconsistent)?;
        let request = acquire_request(selector.clone(), consumer, observed_at, required_through)
            .map_err(workflow_dispatch_source_handoff_error)?;
        let handoff = self
            .handoffs
            .acquire(request)
            .await
            .map_err(workflow_dispatch_source_handoff_error)?;
        let exact = handoff.selector == *selector
            && handoff.consumer == consumer
            && handoff.key.authority_id() == selector.authority_id()
            && handoff.required_through == required_through
            && handoff.acquired_at == observed_at
            && handoff.usable_until >= required_through;
        if !exact {
            release_invalid_handoff(handoff).await;
            return Err(GithubWorkflowDispatchSourceCredentialError::Inconsistent);
        }
        let canonical_repository = github_server_service_credential_request(&authority)
            .ok()
            .map(|request| request.repository().repository().clone());
        let (handoff, repository) = validate_workflow_dispatch_source_repository(
            handoff,
            canonical_repository,
            manifest.github_repository_name().as_str(),
        )
        .await?;
        let drop_release_arm = handoff.drop_release_arm.clone();
        let credential = GithubWorkflowDispatchSourceCredential {
            selector: handoff.selector,
            consumer: handoff.consumer,
            repository,
            required_through: handoff.required_through,
            token: handoff.token,
            release: handoff.release,
        };
        arm_drop_release(drop_release_arm);
        Ok(credential)
    }

    /// Borrows exactly `Administration: read` to observe one manifest's
    /// effective repository workflow-permission defaults.
    ///
    /// # Errors
    ///
    /// Returns a sanitized observation error when the authority or exact
    /// credential binding is invalid, provider access fails, or bounded
    /// release custody is unavailable.
    #[allow(clippy::too_many_lines)]
    pub async fn observe_workflow_permission_defaults(
        &self,
        endpoint: &GithubHttpEndpoint,
        manifest: &GithubProviderManifest,
        candidate: &GithubWorkflowPermissionObservationCandidate,
        deadline: Instant,
    ) -> Result<GithubWorkflowPermissionObservationAttempt, GithubWorkflowPermissionObservationError>
    {
        let issuer = self
            .workflow_permission_issuer
            .as_ref()
            .ok_or(GithubWorkflowPermissionObservationError::Inconsistent)?;
        let observation_clock = self
            .observation_clock
            .as_ref()
            .ok_or(GithubWorkflowPermissionObservationError::Inconsistent)?;
        let releases = self
            .releases
            .as_ref()
            .ok_or(GithubWorkflowPermissionObservationError::Inconsistent)?;
        let repository = self
            .workflow_permission_repository
            .as_ref()
            .ok_or(GithubWorkflowPermissionObservationError::Inconsistent)?;
        let observation_repository = self
            .workflow_permission_observations
            .as_ref()
            .ok_or(GithubWorkflowPermissionObservationError::Inconsistent)?;
        let release_reservation = releases
            .reserve_until(deadline)
            .await
            .ok_or(GithubWorkflowPermissionObservationError::Unavailable)?;
        let selector = candidate.authority_selector();
        let authority = self
            .authority(selector, GithubServerServiceScope::WorkflowPermissionsRead)
            .await
            .map_err(workflow_permission_handoff_error)?;
        if !workflow_permission_identity_matches(&authority, manifest) {
            return Err(GithubWorkflowPermissionObservationError::Rejected);
        }
        let consumer = candidate.consumer();
        let required_through = candidate
            .claimed_at()
            .get()
            .checked_add(consumer.action().provider_tail_millis())
            .map(UnixMillis::new)
            .ok_or(GithubWorkflowPermissionObservationError::Inconsistent)?;
        let request = acquire_request(
            selector.clone(),
            consumer,
            candidate.claimed_at(),
            required_through,
        )
        .map_err(workflow_permission_handoff_error)?;
        let reconciliation = ReconcileGithubWorkflowPermissionHandoff::new(candidate.clone())
            .map_err(|_| GithubWorkflowPermissionObservationError::Inconsistent)?;
        let mut acquisition_custody = WorkflowPermissionAcquireCustody::new(
            Arc::clone(observation_repository),
            Arc::clone(releases),
            reconciliation,
            release_reservation,
        );
        let credential = issuer
            .acquire(request)
            .await
            .map_err(|error| workflow_permission_handoff_error(map_handoff_error(&error)))?;
        let release_reservation = acquisition_custody.confirm_acquired()?;
        let binding_evidence = credential.binding().clone();
        let handoff_generation = binding_evidence.key().generation();
        let (token, binding) = credential.into_secret_and_binding();
        let mut custody = WorkflowPermissionHandoffCustody::new(
            Arc::clone(issuer),
            Arc::clone(repository),
            Arc::clone(releases),
            binding,
            release_reservation,
            required_through,
        );
        if binding_evidence.selector() != selector
            || binding_evidence.consumer() != consumer
            || binding_evidence.required_through() != required_through
            || binding_evidence.acquired_at() != candidate.claimed_at()
        {
            drop(token);
            return Err(GithubWorkflowPermissionObservationError::Inconsistent);
        }
        let Ok(canonical_request) = github_server_service_credential_request(&authority) else {
            drop(token);
            return Err(GithubWorkflowPermissionObservationError::Inconsistent);
        };
        if canonical_request.repository().repository().as_str()
            != manifest.github_repository_name().as_str()
        {
            drop(token);
            return Err(GithubWorkflowPermissionObservationError::Inconsistent);
        }
        let result = endpoint
            .workflow_permission_defaults(GithubWorkflowPermissionDefaultsRequest::new(
                canonical_request.repository().repository(),
                &token,
                deadline,
            ))
            .await;
        let provider_observed_at = observation_clock.now().max(candidate.claimed_at());
        drop(token);
        let (release, release_reservation) = custody.freeze_at(provider_observed_at)?;
        match result {
            Ok(defaults) => Ok(GithubWorkflowPermissionObservationAttempt {
                defaults,
                provider_observed_at,
                handoff_generation,
                release: Some(release),
                release_reservation: Some(release_reservation),
                releases: Arc::clone(releases),
                repository: Arc::clone(repository),
                required_through,
            }),
            Err(error) => {
                self.retain_workflow_permission_release(
                    release,
                    release_reservation,
                    required_through,
                );
                Err(map_workflow_permission_endpoint_error(error))
            }
        }
    }

    /// Transfers an unfinalized observation release into the bounded exact-release supervisor.
    pub fn retain_workflow_permission_attempt(
        &self,
        mut attempt: GithubWorkflowPermissionObservationAttempt,
    ) {
        attempt.supervise_release();
    }

    fn retain_workflow_permission_release(
        &self,
        pending: PendingGithubServerServiceHandoffRelease,
        reservation: GithubProviderCredentialReleaseReservation,
        required_through: UnixMillis,
    ) {
        let releases = self
            .releases
            .as_ref()
            .expect("observation handoffs are configured only with a release supervisor");
        let repository = self
            .workflow_permission_repository
            .as_ref()
            .expect("observation handoffs are configured only with a credential repository");
        drop(releases.supervise(
            reservation,
            Box::new(RetainedPendingRelease {
                pending: Arc::new(CorePendingHandoffRelease {
                    repository: Arc::clone(repository),
                    pending,
                }),
            }),
            required_through,
        ));
    }
}

async fn validate_workflow_dispatch_source_repository(
    handoff: GithubProviderCredentialHandoff,
    canonical_repository: Option<automata_ci_scm::RepositoryId>,
    expected_repository: &str,
) -> Result<
    (
        GithubProviderCredentialHandoff,
        automata_ci_scm::RepositoryId,
    ),
    GithubWorkflowDispatchSourceCredentialError,
> {
    let Some(repository) = canonical_repository else {
        release_invalid_handoff(handoff).await;
        return Err(GithubWorkflowDispatchSourceCredentialError::Inconsistent);
    };
    if repository.as_str() != expected_repository {
        release_invalid_handoff(handoff).await;
        return Err(GithubWorkflowDispatchSourceCredentialError::Inconsistent);
    }
    Ok((handoff, repository))
}

fn workflow_permission_identity_matches(
    authority: &GithubServerServiceAuthorityIdentity,
    manifest: &GithubProviderManifest,
) -> bool {
    authority.scope() == GithubServerServiceScope::WorkflowPermissionsRead
        && authority.tenant() == manifest.tenant()
        && authority.repository_id() == manifest.repository_id()
        && authority.connection_id() == manifest.connection_id()
        && authority.installation_id() == manifest.installation_id()
        && authority.github_app_id() == manifest.github_app_id()
        && authority.github_repository_id() == manifest.github_repository_id()
        && authority.github_repository_name() == manifest.github_repository_name()
        && authority.app_configuration_revision() == manifest.app_configuration_revision()
        && authority.policy_revision() == manifest.policy_revision()
}

const fn workflow_permission_handoff_error(
    error: GithubProviderCredentialHandoffError,
) -> GithubWorkflowPermissionObservationError {
    match error {
        GithubProviderCredentialHandoffError::Unavailable => {
            GithubWorkflowPermissionObservationError::Unavailable
        }
        GithubProviderCredentialHandoffError::Rejected => {
            GithubWorkflowPermissionObservationError::Rejected
        }
        GithubProviderCredentialHandoffError::Inconsistent => {
            GithubWorkflowPermissionObservationError::Inconsistent
        }
    }
}

const fn workflow_dispatch_source_handoff_error(
    error: GithubProviderCredentialHandoffError,
) -> GithubWorkflowDispatchSourceCredentialError {
    match error {
        GithubProviderCredentialHandoffError::Unavailable => {
            GithubWorkflowDispatchSourceCredentialError::Unavailable
        }
        GithubProviderCredentialHandoffError::Rejected => {
            GithubWorkflowDispatchSourceCredentialError::Rejected
        }
        GithubProviderCredentialHandoffError::Inconsistent => {
            GithubWorkflowDispatchSourceCredentialError::Inconsistent
        }
    }
}

const fn map_workflow_permission_endpoint_error(
    error: GithubEndpointError,
) -> GithubWorkflowPermissionObservationError {
    match error {
        GithubEndpointError::Unauthorized | GithubEndpointError::Forbidden => {
            GithubWorkflowPermissionObservationError::Rejected
        }
        GithubEndpointError::RateLimited { .. } | GithubEndpointError::Unavailable => {
            GithubWorkflowPermissionObservationError::Unavailable
        }
        GithubEndpointError::InvalidResponse => {
            GithubWorkflowPermissionObservationError::Inconsistent
        }
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
            .field(
                "workflow_permission_issuer",
                &self.workflow_permission_issuer.is_some(),
            )
            .field(
                "workflow_permission_repository",
                &self.workflow_permission_repository.is_some(),
            )
            .field(
                "workflow_permission_observations",
                &self.workflow_permission_observations.is_some(),
            )
            .field("releases", &self.releases.is_some())
            .field("observation_clock", &self.observation_clock.is_some())
            .field("authority_count", &self.authorities.len())
            .field("durable_authorities", &self.durable_authorities.is_some())
            .finish()
    }
}

#[async_trait]
impl GithubChecksCredentialProvider for GithubProviderCredentialAdapters {
    async fn acquire(
        &self,
        request: GithubChecksCredentialRequest<'_>,
    ) -> Result<GithubChecksServerServiceCredential, GithubChecksCredentialProviderError> {
        let consumer = request
            .consumer_claim()
            .map_err(|_| GithubChecksCredentialProviderError::InvariantViolation)?;
        self.acquire_checks(ChecksCredentialContext {
            identity: request.identity().clone(),
            selector: request.authority_selector().clone(),
            consumer,
            observed_at: request.observed_at(),
            required_through: request.required_through(),
        })
        .await
    }
}

struct CommonResultCredentialRelease {
    inner: Box<dyn GithubServerServiceCredentialRelease>,
}

#[async_trait]
impl GithubResultCredentialRelease for CommonResultCredentialRelease {
    async fn release(self: Box<Self>) {
        self.inner.release().await;
    }
}

impl fmt::Debug for CommonResultCredentialRelease {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CommonResultCredentialRelease")
            .field("inner", &"[exact supervised release]")
            .finish()
    }
}

#[async_trait]
impl GithubResultCredentialProvider for GithubProviderCredentialAdapters {
    async fn acquire(
        &self,
        request: GithubResultCredentialRequest<'_>,
    ) -> Result<GithubResultCredential, GithubResultCredentialProviderError> {
        self.acquire_common_result(request).await
    }
}

struct CommonTriggerCredentialRelease {
    inner: Box<dyn GithubServerServiceCredentialRelease>,
}

#[async_trait]
impl GithubTriggerCredentialRelease for CommonTriggerCredentialRelease {
    async fn release(self: Box<Self>) {
        self.inner.release().await;
    }
}

impl fmt::Debug for CommonTriggerCredentialRelease {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CommonTriggerCredentialRelease")
            .field("inner", &"[exact supervised release]")
            .finish()
    }
}

#[async_trait]
impl GithubTriggerCredentialProvider for GithubProviderCredentialAdapters {
    async fn acquire(
        &self,
        request: GithubTriggerCredentialRequest<'_>,
    ) -> Result<GithubTriggerCredential, GithubTriggerCredentialProviderError> {
        self.acquire_common_trigger(request).await
    }
}

#[async_trait]
impl GithubDeliverySourceCredentialProvider for GithubProviderCredentialAdapters {
    async fn acquire(
        &self,
        request: GithubDeliverySourceCredentialRequest<'_>,
    ) -> Result<GithubDeliverySourceCredential, GithubDeliverySourceCredentialProviderError> {
        let consumer = request
            .consumer_claim()
            .map_err(|_| GithubDeliverySourceCredentialProviderError::InvariantViolation)?;
        self.acquire_source(SourceCredentialContext {
            identity: request.identity().clone(),
            repository_owner_id: request.repository_owner_id(),
            selector: request.authority_selector().clone(),
            action: request.action(),
            consumer,
            observed_at: request.observed_at(),
            required_through: request.required_through(),
        })
        .await
    }
}

#[async_trait]
impl GithubScheduleSourceCredentialProvider for GithubProviderCredentialAdapters {
    async fn acquire(
        &self,
        request: GithubScheduleSourceCredentialRequest<'_>,
    ) -> Result<GithubScheduleSourceCredential, GithubScheduleSourceCredentialProviderError> {
        self.acquire_schedule_source(request).await
    }
}

struct ChecksCredentialContext {
    identity: GithubCheckSubjectIdentity,
    selector: GithubServerServiceAuthoritySelector,
    consumer: GithubServerServiceConsumerClaim,
    observed_at: UnixMillis,
    required_through: UnixMillis,
}

struct SourceCredentialContext {
    identity: ProviderDeliveryIdentity,
    repository_owner_id: ProviderRepositoryOwnerId,
    selector: GithubServerServiceAuthoritySelector,
    action: GithubDeliveryRepositoryAction,
    consumer: GithubServerServiceConsumerClaim,
    observed_at: UnixMillis,
    required_through: UnixMillis,
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

fn checks_identity_matches(
    authority: &GithubServerServiceAuthorityIdentity,
    identity: &GithubCheckSubjectIdentity,
) -> bool {
    authority.tenant() == identity.tenant()
        && authority.repository_id() == identity.repository_id()
        && authority.connection_id() == identity.connection_id()
        && authority.installation_id() == identity.installation_id()
        && authority.github_repository_id() == identity.github_repository_id()
        && authority.github_repository_name() == identity.github_repository_name()
        && authority.github_app_id().get() == identity.app_id().get()
}

fn repository_identity_matches(
    authority: &GithubServerServiceAuthorityIdentity,
    identity: &ProviderDeliveryIdentity,
) -> bool {
    identity.provider() == "github"
        && authority.tenant() == identity.tenant()
        && authority.connection_id() == identity.connection_id()
        && authority.installation_id() == identity.installation_id()
        && authority.github_repository_id() == identity.repository_id()
        && authority.github_repository_name().as_str() == identity.repository_identity()
}

fn schedule_identity_matches(
    authority: &GithubServerServiceAuthorityIdentity,
    manifest: &GithubProviderManifest,
) -> bool {
    authority.tenant() == manifest.tenant()
        && authority.repository_id() == manifest.repository_id()
        && authority.connection_id() == manifest.connection_id()
        && authority.installation_id() == manifest.installation_id()
        && authority.github_app_id() == manifest.github_app_id()
        && authority.github_repository_id() == manifest.github_repository_id()
        && authority.github_repository_name() == manifest.github_repository_name()
        && authority.app_client_id() == manifest.app_client_id()
        && authority.jwt_issuer() == manifest.jwt_issuer()
        && authority.app_key_spki_sha256() == manifest.app_key_spki_sha256()
        && authority.app_configuration_revision() == manifest.app_configuration_revision()
        && authority.policy_revision() == manifest.policy_revision()
}

fn handoff_matches(
    handoff: &GithubProviderCredentialHandoff,
    context: &ChecksCredentialContext,
) -> bool {
    handoff.selector == context.selector
        && handoff.consumer == context.consumer
        && handoff.key.authority_id() == context.selector.authority_id()
        && handoff.required_through == context.required_through
        && handoff.acquired_at == context.observed_at
        && handoff.usable_until > context.required_through
}

fn repository_handoff_matches(
    handoff: &GithubProviderCredentialHandoff,
    context: &SourceCredentialContext,
) -> bool {
    handoff.selector == context.selector
        && handoff.consumer == context.consumer
        && handoff.key.authority_id() == context.selector.authority_id()
        && handoff.required_through == context.required_through
        && handoff.acquired_at == context.observed_at
        && handoff.usable_until >= context.required_through
}

fn schedule_handoff_matches(
    handoff: &GithubProviderCredentialHandoff,
    request: &GithubScheduleSourceCredentialRequest<'_>,
    consumer: GithubServerServiceConsumerClaim,
) -> bool {
    handoff.selector == *request.authority_selector()
        && handoff.consumer == consumer
        && handoff.key.authority_id() == request.authority_selector().authority_id()
        && handoff.required_through == request.required_through()
        && handoff.acquired_at == request.observed_at()
        && handoff.usable_until >= request.required_through()
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

const fn repository_action(action: GithubDeliveryRepositoryAction) -> GithubServerServiceAction {
    match action {
        GithubDeliveryRepositoryAction::FetchRepositoryRevision => {
            GithubServerServiceAction::FetchRepositoryRevision
        }
        GithubDeliveryRepositoryAction::FetchRepositoryChangedFiles => {
            GithubServerServiceAction::FetchRepositoryChangedFiles
        }
        GithubDeliveryRepositoryAction::FetchPullRequestFiles => {
            GithubServerServiceAction::FetchPullRequestFiles
        }
    }
}

fn common_result_consumer(
    request: &GithubResultCredentialRequest<'_>,
) -> Result<GithubServerServiceConsumerClaim, GithubResultCredentialProviderError> {
    let claim = request.claim();
    let consumer_id = GithubServerServiceConsumerId::from_uuid(claim.subject_id().as_uuid())
        .map_err(|_| GithubResultCredentialProviderError::InvariantViolation)?;
    let owner = GithubServerServiceWorkerId::from_uuid(claim.worker_id().as_uuid())
        .map_err(|_| GithubResultCredentialProviderError::InvariantViolation)?;
    let fence = GithubServerServiceClaimFence::new(claim.fence())
        .map_err(|_| GithubResultCredentialProviderError::InvariantViolation)?;
    let revision = GithubServerServiceRevision::new(request.claimed().desired().generation())
        .map_err(|_| GithubResultCredentialProviderError::InvariantViolation)?;
    Ok(GithubServerServiceConsumerClaim::new(
        consumer_id,
        owner,
        fence,
        common_result_action(request.operation()),
        revision,
    ))
}

fn common_trigger_consumer(
    request: &GithubTriggerCredentialRequest<'_>,
) -> Result<GithubServerServiceConsumerClaim, GithubTriggerCredentialProviderError> {
    let receipt = request.invocation().receipt();
    let fence = request.fence();
    let consumer_id = GithubServerServiceConsumerId::from_uuid(receipt.invocation_id().as_uuid())
        .map_err(|_| GithubTriggerCredentialProviderError::InvariantViolation)?;
    let owner = GithubServerServiceWorkerId::from_uuid(fence.worker_id().as_uuid())
        .map_err(|_| GithubTriggerCredentialProviderError::InvariantViolation)?;
    let claim_fence = GithubServerServiceClaimFence::new(fence.token())
        .map_err(|_| GithubTriggerCredentialProviderError::InvariantViolation)?;
    let revision = GithubServerServiceRevision::new(u64::from(receipt.attempts()))
        .map_err(|_| GithubTriggerCredentialProviderError::InvariantViolation)?;
    Ok(GithubServerServiceConsumerClaim::new(
        consumer_id,
        owner,
        claim_fence,
        common_trigger_action(request.operation()),
        revision,
    ))
}

const fn common_trigger_action(
    operation: GithubTriggerCredentialOperation,
) -> GithubServerServiceAction {
    match operation {
        GithubTriggerCredentialOperation::ReadSource => {
            GithubServerServiceAction::FetchRepositoryRevision
        }
        GithubTriggerCredentialOperation::ReadPushChangedFiles => {
            GithubServerServiceAction::FetchRepositoryChangedFiles
        }
        GithubTriggerCredentialOperation::ReadPullRequestChangedFiles => {
            GithubServerServiceAction::FetchPullRequestFiles
        }
    }
}

const fn common_result_action(operation: GithubResultOperation) -> GithubServerServiceAction {
    match operation {
        GithubResultOperation::EnsureSuite => GithubServerServiceAction::EnsureCheckSuite,
        GithubResultOperation::CreateRun => GithubServerServiceAction::CreateCheckRun,
        GithubResultOperation::ReconcileRun => GithubServerServiceAction::ReconcileCheckRun,
        GithubResultOperation::ReadRun
        | GithubResultOperation::StartRun
        | GithubResultOperation::CompleteRun
        | GithubResultOperation::ReadAnnotations
        | GithubResultOperation::AppendAnnotations => GithubServerServiceAction::PublishCheckRun,
    }
}

const fn common_result_handoff_error(
    error: GithubProviderCredentialHandoffError,
) -> GithubResultCredentialProviderError {
    match error {
        GithubProviderCredentialHandoffError::Unavailable => {
            GithubResultCredentialProviderError::Unavailable
        }
        GithubProviderCredentialHandoffError::Rejected => {
            GithubResultCredentialProviderError::Rejected
        }
        GithubProviderCredentialHandoffError::Inconsistent => {
            GithubResultCredentialProviderError::InvariantViolation
        }
    }
}

const fn common_trigger_handoff_error(
    error: GithubProviderCredentialHandoffError,
) -> GithubTriggerCredentialProviderError {
    match error {
        GithubProviderCredentialHandoffError::Unavailable => {
            GithubTriggerCredentialProviderError::Unavailable
        }
        GithubProviderCredentialHandoffError::Rejected => {
            GithubTriggerCredentialProviderError::Rejected
        }
        GithubProviderCredentialHandoffError::Inconsistent => {
            GithubTriggerCredentialProviderError::InvariantViolation
        }
    }
}

const fn checks_handoff_error(
    error: GithubProviderCredentialHandoffError,
) -> GithubChecksCredentialProviderError {
    match error {
        GithubProviderCredentialHandoffError::Unavailable => {
            GithubChecksCredentialProviderError::Unavailable
        }
        GithubProviderCredentialHandoffError::Rejected => {
            GithubChecksCredentialProviderError::Rejected
        }
        GithubProviderCredentialHandoffError::Inconsistent => {
            GithubChecksCredentialProviderError::InvariantViolation
        }
    }
}

const fn source_handoff_error(
    error: GithubProviderCredentialHandoffError,
) -> GithubDeliverySourceCredentialProviderError {
    match error {
        GithubProviderCredentialHandoffError::Unavailable => {
            GithubDeliverySourceCredentialProviderError::Unavailable
        }
        GithubProviderCredentialHandoffError::Rejected => {
            GithubDeliverySourceCredentialProviderError::Rejected
        }
        GithubProviderCredentialHandoffError::Inconsistent => {
            GithubDeliverySourceCredentialProviderError::InvariantViolation
        }
    }
}

const fn schedule_source_handoff_error(
    error: GithubProviderCredentialHandoffError,
) -> GithubScheduleSourceCredentialProviderError {
    match error {
        GithubProviderCredentialHandoffError::Unavailable => {
            GithubScheduleSourceCredentialProviderError::Unavailable
        }
        GithubProviderCredentialHandoffError::Rejected => {
            GithubScheduleSourceCredentialProviderError::Rejected
        }
        GithubProviderCredentialHandoffError::Inconsistent => {
            GithubScheduleSourceCredentialProviderError::InvariantViolation
        }
    }
}

#[cfg(test)]
#[path = "github_provider_credentials_tests.rs"]
mod tests;
