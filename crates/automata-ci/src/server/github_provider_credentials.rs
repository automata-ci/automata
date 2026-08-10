//! Product adapters for exact GitHub server-service credential handoffs.

use std::{
    collections::BTreeMap,
    fmt,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    time::Duration,
};

use async_trait::async_trait;
use automata_ci_auth::secret::SecretString;
use automata_ci_core::UnixMillis;
use automata_ci_credential_github::{
    GithubServerServiceCoordinatorClock, GithubServerServiceCredentialIssuer,
    GithubServerServiceCredentialRepository, GithubServerServiceHandoffBinding,
    GithubServerServiceHandoffError, GithubServerServiceHandoffReleaseOutcome,
    PendingGithubServerServiceCorruptionCleanup, PendingGithubServerServiceHandoffRelease,
    github_server_service_credential_request,
};
use automata_ci_github_delivery::{
    GithubChecksCredentialProvider, GithubChecksCredentialProviderError,
    GithubChecksCredentialRequest, GithubChecksServerServiceCredential,
    GithubDeliveryPrivateRepositoryAction, GithubDeliverySourceCredential,
    GithubDeliverySourceCredentialBinding, GithubDeliverySourceCredentialProvider,
    GithubDeliverySourceCredentialProviderError, GithubDeliverySourceCredentialRequest,
    GithubServerServiceCredentialRelease,
};
use automata_ci_store::{
    AcquireGithubServerServiceHandoff, GithubCheckSubjectIdentity, GithubServerServiceAction,
    GithubServerServiceAuthorityId, GithubServerServiceAuthorityIdentity,
    GithubServerServiceAuthoritySelector, GithubServerServiceConsumerClaim,
    GithubServerServiceHandoffId, GithubServerServiceIssuanceKey, GithubServerServiceScope,
    ProviderDeliveryIdentity, ProviderRepositoryOwnerId,
};
use thiserror::Error;
use tokio::{
    runtime::Handle,
    sync::{OwnedSemaphorePermit, Semaphore, oneshot},
};
use uuid::Uuid;

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
/// request in the task and replays it without mutation until Store confirms it
/// or the immutable handoff horizon closes.
pub struct GithubProviderCredentialReleaseSupervisor {
    clock: Arc<dyn GithubServerServiceCoordinatorClock>,
    runtime: Handle,
    retry_interval: Duration,
    permits: Arc<Semaphore>,
    capacity: usize,
    pending: Arc<AtomicUsize>,
    inconsistent: Arc<AtomicUsize>,
    expired_unconfirmed: Arc<AtomicUsize>,
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
            inconsistent: Arc::new(AtomicUsize::new(0)),
            expired_unconfirmed: Arc::new(AtomicUsize::new(0)),
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

    /// Returns release bindings the issuer could not represent consistently.
    #[must_use]
    pub fn inconsistent_release_count(&self) -> usize {
        self.inconsistent.load(Ordering::Acquire)
    }

    /// Returns ambiguous releases retained until their immutable horizon closed.
    #[must_use]
    pub fn expired_unconfirmed_release_count(&self) -> usize {
        self.expired_unconfirmed.load(Ordering::Acquire)
    }

    /// Waits until every reserved live or release-pending handoff has left the supervisor.
    ///
    /// Product shutdown must first stop every Checks publisher and private-source
    /// delivery worker, so no new reservation can race this drain. A caller may
    /// impose its own shutdown deadline; abandoning this future cannot erase
    /// the authoritative durable handoff or extend its immutable horizon.
    pub async fn wait_for_idle(&self) {
        let permit_count = u32::try_from(self.capacity).unwrap_or(u32::MAX);
        let Ok(permits) = Arc::clone(&self.permits)
            .acquire_many_owned(permit_count)
            .await
        else {
            return;
        };
        drop(permits);
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
        let clock = Arc::clone(&self.clock);
        let pending_count = Arc::clone(&self.pending);
        let inconsistent_count = Arc::clone(&self.inconsistent);
        let expired_count = Arc::clone(&self.expired_unconfirmed);
        let retry_interval = self.retry_interval;
        let (initial_attempt_sender, initial_attempt_receiver) = oneshot::channel();
        self.runtime.spawn(async move {
            let _reservation = reservation;
            match operation.release().await {
                GithubProviderExactReleaseOutcome::Released => {
                    let _send_result = initial_attempt_sender.send(());
                }
                GithubProviderExactReleaseOutcome::Inconsistent => {
                    inconsistent_count.fetch_add(1, Ordering::AcqRel);
                    let _send_result = initial_attempt_sender.send(());
                }
                GithubProviderExactReleaseOutcome::Pending(pending) => {
                    pending_count.fetch_add(1, Ordering::AcqRel);
                    let _pending_observation = PendingReleaseObservation {
                        count: pending_count,
                    };
                    let _send_result = initial_attempt_sender.send(());
                    loop {
                        if clock.now() >= required_through {
                            expired_count.fetch_add(1, Ordering::AcqRel);
                            break;
                        }
                        tokio::time::sleep(retry_interval).await;
                        if clock.now() >= required_through {
                            expired_count.fetch_add(1, Ordering::AcqRel);
                            break;
                        }
                        if pending.replay().await {
                            break;
                        }
                    }
                }
            }
        });
        initial_attempt_receiver
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
                "inconsistent_release_count",
                &self.inconsistent_release_count(),
            )
            .field(
                "expired_unconfirmed_release_count",
                &self.expired_unconfirmed_release_count(),
            )
            .finish_non_exhaustive()
    }
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

enum GithubProviderExactReleaseOutcome {
    Released,
    Pending(Box<dyn GithubProviderPendingHandoffRelease>),
    Inconsistent,
}

#[async_trait]
trait GithubProviderExactHandoffRelease: fmt::Debug + Send + Sync {
    async fn release(self: Box<Self>) -> GithubProviderExactReleaseOutcome;
}

struct IssuerHandoffRelease {
    issuer: Arc<GithubServerServiceCredentialIssuer>,
    repository: Arc<dyn GithubServerServiceCredentialRepository>,
    binding: GithubServerServiceHandoffBinding,
}

#[async_trait]
impl GithubProviderExactHandoffRelease for IssuerHandoffRelease {
    async fn release(self: Box<Self>) -> GithubProviderExactReleaseOutcome {
        match self.issuer.release_binding(self.binding).await {
            Ok(GithubServerServiceHandoffReleaseOutcome::Released) => {
                GithubProviderExactReleaseOutcome::Released
            }
            Ok(GithubServerServiceHandoffReleaseOutcome::Pending(pending)) => {
                GithubProviderExactReleaseOutcome::Pending(Box::new(CorePendingHandoffRelease {
                    repository: self.repository,
                    pending,
                }))
            }
            Err(_) => GithubProviderExactReleaseOutcome::Inconsistent,
        }
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
    pending: Option<Box<dyn GithubProviderPendingHandoffRelease>>,
}

#[async_trait]
impl GithubProviderExactHandoffRelease for RetainedPendingRelease {
    async fn release(mut self: Box<Self>) -> GithubProviderExactReleaseOutcome {
        self.pending.take().map_or(
            GithubProviderExactReleaseOutcome::Inconsistent,
            GithubProviderExactReleaseOutcome::Pending,
        )
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
                        pending: Some(Box::new(CorePendingCorruptionCleanup {
                            repository: Arc::clone(&self.repository),
                            pending: *pending,
                        })),
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
/// The Checks implementation accepts both public and private repository
/// subjects. The source implementation is deliberately private-only; public
/// archive and changed-file reads remain anonymous and never enter this object.
pub struct GithubProviderCredentialAdapters {
    handoffs: Arc<dyn GithubProviderCredentialHandoffIssuer>,
    authorities:
        Arc<BTreeMap<GithubServerServiceAuthorityId, GithubServerServiceAuthorityIdentity>>,
}

impl GithubProviderCredentialAdapters {
    /// Constructs product adapters from a bootstrap-projected exact authority set.
    ///
    /// The repository must be the same durable 0032 implementation used by the
    /// issuer. It is retained only inside redacted pending-release replay
    /// evidence.
    ///
    /// # Errors
    ///
    /// Rejects an empty, excessive, duplicate, or ambiguously routed authority set.
    pub fn new(
        issuer: Arc<GithubServerServiceCredentialIssuer>,
        repository: Arc<dyn GithubServerServiceCredentialRepository>,
        releases: Arc<GithubProviderCredentialReleaseSupervisor>,
        authorities: &[GithubServerServiceAuthorityIdentity],
    ) -> Result<Self, GithubProviderCredentialAdapterConfigurationError> {
        let handoffs = Arc::new(ExactCredentialHandoffIssuer {
            issuer,
            repository,
            releases,
        });
        Self::with_handoffs(handoffs, authorities)
    }

    fn with_handoffs(
        handoffs: Arc<dyn GithubProviderCredentialHandoffIssuer>,
        authorities: &[GithubServerServiceAuthorityIdentity],
    ) -> Result<Self, GithubProviderCredentialAdapterConfigurationError> {
        let maximum_authorities = 2 * super::MAX_GITHUB_PROVIDER_REPOSITORIES;
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
            authorities: Arc::new(exact),
        })
    }

    fn authority(
        &self,
        selector: &GithubServerServiceAuthoritySelector,
        scope: GithubServerServiceScope,
    ) -> Result<&GithubServerServiceAuthorityIdentity, GithubProviderCredentialHandoffError> {
        let identity = self
            .authorities
            .get(&selector.authority_id())
            .ok_or(GithubProviderCredentialHandoffError::Rejected)?;
        if identity.scope() != scope
            || GithubServerServiceAuthoritySelector::from_identity(identity) != *selector
        {
            return Err(GithubProviderCredentialHandoffError::Rejected);
        }
        Ok(identity)
    }

    async fn acquire_checks(
        &self,
        context: ChecksCredentialContext,
    ) -> Result<GithubChecksServerServiceCredential, GithubChecksCredentialProviderError> {
        let authority = self
            .authority(&context.selector, GithubServerServiceScope::ChecksWrite)
            .map_err(checks_handoff_error)?;
        if !checks_identity_matches(authority, &context.identity)
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
        let Ok(canonical_request) = github_server_service_credential_request(authority) else {
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

    async fn acquire_private_source(
        &self,
        context: PrivateSourceCredentialContext,
    ) -> Result<GithubDeliverySourceCredential, GithubDeliverySourceCredentialProviderError> {
        let authority = self
            .authority(
                &context.selector,
                GithubServerServiceScope::PrivateRepositorySourceRead,
            )
            .map_err(source_handoff_error)?;
        if !private_identity_matches(authority, &context.identity)
            || context.consumer.action() != private_action(context.action)
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
        if !private_handoff_matches(&handoff, &context) {
            release_invalid_handoff(handoff).await;
            return Err(GithubDeliverySourceCredentialProviderError::InvariantViolation);
        }
        let Ok(canonical_request) = github_server_service_credential_request(authority) else {
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
}

impl fmt::Debug for GithubProviderCredentialAdapters {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GithubProviderCredentialAdapters")
            .field("handoffs", &self.handoffs)
            .field("authority_count", &self.authorities.len())
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

#[async_trait]
impl GithubDeliverySourceCredentialProvider for GithubProviderCredentialAdapters {
    async fn acquire(
        &self,
        request: GithubDeliverySourceCredentialRequest<'_>,
    ) -> Result<GithubDeliverySourceCredential, GithubDeliverySourceCredentialProviderError> {
        let consumer = request
            .consumer_claim()
            .map_err(|_| GithubDeliverySourceCredentialProviderError::InvariantViolation)?;
        self.acquire_private_source(PrivateSourceCredentialContext {
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

struct ChecksCredentialContext {
    identity: GithubCheckSubjectIdentity,
    selector: GithubServerServiceAuthoritySelector,
    consumer: GithubServerServiceConsumerClaim,
    observed_at: UnixMillis,
    required_through: UnixMillis,
}

struct PrivateSourceCredentialContext {
    identity: ProviderDeliveryIdentity,
    repository_owner_id: ProviderRepositoryOwnerId,
    selector: GithubServerServiceAuthoritySelector,
    action: GithubDeliveryPrivateRepositoryAction,
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

fn private_identity_matches(
    authority: &GithubServerServiceAuthorityIdentity,
    identity: &ProviderDeliveryIdentity,
) -> bool {
    identity.provider() == "github"
        && identity.repository_visibility()
            == automata_ci_store::ProviderRepositoryVisibility::Private
        && authority.tenant() == identity.tenant()
        && authority.connection_id() == identity.connection_id()
        && authority.installation_id() == identity.installation_id()
        && authority.github_repository_id() == identity.repository_id()
        && authority.github_repository_name().as_str() == identity.repository_identity()
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

fn private_handoff_matches(
    handoff: &GithubProviderCredentialHandoff,
    context: &PrivateSourceCredentialContext,
) -> bool {
    handoff.selector == context.selector
        && handoff.consumer == context.consumer
        && handoff.key.authority_id() == context.selector.authority_id()
        && handoff.required_through == context.required_through
        && handoff.acquired_at == context.observed_at
        && handoff.usable_until >= context.required_through
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

const fn private_action(
    action: GithubDeliveryPrivateRepositoryAction,
) -> GithubServerServiceAction {
    match action {
        GithubDeliveryPrivateRepositoryAction::FetchPrivateRepositoryRevision => {
            GithubServerServiceAction::FetchPrivateRepositoryRevision
        }
        GithubDeliveryPrivateRepositoryAction::FetchPrivateRepositoryChangedFiles => {
            GithubServerServiceAction::FetchPrivateRepositoryChangedFiles
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

#[cfg(test)]
#[path = "github_provider_credentials_tests.rs"]
mod tests;
