//! Durable cryptographic erasure for built-in repository-secret versions.

use std::{
    fmt,
    future::Future,
    sync::{
        Arc,
        atomic::{AtomicI64, Ordering},
    },
    time::{Duration, SystemTime},
};

use automata_ci_core::UnixMillis;
use automata_ci_secret::{
    DestroySecretVersionRequest, ProviderError, ProviderErrorKind, ProviderOperationContext,
    ProviderRequestId, ProviderSecretLocator, ProviderVersionId, RepositoryScopeId,
    SecretDescriptor, SecretId, SecretName, SecretProviderRegistry, SecretScope, TenantScopeId,
};
use automata_ci_store::{
    BUILTIN_SECRET_PROVIDER_ID, BuiltinSecretCleanupRepository, BuiltinSecretCleanupTask,
    ClaimBuiltinSecretCleanup, ClaimBuiltinSecretCleanupOutcome, CompleteBuiltinSecretCleanup,
    CompleteBuiltinSecretCleanupOutcome, MAX_SECRET_CLEANUP_ATTEMPTS,
    MAX_SECRET_CLEANUP_CLAIM_MILLIS, MAX_SECRET_CLEANUP_RETRY_BACKOFF_MILLIS,
    RetryBuiltinSecretCleanup, RetryBuiltinSecretCleanupOutcome, SecretCleanupFailureKind,
    SecretCleanupWorkerId, SecretManagementRepositoryError,
};
use thiserror::Error;
use tokio_util::sync::CancellationToken;

use super::{
    secret_custody::SecretCustodyVerifier,
    secret_management::{exact_provider, valid_builtin_registry},
};

/// Trusted wall-clock source for durable secret-cleanup observations.
pub(crate) trait SecretCleanupClock: fmt::Debug + Send + Sync {
    /// Returns a whole-millisecond wall-clock observation.
    fn now(&self) -> UnixMillis;
}

/// Host wall-clock adapter that never regresses within one process lifetime.
#[derive(Debug, Default)]
pub(crate) struct SystemSecretCleanupClock {
    last_observation: AtomicI64,
}

impl SecretCleanupClock for SystemSecretCleanupClock {
    fn now(&self) -> UnixMillis {
        let wall_clock = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .map_or(0, |duration| {
                i64::try_from(duration.as_millis()).unwrap_or(i64::MAX)
            });
        let previous = self
            .last_observation
            .fetch_max(wall_clock, Ordering::AcqRel);
        UnixMillis::new(previous.max(wall_clock))
    }
}

/// One replica's durable built-in-secret cryptographic-erasure loop.
pub(crate) struct BuiltinSecretCleanupLoop {
    repository: Arc<dyn BuiltinSecretCleanupRepository>,
    providers: Arc<SecretProviderRegistry>,
    custody: Arc<SecretCustodyVerifier>,
    clock: Arc<dyn SecretCleanupClock>,
    worker_id: SecretCleanupWorkerId,
    poll_interval: Duration,
    poll_interval_millis: u64,
    operation_timeout: Duration,
    stale_after_millis: u64,
}

/// Exact durable, provider, and custody ports used by one cleanup loop.
pub(crate) struct BuiltinSecretCleanupPorts {
    repository: Arc<dyn BuiltinSecretCleanupRepository>,
    providers: Arc<SecretProviderRegistry>,
    custody: Arc<SecretCustodyVerifier>,
}

impl BuiltinSecretCleanupPorts {
    pub(crate) const fn new(
        repository: Arc<dyn BuiltinSecretCleanupRepository>,
        providers: Arc<SecretProviderRegistry>,
        custody: Arc<SecretCustodyVerifier>,
    ) -> Self {
        Self {
            repository,
            providers,
            custody,
        }
    }
}

impl BuiltinSecretCleanupLoop {
    /// Composes one worker from the durable outbox, exact built-in adapter, and bounded timing.
    ///
    /// # Errors
    ///
    /// Rejects sub-millisecond, zero, oversized, or internally inconsistent timing and any
    /// provider that is not the encrypted built-in exact-version destruction adapter.
    pub(crate) fn new(
        ports: BuiltinSecretCleanupPorts,
        clock: Arc<dyn SecretCleanupClock>,
        worker_id: SecretCleanupWorkerId,
        poll_interval: Duration,
        operation_timeout: Duration,
        stale_after: Duration,
    ) -> Result<Self, SecretCleanupLoopConfigError> {
        let poll_interval_millis = exact_millis(poll_interval)
            .filter(|value| *value <= MAX_SECRET_CLEANUP_RETRY_BACKOFF_MILLIS)
            .ok_or(SecretCleanupLoopConfigError::InvalidPollInterval)?;
        let stale_after_millis = exact_millis(stale_after)
            .filter(|value| *value <= MAX_SECRET_CLEANUP_CLAIM_MILLIS)
            .ok_or(SecretCleanupLoopConfigError::InvalidStaleTimeout)?;
        let operation_timeout_millis = exact_millis(operation_timeout)
            .filter(|value| *value <= MAX_SECRET_CLEANUP_CLAIM_MILLIS)
            .ok_or(SecretCleanupLoopConfigError::InvalidOperationTimeout)?;
        if poll_interval_millis > stale_after_millis {
            return Err(SecretCleanupLoopConfigError::PollExceedsStaleTimeout);
        }
        if operation_timeout_millis >= stale_after_millis {
            return Err(SecretCleanupLoopConfigError::OperationTimeoutReachesStaleTimeout);
        }
        if !valid_builtin_registry(&ports.providers) {
            return Err(SecretCleanupLoopConfigError::InvalidProvider);
        }
        Ok(Self {
            repository: ports.repository,
            providers: ports.providers,
            custody: ports.custody,
            clock,
            worker_id,
            poll_interval,
            poll_interval_millis,
            operation_timeout,
            stale_after_millis,
        })
    }

    /// Drains ready erasure work until cancellation, polling after empty or unavailable passes.
    ///
    /// Cancellation may interrupt any repository or provider future. The exact provider request
    /// is idempotent and an unacknowledged durable fence is reclaimed only after the configured
    /// stale timeout, so every interruption remains safely replayable.
    pub(crate) async fn run(&self, cancellation: CancellationToken) {
        loop {
            match self.run_once(&cancellation).await {
                LoopAction::Stop => break,
                LoopAction::Drain => {}
                LoopAction::Poll => {
                    tokio::select! {
                        biased;
                        () = cancellation.cancelled() => break,
                        () = tokio::time::sleep(self.poll_interval) => {}
                    }
                }
            }
        }
    }

    async fn run_once(&self, cancellation: &CancellationToken) -> LoopAction {
        if let Err(action) = self.verify_custody(cancellation, LoopAction::Poll).await {
            return action;
        }
        let claimed_at = self.clock.now();
        let Ok(request) = ClaimBuiltinSecretCleanup::new(
            self.worker_id.clone(),
            claimed_at,
            self.stale_after_millis,
        ) else {
            tracing::error!(
                error_kind = "invalid_clock_observation",
                "built-in secret cleanup claim could not be constructed"
            );
            return LoopAction::Poll;
        };
        let outcome = match wait_for_operation(
            cancellation,
            self.operation_timeout,
            self.repository.claim_builtin_secret_cleanup(request),
        )
        .await
        {
            OperationWait::Completed(outcome) => outcome,
            OperationWait::Cancelled => return LoopAction::Stop,
            OperationWait::TimedOut => {
                log_operation_timeout("claim");
                return LoopAction::Poll;
            }
        };
        let task = match outcome {
            Ok(ClaimBuiltinSecretCleanupOutcome::Claimed(task)) => task,
            Ok(ClaimBuiltinSecretCleanupOutcome::NoWork) => return LoopAction::Poll,
            Err(error) => {
                log_repository_failure("claim", error);
                return LoopAction::Poll;
            }
        };
        if !self.valid_claim_fence(&task, claimed_at) {
            tracing::error!(
                error_kind = "invalid_claim_fence",
                "built-in secret cleanup repository returned an invalid claim"
            );
            return LoopAction::Poll;
        }

        let Ok(provider) = exact_provider(&self.providers, task.provider_id()) else {
            tracing::error!(
                error_kind = "provider_unavailable",
                "built-in secret cleanup could not route its durable provider"
            );
            return LoopAction::Poll;
        };

        let Ok(destroy) = destroy_request(&task) else {
            tracing::error!(
                error_kind = "invalid_durable_task",
                "built-in secret cleanup task violates the current contract"
            );
            return self
                .record_failure(
                    &task,
                    SecretCleanupFailureKind::IntegrityFailure,
                    None,
                    cancellation,
                )
                .await;
        };
        if let Err(action) = self.verify_custody(cancellation, LoopAction::Drain).await {
            return action;
        }
        let provider_result = match wait_for_operation(
            cancellation,
            self.operation_timeout,
            provider.destroy_version(destroy),
        )
        .await
        {
            OperationWait::Completed(result) => result,
            OperationWait::Cancelled => return LoopAction::Stop,
            OperationWait::TimedOut => {
                log_operation_timeout("destroy");
                return LoopAction::Drain;
            }
        };
        match provider_result {
            Ok(()) => self.complete_erasure(&task, cancellation).await,
            Err(error) => {
                let failure = provider_failure(error.kind());
                tracing::warn!(
                    error_kind = cleanup_failure_label(failure),
                    "built-in secret version erasure did not complete"
                );
                self.record_failure(&task, failure, transient_retry_hint(error), cancellation)
                    .await
            }
        }
    }

    fn valid_claim_fence(&self, task: &BuiltinSecretCleanupTask, claimed_at: UnixMillis) -> bool {
        !task.fence().operation_id().is_nil()
            && task.fence().worker_id() == &self.worker_id
            && task.fence().claim_generation() > 0
            && task.fence().locked_at() == claimed_at
            && task.provider_id().as_str() == BUILTIN_SECRET_PROVIDER_ID
            && (1..=MAX_SECRET_CLEANUP_ATTEMPTS).contains(&task.attempts())
    }

    async fn complete_erasure(
        &self,
        task: &BuiltinSecretCleanupTask,
        cancellation: &CancellationToken,
    ) -> LoopAction {
        if let Err(action) = self.verify_custody(cancellation, LoopAction::Drain).await {
            return action;
        }
        let completed_at = self.observed_after_fence(task);
        let Ok(request) = CompleteBuiltinSecretCleanup::new(task.fence().clone(), completed_at)
        else {
            tracing::error!(
                error_kind = "invalid_completion_time",
                "built-in secret cleanup completion could not be constructed"
            );
            return LoopAction::Drain;
        };
        let outcome = match wait_for_operation(
            cancellation,
            self.operation_timeout,
            self.repository.complete_builtin_secret_cleanup(request),
        )
        .await
        {
            OperationWait::Completed(outcome) => outcome,
            OperationWait::Cancelled => return LoopAction::Stop,
            OperationWait::TimedOut => {
                log_operation_timeout("complete");
                return LoopAction::Drain;
            }
        };
        match outcome {
            Ok(CompleteBuiltinSecretCleanupOutcome::Completed) => LoopAction::Drain,
            Ok(CompleteBuiltinSecretCleanupOutcome::FenceRejected) => {
                tracing::warn!(
                    error_kind = "fence_rejected",
                    "built-in secret cleanup completion lost its durable fence"
                );
                LoopAction::Drain
            }
            Ok(CompleteBuiltinSecretCleanupOutcome::NotFound) => {
                tracing::error!(
                    error_kind = "operation_not_found",
                    "built-in secret cleanup completion target is absent"
                );
                LoopAction::Drain
            }
            Ok(CompleteBuiltinSecretCleanupOutcome::ProviderErasureIncomplete) => {
                tracing::error!(
                    error_kind = "erasure_unverified",
                    "built-in secret cleanup repository did not verify provider erasure"
                );
                self.record_failure(
                    task,
                    SecretCleanupFailureKind::IntegrityFailure,
                    None,
                    cancellation,
                )
                .await
            }
            Err(error) => {
                log_repository_failure("complete", error);
                LoopAction::Drain
            }
        }
    }

    async fn record_failure(
        &self,
        task: &BuiltinSecretCleanupTask,
        failure_kind: SecretCleanupFailureKind,
        retry_hint_millis: Option<u64>,
        cancellation: &CancellationToken,
    ) -> LoopAction {
        if let Err(action) = self.verify_custody(cancellation, LoopAction::Drain).await {
            return action;
        }
        let failed_at = self.observed_after_fence(task);
        let delay = retry_delay_millis(
            self.poll_interval_millis,
            task.attempts(),
            failure_kind,
            retry_hint_millis,
        );
        let Some(retry_at) = failed_at
            .get()
            .checked_add(i64::try_from(delay).unwrap_or(i64::MAX))
            .map(UnixMillis::new)
        else {
            tracing::error!(
                error_kind = "retry_time_overflow",
                "built-in secret cleanup retry could not be constructed"
            );
            return LoopAction::Drain;
        };
        let Ok(request) =
            RetryBuiltinSecretCleanup::new(task.fence().clone(), failed_at, retry_at, failure_kind)
        else {
            tracing::error!(
                error_kind = "invalid_retry_time",
                "built-in secret cleanup retry could not be constructed"
            );
            return LoopAction::Drain;
        };
        let outcome = match wait_for_operation(
            cancellation,
            self.operation_timeout,
            self.repository.retry_builtin_secret_cleanup(request),
        )
        .await
        {
            OperationWait::Completed(outcome) => outcome,
            OperationWait::Cancelled => return LoopAction::Stop,
            OperationWait::TimedOut => {
                log_operation_timeout("retry");
                return LoopAction::Drain;
            }
        };
        match outcome {
            Ok(
                RetryBuiltinSecretCleanupOutcome::RetryScheduled
                | RetryBuiltinSecretCleanupOutcome::DeadLettered,
            ) => LoopAction::Drain,
            Ok(RetryBuiltinSecretCleanupOutcome::FenceRejected) => {
                tracing::warn!(
                    error_kind = "fence_rejected",
                    "built-in secret cleanup retry lost its durable fence"
                );
                LoopAction::Drain
            }
            Ok(RetryBuiltinSecretCleanupOutcome::NotFound) => {
                tracing::error!(
                    error_kind = "operation_not_found",
                    "built-in secret cleanup retry target is absent"
                );
                LoopAction::Drain
            }
            Err(error) => {
                log_repository_failure("retry", error);
                LoopAction::Drain
            }
        }
    }

    fn observed_after_fence(&self, task: &BuiltinSecretCleanupTask) -> UnixMillis {
        self.clock.now().max(task.fence().locked_at())
    }

    async fn verify_custody(
        &self,
        cancellation: &CancellationToken,
        failure_action: LoopAction,
    ) -> Result<(), LoopAction> {
        match wait_for_operation(cancellation, self.operation_timeout, self.custody.verify()).await
        {
            OperationWait::Completed(Ok(())) => Ok(()),
            OperationWait::Completed(Err(_)) => {
                tracing::warn!(
                    error_kind = "custody_unavailable",
                    "built-in secret cleanup paused because custody verification failed"
                );
                Err(failure_action)
            }
            OperationWait::Cancelled => Err(LoopAction::Stop),
            OperationWait::TimedOut => {
                log_operation_timeout("custody");
                Err(failure_action)
            }
        }
    }
}

impl fmt::Debug for BuiltinSecretCleanupLoop {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BuiltinSecretCleanupLoop")
            .field("providers", &self.providers)
            .field("custody", &self.custody)
            .field("worker_id", &self.worker_id)
            .field("poll_interval", &self.poll_interval)
            .field("operation_timeout", &self.operation_timeout)
            .field("stale_after_millis", &self.stale_after_millis)
            .finish_non_exhaustive()
    }
}

/// Invalid composition or timing for the built-in secret cleanup loop.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub(crate) enum SecretCleanupLoopConfigError {
    /// The polling delay is not an exact bounded positive millisecond duration.
    #[error("secret cleanup poll interval is invalid")]
    InvalidPollInterval,
    /// The stale-claim timeout is not an exact bounded positive millisecond duration.
    #[error("secret cleanup stale timeout is invalid")]
    InvalidStaleTimeout,
    /// Polling less frequently than stale takeover would delay durable recovery.
    #[error("secret cleanup poll interval exceeds its stale timeout")]
    PollExceedsStaleTimeout,
    /// The repository/provider operation deadline is not an exact bounded positive duration.
    #[error("secret cleanup operation timeout is invalid")]
    InvalidOperationTimeout,
    /// An operation could remain in flight until stale takeover becomes legal.
    #[error("secret cleanup operation timeout reaches its stale timeout")]
    OperationTimeoutReachesStaleTimeout,
    /// The adapter is not the encrypted built-in exact-version provider.
    #[error("secret cleanup provider contract is invalid")]
    InvalidProvider,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum LoopAction {
    Stop,
    Drain,
    Poll,
}

enum OperationWait<T> {
    Completed(T),
    Cancelled,
    TimedOut,
}

async fn wait_for_operation<T>(
    cancellation: &CancellationToken,
    timeout: Duration,
    operation: impl Future<Output = T>,
) -> OperationWait<T> {
    tokio::select! {
        biased;
        () = cancellation.cancelled() => OperationWait::Cancelled,
        outcome = tokio::time::timeout(timeout, operation) => match outcome {
            Ok(value) => OperationWait::Completed(value),
            Err(_) => OperationWait::TimedOut,
        },
    }
}

fn exact_millis(duration: Duration) -> Option<u64> {
    let millis = u64::try_from(duration.as_millis()).ok()?;
    (millis != 0 && Duration::from_millis(millis) == duration).then_some(millis)
}

fn destroy_request(task: &BuiltinSecretCleanupTask) -> Result<DestroySecretVersionRequest, ()> {
    if task.repository_id().as_uuid().is_nil()
        || task.secret_version_id().is_nil()
        || task.version_number() == 0
        || task.provider_destroy_request_id()
            != format!("secret-destroy:{}", task.secret_version_id().hyphenated())
    {
        return Err(());
    }
    let tenant = TenantScopeId::new(task.tenant().as_str().to_owned()).map_err(|_| ())?;
    let context = ProviderOperationContext::new(
        tenant.clone(),
        ProviderRequestId::new(task.provider_destroy_request_id().to_owned()).map_err(|_| ())?,
    );
    let repository =
        RepositoryScopeId::new(task.repository_id().as_uuid().hyphenated().to_string())
            .map_err(|_| ())?;
    let scope = SecretScope::repository(tenant, repository);
    let secret_id = task.secret_id().as_uuid().hyphenated().to_string();
    let descriptor = SecretDescriptor::new(
        SecretId::new(secret_id.clone()).map_err(|_| ())?,
        SecretName::new(task.name().as_str()).map_err(|_| ())?,
        scope,
    );
    DestroySecretVersionRequest::new(
        context,
        descriptor,
        ProviderSecretLocator::new(secret_id).map_err(|_| ())?,
        ProviderVersionId::new(task.secret_version_id().hyphenated().to_string())
            .map_err(|_| ())?,
    )
    .map_err(|_| ())
}

const fn provider_failure(kind: ProviderErrorKind) -> SecretCleanupFailureKind {
    match kind {
        ProviderErrorKind::InvalidRequest => SecretCleanupFailureKind::InvalidRequest,
        ProviderErrorKind::Unsupported => SecretCleanupFailureKind::Unsupported,
        ProviderErrorKind::Unauthorized => SecretCleanupFailureKind::Unauthorized,
        ProviderErrorKind::Forbidden => SecretCleanupFailureKind::Forbidden,
        ProviderErrorKind::NotFound => SecretCleanupFailureKind::NotFound,
        ProviderErrorKind::Conflict => SecretCleanupFailureKind::Conflict,
        ProviderErrorKind::RateLimited => SecretCleanupFailureKind::RateLimited,
        ProviderErrorKind::Unavailable => SecretCleanupFailureKind::Unavailable,
        ProviderErrorKind::IntegrityFailure => SecretCleanupFailureKind::IntegrityFailure,
        ProviderErrorKind::InvalidResponse => SecretCleanupFailureKind::InvalidResponse,
    }
}

fn transient_retry_hint(error: ProviderError) -> Option<u64> {
    matches!(
        error.kind(),
        ProviderErrorKind::RateLimited | ProviderErrorKind::Unavailable
    )
    .then(|| {
        error
            .retry_after_seconds()
            .unwrap_or_default()
            .saturating_mul(1_000)
            .min(MAX_SECRET_CLEANUP_RETRY_BACKOFF_MILLIS)
    })
}

fn retry_delay_millis(
    base_millis: u64,
    attempts: u16,
    failure_kind: SecretCleanupFailureKind,
    provider_hint_millis: Option<u64>,
) -> u64 {
    let shift = u32::from(attempts.saturating_sub(1)).min(63);
    let attempt_delay = base_millis
        .checked_mul(1_u64.checked_shl(shift).unwrap_or(u64::MAX))
        .unwrap_or(MAX_SECRET_CLEANUP_RETRY_BACKOFF_MILLIS)
        .min(MAX_SECRET_CLEANUP_RETRY_BACKOFF_MILLIS);
    let provider_delay = if matches!(
        failure_kind,
        SecretCleanupFailureKind::RateLimited | SecretCleanupFailureKind::Unavailable
    ) {
        provider_hint_millis.unwrap_or_default()
    } else {
        0
    };
    attempt_delay
        .max(provider_delay)
        .min(MAX_SECRET_CLEANUP_RETRY_BACKOFF_MILLIS)
}

const fn cleanup_failure_label(kind: SecretCleanupFailureKind) -> &'static str {
    match kind {
        SecretCleanupFailureKind::InvalidRequest => "invalid_request",
        SecretCleanupFailureKind::Unsupported => "unsupported",
        SecretCleanupFailureKind::Unauthorized => "unauthorized",
        SecretCleanupFailureKind::Forbidden => "forbidden",
        SecretCleanupFailureKind::NotFound => "not_found",
        SecretCleanupFailureKind::Conflict => "conflict",
        SecretCleanupFailureKind::RateLimited => "rate_limited",
        SecretCleanupFailureKind::Unavailable => "unavailable",
        SecretCleanupFailureKind::IntegrityFailure => "integrity_failure",
        SecretCleanupFailureKind::InvalidResponse => "invalid_response",
    }
}

fn log_repository_failure(operation: &'static str, error: SecretManagementRepositoryError) {
    let error_kind = match error {
        SecretManagementRepositoryError::InvalidRequest => "invalid_request",
        SecretManagementRepositoryError::Unavailable => "unavailable",
        SecretManagementRepositoryError::CorruptData => "corrupt_data",
    };
    if error == SecretManagementRepositoryError::Unavailable {
        tracing::warn!(
            operation,
            error_kind,
            "built-in secret cleanup repository operation failed"
        );
    } else {
        tracing::error!(
            operation,
            error_kind,
            "built-in secret cleanup repository operation failed"
        );
    }
}

fn log_operation_timeout(operation: &'static str) {
    tracing::warn!(
        operation,
        error_kind = "timeout",
        "built-in secret cleanup operation exceeded its deadline"
    );
}

#[cfg(test)]
mod tests {
    use std::{
        collections::VecDeque,
        sync::{Mutex, atomic::AtomicUsize},
    };

    use async_trait::async_trait;
    use automata_ci_core::RunId;
    use automata_ci_secret::{
        CreateSecretVersionRequest, CreatedSecretVersion, ProviderCapabilities, ProviderCapability,
        ProviderHealth, ReconcileCreateSecretVersionOutcome, ReconcileCreateSecretVersionRequest,
        ResolveSecretVersionRequest, ResolvedSecretVersion, SecretAtRestProtection, SecretProvider,
        SecretProviderId,
    };
    use automata_ci_store::{
        CompleteBuiltinSecretCleanup, RepositoryId, RepositorySecretId, RepositorySecretName,
        RetryBuiltinSecretCleanup, SecretCleanupFence, TenantScope,
    };
    use tokio::sync::Notify;

    use super::*;

    const REPOSITORY: &str = "11111111-1111-4111-8111-111111111111";
    const SECRET: &str = "22222222-2222-4222-8222-222222222222";
    const VERSION: &str = "33333333-3333-4333-8333-333333333333";
    const OPERATION: &str = "44444444-4444-4444-8444-444444444444";

    #[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
    enum BlockRepositoryOperation {
        #[default]
        None,
        Claim,
        Complete,
        Retry,
    }

    #[derive(Debug)]
    struct SequenceClock {
        values: Mutex<VecDeque<UnixMillis>>,
        last: AtomicI64,
    }

    impl SequenceClock {
        fn new(values: impl IntoIterator<Item = i64>) -> Self {
            Self {
                values: Mutex::new(values.into_iter().map(UnixMillis::new).collect()),
                last: AtomicI64::new(0),
            }
        }
    }

    impl SecretCleanupClock for SequenceClock {
        fn now(&self) -> UnixMillis {
            let value = self
                .values
                .lock()
                .expect("clock lock")
                .pop_front()
                .map_or_else(|| self.last.load(Ordering::SeqCst), UnixMillis::get);
            self.last.store(value, Ordering::SeqCst);
            UnixMillis::new(value)
        }
    }

    #[derive(Debug)]
    struct FakeRepository {
        claims: Mutex<
            VecDeque<Result<ClaimBuiltinSecretCleanupOutcome, SecretManagementRepositoryError>>,
        >,
        claim_requests: Mutex<Vec<ClaimBuiltinSecretCleanup>>,
        completions: Mutex<Vec<CompleteBuiltinSecretCleanup>>,
        retries: Mutex<Vec<RetryBuiltinSecretCleanup>>,
        completion_outcome: CompleteBuiltinSecretCleanupOutcome,
        retry_outcome: RetryBuiltinSecretCleanupOutcome,
        blocked_operation: BlockRepositoryOperation,
        changed: Notify,
    }

    impl FakeRepository {
        fn with_task(task: BuiltinSecretCleanupTask) -> Self {
            Self::with_claims([
                Ok(ClaimBuiltinSecretCleanupOutcome::Claimed(task)),
                Ok(ClaimBuiltinSecretCleanupOutcome::NoWork),
            ])
        }

        fn with_claims(
            claims: impl IntoIterator<
                Item = Result<ClaimBuiltinSecretCleanupOutcome, SecretManagementRepositoryError>,
            >,
        ) -> Self {
            Self {
                claims: Mutex::new(claims.into_iter().collect()),
                claim_requests: Mutex::new(Vec::new()),
                completions: Mutex::new(Vec::new()),
                retries: Mutex::new(Vec::new()),
                completion_outcome: CompleteBuiltinSecretCleanupOutcome::Completed,
                retry_outcome: RetryBuiltinSecretCleanupOutcome::RetryScheduled,
                blocked_operation: BlockRepositoryOperation::None,
                changed: Notify::new(),
            }
        }

        fn with_completion_outcome(mut self, outcome: CompleteBuiltinSecretCleanupOutcome) -> Self {
            self.completion_outcome = outcome;
            self
        }

        fn blocking(mut self, operation: BlockRepositoryOperation) -> Self {
            self.blocked_operation = operation;
            self
        }

        async fn wait_for_change(&self) {
            self.changed.notified().await;
        }
    }

    #[async_trait]
    impl BuiltinSecretCleanupRepository for FakeRepository {
        async fn claim_builtin_secret_cleanup(
            &self,
            request: ClaimBuiltinSecretCleanup,
        ) -> Result<ClaimBuiltinSecretCleanupOutcome, SecretManagementRepositoryError> {
            self.claim_requests
                .lock()
                .expect("claim requests lock")
                .push(request);
            if self.blocked_operation == BlockRepositoryOperation::Claim {
                std::future::pending::<()>().await;
                unreachable!("blocked repository claim completed");
            }
            self.claims
                .lock()
                .expect("claims lock")
                .pop_front()
                .unwrap_or(Ok(ClaimBuiltinSecretCleanupOutcome::NoWork))
        }

        async fn complete_builtin_secret_cleanup(
            &self,
            request: CompleteBuiltinSecretCleanup,
        ) -> Result<CompleteBuiltinSecretCleanupOutcome, SecretManagementRepositoryError> {
            self.completions
                .lock()
                .expect("completions lock")
                .push(request);
            if self.blocked_operation == BlockRepositoryOperation::Complete {
                std::future::pending::<()>().await;
                unreachable!("blocked repository completion completed");
            }
            self.changed.notify_one();
            Ok(self.completion_outcome)
        }

        async fn retry_builtin_secret_cleanup(
            &self,
            request: RetryBuiltinSecretCleanup,
        ) -> Result<RetryBuiltinSecretCleanupOutcome, SecretManagementRepositoryError> {
            self.retries.lock().expect("retries lock").push(request);
            if self.blocked_operation == BlockRepositoryOperation::Retry {
                std::future::pending::<()>().await;
                unreachable!("blocked repository retry completed");
            }
            self.changed.notify_one();
            Ok(self.retry_outcome)
        }
    }

    struct FakeProvider {
        id: SecretProviderId,
        capabilities: ProviderCapabilities,
        protection: SecretAtRestProtection,
        destroy_result: Mutex<Option<Result<(), ProviderError>>>,
        request: Mutex<Option<DestroySecretVersionRequest>>,
        entered: Notify,
        release: Notify,
        block: bool,
        cancel_after_destroy: Option<CancellationToken>,
        calls: AtomicUsize,
    }

    impl FakeProvider {
        fn new(destroy_result: Result<(), ProviderError>) -> Self {
            Self {
                id: SecretProviderId::new(BUILTIN_SECRET_PROVIDER_ID).expect("provider ID"),
                capabilities: ProviderCapabilities::new([
                    ProviderCapability::CreateVersion,
                    ProviderCapability::ReconcileCreateVersion,
                    ProviderCapability::DestroyVersion,
                ])
                .expect("capabilities"),
                protection: SecretAtRestProtection::AutomataEnvelope,
                destroy_result: Mutex::new(Some(destroy_result)),
                request: Mutex::new(None),
                entered: Notify::new(),
                release: Notify::new(),
                block: false,
                cancel_after_destroy: None,
                calls: AtomicUsize::new(0),
            }
        }

        fn blocking() -> Self {
            Self {
                block: true,
                ..Self::new(Ok(()))
            }
        }

        fn cancelling_after_destroy(cancellation: CancellationToken) -> Self {
            Self {
                cancel_after_destroy: Some(cancellation),
                ..Self::new(Ok(()))
            }
        }
    }

    impl fmt::Debug for FakeProvider {
        fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str("FakeProvider([REDACTED])")
        }
    }

    #[async_trait]
    impl SecretProvider for FakeProvider {
        fn provider_id(&self) -> &SecretProviderId {
            &self.id
        }

        fn capabilities(&self) -> &ProviderCapabilities {
            &self.capabilities
        }

        fn at_rest_protection(&self) -> SecretAtRestProtection {
            self.protection
        }

        async fn health(
            &self,
            _context: &ProviderOperationContext,
        ) -> Result<ProviderHealth, ProviderError> {
            Ok(ProviderHealth::Healthy)
        }

        async fn create_version(
            &self,
            _request: CreateSecretVersionRequest,
        ) -> Result<CreatedSecretVersion, ProviderError> {
            Err(ProviderError::unsupported())
        }

        async fn reconcile_create_version(
            &self,
            _request: ReconcileCreateSecretVersionRequest,
        ) -> Result<ReconcileCreateSecretVersionOutcome, ProviderError> {
            Ok(ReconcileCreateSecretVersionOutcome::DefinitivelyNotCommitted)
        }

        async fn resolve_version(
            &self,
            _request: ResolveSecretVersionRequest,
        ) -> Result<ResolvedSecretVersion, ProviderError> {
            Err(ProviderError::unsupported())
        }

        async fn destroy_version(
            &self,
            request: DestroySecretVersionRequest,
        ) -> Result<(), ProviderError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            *self.request.lock().expect("provider request lock") = Some(request);
            self.entered.notify_one();
            if self.block {
                self.release.notified().await;
            }
            let result = self
                .destroy_result
                .lock()
                .expect("provider result lock")
                .take()
                .unwrap_or(Ok(()));
            if let Some(cancellation) = &self.cancel_after_destroy {
                cancellation.cancel();
            }
            result
        }
    }

    fn parse_id(value: &str) -> RunId {
        value.parse().expect("canonical UUID")
    }

    fn worker_id() -> SecretCleanupWorkerId {
        SecretCleanupWorkerId::new("cleanup-worker-a").expect("worker ID")
    }

    fn cleanup_task_with_generation(
        attempts: u16,
        request_id: String,
        claim_generation: u64,
    ) -> BuiltinSecretCleanupTask {
        cleanup_task_with_provider(
            attempts,
            request_id,
            claim_generation,
            BUILTIN_SECRET_PROVIDER_ID,
        )
    }

    fn cleanup_task_with_provider(
        attempts: u16,
        request_id: String,
        claim_generation: u64,
        provider_id: &str,
    ) -> BuiltinSecretCleanupTask {
        BuiltinSecretCleanupTask::new(
            SecretCleanupFence::new(
                parse_id(OPERATION).as_uuid(),
                worker_id(),
                claim_generation,
                UnixMillis::new(1_000),
            ),
            TenantScope::from_authenticated_tenant_id("tenant-a").expect("tenant"),
            automata_ci_store::ManagedSecretProviderId::new(provider_id).expect("provider ID"),
            RepositorySecretId::from_uuid(parse_id(SECRET).as_uuid()).expect("secret ID"),
            RepositoryId::from_uuid(parse_id(REPOSITORY).as_uuid()),
            RepositorySecretName::new("DEPLOY_TOKEN").expect("secret name"),
            parse_id(VERSION).as_uuid(),
            7,
            request_id,
            attempts,
        )
    }

    fn cleanup_task(attempts: u16, request_id: String) -> BuiltinSecretCleanupTask {
        cleanup_task_with_generation(attempts, request_id, 1)
    }

    fn exact_task(attempts: u16) -> BuiltinSecretCleanupTask {
        cleanup_task(attempts, format!("secret-destroy:{VERSION}"))
    }

    fn provider_registry(provider: Arc<FakeProvider>) -> Arc<SecretProviderRegistry> {
        let provider: Arc<dyn SecretProvider> = provider;
        Arc::new(
            SecretProviderRegistry::new(provider.provider_id().clone(), [provider])
                .expect("provider registry"),
        )
    }

    fn loop_for(
        repository: Arc<FakeRepository>,
        provider: Arc<FakeProvider>,
        clock: Arc<SequenceClock>,
    ) -> BuiltinSecretCleanupLoop {
        loop_for_with_timeout(repository, provider, clock, Duration::from_millis(100))
    }

    fn loop_for_with_timeout(
        repository: Arc<FakeRepository>,
        provider: Arc<FakeProvider>,
        clock: Arc<SequenceClock>,
        operation_timeout: Duration,
    ) -> BuiltinSecretCleanupLoop {
        loop_for_with_timeout_and_custody(
            repository,
            provider,
            clock,
            operation_timeout,
            SecretCustodyVerifier::verified_for_tests(),
        )
    }

    fn loop_for_with_timeout_and_custody(
        repository: Arc<FakeRepository>,
        provider: Arc<FakeProvider>,
        clock: Arc<SequenceClock>,
        operation_timeout: Duration,
        custody: Arc<SecretCustodyVerifier>,
    ) -> BuiltinSecretCleanupLoop {
        let repository: Arc<dyn BuiltinSecretCleanupRepository> = repository;
        let providers = provider_registry(provider);
        let clock: Arc<dyn SecretCleanupClock> = clock;
        BuiltinSecretCleanupLoop::new(
            BuiltinSecretCleanupPorts::new(repository, providers, custody),
            clock,
            worker_id(),
            Duration::from_millis(10),
            operation_timeout,
            Duration::from_mins(1),
        )
        .expect("cleanup loop")
    }

    async fn run_until_repository_change(
        worker: BuiltinSecretCleanupLoop,
        repository: &FakeRepository,
    ) {
        let cancellation = CancellationToken::new();
        let run_cancellation = cancellation.clone();
        let run = tokio::spawn(async move { worker.run(run_cancellation).await });
        tokio::time::timeout(Duration::from_secs(1), repository.wait_for_change())
            .await
            .expect("repository change");
        cancellation.cancel();
        tokio::time::timeout(Duration::from_secs(1), run)
            .await
            .expect("worker shutdown")
            .expect("worker task");
    }

    async fn wait_until(condition: impl Fn() -> bool) {
        tokio::time::timeout(Duration::from_secs(1), async {
            while !condition() {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("condition became true");
    }

    async fn run_once_bounded(worker: &BuiltinSecretCleanupLoop) -> LoopAction {
        let cancellation = CancellationToken::new();
        tokio::time::timeout(Duration::from_secs(1), worker.run_once(&cancellation))
            .await
            .expect("cleanup pass respected its operation deadline")
    }

    #[tokio::test]
    async fn successful_erasure_builds_the_exact_request_before_completion() {
        let repository = Arc::new(FakeRepository::with_task(exact_task(1)));
        let provider = Arc::new(FakeProvider::new(Ok(())));
        let clock = Arc::new(SequenceClock::new([1_000, 2_000]));
        let worker = loop_for(repository.clone(), provider.clone(), clock);

        run_until_repository_change(worker, repository.as_ref()).await;

        let request = provider
            .request
            .lock()
            .expect("provider request lock")
            .take()
            .expect("destroy request");
        assert_eq!(request.context().tenant_id().as_str(), "tenant-a");
        assert_eq!(
            request.context().request_id().as_str(),
            format!("secret-destroy:{VERSION}")
        );
        assert_eq!(request.secret().id().as_str(), SECRET);
        assert_eq!(request.secret().name().as_str(), "DEPLOY_TOKEN");
        assert_eq!(
            request
                .secret()
                .scope()
                .repository_id()
                .expect("repository scope")
                .as_str(),
            REPOSITORY
        );
        assert_eq!(request.locator().as_str(), SECRET);
        assert_eq!(request.version().as_str(), VERSION);
        let claims = repository.claim_requests.lock().expect("claims lock");
        assert_eq!(claims[0].worker_id(), &worker_id());
        assert_eq!(claims[0].now(), UnixMillis::new(1_000));
        assert_eq!(claims[0].stale_after_millis(), 60_000);
        let completions = repository.completions.lock().expect("completions lock");
        assert_eq!(completions.len(), 1);
        assert_eq!(completions[0].completed_at(), UnixMillis::new(2_000));
        assert!(repository.retries.lock().expect("retries lock").is_empty());
    }

    #[tokio::test]
    async fn custody_failure_precedes_cleanup_claim_and_provider_erasure() {
        let repository = Arc::new(FakeRepository::with_task(exact_task(1)));
        let provider = Arc::new(FakeProvider::new(Ok(())));
        let repository_port: Arc<dyn BuiltinSecretCleanupRepository> = repository.clone();
        let clock: Arc<dyn SecretCleanupClock> = Arc::new(SequenceClock::new([1_000]));
        let worker = BuiltinSecretCleanupLoop::new(
            BuiltinSecretCleanupPorts::new(
                repository_port,
                provider_registry(provider.clone()),
                SecretCustodyVerifier::unavailable_for_tests(),
            ),
            clock,
            worker_id(),
            Duration::from_millis(10),
            Duration::from_millis(100),
            Duration::from_mins(1),
        )
        .expect("cleanup loop");

        assert_eq!(
            worker.run_once(&CancellationToken::new()).await,
            LoopAction::Poll
        );
        assert!(
            repository
                .claim_requests
                .lock()
                .expect("claim requests lock")
                .is_empty()
        );
        assert_eq!(provider.calls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn cleanup_never_falls_back_from_the_tasks_exact_provider() {
        let task =
            cleanup_task_with_provider(1, format!("secret-destroy:{VERSION}"), 1, "external-vault");
        let repository = Arc::new(FakeRepository::with_task(task));
        let provider = Arc::new(FakeProvider::new(Ok(())));
        let worker = loop_for(
            Arc::clone(&repository),
            Arc::clone(&provider),
            Arc::new(SequenceClock::new([1_000])),
        );

        assert_eq!(
            worker.run_once(&CancellationToken::new()).await,
            LoopAction::Poll
        );
        assert_eq!(provider.calls.load(Ordering::SeqCst), 0);
        assert!(
            repository
                .completions
                .lock()
                .expect("completions lock")
                .is_empty()
        );
        assert!(repository.retries.lock().expect("retries lock").is_empty());
    }

    #[tokio::test]
    async fn custody_failure_after_claim_precedes_provider_erasure() {
        let repository = Arc::new(FakeRepository::with_task(exact_task(1)));
        let provider = Arc::new(FakeProvider::new(Ok(())));
        let clock = Arc::new(SequenceClock::new([1_000]));
        let worker = loop_for_with_timeout_and_custody(
            repository.clone(),
            provider.clone(),
            clock,
            Duration::from_millis(100),
            SecretCustodyVerifier::available_then_unavailable_for_tests(1),
        );

        assert_eq!(
            worker.run_once(&CancellationToken::new()).await,
            LoopAction::Drain
        );
        assert_eq!(
            repository
                .claim_requests
                .lock()
                .expect("claim requests lock")
                .len(),
            1
        );
        assert_eq!(provider.calls.load(Ordering::SeqCst), 0);
        assert!(
            repository
                .completions
                .lock()
                .expect("completions lock")
                .is_empty()
        );
        assert!(repository.retries.lock().expect("retries lock").is_empty());
    }

    #[tokio::test]
    async fn custody_failure_after_provider_erasure_precedes_terminalization() {
        let repository = Arc::new(FakeRepository::with_task(exact_task(1)));
        let provider = Arc::new(FakeProvider::new(Ok(())));
        let clock = Arc::new(SequenceClock::new([1_000]));
        let worker = loop_for_with_timeout_and_custody(
            repository.clone(),
            provider.clone(),
            clock,
            Duration::from_millis(100),
            SecretCustodyVerifier::available_then_unavailable_for_tests(2),
        );

        assert_eq!(
            worker.run_once(&CancellationToken::new()).await,
            LoopAction::Drain
        );
        assert_eq!(provider.calls.load(Ordering::SeqCst), 1);
        assert!(
            repository
                .completions
                .lock()
                .expect("completions lock")
                .is_empty()
        );
        assert!(repository.retries.lock().expect("retries lock").is_empty());
    }

    #[tokio::test]
    async fn transient_provider_failure_is_fenced_and_exponentially_rescheduled() {
        let repository = Arc::new(FakeRepository::with_task(exact_task(3)));
        let provider = Arc::new(FakeProvider::new(Err(ProviderError::retryable(
            ProviderErrorKind::RateLimited,
            Some(1),
        ))));
        let clock = Arc::new(SequenceClock::new([1_000, 2_000]));
        let worker = loop_for(repository.clone(), provider, clock);

        run_until_repository_change(worker, repository.as_ref()).await;

        assert!(
            repository
                .completions
                .lock()
                .expect("completions lock")
                .is_empty()
        );
        let retries = repository.retries.lock().expect("retries lock");
        assert_eq!(retries.len(), 1);
        assert_eq!(
            retries[0].failure_kind(),
            SecretCleanupFailureKind::RateLimited
        );
        assert_eq!(retries[0].failed_at(), UnixMillis::new(2_000));
        assert_eq!(retries[0].retry_at(), UnixMillis::new(3_000));
        assert_eq!(
            retries[0].fence().operation_id(),
            parse_id(OPERATION).as_uuid()
        );
    }

    #[tokio::test]
    async fn malformed_current_task_never_crosses_the_provider_boundary() {
        let repository = Arc::new(FakeRepository::with_task(cleanup_task(
            1,
            "secret-destroy:foreign-version".to_owned(),
        )));
        let provider = Arc::new(FakeProvider::new(Ok(())));
        let clock = Arc::new(SequenceClock::new([1_000, 2_000]));
        let worker = loop_for(repository.clone(), provider.clone(), clock);

        run_until_repository_change(worker, repository.as_ref()).await;

        assert_eq!(provider.calls.load(Ordering::SeqCst), 0);
        assert!(
            repository
                .completions
                .lock()
                .expect("completions lock")
                .is_empty()
        );
        let retries = repository.retries.lock().expect("retries lock");
        assert_eq!(retries.len(), 1);
        assert_eq!(
            retries[0].failure_kind(),
            SecretCleanupFailureKind::IntegrityFailure
        );
    }

    #[tokio::test]
    async fn zero_claim_generation_never_crosses_the_provider_boundary() {
        let repository = Arc::new(FakeRepository::with_task(cleanup_task_with_generation(
            1,
            format!("secret-destroy:{VERSION}"),
            0,
        )));
        let provider = Arc::new(FakeProvider::new(Ok(())));
        let clock = Arc::new(SequenceClock::new([1_000]));
        let worker = loop_for(repository.clone(), provider.clone(), clock);

        assert_eq!(
            worker.run_once(&CancellationToken::new()).await,
            LoopAction::Poll
        );
        assert_eq!(provider.calls.load(Ordering::SeqCst), 0);
        assert!(
            repository
                .completions
                .lock()
                .expect("completions lock")
                .is_empty()
        );
        assert!(repository.retries.lock().expect("retries lock").is_empty());
    }

    #[tokio::test]
    async fn durable_verification_failure_is_never_acknowledged_as_complete() {
        let repository = Arc::new(
            FakeRepository::with_task(exact_task(1)).with_completion_outcome(
                CompleteBuiltinSecretCleanupOutcome::ProviderErasureIncomplete,
            ),
        );
        let provider = Arc::new(FakeProvider::new(Ok(())));
        let clock = Arc::new(SequenceClock::new([1_000, 2_000, 2_001]));
        let worker = loop_for(repository.clone(), provider, clock);
        let cancellation = CancellationToken::new();
        let run_cancellation = cancellation.clone();
        let run = tokio::spawn(async move { worker.run(run_cancellation).await });

        wait_until(|| !repository.retries.lock().expect("retries lock").is_empty()).await;
        cancellation.cancel();
        tokio::time::timeout(Duration::from_secs(1), run)
            .await
            .expect("worker shutdown")
            .expect("worker task");

        assert_eq!(
            repository
                .completions
                .lock()
                .expect("completions lock")
                .len(),
            1
        );
        let retries = repository.retries.lock().expect("retries lock");
        assert_eq!(retries.len(), 1);
        assert_eq!(
            retries[0].failure_kind(),
            SecretCleanupFailureKind::IntegrityFailure
        );
    }

    #[tokio::test]
    async fn repository_unavailability_remains_internal_and_polling_recovers() {
        let repository = Arc::new(FakeRepository::with_claims([
            Err(SecretManagementRepositoryError::Unavailable),
            Ok(ClaimBuiltinSecretCleanupOutcome::Claimed(exact_task(1))),
            Ok(ClaimBuiltinSecretCleanupOutcome::NoWork),
        ]));
        let provider = Arc::new(FakeProvider::new(Ok(())));
        let clock = Arc::new(SequenceClock::new([900, 1_000, 2_000]));
        let worker = loop_for(repository.clone(), provider, clock);

        run_until_repository_change(worker, repository.as_ref()).await;

        let claims = repository
            .claim_requests
            .lock()
            .expect("claim requests lock");
        assert!(claims.len() >= 2);
        assert_eq!(claims[0].now(), UnixMillis::new(900));
        assert_eq!(claims[1].now(), UnixMillis::new(1_000));
        assert_eq!(
            repository
                .completions
                .lock()
                .expect("completions lock")
                .len(),
            1
        );
    }

    #[tokio::test]
    async fn cancellation_during_provider_io_leaves_the_fence_for_stale_replay() {
        let repository = Arc::new(FakeRepository::with_task(exact_task(1)));
        let provider = Arc::new(FakeProvider::blocking());
        let clock = Arc::new(SequenceClock::new([1_000]));
        let worker = loop_for(repository.clone(), provider.clone(), clock);
        let cancellation = CancellationToken::new();
        let run_cancellation = cancellation.clone();
        let run = tokio::spawn(async move { worker.run(run_cancellation).await });

        tokio::time::timeout(Duration::from_secs(1), provider.entered.notified())
            .await
            .expect("provider call entered");
        cancellation.cancel();
        tokio::time::timeout(Duration::from_secs(1), run)
            .await
            .expect("worker shutdown")
            .expect("worker task");

        assert!(
            repository
                .completions
                .lock()
                .expect("completions lock")
                .is_empty()
        );
        assert!(repository.retries.lock().expect("retries lock").is_empty());
    }

    #[tokio::test]
    async fn cancellation_after_provider_erasure_leaves_completion_for_exact_replay() {
        let repository = Arc::new(FakeRepository::with_task(exact_task(1)));
        let cancellation = CancellationToken::new();
        let provider = Arc::new(FakeProvider::cancelling_after_destroy(cancellation.clone()));
        let clock = Arc::new(SequenceClock::new([1_000, 2_000]));
        let worker = loop_for(repository.clone(), provider.clone(), clock);

        tokio::time::timeout(Duration::from_secs(1), worker.run(cancellation))
            .await
            .expect("worker shutdown");

        assert_eq!(provider.calls.load(Ordering::SeqCst), 1);
        assert!(
            repository
                .completions
                .lock()
                .expect("completions lock")
                .is_empty()
        );
        assert!(repository.retries.lock().expect("retries lock").is_empty());
    }

    #[tokio::test]
    async fn claim_timeout_never_crosses_the_provider_or_write_boundaries() {
        let repository = Arc::new(
            FakeRepository::with_task(exact_task(1)).blocking(BlockRepositoryOperation::Claim),
        );
        let provider = Arc::new(FakeProvider::new(Ok(())));
        let clock = Arc::new(SequenceClock::new([1_000]));
        let worker = loop_for_with_timeout(
            repository.clone(),
            provider.clone(),
            clock,
            Duration::from_millis(10),
        );

        assert_eq!(run_once_bounded(&worker).await, LoopAction::Poll);
        assert_eq!(
            repository
                .claim_requests
                .lock()
                .expect("claim requests lock")
                .len(),
            1
        );
        assert_eq!(provider.calls.load(Ordering::SeqCst), 0);
        assert!(
            repository
                .completions
                .lock()
                .expect("completions lock")
                .is_empty()
        );
        assert!(repository.retries.lock().expect("retries lock").is_empty());
    }

    #[tokio::test]
    async fn provider_timeout_leaves_the_claim_for_stale_replay() {
        let repository = Arc::new(FakeRepository::with_task(exact_task(1)));
        let provider = Arc::new(FakeProvider::blocking());
        let clock = Arc::new(SequenceClock::new([1_000]));
        let worker = loop_for_with_timeout(
            repository.clone(),
            provider.clone(),
            clock,
            Duration::from_millis(10),
        );

        assert_eq!(run_once_bounded(&worker).await, LoopAction::Drain);
        assert_eq!(provider.calls.load(Ordering::SeqCst), 1);
        assert!(
            repository
                .completions
                .lock()
                .expect("completions lock")
                .is_empty()
        );
        assert!(repository.retries.lock().expect("retries lock").is_empty());
    }

    #[tokio::test]
    async fn completion_timeout_never_retries_or_repeats_provider_erasure() {
        let repository = Arc::new(
            FakeRepository::with_task(exact_task(1)).blocking(BlockRepositoryOperation::Complete),
        );
        let provider = Arc::new(FakeProvider::new(Ok(())));
        let clock = Arc::new(SequenceClock::new([1_000, 2_000]));
        let worker = loop_for_with_timeout(
            repository.clone(),
            provider.clone(),
            clock,
            Duration::from_millis(10),
        );

        assert_eq!(run_once_bounded(&worker).await, LoopAction::Drain);
        assert_eq!(provider.calls.load(Ordering::SeqCst), 1);
        assert_eq!(
            repository
                .completions
                .lock()
                .expect("completions lock")
                .len(),
            1
        );
        assert!(repository.retries.lock().expect("retries lock").is_empty());
    }

    #[tokio::test]
    async fn retry_timeout_leaves_the_claim_for_stale_replay() {
        let repository = Arc::new(
            FakeRepository::with_task(exact_task(1)).blocking(BlockRepositoryOperation::Retry),
        );
        let provider = Arc::new(FakeProvider::new(Err(ProviderError::retryable(
            ProviderErrorKind::Unavailable,
            None,
        ))));
        let clock = Arc::new(SequenceClock::new([1_000, 2_000]));
        let worker = loop_for_with_timeout(
            repository.clone(),
            provider.clone(),
            clock,
            Duration::from_millis(10),
        );

        assert_eq!(run_once_bounded(&worker).await, LoopAction::Drain);
        assert_eq!(provider.calls.load(Ordering::SeqCst), 1);
        assert!(
            repository
                .completions
                .lock()
                .expect("completions lock")
                .is_empty()
        );
        assert_eq!(repository.retries.lock().expect("retries lock").len(), 1);
    }

    #[test]
    fn timing_and_provider_contracts_are_bounded_and_fail_closed() {
        let repository = Arc::new(FakeRepository::with_task(exact_task(1)));
        let valid_provider = Arc::new(FakeProvider::new(Ok(())));
        let clock = Arc::new(SequenceClock::new([1_000]));
        let make = |poll, operation_timeout, stale, provider: Arc<FakeProvider>| {
            let repository: Arc<dyn BuiltinSecretCleanupRepository> = repository.clone();
            let providers = provider_registry(provider);
            let clock: Arc<dyn SecretCleanupClock> = clock.clone();
            BuiltinSecretCleanupLoop::new(
                BuiltinSecretCleanupPorts::new(
                    repository,
                    providers,
                    SecretCustodyVerifier::verified_for_tests(),
                ),
                clock,
                worker_id(),
                poll,
                operation_timeout,
                stale,
            )
            .map(|_| ())
        };

        assert_eq!(
            make(
                Duration::from_nanos(1),
                Duration::from_millis(1),
                Duration::from_secs(1),
                valid_provider.clone(),
            ),
            Err(SecretCleanupLoopConfigError::InvalidPollInterval)
        );
        assert_eq!(
            make(
                Duration::from_secs(2),
                Duration::from_millis(1),
                Duration::from_secs(1),
                valid_provider.clone(),
            ),
            Err(SecretCleanupLoopConfigError::PollExceedsStaleTimeout)
        );
        assert_eq!(
            make(
                Duration::from_millis(1),
                Duration::from_millis(1),
                Duration::from_millis(MAX_SECRET_CLEANUP_CLAIM_MILLIS + 1),
                valid_provider.clone(),
            ),
            Err(SecretCleanupLoopConfigError::InvalidStaleTimeout)
        );
        assert_eq!(
            make(
                Duration::from_millis(1),
                Duration::ZERO,
                Duration::from_secs(1),
                valid_provider.clone(),
            ),
            Err(SecretCleanupLoopConfigError::InvalidOperationTimeout)
        );
        assert_eq!(
            make(
                Duration::from_millis(1),
                Duration::from_secs(1),
                Duration::from_secs(1),
                valid_provider.clone(),
            ),
            Err(SecretCleanupLoopConfigError::OperationTimeoutReachesStaleTimeout)
        );
        assert_eq!(
            make(
                Duration::from_millis(1),
                Duration::from_secs(2),
                Duration::from_secs(1),
                valid_provider,
            ),
            Err(SecretCleanupLoopConfigError::OperationTimeoutReachesStaleTimeout)
        );

        let mut invalid_provider = FakeProvider::new(Ok(()));
        invalid_provider.protection = SecretAtRestProtection::ProviderManagedEncryption;
        assert_eq!(
            make(
                Duration::from_millis(1),
                Duration::from_millis(1),
                Duration::from_secs(1),
                Arc::new(invalid_provider),
            ),
            Err(SecretCleanupLoopConfigError::InvalidProvider)
        );
    }

    #[test]
    fn every_provider_failure_maps_to_the_closed_durable_kind() {
        let mappings = [
            (
                ProviderErrorKind::InvalidRequest,
                SecretCleanupFailureKind::InvalidRequest,
            ),
            (
                ProviderErrorKind::Unsupported,
                SecretCleanupFailureKind::Unsupported,
            ),
            (
                ProviderErrorKind::Unauthorized,
                SecretCleanupFailureKind::Unauthorized,
            ),
            (
                ProviderErrorKind::Forbidden,
                SecretCleanupFailureKind::Forbidden,
            ),
            (
                ProviderErrorKind::NotFound,
                SecretCleanupFailureKind::NotFound,
            ),
            (
                ProviderErrorKind::Conflict,
                SecretCleanupFailureKind::Conflict,
            ),
            (
                ProviderErrorKind::RateLimited,
                SecretCleanupFailureKind::RateLimited,
            ),
            (
                ProviderErrorKind::Unavailable,
                SecretCleanupFailureKind::Unavailable,
            ),
            (
                ProviderErrorKind::IntegrityFailure,
                SecretCleanupFailureKind::IntegrityFailure,
            ),
            (
                ProviderErrorKind::InvalidResponse,
                SecretCleanupFailureKind::InvalidResponse,
            ),
        ];
        for (provider, durable) in mappings {
            assert_eq!(provider_failure(provider), durable);
        }
    }

    #[test]
    fn retry_policy_caps_exponential_and_ignores_nontransient_guidance() {
        assert_eq!(
            retry_delay_millis(
                10,
                MAX_SECRET_CLEANUP_ATTEMPTS,
                SecretCleanupFailureKind::Unavailable,
                Some(u64::MAX),
            ),
            MAX_SECRET_CLEANUP_RETRY_BACKOFF_MILLIS
        );
        assert_eq!(
            retry_delay_millis(
                10,
                2,
                SecretCleanupFailureKind::IntegrityFailure,
                Some(MAX_SECRET_CLEANUP_RETRY_BACKOFF_MILLIS),
            ),
            20
        );
    }
}
