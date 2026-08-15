//! Bounded cancellation-only recovery for abandoned repository-secret mutations.

use std::{fmt, sync::Arc, time::Duration};

use automata_ci_core::UnixMillis;
use automata_ci_secret::{
    ProviderErrorKind, ReconcileCreateSecretVersionOutcome, SecretProviderRegistry,
};
use automata_ci_store::{
    BUILTIN_SECRET_PROVIDER_ID, ClaimSecretMutationRecovery, ClaimSecretMutationRecoveryOutcome,
    MAX_SECRET_MUTATION_RECOVERY_CLAIM_MILLIS, RecoverSecretMutationReservation,
    RecoverSecretMutationReservationOutcome, SecretCleanupWorkerId,
    SecretManagementRepositoryError, SecretMutationRecoveryReconciliation,
    SecretMutationRecoveryRepository, SecretMutationRecoveryTask,
};
use thiserror::Error;
use tokio_util::sync::CancellationToken;

use super::{
    secret_cleanup::SecretCleanupClock,
    secret_custody::SecretCustodyVerifier,
    secret_loop_support::{LoopAction, OperationWait, exact_millis, wait_for_operation},
    secret_management::{
        ProviderCreateIntent, created_builtin_target, exact_provider, valid_builtin_registry,
    },
};

/// One replica's value-free stale-mutation reconciliation loop.
pub(crate) struct SecretMutationRecoveryLoop {
    repository: Arc<dyn SecretMutationRecoveryRepository>,
    providers: Arc<SecretProviderRegistry>,
    custody: Arc<SecretCustodyVerifier>,
    clock: Arc<dyn SecretCleanupClock>,
    worker_id: SecretCleanupWorkerId,
    poll_interval: Duration,
    operation_timeout: Duration,
    stale_after_millis: u64,
}

/// Exact durable, provider-registry, and custody ports used by recovery.
pub(crate) struct SecretMutationRecoveryPorts {
    repository: Arc<dyn SecretMutationRecoveryRepository>,
    providers: Arc<SecretProviderRegistry>,
    custody: Arc<SecretCustodyVerifier>,
}

impl SecretMutationRecoveryPorts {
    pub(crate) const fn new(
        repository: Arc<dyn SecretMutationRecoveryRepository>,
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

impl SecretMutationRecoveryLoop {
    /// Composes one recovery loop with exact bounded polling, operation, and takeover timing.
    ///
    /// # Errors
    ///
    /// Rejects zero, sub-millisecond, oversized, or internally inconsistent timing.
    pub(crate) fn new(
        ports: SecretMutationRecoveryPorts,
        clock: Arc<dyn SecretCleanupClock>,
        worker_id: SecretCleanupWorkerId,
        poll_interval: Duration,
        operation_timeout: Duration,
        stale_after: Duration,
    ) -> Result<Self, SecretMutationRecoveryLoopConfigError> {
        if !valid_builtin_registry(&ports.providers) {
            return Err(SecretMutationRecoveryLoopConfigError::InvalidProviderRegistry);
        }
        let poll_interval_millis = exact_millis(poll_interval)
            .filter(|value| *value <= MAX_SECRET_MUTATION_RECOVERY_CLAIM_MILLIS)
            .ok_or(SecretMutationRecoveryLoopConfigError::InvalidPollInterval)?;
        let operation_timeout_millis = exact_millis(operation_timeout)
            .filter(|value| *value <= MAX_SECRET_MUTATION_RECOVERY_CLAIM_MILLIS)
            .ok_or(SecretMutationRecoveryLoopConfigError::InvalidOperationTimeout)?;
        let stale_after_millis = exact_millis(stale_after)
            .filter(|value| *value <= MAX_SECRET_MUTATION_RECOVERY_CLAIM_MILLIS)
            .ok_or(SecretMutationRecoveryLoopConfigError::InvalidStaleTimeout)?;
        if poll_interval_millis > stale_after_millis {
            return Err(SecretMutationRecoveryLoopConfigError::PollExceedsStaleTimeout);
        }
        if operation_timeout_millis >= stale_after_millis {
            return Err(SecretMutationRecoveryLoopConfigError::OperationTimeoutReachesStaleTimeout);
        }
        Ok(Self {
            repository: ports.repository,
            providers: ports.providers,
            custody: ports.custody,
            clock,
            worker_id,
            poll_interval,
            operation_timeout,
            stale_after_millis,
        })
    }

    /// Reconciles due reservations until the process cancellation boundary closes.
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
        let Ok(claim) = ClaimSecretMutationRecovery::new(
            self.worker_id.clone(),
            claimed_at,
            self.stale_after_millis,
        ) else {
            tracing::error!(
                error_kind = "invalid_clock_observation",
                "secret mutation recovery claim could not be constructed"
            );
            return LoopAction::Poll;
        };
        let claim_outcome = wait_for_operation(
            cancellation,
            self.operation_timeout,
            self.repository.claim_secret_mutation_recovery(claim),
        )
        .await;
        let task = match claim_outcome {
            OperationWait::Cancelled => return LoopAction::Stop,
            OperationWait::TimedOut => {
                log_operation_timeout("claim");
                return LoopAction::Poll;
            }
            OperationWait::Completed(Ok(ClaimSecretMutationRecoveryOutcome::Claimed(task))) => task,
            OperationWait::Completed(Ok(ClaimSecretMutationRecoveryOutcome::NoWork)) => {
                return LoopAction::Poll;
            }
            OperationWait::Completed(Err(error)) => {
                log_repository_failure("claim", error);
                return LoopAction::Poll;
            }
        };
        if !self.valid_claim(&task, claimed_at) {
            tracing::error!(
                error_kind = "invalid_claim_fence",
                "secret mutation recovery repository returned an invalid claim"
            );
            return LoopAction::Poll;
        }

        let reconciliation = match self.reconcile_task(&task, cancellation).await {
            Ok(reconciliation) => reconciliation,
            Err(action) => return action,
        };
        self.complete_task(&task, reconciliation, cancellation)
            .await
    }

    async fn complete_task(
        &self,
        task: &SecretMutationRecoveryTask,
        reconciliation: SecretMutationRecoveryReconciliation,
        cancellation: &CancellationToken,
    ) -> LoopAction {
        let recovered_at = self
            .clock
            .now()
            .max(task.fence().locked_at())
            .max(task.confirmation_deadline());
        let Ok(recover) = RecoverSecretMutationReservation::new(
            task.fence().clone(),
            recovered_at,
            reconciliation,
        ) else {
            tracing::error!(
                error_kind = "invalid_recovery_time",
                "secret mutation recovery completion could not be constructed"
            );
            return LoopAction::Poll;
        };
        if let Err(action) = self.verify_custody(cancellation, LoopAction::Drain).await {
            return action;
        }
        let outcome = wait_for_operation(
            cancellation,
            self.operation_timeout,
            self.repository.recover_secret_mutation_reservation(recover),
        )
        .await;
        match outcome {
            OperationWait::Cancelled => LoopAction::Stop,
            OperationWait::TimedOut => {
                log_operation_timeout("recover");
                LoopAction::Poll
            }
            OperationWait::Completed(Ok(
                RecoverSecretMutationReservationOutcome::ExpiredWithoutStage
                | RecoverSecretMutationReservationOutcome::ExpiredWithCleanup
                | RecoverSecretMutationReservationOutcome::AlreadyTerminal,
            )) => LoopAction::Drain,
            OperationWait::Completed(Ok(
                RecoverSecretMutationReservationOutcome::FenceRejected,
            )) => {
                tracing::warn!(
                    error_kind = "fence_rejected",
                    "secret mutation recovery lost its durable fence"
                );
                LoopAction::Drain
            }
            OperationWait::Completed(Ok(RecoverSecretMutationReservationOutcome::NotFound)) => {
                tracing::error!(
                    error_kind = "operation_not_found",
                    "secret mutation recovery target is absent"
                );
                LoopAction::Drain
            }
            OperationWait::Completed(Err(error)) => {
                log_repository_failure("recover", error);
                LoopAction::Poll
            }
        }
    }

    async fn reconcile_task(
        &self,
        task: &SecretMutationRecoveryTask,
        cancellation: &CancellationToken,
    ) -> Result<SecretMutationRecoveryReconciliation, LoopAction> {
        self.verify_custody(cancellation, LoopAction::Drain).await?;
        let Ok(provider) = exact_provider(&self.providers, task.provider_id()) else {
            tracing::error!(
                error_kind = "provider_unavailable",
                "secret mutation recovery could not route its durable provider"
            );
            return Err(LoopAction::Poll);
        };
        let Ok(reconcile) = ProviderCreateIntent::new(
            task.tenant().as_str(),
            task.provider_create_request_id(),
            task.secret_id(),
            task.repository_id(),
            task.name(),
            task.expected_predecessor(),
        )
        .and_then(ProviderCreateIntent::into_reconcile) else {
            tracing::error!(
                error_kind = "invalid_durable_task",
                "secret mutation recovery task violates the provider intent contract"
            );
            return Err(LoopAction::Poll);
        };
        match wait_for_operation(
            cancellation,
            self.operation_timeout,
            provider.reconcile_create_version(reconcile),
        )
        .await
        {
            OperationWait::Cancelled => Err(LoopAction::Stop),
            OperationWait::TimedOut => {
                log_operation_timeout("reconcile");
                Err(LoopAction::Poll)
            }
            OperationWait::Completed(Ok(
                ReconcileCreateSecretVersionOutcome::DefinitivelyNotCommitted,
            )) => Ok(SecretMutationRecoveryReconciliation::DefinitivelyNotCommitted),
            OperationWait::Completed(Ok(
                ReconcileCreateSecretVersionOutcome::AlreadyCommitted(created),
            )) => {
                let Ok(target) = created_builtin_target(
                    task.secret_id(),
                    task.reserved_version_number(),
                    &created,
                ) else {
                    tracing::error!(
                        error_kind = "invalid_provider_result",
                        "secret mutation recovery provider result violates its durable intent"
                    );
                    return Err(LoopAction::Poll);
                };
                Ok(SecretMutationRecoveryReconciliation::AlreadyCommitted(
                    target,
                ))
            }
            OperationWait::Completed(Err(error)) => {
                log_provider_failure(error.kind());
                Err(LoopAction::Poll)
            }
        }
    }

    fn valid_claim(&self, task: &SecretMutationRecoveryTask, claimed_at: UnixMillis) -> bool {
        !task.fence().operation_id().is_nil()
            && task.fence().worker_id() == &self.worker_id
            && task.fence().claim_generation() > 0
            && task.fence().locked_at() == claimed_at
            && task.confirmation_deadline() <= claimed_at
            && task.mutation_id().as_uuid() != task.secret_id().as_uuid()
            && task.provider_id().as_str() == BUILTIN_SECRET_PROVIDER_ID
            && !task.repository_id().as_uuid().is_nil()
            && task.provider_create_request_id()
                == format!(
                    "secret-version:{}",
                    task.mutation_id().as_uuid().hyphenated()
                )
            && match task.kind() {
                automata_ci_store::RepositorySecretMutationKind::Create => {
                    task.reserved_version_number() == 1 && task.expected_predecessor().is_none()
                }
                automata_ci_store::RepositorySecretMutationKind::Replace => {
                    task.expected_predecessor().is_some_and(|predecessor| {
                        predecessor.secret_id() == task.secret_id()
                            && predecessor.version_number() < task.reserved_version_number()
                    })
                }
            }
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
                    "secret mutation recovery paused because custody verification failed"
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

impl fmt::Debug for SecretMutationRecoveryLoop {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SecretMutationRecoveryLoop")
            .field("providers", &self.providers)
            .field("custody", &self.custody)
            .field("worker_id", &self.worker_id)
            .field("poll_interval", &self.poll_interval)
            .field("operation_timeout", &self.operation_timeout)
            .field("stale_after_millis", &self.stale_after_millis)
            .finish_non_exhaustive()
    }
}

/// Invalid bounded timing for stale repository-secret mutation recovery.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub(crate) enum SecretMutationRecoveryLoopConfigError {
    /// The registry is not the exact current encrypted built-in provider set.
    #[error("secret mutation recovery provider registry is invalid")]
    InvalidProviderRegistry,
    /// The polling delay is not an exact bounded positive millisecond duration.
    #[error("secret mutation recovery poll interval is invalid")]
    InvalidPollInterval,
    /// The repository operation deadline is not an exact bounded positive duration.
    #[error("secret mutation recovery operation timeout is invalid")]
    InvalidOperationTimeout,
    /// The stale-claim timeout is not an exact bounded positive millisecond duration.
    #[error("secret mutation recovery stale timeout is invalid")]
    InvalidStaleTimeout,
    /// Polling less frequently than stale takeover would delay durable recovery.
    #[error("secret mutation recovery poll interval exceeds its stale timeout")]
    PollExceedsStaleTimeout,
    /// An operation could remain in flight until stale takeover becomes legal.
    #[error("secret mutation recovery operation timeout reaches its stale timeout")]
    OperationTimeoutReachesStaleTimeout,
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
            "secret mutation recovery repository operation failed"
        );
    } else {
        tracing::error!(
            operation,
            error_kind,
            "secret mutation recovery repository operation failed"
        );
    }
}

fn log_provider_failure(kind: ProviderErrorKind) {
    let error_kind = match kind {
        ProviderErrorKind::InvalidRequest => "invalid_request",
        ProviderErrorKind::Unsupported => "unsupported",
        ProviderErrorKind::Unauthorized => "unauthorized",
        ProviderErrorKind::Forbidden => "forbidden",
        ProviderErrorKind::NotFound => "not_found",
        ProviderErrorKind::Conflict => "conflict",
        ProviderErrorKind::RateLimited => "rate_limited",
        ProviderErrorKind::Unavailable => "unavailable",
        ProviderErrorKind::IntegrityFailure => "integrity_failure",
        ProviderErrorKind::InvalidResponse => "invalid_response",
    };
    tracing::warn!(
        operation = "reconcile",
        error_kind,
        "secret mutation recovery provider reconciliation failed"
    );
}

fn log_operation_timeout(operation: &'static str) {
    tracing::warn!(
        operation,
        error_kind = "timeout",
        "secret mutation recovery operation exceeded its deadline"
    );
}

#[cfg(test)]
mod tests {
    use std::{
        collections::VecDeque,
        sync::{
            Mutex,
            atomic::{AtomicU64, Ordering},
        },
    };

    use async_trait::async_trait;
    use automata_ci_core::RunId;
    use automata_ci_secret::{
        CreateSecretVersionRequest, CreatedSecretVersion, DestroySecretVersionRequest,
        ProviderCapabilities, ProviderCapability, ProviderError, ProviderHealth,
        ProviderSecretLocator, ProviderVersionId, ReconcileCreateSecretVersionRequest,
        ResolveSecretVersionRequest, ResolvedSecretVersion, SecretAtRestProtection, SecretProvider,
        SecretProviderId,
    };
    use automata_ci_store::{
        BuiltinRepositorySecretVersion, ManagedSecretProviderId, RepositoryId, RepositorySecretId,
        RepositorySecretMutationId, RepositorySecretMutationKind, RepositorySecretName,
        RepositorySecretVersionId, SecretMutationRecoveryFence, TenantScope,
    };

    use super::*;

    const RECOVERY_VERSION: &str = "70000000-0000-4000-8000-000000000007";

    #[derive(Debug)]
    struct FakeRecoveryProvider {
        id: SecretProviderId,
        capabilities: ProviderCapabilities,
        reconcile_calls: AtomicU64,
        committed: bool,
        failure: Option<ProviderErrorKind>,
    }

    impl FakeRecoveryProvider {
        fn new() -> Self {
            Self {
                id: SecretProviderId::new(BUILTIN_SECRET_PROVIDER_ID).expect("provider ID"),
                capabilities: ProviderCapabilities::new([
                    ProviderCapability::CreateVersion,
                    ProviderCapability::ReconcileCreateVersion,
                    ProviderCapability::DestroyVersion,
                ])
                .expect("capabilities"),
                reconcile_calls: AtomicU64::new(0),
                committed: false,
                failure: None,
            }
        }

        fn committed(mut self) -> Self {
            self.committed = true;
            self
        }

        fn failing(mut self, kind: ProviderErrorKind) -> Self {
            self.failure = Some(kind);
            self
        }
    }

    #[async_trait]
    impl SecretProvider for FakeRecoveryProvider {
        fn provider_id(&self) -> &SecretProviderId {
            &self.id
        }

        fn capabilities(&self) -> &ProviderCapabilities {
            &self.capabilities
        }

        fn at_rest_protection(&self) -> SecretAtRestProtection {
            SecretAtRestProtection::AutomataEnvelope
        }

        async fn health(
            &self,
            _context: &automata_ci_secret::ProviderOperationContext,
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
            request: ReconcileCreateSecretVersionRequest,
        ) -> Result<ReconcileCreateSecretVersionOutcome, ProviderError> {
            self.reconcile_calls.fetch_add(1, Ordering::SeqCst);
            if let Some(kind) = self.failure {
                return Err(ProviderError::new(kind));
            }
            if !self.committed {
                return Ok(ReconcileCreateSecretVersionOutcome::DefinitivelyNotCommitted);
            }
            Ok(ReconcileCreateSecretVersionOutcome::AlreadyCommitted(
                CreatedSecretVersion::new(
                    ProviderSecretLocator::new(request.secret().id().as_str().to_owned())
                        .expect("locator"),
                    ProviderVersionId::new(RECOVERY_VERSION).expect("version"),
                ),
            ))
        }

        async fn resolve_version(
            &self,
            _request: ResolveSecretVersionRequest,
        ) -> Result<ResolvedSecretVersion, ProviderError> {
            Err(ProviderError::unsupported())
        }

        async fn destroy_version(
            &self,
            _request: DestroySecretVersionRequest,
        ) -> Result<(), ProviderError> {
            Ok(())
        }
    }

    #[derive(Debug)]
    struct SequenceClock(Mutex<VecDeque<UnixMillis>>);

    impl SequenceClock {
        fn new(values: impl IntoIterator<Item = i64>) -> Self {
            Self(Mutex::new(
                values.into_iter().map(UnixMillis::new).collect(),
            ))
        }
    }

    impl SecretCleanupClock for SequenceClock {
        fn now(&self) -> UnixMillis {
            self.0
                .lock()
                .expect("clock lock")
                .pop_front()
                .expect("clock observation")
        }
    }

    #[derive(Debug)]
    struct FakeRepository {
        claims: Mutex<
            VecDeque<Result<ClaimSecretMutationRecoveryOutcome, SecretManagementRepositoryError>>,
        >,
        recover_outcome: RecoverSecretMutationReservationOutcome,
        recoveries: Mutex<Vec<RecoverSecretMutationReservation>>,
        block_claim: bool,
    }

    impl FakeRepository {
        fn with_task(
            task: SecretMutationRecoveryTask,
            recover_outcome: RecoverSecretMutationReservationOutcome,
        ) -> Self {
            Self::with_tasks([task], recover_outcome)
        }

        fn with_tasks(
            tasks: impl IntoIterator<Item = SecretMutationRecoveryTask>,
            recover_outcome: RecoverSecretMutationReservationOutcome,
        ) -> Self {
            Self {
                claims: Mutex::new(
                    tasks
                        .into_iter()
                        .map(|task| Ok(ClaimSecretMutationRecoveryOutcome::Claimed(task)))
                        .collect(),
                ),
                recover_outcome,
                recoveries: Mutex::new(Vec::new()),
                block_claim: false,
            }
        }

        fn blocking() -> Self {
            Self {
                claims: Mutex::new(VecDeque::new()),
                recover_outcome: RecoverSecretMutationReservationOutcome::AlreadyTerminal,
                recoveries: Mutex::new(Vec::new()),
                block_claim: true,
            }
        }
    }

    #[derive(Debug)]
    struct TimeoutThenTakeoverRepository {
        claims: Mutex<VecDeque<SecretMutationRecoveryTask>>,
        timed_out_generation: u64,
        recoveries: Mutex<Vec<RecoverSecretMutationReservation>>,
    }

    #[async_trait]
    impl SecretMutationRecoveryRepository for TimeoutThenTakeoverRepository {
        async fn claim_secret_mutation_recovery(
            &self,
            _request: ClaimSecretMutationRecovery,
        ) -> Result<ClaimSecretMutationRecoveryOutcome, SecretManagementRepositoryError> {
            Ok(self
                .claims
                .lock()
                .expect("claim lock")
                .pop_front()
                .map_or(ClaimSecretMutationRecoveryOutcome::NoWork, |task| {
                    ClaimSecretMutationRecoveryOutcome::Claimed(task)
                }))
        }

        async fn recover_secret_mutation_reservation(
            &self,
            request: RecoverSecretMutationReservation,
        ) -> Result<RecoverSecretMutationReservationOutcome, SecretManagementRepositoryError>
        {
            let timed_out = request.fence().claim_generation() == self.timed_out_generation;
            self.recoveries.lock().expect("recovery lock").push(request);
            if timed_out {
                return std::future::pending().await;
            }
            Ok(RecoverSecretMutationReservationOutcome::ExpiredWithoutStage)
        }
    }

    #[async_trait]
    impl SecretMutationRecoveryRepository for FakeRepository {
        async fn claim_secret_mutation_recovery(
            &self,
            _request: ClaimSecretMutationRecovery,
        ) -> Result<ClaimSecretMutationRecoveryOutcome, SecretManagementRepositoryError> {
            if self.block_claim {
                std::future::pending::<()>().await;
            }
            self.claims
                .lock()
                .expect("claim lock")
                .pop_front()
                .unwrap_or(Ok(ClaimSecretMutationRecoveryOutcome::NoWork))
        }

        async fn recover_secret_mutation_reservation(
            &self,
            request: RecoverSecretMutationReservation,
        ) -> Result<RecoverSecretMutationReservationOutcome, SecretManagementRepositoryError>
        {
            self.recoveries.lock().expect("recovery lock").push(request);
            Ok(self.recover_outcome)
        }
    }

    fn worker_id() -> SecretCleanupWorkerId {
        SecretCleanupWorkerId::new("secret-recovery-worker-a").expect("worker ID")
    }

    fn task(claim_generation: u64, locked_at: i64, deadline: i64) -> SecretMutationRecoveryTask {
        let secret_id = RepositorySecretId::from_uuid(RunId::new().as_uuid()).expect("secret ID");
        let mutation_id = RepositorySecretMutationId::from_uuid(RunId::new().as_uuid(), secret_id)
            .expect("mutation ID");
        let predecessor = BuiltinRepositorySecretVersion::new(
            secret_id,
            RepositorySecretVersionId::from_uuid(RunId::new().as_uuid())
                .expect("predecessor version ID"),
            1,
        )
        .expect("predecessor");
        SecretMutationRecoveryTask::new(
            SecretMutationRecoveryFence::new(
                RunId::new().as_uuid(),
                worker_id(),
                claim_generation,
                UnixMillis::new(locked_at),
            )
            .expect("recovery fence"),
            TenantScope::from_authenticated_tenant_id("recovery-test").expect("tenant"),
            mutation_id,
            secret_id,
            ManagedSecretProviderId::new(BUILTIN_SECRET_PROVIDER_ID).expect("provider ID"),
            RepositoryId::from_uuid(RunId::new().as_uuid()),
            RepositorySecretName::new("RECOVERY_TOKEN").expect("secret name"),
            RepositorySecretMutationKind::Replace,
            2,
            Some(predecessor),
            format!("secret-version:{}", mutation_id.as_uuid().hyphenated()),
            UnixMillis::new(deadline),
        )
    }

    fn provider_registry(provider: Arc<FakeRecoveryProvider>) -> Arc<SecretProviderRegistry> {
        let provider: Arc<dyn SecretProvider> = provider;
        Arc::new(
            SecretProviderRegistry::new(provider.provider_id().clone(), [provider])
                .expect("provider registry"),
        )
    }

    fn default_provider_registry() -> Arc<SecretProviderRegistry> {
        provider_registry(Arc::new(FakeRecoveryProvider::new()))
    }

    fn worker<R>(
        repository: Arc<R>,
        clock: Arc<SequenceClock>,
        operation_timeout: Duration,
    ) -> SecretMutationRecoveryLoop
    where
        R: SecretMutationRecoveryRepository + 'static,
    {
        worker_with_custody(
            repository,
            clock,
            operation_timeout,
            SecretCustodyVerifier::verified_for_tests(),
        )
    }

    fn worker_with_custody<R>(
        repository: Arc<R>,
        clock: Arc<SequenceClock>,
        operation_timeout: Duration,
        custody: Arc<SecretCustodyVerifier>,
    ) -> SecretMutationRecoveryLoop
    where
        R: SecretMutationRecoveryRepository + 'static,
    {
        worker_with_provider(
            repository,
            clock,
            operation_timeout,
            custody,
            default_provider_registry(),
        )
    }

    fn worker_with_provider<R>(
        repository: Arc<R>,
        clock: Arc<SequenceClock>,
        operation_timeout: Duration,
        custody: Arc<SecretCustodyVerifier>,
        providers: Arc<SecretProviderRegistry>,
    ) -> SecretMutationRecoveryLoop
    where
        R: SecretMutationRecoveryRepository + 'static,
    {
        let repository: Arc<dyn SecretMutationRecoveryRepository> = repository;
        let clock: Arc<dyn SecretCleanupClock> = clock;
        SecretMutationRecoveryLoop::new(
            SecretMutationRecoveryPorts::new(repository, providers, custody),
            clock,
            worker_id(),
            Duration::from_millis(1),
            operation_timeout,
            Duration::from_millis(10),
        )
        .expect("worker")
    }

    #[tokio::test]
    async fn due_claim_is_recovered_with_the_exact_generation() {
        let claim_generation = 4;
        let repository = Arc::new(FakeRepository::with_task(
            task(claim_generation, 100, 100),
            RecoverSecretMutationReservationOutcome::ExpiredWithCleanup,
        ));
        let loop_ = worker(
            Arc::clone(&repository),
            Arc::new(SequenceClock::new([100, 101])),
            Duration::from_millis(5),
        );

        assert_eq!(
            loop_.run_once(&CancellationToken::new()).await,
            LoopAction::Drain
        );
        let recoveries = repository.recoveries.lock().expect("recovery lock");
        assert_eq!(recoveries.len(), 1);
        assert_eq!(recoveries[0].fence().claim_generation(), claim_generation);
        assert_eq!(recoveries[0].recovered_at(), UnixMillis::new(101));
        assert_eq!(
            recoveries[0].reconciliation(),
            SecretMutationRecoveryReconciliation::DefinitivelyNotCommitted
        );
    }

    #[tokio::test]
    async fn committed_reconciliation_is_value_free_and_precedes_terminalization() {
        let recovery_task = task(1, 100, 100);
        let expected_secret = recovery_task.secret_id();
        let repository = Arc::new(FakeRepository::with_task(
            recovery_task,
            RecoverSecretMutationReservationOutcome::ExpiredWithCleanup,
        ));
        let provider = Arc::new(FakeRecoveryProvider::new().committed());
        let worker = worker_with_provider(
            Arc::clone(&repository),
            Arc::new(SequenceClock::new([100, 101])),
            Duration::from_millis(5),
            SecretCustodyVerifier::verified_for_tests(),
            provider_registry(Arc::clone(&provider)),
        );

        assert_eq!(
            worker.run_once(&CancellationToken::new()).await,
            LoopAction::Drain
        );
        assert_eq!(provider.reconcile_calls.load(Ordering::SeqCst), 1);
        let recoveries = repository.recoveries.lock().expect("recovery lock");
        let SecretMutationRecoveryReconciliation::AlreadyCommitted(target) =
            recoveries[0].reconciliation()
        else {
            panic!("committed reconciliation evidence was not forwarded");
        };
        assert_eq!(target.secret_id(), expected_secret);
        assert_eq!(target.version_number(), 2);
        assert_eq!(
            target.version_id(),
            RepositorySecretVersionId::from_uuid(
                RECOVERY_VERSION
                    .parse::<RunId>()
                    .expect("version")
                    .as_uuid()
            )
            .expect("version ID")
        );
    }

    #[tokio::test]
    async fn provider_reconciliation_failure_never_terminalizes_the_claim() {
        let repository = Arc::new(FakeRepository::with_task(
            task(1, 100, 100),
            RecoverSecretMutationReservationOutcome::ExpiredWithoutStage,
        ));
        let provider =
            Arc::new(FakeRecoveryProvider::new().failing(ProviderErrorKind::Unavailable));
        let worker = worker_with_provider(
            Arc::clone(&repository),
            Arc::new(SequenceClock::new([100])),
            Duration::from_millis(5),
            SecretCustodyVerifier::verified_for_tests(),
            provider_registry(Arc::clone(&provider)),
        );

        assert_eq!(
            worker.run_once(&CancellationToken::new()).await,
            LoopAction::Poll
        );
        assert_eq!(provider.reconcile_calls.load(Ordering::SeqCst), 1);
        assert!(
            repository
                .recoveries
                .lock()
                .expect("recovery lock")
                .is_empty()
        );
    }

    #[tokio::test]
    async fn custody_failure_precedes_recovery_claim_and_terminalization() {
        let repository = Arc::new(FakeRepository::with_task(
            task(1, 100, 100),
            RecoverSecretMutationReservationOutcome::ExpiredWithCleanup,
        ));
        let repository_port: Arc<dyn SecretMutationRecoveryRepository> = repository.clone();
        let clock: Arc<dyn SecretCleanupClock> = Arc::new(SequenceClock::new([100]));
        let worker = SecretMutationRecoveryLoop::new(
            SecretMutationRecoveryPorts::new(
                repository_port,
                default_provider_registry(),
                SecretCustodyVerifier::unavailable_for_tests(),
            ),
            clock,
            worker_id(),
            Duration::from_millis(1),
            Duration::from_millis(5),
            Duration::from_millis(10),
        )
        .expect("worker");

        assert_eq!(
            worker.run_once(&CancellationToken::new()).await,
            LoopAction::Poll
        );
        assert_eq!(repository.claims.lock().expect("claims lock").len(), 1);
        assert!(
            repository
                .recoveries
                .lock()
                .expect("recoveries lock")
                .is_empty()
        );
    }

    #[tokio::test]
    async fn custody_failure_after_claim_precedes_recovery_terminalization() {
        let repository = Arc::new(FakeRepository::with_task(
            task(1, 100, 100),
            RecoverSecretMutationReservationOutcome::ExpiredWithCleanup,
        ));
        let worker = worker_with_custody(
            Arc::clone(&repository),
            Arc::new(SequenceClock::new([100, 101])),
            Duration::from_millis(5),
            SecretCustodyVerifier::available_then_unavailable_for_tests(1),
        );

        assert_eq!(
            worker.run_once(&CancellationToken::new()).await,
            LoopAction::Drain
        );
        assert!(repository.claims.lock().expect("claims lock").is_empty());
        assert!(
            repository
                .recoveries
                .lock()
                .expect("recoveries lock")
                .is_empty()
        );
    }

    #[tokio::test]
    async fn mismatched_lock_or_future_deadline_never_reaches_recovery() {
        for invalid in [task(4, 99, 99), task(5, 100, 101)] {
            let repository = Arc::new(FakeRepository::with_task(
                invalid,
                RecoverSecretMutationReservationOutcome::ExpiredWithoutStage,
            ));
            let loop_ = worker(
                Arc::clone(&repository),
                Arc::new(SequenceClock::new([100])),
                Duration::from_millis(5),
            );
            assert_eq!(
                loop_.run_once(&CancellationToken::new()).await,
                LoopAction::Poll
            );
            assert!(
                repository
                    .recoveries
                    .lock()
                    .expect("recovery lock")
                    .is_empty()
            );
        }
    }

    #[tokio::test]
    async fn cancellation_and_operation_timeout_are_bounded() {
        let cancelled = CancellationToken::new();
        cancelled.cancel();
        let repository = Arc::new(FakeRepository::blocking());
        let loop_ = worker(
            Arc::clone(&repository),
            Arc::new(SequenceClock::new([100])),
            Duration::from_millis(2),
        );
        assert_eq!(loop_.run_once(&cancelled).await, LoopAction::Stop);

        let loop_ = worker(
            repository,
            Arc::new(SequenceClock::new([100])),
            Duration::from_millis(2),
        );
        assert_eq!(
            loop_.run_once(&CancellationToken::new()).await,
            LoopAction::Poll
        );
    }

    #[tokio::test]
    async fn timed_out_recovery_is_replaced_by_a_fresh_stale_takeover() {
        let timed_out_generation = 4;
        let takeover_generation = 5;
        let repository = Arc::new(TimeoutThenTakeoverRepository {
            claims: Mutex::new(VecDeque::from([
                task(timed_out_generation, 100, 100),
                task(takeover_generation, 110, 100),
            ])),
            timed_out_generation,
            recoveries: Mutex::new(Vec::new()),
        });
        let loop_ = worker(
            Arc::clone(&repository),
            Arc::new(SequenceClock::new([100, 101, 110, 111])),
            Duration::from_millis(2),
        );

        assert_eq!(
            loop_.run_once(&CancellationToken::new()).await,
            LoopAction::Poll,
            "an ambiguous recovery timeout must leave the durable fence untouched"
        );
        assert_eq!(
            loop_.run_once(&CancellationToken::new()).await,
            LoopAction::Drain,
            "the repository's later stale takeover must be recoverable"
        );
        let recoveries = repository.recoveries.lock().expect("recovery lock");
        assert_eq!(recoveries.len(), 2);
        assert_eq!(
            recoveries[0].fence().claim_generation(),
            timed_out_generation
        );
        assert_eq!(
            recoveries[1].fence().claim_generation(),
            takeover_generation
        );
        assert!(recoveries[1].fence().locked_at() > recoveries[0].fence().locked_at());
    }

    #[tokio::test]
    async fn exact_terminal_replay_is_forwarded_without_fence_rewriting() {
        let claim_generation = 4;
        let recovery_task = task(claim_generation, 100, 100);
        let repository = Arc::new(FakeRepository::with_tasks(
            [recovery_task.clone(), recovery_task],
            RecoverSecretMutationReservationOutcome::ExpiredWithCleanup,
        ));
        let loop_ = worker(
            Arc::clone(&repository),
            Arc::new(SequenceClock::new([100, 101, 100, 101])),
            Duration::from_millis(5),
        );

        assert_eq!(
            loop_.run_once(&CancellationToken::new()).await,
            LoopAction::Drain
        );
        assert_eq!(
            loop_.run_once(&CancellationToken::new()).await,
            LoopAction::Drain
        );
        let recoveries = repository.recoveries.lock().expect("recovery lock");
        assert_eq!(recoveries.len(), 2);
        assert_eq!(recoveries[0], recoveries[1]);
        assert_eq!(recoveries[0].fence().claim_generation(), claim_generation);
    }

    #[test]
    fn timing_configuration_fails_closed() {
        let repository: Arc<dyn SecretMutationRecoveryRepository> =
            Arc::new(FakeRepository::blocking());
        let clock: Arc<dyn SecretCleanupClock> = Arc::new(SequenceClock::new([]));
        let compose = |poll, operation, stale| {
            SecretMutationRecoveryLoop::new(
                SecretMutationRecoveryPorts::new(
                    Arc::clone(&repository),
                    default_provider_registry(),
                    SecretCustodyVerifier::verified_for_tests(),
                ),
                Arc::clone(&clock),
                worker_id(),
                poll,
                operation,
                stale,
            )
        };
        assert!(matches!(
            compose(
                Duration::ZERO,
                Duration::from_millis(1),
                Duration::from_millis(2)
            ),
            Err(SecretMutationRecoveryLoopConfigError::InvalidPollInterval)
        ));
        assert!(matches!(
            compose(
                Duration::from_millis(3),
                Duration::from_millis(1),
                Duration::from_millis(2)
            ),
            Err(SecretMutationRecoveryLoopConfigError::PollExceedsStaleTimeout)
        ));
        assert!(matches!(
            compose(
                Duration::from_millis(1),
                Duration::from_millis(2),
                Duration::from_millis(2)
            ),
            Err(SecretMutationRecoveryLoopConfigError::OperationTimeoutReachesStaleTimeout)
        ));
    }
}
