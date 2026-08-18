use std::{fmt, sync::Arc};

use async_trait::async_trait;
use automata_ci_core::UnixMillis;
use automata_ci_provider::{
    BindProviderProcessingSource, ClaimProviderProcessing, ClaimedProviderProcessing,
    CompleteProviderProcessing, FailProviderProcessing, ProviderDeliveryId,
    ProviderProcessingFailure, ProviderProcessingInput, ProviderProcessingReceipt,
    ProviderProcessingRepository, ProviderProcessingRepositoryError, ProviderProcessingState,
    ProviderProcessingWorkerId, RenewProviderProcessing, RetryProviderProcessing,
};
use thiserror::Error;
use tokio::{
    sync::watch,
    time::{Duration, sleep},
};
use tokio_util::sync::CancellationToken;

use crate::ProviderDeliveryClock;

/// Final disposition returned by provider-neutral workflow admission.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProviderProcessingOutcome {
    /// All idempotent workflow-admission work completed.
    Complete,
    /// Resolve an authenticated control to this immutable trigger delivery.
    ResolveControl(ProviderDeliveryId),
    /// A transient dependency failure should use the worker retry policy.
    Retry(ProviderProcessingFailure),
    /// Policy or evidence terminally rejects this delivery.
    Fail(ProviderProcessingFailure),
}

/// Provider-independent workflow admission port invoked under a live claim fence.
#[async_trait]
pub trait ProviderProcessingProcessor: fmt::Debug + Send + Sync {
    /// Performs idempotent admission for one normalized provider trigger.
    async fn process(
        &self,
        delivery: &ClaimedProviderProcessing,
        lease: &ProviderProcessingLease,
    ) -> ProviderProcessingOutcome;
}

/// Read-only live view of the exact processing fence held by a worker.
///
/// The worker updates this handle after every durable renewal. Processors must
/// take a fresh snapshot immediately before any fenced downstream mutation;
/// retaining the fence embedded in [`ClaimedProviderProcessing`] would lose a
/// renewal race during long-running provider or workflow operations.
#[derive(Clone)]
pub struct ProviderProcessingLease {
    fence: watch::Receiver<automata_ci_provider::ProviderProcessingClaimFence>,
}

impl ProviderProcessingLease {
    fn new(fence: watch::Receiver<automata_ci_provider::ProviderProcessingClaimFence>) -> Self {
        Self { fence }
    }

    /// Returns the most recently committed processing fence.
    #[must_use]
    pub fn current(&self) -> automata_ci_provider::ProviderProcessingClaimFence {
        *self.fence.borrow()
    }
}

impl automata_ci_provider::ProviderProcessingClaimSource for ProviderProcessingLease {
    fn current_fence(&self) -> automata_ci_provider::ProviderProcessingClaimFence {
        self.current()
    }
}

impl fmt::Debug for ProviderProcessingLease {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProviderProcessingLease")
            .field("fence", &self.current())
            .finish()
    }
}

/// Bounded generic processing-worker lease and retry policy.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProviderProcessingWorkerConfig {
    lease_millis: u64,
    retry_millis: i64,
}

impl ProviderProcessingWorkerConfig {
    /// Constructs worker timing policy accepted by the common processing model.
    ///
    /// # Errors
    ///
    /// Rejects zero values or values beyond common lease/retry ceilings.
    pub const fn new(
        lease_millis: u64,
        retry_millis: i64,
    ) -> Result<Self, ProviderProcessingWorkerError> {
        if lease_millis == 0
            || lease_millis > automata_ci_provider::MAX_PROVIDER_PROCESSING_LEASE_MILLIS as u64
            || retry_millis <= 0
            || retry_millis > automata_ci_provider::MAX_PROVIDER_PROCESSING_RETRY_MILLIS
        {
            return Err(ProviderProcessingWorkerError::InvalidConfiguration);
        }
        Ok(Self {
            lease_millis,
            retry_millis,
        })
    }

    /// Returns the claim lease duration.
    #[must_use]
    pub const fn lease_millis(self) -> u64 {
        self.lease_millis
    }

    /// Returns the fixed transient retry delay.
    #[must_use]
    pub const fn retry_millis(self) -> i64 {
        self.retry_millis
    }
}

/// One provider-neutral fenced processing worker.
pub struct ProviderProcessingWorker {
    worker_id: ProviderProcessingWorkerId,
    repository: Arc<dyn ProviderProcessingRepository>,
    processor: Arc<dyn ProviderProcessingProcessor>,
    clock: Arc<dyn ProviderDeliveryClock>,
    config: ProviderProcessingWorkerConfig,
}

impl ProviderProcessingWorker {
    /// Composes a stable worker identity, durable queue, processor, and clock.
    #[must_use]
    pub fn new(
        worker_id: ProviderProcessingWorkerId,
        repository: Arc<dyn ProviderProcessingRepository>,
        processor: Arc<dyn ProviderProcessingProcessor>,
        clock: Arc<dyn ProviderDeliveryClock>,
        config: ProviderProcessingWorkerConfig,
    ) -> Self {
        Self {
            worker_id,
            repository,
            processor,
            clock,
            config,
        }
    }

    /// Returns this process-lifetime worker identity.
    #[must_use]
    pub const fn worker_id(&self) -> ProviderProcessingWorkerId {
        self.worker_id
    }

    /// Claims and processes at most one provider invocation.
    ///
    /// # Errors
    ///
    /// Returns sanitized clock, model, repository, or stale-claim failures.
    pub async fn run_once(
        &self,
    ) -> Result<ProviderProcessingWorkerOutcome, ProviderProcessingWorkerError> {
        let claimed_at = self.now()?;
        let claim =
            ClaimProviderProcessing::new(self.worker_id, claimed_at, self.config.lease_millis)
                .map_err(|_| ProviderProcessingWorkerError::InvalidConfiguration)?;
        let Some(mut invocation) = self
            .repository
            .claim_processing(claim)
            .await
            .map_err(repository_error)?
        else {
            return Ok(ProviderProcessingWorkerOutcome::Idle);
        };
        loop {
            let disposition = self.process_with_renewal(&invocation).await?;
            match self.apply_outcome(&invocation, disposition).await? {
                WorkerStep::Continue(bound) => invocation = bound,
                WorkerStep::Finished(outcome) => return Ok(outcome),
            }
        }
    }

    /// Polls and processes provider invocations until shutdown.
    ///
    /// Transient clock or repository unavailability uses the configured retry
    /// delay. A lost claim is already fenced and immediately returns to the
    /// queue. Invalid configuration, source binding, or durable state stops the
    /// service instead of spinning on corruption.
    ///
    /// The current provider operation is allowed to reach its bounded result
    /// after shutdown is requested; a new claim is never started afterward.
    ///
    /// # Errors
    ///
    /// Returns the first non-retryable worker failure.
    pub async fn run(
        &self,
        shutdown: CancellationToken,
    ) -> Result<(), ProviderProcessingWorkerError> {
        loop {
            if shutdown.is_cancelled() {
                return Ok(());
            }
            match self.run_once().await {
                Ok(
                    ProviderProcessingWorkerOutcome::Completed
                    | ProviderProcessingWorkerOutcome::Retried
                    | ProviderProcessingWorkerOutcome::Failed,
                )
                | Err(ProviderProcessingWorkerError::ClaimExpired) => {}
                Ok(ProviderProcessingWorkerOutcome::Idle)
                | Err(
                    ProviderProcessingWorkerError::Clock
                    | ProviderProcessingWorkerError::Unavailable,
                ) => {
                    if sleep_or_shutdown(self.retry_duration(), &shutdown).await {
                        return Ok(());
                    }
                }
                Err(error) => return Err(error),
            }
        }
    }

    fn retry_duration(&self) -> Duration {
        Duration::from_millis(
            u64::try_from(self.config.retry_millis)
                .expect("validated positive provider retry duration fits u64"),
        )
    }

    async fn apply_outcome(
        &self,
        invocation: &ClaimedProviderProcessing,
        disposition: ProcessedInvocation,
    ) -> Result<WorkerStep, ProviderProcessingWorkerError> {
        let finished_at = self.now()?;
        match disposition.outcome {
            ProviderProcessingOutcome::ResolveControl(source_delivery_id) => {
                if !matches!(invocation.input(), ProviderProcessingInput::Control(_)) {
                    return Err(ProviderProcessingWorkerError::InvalidSourceBinding);
                }
                let command = BindProviderProcessingSource::new(
                    disposition.fence,
                    source_delivery_id,
                    finished_at,
                )
                .map_err(|_| ProviderProcessingWorkerError::ClaimExpired)?;
                let bound = self
                    .repository
                    .bind_processing_source(command)
                    .await
                    .map_err(repository_error)?;
                if !valid_source_binding(invocation, &bound, source_delivery_id, disposition.fence)
                {
                    return Err(ProviderProcessingWorkerError::Repository);
                }
                Ok(WorkerStep::Continue(bound))
            }
            ProviderProcessingOutcome::Complete => {
                let command = CompleteProviderProcessing::new(disposition.fence, finished_at)
                    .map_err(|_| ProviderProcessingWorkerError::ClaimExpired)?;
                let receipt = self
                    .repository
                    .complete_processing(command)
                    .await
                    .map_err(repository_error)?;
                validate_terminal(invocation, receipt, ProviderProcessingState::Completed)?;
                Ok(WorkerStep::Finished(
                    ProviderProcessingWorkerOutcome::Completed,
                ))
            }
            ProviderProcessingOutcome::Retry(failure) => {
                let retry_at = finished_at
                    .get()
                    .checked_add(self.config.retry_millis)
                    .map(UnixMillis::new)
                    .ok_or(ProviderProcessingWorkerError::Clock)?;
                let command =
                    RetryProviderProcessing::new(disposition.fence, finished_at, retry_at, failure)
                        .map_err(|_| ProviderProcessingWorkerError::ClaimExpired)?;
                let receipt = self
                    .repository
                    .retry_processing(command)
                    .await
                    .map_err(repository_error)?;
                validate_terminal(invocation, receipt, ProviderProcessingState::RetryPending)?;
                Ok(WorkerStep::Finished(
                    ProviderProcessingWorkerOutcome::Retried,
                ))
            }
            ProviderProcessingOutcome::Fail(failure) => {
                let command = FailProviderProcessing::new(disposition.fence, finished_at, failure)
                    .map_err(|_| ProviderProcessingWorkerError::ClaimExpired)?;
                let receipt = self
                    .repository
                    .fail_processing(command)
                    .await
                    .map_err(repository_error)?;
                validate_terminal(invocation, receipt, ProviderProcessingState::Failed)?;
                Ok(WorkerStep::Finished(
                    ProviderProcessingWorkerOutcome::Failed,
                ))
            }
        }
    }

    fn now(&self) -> Result<UnixMillis, ProviderProcessingWorkerError> {
        self.clock
            .now()
            .map_err(|_| ProviderProcessingWorkerError::Clock)
    }

    async fn process_with_renewal(
        &self,
        delivery: &ClaimedProviderProcessing,
    ) -> Result<ProcessedInvocation, ProviderProcessingWorkerError> {
        let mut fence = delivery.fence();
        let (lease_updates, lease_view) = watch::channel(fence);
        let lease = ProviderProcessingLease::new(lease_view);
        let process = self.processor.process(delivery, &lease);
        tokio::pin!(process);
        let heartbeat = Duration::from_millis((self.config.lease_millis / 3).max(1));
        loop {
            tokio::select! {
                outcome = &mut process => return Ok(ProcessedInvocation { outcome, fence }),
                () = sleep(heartbeat) => {
                    let renewed_at = self.now()?;
                    let renewal = RenewProviderProcessing::new(
                        fence,
                        renewed_at,
                        self.config.lease_millis,
                    )
                    .map_err(|_| ProviderProcessingWorkerError::ClaimExpired)?;
                    let renewed = self.repository
                        .renew_processing(renewal)
                        .await
                        .map_err(repository_error)?;
                    if !valid_renewal(fence, renewed) {
                        return Err(ProviderProcessingWorkerError::Repository);
                    }
                    fence = renewed;
                    lease_updates.send_replace(fence);
                }
            }
        }
    }
}

async fn sleep_or_shutdown(duration: Duration, shutdown: &CancellationToken) -> bool {
    tokio::select! {
        () = shutdown.cancelled() => true,
        () = sleep(duration) => false,
    }
}

fn valid_renewal(
    prior: automata_ci_provider::ProviderProcessingClaimFence,
    renewed: automata_ci_provider::ProviderProcessingClaimFence,
) -> bool {
    renewed.invocation_id() == prior.invocation_id()
        && renewed.worker_id() == prior.worker_id()
        && renewed.token() == prior.token()
        && renewed.claimed_at() == prior.claimed_at()
        && renewed.expires_at() > prior.expires_at()
}

fn valid_source_binding(
    prior: &ClaimedProviderProcessing,
    bound: &ClaimedProviderProcessing,
    source_delivery_id: ProviderDeliveryId,
    fence: automata_ci_provider::ProviderProcessingClaimFence,
) -> bool {
    let prior_receipt = prior.receipt();
    let bound_receipt = bound.receipt();
    bound.fence() == fence
        && bound_receipt.invocation_id() == prior_receipt.invocation_id()
        && bound_receipt.cause_delivery_id() == prior_receipt.cause_delivery_id()
        && bound_receipt.source_delivery_id() == Some(source_delivery_id)
        && bound_receipt.state() == ProviderProcessingState::Claimed
        && bound_receipt.attempts() == prior_receipt.attempts()
        && bound_receipt.created_at() == prior_receipt.created_at()
        && matches!(
            bound.input(),
            ProviderProcessingInput::Trigger(source)
                if source.evidence().delivery_id() == source_delivery_id
        )
}

fn valid_terminal_receipt(
    prior: ProviderProcessingReceipt,
    terminal: ProviderProcessingReceipt,
    state: ProviderProcessingState,
) -> bool {
    terminal.invocation_id() == prior.invocation_id()
        && terminal.cause_delivery_id() == prior.cause_delivery_id()
        && terminal.source_delivery_id() == prior.source_delivery_id()
        && terminal.state() == state
        && terminal.attempts() == prior.attempts()
        && terminal.created_at() == prior.created_at()
}

fn validate_terminal(
    invocation: &ClaimedProviderProcessing,
    receipt: ProviderProcessingReceipt,
    state: ProviderProcessingState,
) -> Result<(), ProviderProcessingWorkerError> {
    if valid_terminal_receipt(invocation.receipt(), receipt, state) {
        Ok(())
    } else {
        Err(ProviderProcessingWorkerError::Repository)
    }
}

struct ProcessedInvocation {
    outcome: ProviderProcessingOutcome,
    fence: automata_ci_provider::ProviderProcessingClaimFence,
}

enum WorkerStep {
    Continue(ClaimedProviderProcessing),
    Finished(ProviderProcessingWorkerOutcome),
}

impl fmt::Debug for ProviderProcessingWorker {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProviderProcessingWorker")
            .field("worker_id", &self.worker_id)
            .field("repository", &self.repository)
            .field("processor", &self.processor)
            .field("clock", &self.clock)
            .field("config", &self.config)
            .finish()
    }
}

/// Result of one bounded generic worker pass.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProviderProcessingWorkerOutcome {
    /// No eligible delivery existed.
    Idle,
    /// One delivery completed.
    Completed,
    /// One transient failure was scheduled for retry.
    Retried,
    /// One delivery failed terminally.
    Failed,
}

/// Sanitized generic processing-worker failure.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum ProviderProcessingWorkerError {
    /// Timing policy violates common processing bounds.
    #[error("provider processing worker configuration is invalid")]
    InvalidConfiguration,
    /// Trusted time could not be obtained or represented.
    #[error("provider processing worker clock is unavailable")]
    Clock,
    /// Processing outlived or lost its exact claim fence.
    #[error("provider processing worker claim expired")]
    ClaimExpired,
    /// A handler attempted to bind source evidence to a trigger invocation.
    #[error("provider processing control source binding is invalid")]
    InvalidSourceBinding,
    /// Durable processing storage is unavailable.
    #[error("provider processing repository is unavailable")]
    Unavailable,
    /// Durable processing state violated queue invariants.
    #[error("provider processing repository rejected the operation")]
    Repository,
}

const fn repository_error(
    error: ProviderProcessingRepositoryError,
) -> ProviderProcessingWorkerError {
    match error {
        ProviderProcessingRepositoryError::Unavailable => {
            ProviderProcessingWorkerError::Unavailable
        }
        ProviderProcessingRepositoryError::ClaimRejected => {
            ProviderProcessingWorkerError::ClaimExpired
        }
        ProviderProcessingRepositoryError::NotFound
        | ProviderProcessingRepositoryError::AttemptLimitReached
        | ProviderProcessingRepositoryError::Corrupt => ProviderProcessingWorkerError::Repository,
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{
        Mutex,
        atomic::{AtomicBool, AtomicI64, AtomicUsize, Ordering},
    };

    use automata_ci_core::{GitObjectId, Sha256Digest, WorkspaceId};
    use automata_ci_provider::{
        ExternalDeliveryId, ExternalDeliveryIdentity, ExternalRepositoryId,
        ExternalRepositoryIdentity, NormalizedTrigger, ProviderArchiveLimits,
        ProviderConfigurationDocument, ProviderConfigurationRevision,
        ProviderConnectionConfiguration, ProviderConnectionId, ProviderConnectionManifest,
        ProviderConnectionPolicyDocument, ProviderConnectionRevision, ProviderControl,
        ProviderControlDocument, ProviderControlKind, ProviderDefaultBranch, ProviderDeliveryId,
        ProviderDeliveryObservations, ProviderEventName, ProviderGitRef, ProviderGitRefKind,
        ProviderInstanceId, ProviderInstanceManifest, ProviderInstanceRecord,
        ProviderLifecycleState, ProviderManifestRepository, ProviderProcessingClaimFence,
        ProviderProcessingFuture, ProviderProcessingInvocationId, ProviderProcessingReceipt,
        ProviderProcessingState, ProviderRepository, ProviderRepositoryError,
        ProviderRepositoryFuture, ProviderRepositoryPath, ProviderRunnerPolicyBinding,
        ProviderSaveOutcome, ProviderSchemaVersion, ProviderSecretBindings,
        ProviderSecretGeneration, ProviderSecretName, ProviderSecretSet, ProviderTypeId,
        ProviderWebhookEndpointId, ProviderWebhookEndpointRevision, ProviderWebhookSecretReference,
        ProviderWebhookSignatureEvidence, ProviderWorkflowSource, PushCommitEvidence, PushTrigger,
        RepositoryVisibility, RetryProviderProcessing, VerifiedProviderControlDelivery,
        VerifiedProviderTriggerDelivery, provider_raw_webhook_descriptor,
    };

    use super::*;
    use crate::ProviderDeliveryClockError;

    #[derive(Debug)]
    struct StepClock(AtomicI64);

    impl ProviderDeliveryClock for StepClock {
        fn now(&self) -> Result<UnixMillis, ProviderDeliveryClockError> {
            Ok(UnixMillis::new(self.0.fetch_add(15, Ordering::SeqCst)))
        }
    }

    #[derive(Debug)]
    struct SlowProcessor {
        initial_expiry: AtomicI64,
        final_expiry: AtomicI64,
    }

    #[derive(Debug)]
    struct StaticProcessor(ProviderProcessingOutcome);

    #[async_trait]
    impl ProviderProcessingProcessor for StaticProcessor {
        async fn process(
            &self,
            _delivery: &ClaimedProviderProcessing,
            _lease: &ProviderProcessingLease,
        ) -> ProviderProcessingOutcome {
            self.0
        }
    }

    #[async_trait]
    impl ProviderProcessingProcessor for SlowProcessor {
        async fn process(
            &self,
            _delivery: &ClaimedProviderProcessing,
            lease: &ProviderProcessingLease,
        ) -> ProviderProcessingOutcome {
            self.initial_expiry
                .store(lease.current().expires_at().get(), Ordering::SeqCst);
            sleep(Duration::from_millis(25)).await;
            self.final_expiry
                .store(lease.current().expires_at().get(), Ordering::SeqCst);
            ProviderProcessingOutcome::Complete
        }
    }

    #[derive(Debug)]
    struct RecordingRuntimeAdapter {
        provider_type: ProviderTypeId,
        source_delivery_id: Option<ProviderDeliveryId>,
        control_calls: AtomicUsize,
        trigger_calls: AtomicUsize,
    }

    #[derive(Debug)]
    struct IdempotentRuntimeAdapter {
        provider_type: ProviderTypeId,
        handled: AtomicBool,
        control_calls: AtomicUsize,
        effects: AtomicUsize,
        trigger_calls: AtomicUsize,
    }

    #[async_trait]
    impl crate::ProviderRuntimeAdapter for IdempotentRuntimeAdapter {
        fn provider_type(&self) -> &ProviderTypeId {
            &self.provider_type
        }

        async fn process_trigger(
            &self,
            context: &crate::ProviderRuntimeContext,
            _trigger: &VerifiedProviderTriggerDelivery,
            _invocation: &ClaimedProviderProcessing,
            _lease: &ProviderProcessingLease,
        ) -> crate::ProviderTriggerOutcome {
            assert_eq!(
                context.provider().manifest().provider_type(),
                &self.provider_type
            );
            self.trigger_calls.fetch_add(1, Ordering::SeqCst);
            crate::ProviderTriggerOutcome::Complete
        }

        async fn handle_control(
            &self,
            context: &crate::ProviderRuntimeContext,
            _control: &VerifiedProviderControlDelivery,
            _invocation: &ClaimedProviderProcessing,
            _lease: &ProviderProcessingLease,
        ) -> Result<Option<ProviderDeliveryId>, crate::ProviderControlHandlingError> {
            assert_eq!(
                context.provider().manifest().provider_type(),
                &self.provider_type
            );
            self.control_calls.fetch_add(1, Ordering::SeqCst);
            if !self.handled.swap(true, Ordering::SeqCst) {
                self.effects.fetch_add(1, Ordering::SeqCst);
            }
            Ok(None)
        }
    }

    #[async_trait]
    impl crate::ProviderRuntimeAdapter for RecordingRuntimeAdapter {
        fn provider_type(&self) -> &ProviderTypeId {
            &self.provider_type
        }

        async fn process_trigger(
            &self,
            context: &crate::ProviderRuntimeContext,
            _trigger: &VerifiedProviderTriggerDelivery,
            _invocation: &ClaimedProviderProcessing,
            _lease: &ProviderProcessingLease,
        ) -> crate::ProviderTriggerOutcome {
            assert_eq!(
                context.provider().manifest().provider_type(),
                &self.provider_type
            );
            self.trigger_calls.fetch_add(1, Ordering::SeqCst);
            crate::ProviderTriggerOutcome::Complete
        }

        async fn handle_control(
            &self,
            context: &crate::ProviderRuntimeContext,
            _control: &VerifiedProviderControlDelivery,
            _invocation: &ClaimedProviderProcessing,
            lease: &ProviderProcessingLease,
        ) -> Result<Option<ProviderDeliveryId>, crate::ProviderControlHandlingError> {
            assert_eq!(
                context.provider().manifest().provider_type(),
                &self.provider_type
            );
            assert!(lease.current().expires_at() > lease.current().claimed_at());
            self.control_calls.fetch_add(1, Ordering::SeqCst);
            Ok(self.source_delivery_id)
        }
    }

    #[derive(Debug)]
    struct RecordingRepository {
        claim: Mutex<Option<ClaimedProviderProcessing>>,
        receipt: ProviderProcessingReceipt,
        claims: AtomicUsize,
        renewals: AtomicUsize,
        completed: Mutex<Option<ProviderProcessingClaimFence>>,
    }

    #[derive(Debug)]
    struct RuntimeManifestRepository {
        manifest: ProviderInstanceManifest,
        connection: ProviderConnectionManifest,
        available: bool,
    }

    impl ProviderManifestRepository for RuntimeManifestRepository {
        fn save_instance(
            &self,
            _record: ProviderInstanceRecord,
        ) -> ProviderRepositoryFuture<'_, ProviderSaveOutcome> {
            Box::pin(async { Err(ProviderRepositoryError::Unavailable) })
        }

        fn load_instance(
            &self,
            instance_id: ProviderInstanceId,
            revision: ProviderConfigurationRevision,
        ) -> ProviderRepositoryFuture<'_, Option<ProviderInstanceRecord>> {
            Box::pin(async move {
                if !self.available {
                    return Err(ProviderRepositoryError::Unavailable);
                }
                if self.manifest.instance_id() != instance_id
                    || self.manifest.revision() != revision
                {
                    return Ok(None);
                }
                let secrets = ProviderSecretSet::new(self.manifest.secrets(), [])
                    .map_err(|_| ProviderRepositoryError::Corrupt)?;
                ProviderInstanceRecord::new(self.manifest.clone(), secrets).map(Some)
            })
        }

        fn current_instance(
            &self,
            instance_id: ProviderInstanceId,
        ) -> ProviderRepositoryFuture<'_, Option<ProviderInstanceRecord>> {
            Box::pin(async move {
                if !self.available {
                    return Err(ProviderRepositoryError::Unavailable);
                }
                if self.manifest.instance_id() != instance_id {
                    return Ok(None);
                }
                let secrets = ProviderSecretSet::new(self.manifest.secrets(), [])
                    .map_err(|_| ProviderRepositoryError::Corrupt)?;
                ProviderInstanceRecord::new(self.manifest.clone(), secrets).map(Some)
            })
        }

        fn save_connection(
            &self,
            _manifest: ProviderConnectionManifest,
        ) -> ProviderRepositoryFuture<'_, ProviderSaveOutcome> {
            Box::pin(async { Err(ProviderRepositoryError::Unavailable) })
        }

        fn load_connection(
            &self,
            connection_id: ProviderConnectionId,
            revision: ProviderConnectionRevision,
        ) -> ProviderRepositoryFuture<'_, Option<ProviderConnectionManifest>> {
            Box::pin(async move {
                if !self.available {
                    return Err(ProviderRepositoryError::Unavailable);
                }
                Ok((self.connection.connection_id() == connection_id
                    && self.connection.revision() == revision)
                    .then(|| self.connection.clone()))
            })
        }

        fn current_connection(
            &self,
            connection_id: ProviderConnectionId,
        ) -> ProviderRepositoryFuture<'_, Option<ProviderConnectionManifest>> {
            Box::pin(async move {
                if !self.available {
                    return Err(ProviderRepositoryError::Unavailable);
                }
                Ok((self.connection.connection_id() == connection_id)
                    .then(|| self.connection.clone()))
            })
        }
    }

    impl ProviderProcessingRepository for RecordingRepository {
        fn claim_processing(
            &self,
            _request: ClaimProviderProcessing,
        ) -> ProviderProcessingFuture<'_, Option<ClaimedProviderProcessing>> {
            Box::pin(async move {
                self.claims.fetch_add(1, Ordering::SeqCst);
                Ok(self.claim.lock().expect("claim lock").take())
            })
        }

        fn bind_processing_source(
            &self,
            _request: automata_ci_provider::BindProviderProcessingSource,
        ) -> ProviderProcessingFuture<'_, ClaimedProviderProcessing> {
            Box::pin(async { Err(ProviderProcessingRepositoryError::Corrupt) })
        }

        fn renew_processing(
            &self,
            request: RenewProviderProcessing,
        ) -> ProviderProcessingFuture<'_, ProviderProcessingClaimFence> {
            Box::pin(async move {
                self.renewals.fetch_add(1, Ordering::SeqCst);
                let fence = request.fence();
                ProviderProcessingClaimFence::new(
                    fence.invocation_id(),
                    fence.worker_id(),
                    fence.token(),
                    fence.claimed_at(),
                    UnixMillis::new(
                        request.renewed_at().get()
                            + i64::try_from(request.lease_millis()).expect("lease"),
                    ),
                )
                .map_err(|_| ProviderProcessingRepositoryError::Corrupt)
            })
        }

        fn complete_processing(
            &self,
            request: CompleteProviderProcessing,
        ) -> ProviderProcessingFuture<'_, ProviderProcessingReceipt> {
            Box::pin(async move {
                *self.completed.lock().expect("completion lock") = Some(request.fence());
                let receipt = self.receipt;
                ProviderProcessingReceipt::new(
                    receipt.invocation_id(),
                    receipt.cause_delivery_id(),
                    receipt.source_delivery_id(),
                    ProviderProcessingState::Completed,
                    receipt.attempts(),
                    receipt.created_at(),
                )
                .map_err(|_| ProviderProcessingRepositoryError::Corrupt)
            })
        }

        fn retry_processing(
            &self,
            _request: RetryProviderProcessing,
        ) -> ProviderProcessingFuture<'_, ProviderProcessingReceipt> {
            Box::pin(async { Err(ProviderProcessingRepositoryError::Corrupt) })
        }

        fn fail_processing(
            &self,
            _request: FailProviderProcessing,
        ) -> ProviderProcessingFuture<'_, ProviderProcessingReceipt> {
            Box::pin(async { Err(ProviderProcessingRepositoryError::Corrupt) })
        }
    }

    #[derive(Debug)]
    struct ResolvingRepository {
        claim: Mutex<Option<ClaimedProviderProcessing>>,
        bound: ClaimedProviderProcessing,
        bindings: AtomicUsize,
        completed: Mutex<Option<ProviderProcessingClaimFence>>,
    }

    impl ProviderProcessingRepository for ResolvingRepository {
        fn claim_processing(
            &self,
            _request: ClaimProviderProcessing,
        ) -> ProviderProcessingFuture<'_, Option<ClaimedProviderProcessing>> {
            Box::pin(async move { Ok(self.claim.lock().expect("claim lock").take()) })
        }

        fn bind_processing_source(
            &self,
            request: BindProviderProcessingSource,
        ) -> ProviderProcessingFuture<'_, ClaimedProviderProcessing> {
            Box::pin(async move {
                assert_eq!(
                    request.source_delivery_id(),
                    self.bound.receipt().source_delivery_id().expect("source")
                );
                assert_eq!(request.fence(), self.bound.fence());
                self.bindings.fetch_add(1, Ordering::SeqCst);
                Ok(self.bound.clone())
            })
        }

        fn renew_processing(
            &self,
            _request: RenewProviderProcessing,
        ) -> ProviderProcessingFuture<'_, ProviderProcessingClaimFence> {
            Box::pin(async { Err(ProviderProcessingRepositoryError::Corrupt) })
        }

        fn complete_processing(
            &self,
            request: CompleteProviderProcessing,
        ) -> ProviderProcessingFuture<'_, ProviderProcessingReceipt> {
            Box::pin(async move {
                *self.completed.lock().expect("completion lock") = Some(request.fence());
                let receipt = self.bound.receipt();
                ProviderProcessingReceipt::new(
                    receipt.invocation_id(),
                    receipt.cause_delivery_id(),
                    receipt.source_delivery_id(),
                    ProviderProcessingState::Completed,
                    receipt.attempts(),
                    receipt.created_at(),
                )
                .map_err(|_| ProviderProcessingRepositoryError::Corrupt)
            })
        }

        fn retry_processing(
            &self,
            _request: RetryProviderProcessing,
        ) -> ProviderProcessingFuture<'_, ProviderProcessingReceipt> {
            Box::pin(async { Err(ProviderProcessingRepositoryError::Corrupt) })
        }

        fn fail_processing(
            &self,
            _request: FailProviderProcessing,
        ) -> ProviderProcessingFuture<'_, ProviderProcessingReceipt> {
            Box::pin(async { Err(ProviderProcessingRepositoryError::Corrupt) })
        }
    }

    #[tokio::test]
    async fn long_processing_renews_and_completes_with_the_latest_fence() {
        let worker_id = ProviderProcessingWorkerId::new();
        let claim = claimed(worker_id);
        let repository = Arc::new(RecordingRepository {
            receipt: claim.receipt(),
            claim: Mutex::new(Some(claim)),
            claims: AtomicUsize::new(0),
            renewals: AtomicUsize::new(0),
            completed: Mutex::new(None),
        });
        let processor = Arc::new(SlowProcessor {
            initial_expiry: AtomicI64::new(0),
            final_expiry: AtomicI64::new(0),
        });
        let worker = ProviderProcessingWorker::new(
            worker_id,
            Arc::clone(&repository) as Arc<dyn ProviderProcessingRepository>,
            Arc::clone(&processor) as Arc<dyn ProviderProcessingProcessor>,
            Arc::new(StepClock(AtomicI64::new(1_000))),
            ProviderProcessingWorkerConfig::new(30, 30).expect("config"),
        );

        assert_eq!(
            worker.run_once().await.expect("worker pass"),
            ProviderProcessingWorkerOutcome::Completed
        );
        assert!(repository.renewals.load(Ordering::SeqCst) >= 1);
        assert!(
            processor.final_expiry.load(Ordering::SeqCst)
                > processor.initial_expiry.load(Ordering::SeqCst)
        );
        assert!(
            repository
                .completed
                .lock()
                .expect("completion lock")
                .expect("completed fence")
                .expires_at()
                > UnixMillis::new(1_030)
        );
    }

    #[tokio::test]
    async fn cancelled_service_does_not_claim_more_work() {
        let worker_id = ProviderProcessingWorkerId::new();
        let fixture = claimed(worker_id);
        let repository = Arc::new(RecordingRepository {
            receipt: fixture.receipt(),
            claim: Mutex::new(Some(fixture)),
            claims: AtomicUsize::new(0),
            renewals: AtomicUsize::new(0),
            completed: Mutex::new(None),
        });
        let worker = ProviderProcessingWorker::new(
            worker_id,
            Arc::clone(&repository) as Arc<dyn ProviderProcessingRepository>,
            Arc::new(StaticProcessor(ProviderProcessingOutcome::Complete)),
            Arc::new(StepClock(AtomicI64::new(1_000))),
            ProviderProcessingWorkerConfig::new(60, 30).expect("config"),
        );
        let shutdown = CancellationToken::new();
        shutdown.cancel();

        worker.run(shutdown).await.expect("clean shutdown");

        assert_eq!(repository.claims.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn service_stops_on_invalid_processing_contract() {
        let worker_id = ProviderProcessingWorkerId::new();
        let fixture = claimed(worker_id);
        let repository = Arc::new(RecordingRepository {
            receipt: fixture.receipt(),
            claim: Mutex::new(Some(fixture)),
            claims: AtomicUsize::new(0),
            renewals: AtomicUsize::new(0),
            completed: Mutex::new(None),
        });
        let worker = ProviderProcessingWorker::new(
            worker_id,
            Arc::clone(&repository) as Arc<dyn ProviderProcessingRepository>,
            Arc::new(StaticProcessor(ProviderProcessingOutcome::ResolveControl(
                ProviderDeliveryId::new(),
            ))),
            Arc::new(StepClock(AtomicI64::new(1_000))),
            ProviderProcessingWorkerConfig::new(60, 30).expect("config"),
        );

        assert_eq!(
            worker.run(CancellationToken::new()).await,
            Err(ProviderProcessingWorkerError::InvalidSourceBinding)
        );
        assert_eq!(repository.claims.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn handled_control_binds_its_source_before_completion() {
        let worker_id = ProviderProcessingWorkerId::new();
        let (control, bound, source_delivery_id) = rerun_claims(worker_id);
        let manifests = runtime_manifests(&control);
        let repository = Arc::new(ResolvingRepository {
            claim: Mutex::new(Some(control)),
            bound,
            bindings: AtomicUsize::new(0),
            completed: Mutex::new(None),
        });
        let runtime = Arc::new(RecordingRuntimeAdapter {
            provider_type: ProviderTypeId::new("github").expect("provider type"),
            source_delivery_id: Some(source_delivery_id),
            control_calls: AtomicUsize::new(0),
            trigger_calls: AtomicUsize::new(0),
        });
        let runtimes = crate::ProviderRuntimeAdapterRegistry::new([
            Arc::clone(&runtime) as Arc<dyn crate::ProviderRuntimeAdapter>
        ])
        .expect("runtime registry");
        let processor = Arc::new(crate::ProviderProcessingDispatcher::new(
            runtimes, manifests,
        ));
        let worker = ProviderProcessingWorker::new(
            worker_id,
            Arc::clone(&repository) as Arc<dyn ProviderProcessingRepository>,
            Arc::clone(&processor) as Arc<dyn ProviderProcessingProcessor>,
            Arc::new(StepClock(AtomicI64::new(1_000))),
            ProviderProcessingWorkerConfig::new(60, 30).expect("config"),
        );

        assert_eq!(
            worker.run_once().await.expect("worker pass"),
            ProviderProcessingWorkerOutcome::Completed
        );
        assert_eq!(repository.bindings.load(Ordering::SeqCst), 1);
        assert_eq!(runtime.control_calls.load(Ordering::SeqCst), 1);
        assert_eq!(runtime.trigger_calls.load(Ordering::SeqCst), 0);
        assert_eq!(
            repository
                .completed
                .lock()
                .expect("completion lock")
                .expect("completion fence"),
            repository.bound.fence()
        );
    }

    #[tokio::test]
    async fn trigger_dispatch_requires_the_exact_provider_runtime() {
        let worker_id = ProviderProcessingWorkerId::new();
        let direct = claimed(worker_id);
        let github = Arc::new(RecordingRuntimeAdapter {
            provider_type: ProviderTypeId::new("github").expect("provider type"),
            source_delivery_id: None,
            control_calls: AtomicUsize::new(0),
            trigger_calls: AtomicUsize::new(0),
        });
        let runtimes = crate::ProviderRuntimeAdapterRegistry::new([
            Arc::clone(&github) as Arc<dyn crate::ProviderRuntimeAdapter>
        ])
        .expect("runtime registry");
        let manifests = runtime_manifests(&direct);
        let dispatcher = crate::ProviderProcessingDispatcher::new(runtimes, manifests);
        let (_updates, view) = watch::channel(direct.fence());
        let lease = ProviderProcessingLease::new(view);

        assert_eq!(
            dispatcher.process(&direct, &lease).await,
            ProviderProcessingOutcome::Complete
        );
        assert_eq!(github.trigger_calls.load(Ordering::SeqCst), 1);
        assert_eq!(github.control_calls.load(Ordering::SeqCst), 0);

        let forgejo = Arc::new(RecordingRuntimeAdapter {
            provider_type: ProviderTypeId::new("forgejo").expect("provider type"),
            source_delivery_id: None,
            control_calls: AtomicUsize::new(0),
            trigger_calls: AtomicUsize::new(0),
        });
        let runtimes = crate::ProviderRuntimeAdapterRegistry::new([
            Arc::clone(&forgejo) as Arc<dyn crate::ProviderRuntimeAdapter>
        ])
        .expect("runtime registry");
        let manifests = runtime_manifests(&direct);
        let dispatcher = crate::ProviderProcessingDispatcher::new(runtimes, manifests);

        assert_eq!(
            dispatcher.process(&direct, &lease).await,
            ProviderProcessingOutcome::Fail(ProviderProcessingFailure::InvalidEvidence)
        );
        assert_eq!(forgejo.trigger_calls.load(Ordering::SeqCst), 0);
        assert_eq!(forgejo.control_calls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn runtime_configuration_unavailability_uses_common_retry_policy() {
        let worker_id = ProviderProcessingWorkerId::new();
        let direct = claimed(worker_id);
        let github = Arc::new(RecordingRuntimeAdapter {
            provider_type: ProviderTypeId::new("github").expect("provider type"),
            source_delivery_id: None,
            control_calls: AtomicUsize::new(0),
            trigger_calls: AtomicUsize::new(0),
        });
        let runtimes = crate::ProviderRuntimeAdapterRegistry::new([
            Arc::clone(&github) as Arc<dyn crate::ProviderRuntimeAdapter>
        ])
        .expect("runtime registry");
        let manifests = runtime_manifests_with_availability(&direct, false);
        let dispatcher = crate::ProviderProcessingDispatcher::new(runtimes, manifests);
        let (_updates, view) = watch::channel(direct.fence());
        let lease = ProviderProcessingLease::new(view);

        assert_eq!(
            dispatcher.process(&direct, &lease).await,
            ProviderProcessingOutcome::Retry(ProviderProcessingFailure::DependencyUnavailable)
        );
        assert_eq!(github.trigger_calls.load(Ordering::SeqCst), 0);
        assert_eq!(github.control_calls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn handled_control_without_trigger_provenance_completes_directly() {
        let worker_id = ProviderProcessingWorkerId::new();
        let (control, _bound, _source_delivery_id) = rerun_claims(worker_id);
        let runtime = Arc::new(RecordingRuntimeAdapter {
            provider_type: ProviderTypeId::new("github").expect("provider type"),
            source_delivery_id: None,
            control_calls: AtomicUsize::new(0),
            trigger_calls: AtomicUsize::new(0),
        });
        let runtimes = crate::ProviderRuntimeAdapterRegistry::new([
            Arc::clone(&runtime) as Arc<dyn crate::ProviderRuntimeAdapter>
        ])
        .expect("runtime registry");
        let manifests = runtime_manifests(&control);
        let dispatcher = crate::ProviderProcessingDispatcher::new(runtimes, manifests);
        let (_updates, view) = watch::channel(control.fence());
        let lease = ProviderProcessingLease::new(view);

        assert_eq!(
            dispatcher.process(&control, &lease).await,
            ProviderProcessingOutcome::Complete
        );
        assert_eq!(runtime.control_calls.load(Ordering::SeqCst), 1);
        assert_eq!(runtime.trigger_calls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn control_replay_after_completion_crash_is_idempotent() {
        let worker_id = ProviderProcessingWorkerId::new();
        let (control, _bound, _source_delivery_id) = rerun_claims(worker_id);
        let runtime = Arc::new(IdempotentRuntimeAdapter {
            provider_type: ProviderTypeId::new("github").expect("provider type"),
            handled: AtomicBool::new(false),
            control_calls: AtomicUsize::new(0),
            effects: AtomicUsize::new(0),
            trigger_calls: AtomicUsize::new(0),
        });
        let runtimes = crate::ProviderRuntimeAdapterRegistry::new([
            Arc::clone(&runtime) as Arc<dyn crate::ProviderRuntimeAdapter>
        ])
        .expect("runtime registry");
        let manifests = runtime_manifests(&control);
        let dispatcher = crate::ProviderProcessingDispatcher::new(runtimes, manifests);
        let (_updates, view) = watch::channel(control.fence());
        let lease = ProviderProcessingLease::new(view);

        // The first outcome is intentionally not persisted, modeling a crash
        // after the native operation but before processing completion.
        assert_eq!(
            dispatcher.process(&control, &lease).await,
            ProviderProcessingOutcome::Complete
        );
        assert_eq!(
            dispatcher.process(&control, &lease).await,
            ProviderProcessingOutcome::Complete
        );
        assert_eq!(runtime.control_calls.load(Ordering::SeqCst), 2);
        assert_eq!(runtime.effects.load(Ordering::SeqCst), 1);
        assert_eq!(runtime.trigger_calls.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn repository_responses_must_preserve_exact_processing_identity() {
        let worker_id = ProviderProcessingWorkerId::new();
        let direct = claimed(worker_id);
        let fence = direct.fence();
        let renewed = ProviderProcessingClaimFence::new(
            fence.invocation_id(),
            fence.worker_id(),
            fence.token(),
            fence.claimed_at(),
            UnixMillis::new(fence.expires_at().get() + 1),
        )
        .expect("renewed fence");
        assert!(valid_renewal(fence, renewed));
        let wrong_worker = ProviderProcessingClaimFence::new(
            fence.invocation_id(),
            ProviderProcessingWorkerId::new(),
            fence.token(),
            fence.claimed_at(),
            renewed.expires_at(),
        )
        .expect("wrong-worker fence");
        assert!(!valid_renewal(fence, wrong_worker));

        let receipt = direct.receipt();
        let completed = ProviderProcessingReceipt::new(
            receipt.invocation_id(),
            receipt.cause_delivery_id(),
            receipt.source_delivery_id(),
            ProviderProcessingState::Completed,
            receipt.attempts(),
            receipt.created_at(),
        )
        .expect("completion");
        assert!(valid_terminal_receipt(
            receipt,
            completed,
            ProviderProcessingState::Completed
        ));
        let wrong_source = ProviderProcessingReceipt::new(
            receipt.invocation_id(),
            receipt.cause_delivery_id(),
            Some(ProviderDeliveryId::new()),
            ProviderProcessingState::Completed,
            receipt.attempts(),
            receipt.created_at(),
        )
        .expect("wrong-source completion");
        assert!(!valid_terminal_receipt(
            receipt,
            wrong_source,
            ProviderProcessingState::Completed
        ));
    }

    fn rerun_claims(
        worker_id: ProviderProcessingWorkerId,
    ) -> (
        ClaimedProviderProcessing,
        ClaimedProviderProcessing,
        ProviderDeliveryId,
    ) {
        let source_claim = claimed(worker_id);
        let ProviderProcessingInput::Trigger(source) = source_claim.input().clone() else {
            unreachable!("fixture is a trigger");
        };
        let source_delivery_id = source.evidence().delivery_id();
        let cause_delivery_id = ProviderDeliveryId::new();
        let source_evidence = source.evidence();
        let control_evidence = automata_ci_provider::ProviderDeliveryEvidence::rehydrate(
            cause_delivery_id,
            source_evidence.endpoint_id(),
            source_evidence.endpoint_revision(),
            source_evidence.provider_type().clone(),
            source_evidence.instance_id(),
            source_evidence.provider_revision(),
            source_evidence.connection_id(),
            source_evidence.connection_revision(),
            ExternalDeliveryIdentity::new(
                source_evidence.instance_id(),
                ExternalDeliveryId::new("delivery-rerequested").expect("delivery"),
            ),
            ProviderEventName::new("check_run").expect("event"),
            source_evidence.received_at(),
            source_evidence.raw_body().clone(),
            source_evidence.raw_retain_until(),
            source_evidence.signature().clone(),
            source_evidence.observations().clone(),
        )
        .expect("control evidence");
        let repository = source
            .trigger()
            .trigger()
            .target_repository()
            .identity()
            .clone();
        let control = ProviderControl::new(
            ProviderControlKind::Rerun,
            repository,
            GitObjectId::from_provider_hex("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")
                .expect("object"),
            None,
            ProviderControlDocument::new(
                ProviderSchemaVersion::new(1).expect("schema"),
                br#"{"schema":1,"target":{"kind":"check_run","run_id":601}}"#.to_vec(),
            )
            .expect("document"),
        )
        .expect("control");
        let control = VerifiedProviderControlDelivery::rehydrate(control_evidence, control)
            .expect("verified control");
        let invocation_id = source_claim.receipt().invocation_id();
        let fence = ProviderProcessingClaimFence::new(
            invocation_id,
            worker_id,
            source_claim.fence().token(),
            UnixMillis::new(1_000),
            UnixMillis::new(1_060),
        )
        .expect("claim fence");
        let control_receipt = ProviderProcessingReceipt::new(
            invocation_id,
            cause_delivery_id,
            None,
            ProviderProcessingState::Claimed,
            1,
            source_claim.receipt().created_at(),
        )
        .expect("control receipt");
        let bound_receipt = ProviderProcessingReceipt::new(
            invocation_id,
            cause_delivery_id,
            Some(source_delivery_id),
            ProviderProcessingState::Claimed,
            1,
            source_claim.receipt().created_at(),
        )
        .expect("bound receipt");
        (
            ClaimedProviderProcessing::new(
                control_receipt,
                ProviderProcessingInput::Control(Box::new(control)),
                fence,
            )
            .expect("control claim"),
            ClaimedProviderProcessing::new(
                bound_receipt,
                ProviderProcessingInput::Trigger(source),
                fence,
            )
            .expect("bound trigger claim"),
            source_delivery_id,
        )
    }

    fn runtime_manifests(
        invocation: &ClaimedProviderProcessing,
    ) -> Arc<dyn ProviderManifestRepository> {
        runtime_manifests_with_availability(invocation, true)
    }

    fn runtime_manifests_with_availability(
        invocation: &ClaimedProviderProcessing,
        available: bool,
    ) -> Arc<dyn ProviderManifestRepository> {
        let (evidence, repository) = match invocation.input() {
            ProviderProcessingInput::Trigger(trigger) => (
                trigger.evidence(),
                trigger.trigger().trigger().target_repository().identity(),
            ),
            ProviderProcessingInput::Control(control) => {
                (control.evidence(), control.control().repository())
            }
        };
        let capabilities = Sha256Digest::from_bytes([4; 32]);
        let provider_configuration = ProviderConfigurationDocument::new(
            ProviderSchemaVersion::new(1).expect("provider schema"),
            br"{}".to_vec(),
        )
        .expect("provider configuration");
        let manifest = ProviderInstanceManifest::new(
            evidence.instance_id(),
            evidence.provider_type().clone(),
            evidence.provider_revision(),
            ProviderLifecycleState::Active,
            automata_ci_provider::ProviderOrigins::new(
                "https://github.com/",
                "https://api.github.com/",
            )
            .expect("provider origins"),
            provider_configuration,
            ProviderSecretBindings::empty(),
            capabilities,
            UnixMillis::new(100),
            Some(UnixMillis::new(100)),
            None,
        )
        .expect("provider manifest");
        let policy = ProviderConnectionPolicyDocument::new(
            ProviderSchemaVersion::new(1).expect("connection schema"),
            br"{}".to_vec(),
        )
        .expect("connection policy");
        let configuration = ProviderConnectionConfiguration::new(
            WorkspaceId::parse("11111111-1111-4111-8111-111111111111").expect("workspace"),
            repository.clone(),
            manifest.revision(),
            manifest.configuration().digest(),
            manifest.capability_digest(),
            RepositoryVisibility::Private,
            ProviderDefaultBranch::new("main").expect("default branch"),
            ProviderWorkflowSource::Directory(
                ProviderRepositoryPath::new(".ci/workflows").expect("workflow source"),
            ),
            ProviderRunnerPolicyBinding::new(
                ProviderSchemaVersion::new(1).expect("runner schema"),
                Sha256Digest::from_bytes([5; 32]),
            ),
            ProviderArchiveLimits::new(1_024, 8_192, 100, 1_024, 10, 1_024)
                .expect("archive limits"),
            policy,
        );
        let connection = ProviderConnectionManifest::new(
            evidence.connection_id(),
            evidence.connection_revision(),
            ProviderLifecycleState::Active,
            configuration,
            UnixMillis::new(100),
            Some(UnixMillis::new(100)),
            None,
        )
        .expect("connection manifest");
        Arc::new(RuntimeManifestRepository {
            manifest,
            connection,
            available,
        })
    }

    fn claimed(worker_id: ProviderProcessingWorkerId) -> ClaimedProviderProcessing {
        let instance_id = ProviderInstanceId::new();
        let delivery_id = ProviderDeliveryId::new();
        let repository = ProviderRepository::new(
            ExternalRepositoryIdentity::new(
                instance_id,
                ExternalRepositoryId::new("42").expect("repository"),
            ),
            automata_ci_provider::ExternalSubjectId::new("7").expect("owner"),
            ProviderRepositoryPath::new("owner/repository").expect("path"),
            RepositoryVisibility::Private,
        );
        let after = GitObjectId::from_provider_hex("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")
            .expect("after");
        let trigger = NormalizedTrigger::Push(
            PushTrigger::new(
                repository,
                ProviderGitRef::new("refs/heads/main", ProviderGitRefKind::Branch).expect("ref"),
                Some(
                    GitObjectId::from_provider_hex("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
                        .expect("before"),
                ),
                Some(after),
                PushCommitEvidence::complete([after]).expect("commits"),
                false,
                None,
            )
            .expect("push"),
        )
        .seal()
        .expect("trigger");
        let endpoint_id = ProviderWebhookEndpointId::new();
        let endpoint_revision = ProviderWebhookEndpointRevision::new(1).expect("endpoint revision");
        let provider_revision = ProviderConfigurationRevision::new(1).expect("provider revision");
        let connection_id = ProviderConnectionId::new();
        let connection_revision = ProviderConnectionRevision::new(1).expect("connection revision");
        let raw = provider_raw_webhook_descriptor(Sha256Digest::from_bytes([7; 32]), 1)
            .expect("raw descriptor");
        let evidence = automata_ci_provider::ProviderDeliveryEvidence::rehydrate(
            delivery_id,
            endpoint_id,
            endpoint_revision,
            ProviderTypeId::new("github").expect("provider"),
            instance_id,
            provider_revision,
            connection_id,
            connection_revision,
            ExternalDeliveryIdentity::new(
                instance_id,
                ExternalDeliveryId::new("delivery-1").expect("delivery"),
            ),
            ProviderEventName::new("push").expect("event"),
            UnixMillis::new(900),
            raw,
            UnixMillis::new(10_000),
            ProviderWebhookSignatureEvidence::new(
                "test",
                ProviderWebhookSecretReference::new(
                    provider_revision,
                    ProviderSecretName::new("webhook").expect("secret"),
                    ProviderSecretGeneration::new(1).expect("generation"),
                ),
            )
            .expect("signature"),
            ProviderDeliveryObservations::new(Vec::new()).expect("observations"),
        )
        .expect("evidence");
        let delivery =
            VerifiedProviderTriggerDelivery::rehydrate(evidence, trigger).expect("delivery");
        let invocation_id = ProviderProcessingInvocationId::new();
        let receipt = ProviderProcessingReceipt::new(
            invocation_id,
            delivery_id,
            Some(delivery_id),
            ProviderProcessingState::Claimed,
            1,
            UnixMillis::new(950),
        )
        .expect("receipt");
        let fence = ProviderProcessingClaimFence::new(
            invocation_id,
            worker_id,
            1,
            UnixMillis::new(1_000),
            UnixMillis::new(1_030),
        )
        .expect("fence");
        ClaimedProviderProcessing::new(
            receipt,
            automata_ci_provider::ProviderProcessingInput::Trigger(Box::new(delivery)),
            fence,
        )
        .expect("claim")
    }
}
