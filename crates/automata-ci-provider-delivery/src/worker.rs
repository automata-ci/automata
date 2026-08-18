use std::{fmt, sync::Arc};

use async_trait::async_trait;
use automata_ci_core::UnixMillis;
use automata_ci_provider::{
    BindProviderProcessingSource, ClaimProviderProcessing, ClaimedProviderProcessing,
    CompleteProviderProcessing, FailProviderProcessing, ProviderDeliveryId,
    ProviderProcessingFailure, ProviderProcessingInput, ProviderProcessingRepository,
    ProviderProcessingRepositoryError, ProviderProcessingWorkerId, RenewProviderProcessing,
    RetryProviderProcessing,
};
use thiserror::Error;
use tokio::time::{Duration, sleep};

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
    async fn process(&self, delivery: &ClaimedProviderProcessing) -> ProviderProcessingOutcome;
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
            let finished_at = self.now()?;
            match disposition.outcome {
                ProviderProcessingOutcome::ResolveControl(source_delivery_id) => {
                    if !matches!(invocation.input(), ProviderProcessingInput::Control(_)) {
                        return Err(ProviderProcessingWorkerError::InvalidResolution);
                    }
                    let command = BindProviderProcessingSource::new(
                        disposition.fence,
                        source_delivery_id,
                        finished_at,
                    )
                    .map_err(|_| ProviderProcessingWorkerError::ClaimExpired)?;
                    invocation = self
                        .repository
                        .bind_processing_source(command)
                        .await
                        .map_err(repository_error)?;
                }
                ProviderProcessingOutcome::Complete => {
                    let command = CompleteProviderProcessing::new(disposition.fence, finished_at)
                        .map_err(|_| ProviderProcessingWorkerError::ClaimExpired)?;
                    self.repository
                        .complete_processing(command)
                        .await
                        .map_err(repository_error)?;
                    return Ok(ProviderProcessingWorkerOutcome::Completed);
                }
                ProviderProcessingOutcome::Retry(failure) => {
                    let retry_at = finished_at
                        .get()
                        .checked_add(self.config.retry_millis)
                        .map(UnixMillis::new)
                        .ok_or(ProviderProcessingWorkerError::Clock)?;
                    let command = RetryProviderProcessing::new(
                        disposition.fence,
                        finished_at,
                        retry_at,
                        failure,
                    )
                    .map_err(|_| ProviderProcessingWorkerError::ClaimExpired)?;
                    self.repository
                        .retry_processing(command)
                        .await
                        .map_err(repository_error)?;
                    return Ok(ProviderProcessingWorkerOutcome::Retried);
                }
                ProviderProcessingOutcome::Fail(failure) => {
                    let command =
                        FailProviderProcessing::new(disposition.fence, finished_at, failure)
                            .map_err(|_| ProviderProcessingWorkerError::ClaimExpired)?;
                    self.repository
                        .fail_processing(command)
                        .await
                        .map_err(repository_error)?;
                    return Ok(ProviderProcessingWorkerOutcome::Failed);
                }
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
        let process = self.processor.process(delivery);
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
                    fence = self.repository
                        .renew_processing(renewal)
                        .await
                        .map_err(repository_error)?;
                }
            }
        }
    }
}

struct ProcessedInvocation {
    outcome: ProviderProcessingOutcome,
    fence: automata_ci_provider::ProviderProcessingClaimFence,
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
    /// A handler attempted to resolve an already resolved trigger invocation.
    #[error("provider processing control resolution is invalid")]
    InvalidResolution,
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
        atomic::{AtomicI64, AtomicUsize, Ordering},
    };

    use automata_ci_core::{GitObjectId, Sha256Digest};
    use automata_ci_provider::{
        ExternalDeliveryId, ExternalDeliveryIdentity, ExternalRepositoryId,
        ExternalRepositoryIdentity, NormalizedTrigger, ProviderConfigurationRevision,
        ProviderConnectionId, ProviderConnectionRevision, ProviderControl, ProviderControlDocument,
        ProviderControlKind, ProviderDeliveryId, ProviderDeliveryObservations, ProviderEventName,
        ProviderGitRef, ProviderGitRefKind, ProviderInstanceId, ProviderProcessingClaimFence,
        ProviderProcessingFuture, ProviderProcessingInvocationId, ProviderProcessingReceipt,
        ProviderProcessingState, ProviderRepository, ProviderRepositoryPath, ProviderSchemaVersion,
        ProviderSecretGeneration, ProviderSecretName, ProviderTypeId, ProviderWebhookEndpointId,
        ProviderWebhookEndpointRevision, ProviderWebhookSecretReference,
        ProviderWebhookSignatureEvidence, PushCommitEvidence, PushTrigger, RepositoryVisibility,
        RetryProviderProcessing, VerifiedProviderControlDelivery, VerifiedProviderTriggerDelivery,
        provider_raw_webhook_descriptor,
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
    struct SlowProcessor;

    #[async_trait]
    impl ProviderProcessingProcessor for SlowProcessor {
        async fn process(
            &self,
            _delivery: &ClaimedProviderProcessing,
        ) -> ProviderProcessingOutcome {
            sleep(Duration::from_millis(25)).await;
            ProviderProcessingOutcome::Complete
        }
    }

    #[derive(Debug)]
    struct ResolvingProcessor {
        source_delivery_id: ProviderDeliveryId,
        calls: AtomicUsize,
    }

    #[async_trait]
    impl ProviderProcessingProcessor for ResolvingProcessor {
        async fn process(&self, delivery: &ClaimedProviderProcessing) -> ProviderProcessingOutcome {
            match (self.calls.fetch_add(1, Ordering::SeqCst), delivery.input()) {
                (0, ProviderProcessingInput::Control(_)) => {
                    ProviderProcessingOutcome::ResolveControl(self.source_delivery_id)
                }
                (1, ProviderProcessingInput::Trigger(source)) => {
                    assert_eq!(source.evidence().delivery_id(), self.source_delivery_id);
                    ProviderProcessingOutcome::Complete
                }
                _ => panic!("rerun processing escaped the control-to-trigger sequence"),
            }
        }
    }

    #[derive(Debug)]
    struct RecordingRepository {
        claim: Mutex<Option<ClaimedProviderProcessing>>,
        renewals: AtomicUsize,
        completed: Mutex<Option<ProviderProcessingClaimFence>>,
    }

    impl ProviderProcessingRepository for RecordingRepository {
        fn claim_processing(
            &self,
            _request: ClaimProviderProcessing,
        ) -> ProviderProcessingFuture<'_, Option<ClaimedProviderProcessing>> {
            Box::pin(async move { Ok(self.claim.lock().expect("claim lock").take()) })
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
                ProviderProcessingReceipt::new(
                    request.fence().invocation_id(),
                    ProviderDeliveryId::new(),
                    Some(ProviderDeliveryId::new()),
                    ProviderProcessingState::Completed,
                    1,
                    UnixMillis::new(1_000),
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
        let repository = Arc::new(RecordingRepository {
            claim: Mutex::new(Some(claimed(worker_id))),
            renewals: AtomicUsize::new(0),
            completed: Mutex::new(None),
        });
        let worker = ProviderProcessingWorker::new(
            worker_id,
            Arc::clone(&repository) as Arc<dyn ProviderProcessingRepository>,
            Arc::new(SlowProcessor),
            Arc::new(StepClock(AtomicI64::new(1_000))),
            ProviderProcessingWorkerConfig::new(30, 30).expect("config"),
        );

        assert_eq!(
            worker.run_once().await.expect("worker pass"),
            ProviderProcessingWorkerOutcome::Completed
        );
        assert!(repository.renewals.load(Ordering::SeqCst) >= 1);
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
    async fn rerun_control_resolves_and_processes_a_fresh_trigger_invocation() {
        let worker_id = ProviderProcessingWorkerId::new();
        let (control, bound, source_delivery_id) = rerun_claims(worker_id);
        let repository = Arc::new(ResolvingRepository {
            claim: Mutex::new(Some(control)),
            bound,
            bindings: AtomicUsize::new(0),
            completed: Mutex::new(None),
        });
        let processor = Arc::new(ResolvingProcessor {
            source_delivery_id,
            calls: AtomicUsize::new(0),
        });
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
        assert_eq!(processor.calls.load(Ordering::SeqCst), 2);
        assert_eq!(
            repository
                .completed
                .lock()
                .expect("completion lock")
                .expect("completion fence"),
            repository.bound.fence()
        );
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

    fn claimed(worker_id: ProviderProcessingWorkerId) -> ClaimedProviderProcessing {
        let instance_id = ProviderInstanceId::new();
        let delivery_id = ProviderDeliveryId::new();
        let repository = ProviderRepository::new(
            ExternalRepositoryIdentity::new(
                instance_id,
                ExternalRepositoryId::new("42").expect("repository"),
            ),
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
