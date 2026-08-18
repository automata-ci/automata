use std::{fmt, sync::Arc};

use async_trait::async_trait;
use automata_ci_core::UnixMillis;
use automata_ci_provider::{
    ClaimProviderDelivery, ClaimedProviderDelivery, CompleteProviderDelivery, FailProviderDelivery,
    ProviderDeliveryFailure, ProviderDeliveryRepository, ProviderDeliveryRepositoryError,
    ProviderDeliveryWorkerId, RenewProviderDelivery, RetryProviderDelivery,
};
use thiserror::Error;
use tokio::time::{Duration, sleep};

use crate::ProviderDeliveryClock;

/// Final disposition returned by provider-neutral workflow admission.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProviderDeliveryProcessOutcome {
    /// All idempotent workflow-admission work completed.
    Complete,
    /// A transient dependency failure should use the worker retry policy.
    Retry(ProviderDeliveryFailure),
    /// Policy or evidence terminally rejects this delivery.
    Fail(ProviderDeliveryFailure),
}

/// Provider-independent workflow admission port invoked under a live claim fence.
#[async_trait]
pub trait ProviderDeliveryProcessor: fmt::Debug + Send + Sync {
    /// Performs idempotent admission for one normalized provider trigger.
    async fn process(&self, delivery: &ClaimedProviderDelivery) -> ProviderDeliveryProcessOutcome;
}

/// Bounded generic delivery-worker lease and retry policy.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProviderDeliveryWorkerConfig {
    lease_millis: u64,
    retry_millis: i64,
}

impl ProviderDeliveryWorkerConfig {
    /// Constructs worker timing policy accepted by the common delivery model.
    ///
    /// # Errors
    ///
    /// Rejects zero values or values beyond common lease/retry ceilings.
    pub const fn new(
        lease_millis: u64,
        retry_millis: i64,
    ) -> Result<Self, ProviderDeliveryWorkerError> {
        if lease_millis == 0
            || lease_millis > automata_ci_provider::MAX_PROVIDER_DELIVERY_LEASE_MILLIS as u64
            || retry_millis <= 0
            || retry_millis > automata_ci_provider::MAX_PROVIDER_DELIVERY_RETRY_MILLIS
        {
            return Err(ProviderDeliveryWorkerError::InvalidConfiguration);
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

/// One provider-neutral fenced delivery worker.
pub struct ProviderDeliveryWorker {
    worker_id: ProviderDeliveryWorkerId,
    repository: Arc<dyn ProviderDeliveryRepository>,
    processor: Arc<dyn ProviderDeliveryProcessor>,
    clock: Arc<dyn ProviderDeliveryClock>,
    config: ProviderDeliveryWorkerConfig,
}

impl ProviderDeliveryWorker {
    /// Composes a stable worker identity, durable queue, processor, and clock.
    #[must_use]
    pub fn new(
        worker_id: ProviderDeliveryWorkerId,
        repository: Arc<dyn ProviderDeliveryRepository>,
        processor: Arc<dyn ProviderDeliveryProcessor>,
        clock: Arc<dyn ProviderDeliveryClock>,
        config: ProviderDeliveryWorkerConfig,
    ) -> Self {
        Self {
            worker_id,
            repository,
            processor,
            clock,
            config,
        }
    }

    /// Claims and processes at most one provider delivery.
    ///
    /// # Errors
    ///
    /// Returns sanitized clock, model, repository, or stale-claim failures.
    pub async fn run_once(
        &self,
    ) -> Result<ProviderDeliveryWorkerOutcome, ProviderDeliveryWorkerError> {
        let claimed_at = self.now()?;
        let claim =
            ClaimProviderDelivery::new(self.worker_id, claimed_at, self.config.lease_millis)
                .map_err(|_| ProviderDeliveryWorkerError::InvalidConfiguration)?;
        let Some(delivery) = self
            .repository
            .claim_delivery(claim)
            .await
            .map_err(repository_error)?
        else {
            return Ok(ProviderDeliveryWorkerOutcome::Idle);
        };
        let disposition = self.process_with_renewal(&delivery).await?;
        let finished_at = self.now()?;
        match disposition.outcome {
            ProviderDeliveryProcessOutcome::Complete => {
                let command = CompleteProviderDelivery::new(disposition.fence, finished_at)
                    .map_err(|_| ProviderDeliveryWorkerError::ClaimExpired)?;
                self.repository
                    .complete_delivery(command)
                    .await
                    .map_err(repository_error)?;
                Ok(ProviderDeliveryWorkerOutcome::Completed)
            }
            ProviderDeliveryProcessOutcome::Retry(failure) => {
                let retry_at = finished_at
                    .get()
                    .checked_add(self.config.retry_millis)
                    .map(UnixMillis::new)
                    .ok_or(ProviderDeliveryWorkerError::Clock)?;
                let command =
                    RetryProviderDelivery::new(disposition.fence, finished_at, retry_at, failure)
                        .map_err(|_| ProviderDeliveryWorkerError::ClaimExpired)?;
                self.repository
                    .retry_delivery(command)
                    .await
                    .map_err(repository_error)?;
                Ok(ProviderDeliveryWorkerOutcome::Retried)
            }
            ProviderDeliveryProcessOutcome::Fail(failure) => {
                let command = FailProviderDelivery::new(disposition.fence, finished_at, failure)
                    .map_err(|_| ProviderDeliveryWorkerError::ClaimExpired)?;
                self.repository
                    .fail_delivery(command)
                    .await
                    .map_err(repository_error)?;
                Ok(ProviderDeliveryWorkerOutcome::Failed)
            }
        }
    }

    fn now(&self) -> Result<UnixMillis, ProviderDeliveryWorkerError> {
        self.clock
            .now()
            .map_err(|_| ProviderDeliveryWorkerError::Clock)
    }

    async fn process_with_renewal(
        &self,
        delivery: &ClaimedProviderDelivery,
    ) -> Result<ProcessedDelivery, ProviderDeliveryWorkerError> {
        let mut fence = delivery.fence();
        let process = self.processor.process(delivery);
        tokio::pin!(process);
        let heartbeat = Duration::from_millis((self.config.lease_millis / 3).max(1));
        loop {
            tokio::select! {
                outcome = &mut process => return Ok(ProcessedDelivery { outcome, fence }),
                () = sleep(heartbeat) => {
                    let renewed_at = self.now()?;
                    let renewal = RenewProviderDelivery::new(
                        fence,
                        renewed_at,
                        self.config.lease_millis,
                    )
                    .map_err(|_| ProviderDeliveryWorkerError::ClaimExpired)?;
                    fence = self.repository
                        .renew_delivery(renewal)
                        .await
                        .map_err(repository_error)?;
                }
            }
        }
    }
}

struct ProcessedDelivery {
    outcome: ProviderDeliveryProcessOutcome,
    fence: automata_ci_provider::ProviderDeliveryClaimFence,
}

impl fmt::Debug for ProviderDeliveryWorker {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProviderDeliveryWorker")
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
pub enum ProviderDeliveryWorkerOutcome {
    /// No eligible delivery existed.
    Idle,
    /// One delivery completed.
    Completed,
    /// One transient failure was scheduled for retry.
    Retried,
    /// One delivery failed terminally.
    Failed,
}

/// Sanitized generic delivery-worker failure.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum ProviderDeliveryWorkerError {
    /// Timing policy violates common delivery bounds.
    #[error("provider delivery worker configuration is invalid")]
    InvalidConfiguration,
    /// Trusted time could not be obtained or represented.
    #[error("provider delivery worker clock is unavailable")]
    Clock,
    /// Processing outlived or lost its exact claim fence.
    #[error("provider delivery worker claim expired")]
    ClaimExpired,
    /// Durable delivery storage is unavailable.
    #[error("provider delivery repository is unavailable")]
    Unavailable,
    /// Durable delivery state violated queue invariants.
    #[error("provider delivery repository rejected the operation")]
    Repository,
}

const fn repository_error(error: ProviderDeliveryRepositoryError) -> ProviderDeliveryWorkerError {
    match error {
        ProviderDeliveryRepositoryError::Unavailable => ProviderDeliveryWorkerError::Unavailable,
        ProviderDeliveryRepositoryError::ClaimRejected => ProviderDeliveryWorkerError::ClaimExpired,
        ProviderDeliveryRepositoryError::EndpointConflict
        | ProviderDeliveryRepositoryError::NotFound
        | ProviderDeliveryRepositoryError::ReplayConflict
        | ProviderDeliveryRepositoryError::AttemptLimitReached
        | ProviderDeliveryRepositoryError::Corrupt => ProviderDeliveryWorkerError::Repository,
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
        AcceptProviderDelivery, ExternalDeliveryId, ExternalDeliveryIdentity, ExternalRepositoryId,
        ExternalRepositoryIdentity, NormalizedTrigger, ProviderConfigurationRevision,
        ProviderConnectionId, ProviderConnectionRevision, ProviderDelivery,
        ProviderDeliveryAcceptOutcome, ProviderDeliveryClaimFence, ProviderDeliveryFuture,
        ProviderDeliveryId, ProviderDeliveryObservations, ProviderDeliveryReceipt,
        ProviderDeliveryState, ProviderEventName, ProviderGitRef, ProviderGitRefKind,
        ProviderInstanceId, ProviderRepository, ProviderRepositoryPath, ProviderSecretGeneration,
        ProviderSecretName, ProviderTypeId, ProviderWebhookEndpointId,
        ProviderWebhookEndpointRevision, ProviderWebhookSecretReference,
        ProviderWebhookSignatureEvidence, PushCommitEvidence, PushTrigger, RepositoryVisibility,
        RetryProviderDelivery, VerifiedProviderDelivery, provider_raw_webhook_descriptor,
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
    impl ProviderDeliveryProcessor for SlowProcessor {
        async fn process(
            &self,
            _delivery: &ClaimedProviderDelivery,
        ) -> ProviderDeliveryProcessOutcome {
            sleep(Duration::from_millis(25)).await;
            ProviderDeliveryProcessOutcome::Complete
        }
    }

    #[derive(Debug)]
    struct RecordingRepository {
        claim: Mutex<Option<ClaimedProviderDelivery>>,
        renewals: AtomicUsize,
        completed: Mutex<Option<ProviderDeliveryClaimFence>>,
    }

    impl ProviderDeliveryRepository for RecordingRepository {
        fn accept_delivery(
            &self,
            _request: AcceptProviderDelivery,
        ) -> ProviderDeliveryFuture<'_, ProviderDeliveryAcceptOutcome> {
            Box::pin(async { Err(ProviderDeliveryRepositoryError::Corrupt) })
        }

        fn load_delivery(
            &self,
            _delivery_id: ProviderDeliveryId,
        ) -> ProviderDeliveryFuture<'_, Option<ProviderDelivery>> {
            Box::pin(async { Err(ProviderDeliveryRepositoryError::Corrupt) })
        }

        fn claim_delivery(
            &self,
            _request: ClaimProviderDelivery,
        ) -> ProviderDeliveryFuture<'_, Option<ClaimedProviderDelivery>> {
            Box::pin(async move { Ok(self.claim.lock().expect("claim lock").take()) })
        }

        fn renew_delivery(
            &self,
            request: RenewProviderDelivery,
        ) -> ProviderDeliveryFuture<'_, ProviderDeliveryClaimFence> {
            Box::pin(async move {
                self.renewals.fetch_add(1, Ordering::SeqCst);
                let fence = request.fence();
                ProviderDeliveryClaimFence::new(
                    fence.delivery_id(),
                    fence.worker_id(),
                    fence.token(),
                    fence.claimed_at(),
                    UnixMillis::new(
                        request.renewed_at().get()
                            + i64::try_from(request.lease_millis()).expect("lease"),
                    ),
                )
                .map_err(|_| ProviderDeliveryRepositoryError::Corrupt)
            })
        }

        fn complete_delivery(
            &self,
            request: CompleteProviderDelivery,
        ) -> ProviderDeliveryFuture<'_, ProviderDeliveryReceipt> {
            Box::pin(async move {
                *self.completed.lock().expect("completion lock") = Some(request.fence());
                ProviderDeliveryReceipt::new(
                    request.fence().delivery_id(),
                    ProviderDeliveryState::Completed,
                    1,
                    UnixMillis::new(1_000),
                )
                .map_err(|_| ProviderDeliveryRepositoryError::Corrupt)
            })
        }

        fn retry_delivery(
            &self,
            _request: RetryProviderDelivery,
        ) -> ProviderDeliveryFuture<'_, ProviderDeliveryReceipt> {
            Box::pin(async { Err(ProviderDeliveryRepositoryError::Corrupt) })
        }

        fn fail_delivery(
            &self,
            _request: FailProviderDelivery,
        ) -> ProviderDeliveryFuture<'_, ProviderDeliveryReceipt> {
            Box::pin(async { Err(ProviderDeliveryRepositoryError::Corrupt) })
        }
    }

    #[tokio::test]
    async fn long_processing_renews_and_completes_with_the_latest_fence() {
        let worker_id = ProviderDeliveryWorkerId::new();
        let repository = Arc::new(RecordingRepository {
            claim: Mutex::new(Some(claimed(worker_id))),
            renewals: AtomicUsize::new(0),
            completed: Mutex::new(None),
        });
        let worker = ProviderDeliveryWorker::new(
            worker_id,
            Arc::clone(&repository) as Arc<dyn ProviderDeliveryRepository>,
            Arc::new(SlowProcessor),
            Arc::new(StepClock(AtomicI64::new(1_000))),
            ProviderDeliveryWorkerConfig::new(30, 30).expect("config"),
        );

        assert_eq!(
            worker.run_once().await.expect("worker pass"),
            ProviderDeliveryWorkerOutcome::Completed
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

    fn claimed(worker_id: ProviderDeliveryWorkerId) -> ClaimedProviderDelivery {
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
        let delivery = VerifiedProviderDelivery::rehydrate(
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
            trigger,
            ProviderDeliveryObservations::new(Vec::new()).expect("observations"),
        )
        .expect("delivery");
        let receipt = ProviderDeliveryReceipt::new(
            delivery_id,
            ProviderDeliveryState::Claimed,
            1,
            UnixMillis::new(950),
        )
        .expect("receipt");
        let fence = ProviderDeliveryClaimFence::new(
            delivery_id,
            worker_id,
            1,
            UnixMillis::new(1_000),
            UnixMillis::new(1_030),
        )
        .expect("fence");
        ClaimedProviderDelivery::new(receipt, delivery, fence).expect("claim")
    }
}
