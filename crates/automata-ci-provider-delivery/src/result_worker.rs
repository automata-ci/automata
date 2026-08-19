//! Provider-neutral desired-result publication worker.

use std::{collections::BTreeMap, fmt, sync::Arc};

use async_trait::async_trait;
use automata_ci_core::{Sha256Digest, UnixMillis};
use automata_ci_provider::{
    ClaimProviderResult, ClaimedProviderResult, CompleteProviderResult, ExternalResultId,
    FailProviderResult, ProviderCapabilities, ProviderConnectionId, ProviderResultFailureKind,
    ProviderResultPublicationEvidence, ProviderResultPublicationModel, ProviderResultRepository,
    ProviderResultRepositoryError, ProviderResultWorkerId, ProviderTypeId, RenewProviderResult,
    ResultPublisherError, RetryProviderResult, provider_capability_digest,
};
use thiserror::Error;
use tokio::{
    sync::watch,
    time::{Duration, sleep},
};
use tokio_util::sync::CancellationToken;

use crate::{
    ProviderDeliveryClock, ProviderRuntimeContext, ProviderRuntimeContextError,
    ProviderRuntimeContextResolver,
};

const MAX_PROVIDER_RESULT_ADAPTERS: usize = 32;

/// Provider-specific result publication behind the common durable outbox.
#[async_trait]
pub trait ProviderResultAdapter: fmt::Debug + Send + Sync {
    /// Returns the exact provider type handled by this adapter.
    fn provider_type(&self) -> &ProviderTypeId;

    /// Returns the complete statically validated provider capability set.
    fn capabilities(&self) -> &ProviderCapabilities;

    /// Returns the publication model implemented by this adapter.
    fn publication_model(&self) -> ProviderResultPublicationModel;

    /// Reconciles one claim-frozen generation using its deterministic marker.
    async fn publish_result(
        &self,
        context: &ProviderRuntimeContext,
        claimed: &ClaimedProviderResult,
        lease: &ProviderResultLease,
    ) -> Result<ProviderResultObservation, ResultPublisherError>;
}

/// Read-only live view of the exact publication fence held by a worker.
///
/// The worker updates this handle after every durable renewal. Adapters must
/// take a fresh snapshot immediately before each provider mutation so a slow
/// publication cannot continue under an obsolete lease horizon.
#[derive(Clone)]
pub struct ProviderResultLease {
    fence: watch::Receiver<automata_ci_provider::ProviderResultClaimFence>,
}

impl ProviderResultLease {
    fn new(fence: watch::Receiver<automata_ci_provider::ProviderResultClaimFence>) -> Self {
        Self { fence }
    }

    /// Returns the most recently committed publication fence.
    #[must_use]
    pub fn current(&self) -> automata_ci_provider::ProviderResultClaimFence {
        *self.fence.borrow()
    }
}

impl fmt::Debug for ProviderResultLease {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProviderResultLease")
            .field("fence", &self.current())
            .finish()
    }
}

/// Sanitized provider-native observation returned to the common worker.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProviderResultObservation {
    external_id: Option<ExternalResultId>,
    provider_state_digest: Sha256Digest,
}

impl ProviderResultObservation {
    /// Captures the reconciled native identity and exact observed-state digest.
    #[must_use]
    pub const fn new(
        external_id: Option<ExternalResultId>,
        provider_state_digest: Sha256Digest,
    ) -> Self {
        Self {
            external_id,
            provider_state_digest,
        }
    }

    /// Returns the provider-native result identity, when the provider exposes one.
    #[must_use]
    pub const fn external_id(&self) -> Option<&ExternalResultId> {
        self.external_id.as_ref()
    }

    /// Returns the adapter-calculated digest of the reconciled native state.
    #[must_use]
    pub const fn provider_state_digest(&self) -> Sha256Digest {
        self.provider_state_digest
    }
}

#[derive(Clone)]
struct RegisteredResultAdapter {
    adapter: Arc<dyn ProviderResultAdapter>,
    publication_model: ProviderResultPublicationModel,
    capability_digest: Sha256Digest,
}

/// Exact duplicate-free registry of provider result adapters.
#[derive(Clone)]
pub struct ProviderResultAdapterRegistry {
    adapters: BTreeMap<ProviderTypeId, RegisteredResultAdapter>,
}

impl ProviderResultAdapterRegistry {
    /// Builds a bounded nonempty result adapter registry.
    ///
    /// # Errors
    ///
    /// Rejects an empty, excessive, duplicate, or self-inconsistent adapter set.
    pub fn new(
        adapters: impl IntoIterator<Item = Arc<dyn ProviderResultAdapter>>,
    ) -> Result<Self, ProviderResultAdapterRegistryError> {
        let mut values = BTreeMap::new();
        for adapter in adapters {
            let key = adapter.provider_type().clone();
            let publication_model = adapter.publication_model();
            if !publication_model.is_declared_by(adapter.capabilities()) {
                return Err(ProviderResultAdapterRegistryError::InvalidCapabilities);
            }
            let capability_digest = provider_capability_digest(adapter.capabilities())
                .map_err(|_| ProviderResultAdapterRegistryError::InvalidCapabilities)?;
            let registered = RegisteredResultAdapter {
                adapter,
                publication_model,
                capability_digest,
            };
            if values.insert(key, registered).is_some() {
                return Err(ProviderResultAdapterRegistryError::Duplicate);
            }
        }
        if values.is_empty() || values.len() > MAX_PROVIDER_RESULT_ADAPTERS {
            return Err(ProviderResultAdapterRegistryError::InvalidSize);
        }
        if values
            .iter()
            .any(|(key, registered)| registered.adapter.provider_type() != key)
        {
            return Err(ProviderResultAdapterRegistryError::Inconsistent);
        }
        Ok(Self { adapters: values })
    }

    fn adapter(&self, provider_type: &ProviderTypeId) -> Option<&RegisteredResultAdapter> {
        self.adapters.get(provider_type)
    }
}

impl fmt::Debug for ProviderResultAdapterRegistry {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProviderResultAdapterRegistry")
            .field("provider_types", &self.adapters.keys().collect::<Vec<_>>())
            .finish()
    }
}

/// Bounded result-publication lease and retry policy.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProviderResultWorkerConfig {
    lease_millis: u64,
    retry_millis: u64,
}

impl ProviderResultWorkerConfig {
    /// Constructs timing policy accepted by the common result model.
    ///
    /// # Errors
    ///
    /// Rejects zero values or values beyond common lease/retry ceilings.
    pub const fn new(
        lease_millis: u64,
        retry_millis: u64,
    ) -> Result<Self, ProviderResultWorkerError> {
        if lease_millis == 0
            || lease_millis > automata_ci_provider::MAX_PROVIDER_RESULT_LEASE_MILLIS
            || retry_millis == 0
            || retry_millis > automata_ci_provider::MAX_PROVIDER_RESULT_RETRY_MILLIS
        {
            return Err(ProviderResultWorkerError::InvalidConfiguration);
        }
        Ok(Self {
            lease_millis,
            retry_millis,
        })
    }

    /// Returns the exclusive publication lease duration.
    #[must_use]
    pub const fn lease_millis(self) -> u64 {
        self.lease_millis
    }

    /// Returns the default transient retry delay.
    #[must_use]
    pub const fn retry_millis(self) -> u64 {
        self.retry_millis
    }
}

/// One connection-scoped provider result publication worker.
pub struct ProviderResultWorker {
    connection_id: ProviderConnectionId,
    worker_id: ProviderResultWorkerId,
    repository: Arc<dyn ProviderResultRepository>,
    contexts: ProviderRuntimeContextResolver,
    adapters: ProviderResultAdapterRegistry,
    clock: Arc<dyn ProviderDeliveryClock>,
    config: ProviderResultWorkerConfig,
}

impl ProviderResultWorker {
    /// Composes one exact connection queue with common context and adapter registries.
    #[must_use]
    pub fn new(
        connection_id: ProviderConnectionId,
        worker_id: ProviderResultWorkerId,
        repository: Arc<dyn ProviderResultRepository>,
        contexts: ProviderRuntimeContextResolver,
        adapters: ProviderResultAdapterRegistry,
        clock: Arc<dyn ProviderDeliveryClock>,
        config: ProviderResultWorkerConfig,
    ) -> Self {
        Self {
            connection_id,
            worker_id,
            repository,
            contexts,
            adapters,
            clock,
            config,
        }
    }

    /// Claims and publishes at most one desired result generation.
    ///
    /// # Errors
    ///
    /// Returns sanitized clock, configuration, claim, or repository failures.
    pub async fn run_once(&self) -> Result<ProviderResultWorkerOutcome, ProviderResultWorkerError> {
        let claimed_at = self.now()?;
        let request = ClaimProviderResult::new(
            self.connection_id,
            self.worker_id,
            claimed_at,
            self.config.lease_millis,
        )
        .map_err(|_| ProviderResultWorkerError::InvalidConfiguration)?;
        let Some(mut claimed) = self
            .repository
            .claim_result(request)
            .await
            .map_err(repository_error)?
        else {
            return Ok(ProviderResultWorkerOutcome::Idle);
        };
        if claimed.subject().connection_id() != self.connection_id
            || claimed.claim().worker_id() != self.worker_id
            || claimed.claim().subject_id() != claimed.subject().subject_id()
            || claimed.claim().generation() != claimed.desired().generation()
        {
            return Err(ProviderResultWorkerError::Repository);
        }
        let disposition = match self.contexts.resolve_result(claimed.subject()).await {
            Ok(context) => {
                let (disposition, renewed) = self.publish(&context, &claimed).await?;
                if renewed != claimed.claim() {
                    claimed
                        .renew_claim(renewed)
                        .map_err(|_| ProviderResultWorkerError::Repository)?;
                }
                match disposition {
                    ResultDisposition::Observed { observation, model } => {
                        let evidence = ProviderResultPublicationEvidence::new(
                            &claimed,
                            model,
                            observation.external_id().cloned(),
                            observation.provider_state_digest(),
                            self.now()?,
                        )
                        .map_err(|_| ProviderResultWorkerError::ClaimExpired)?;
                        ResultDisposition::Complete(evidence)
                    }
                    disposition => disposition,
                }
            }
            Err(ProviderRuntimeContextError::Unavailable) => ResultDisposition::Retry(None),
            Err(ProviderRuntimeContextError::InvalidEvidence) => {
                ResultDisposition::Fail(ProviderResultFailureKind::Conflict)
            }
        };
        self.apply_disposition(&claimed, disposition).await
    }

    /// Polls this connection's outbox until shutdown.
    ///
    /// The in-flight provider operation reaches its bounded result after
    /// shutdown; no new claim begins once cancellation is observed.
    ///
    /// # Errors
    ///
    /// Returns the first non-retryable worker failure.
    pub async fn run(&self, shutdown: CancellationToken) -> Result<(), ProviderResultWorkerError> {
        loop {
            if shutdown.is_cancelled() {
                return Ok(());
            }
            match self.run_once().await {
                Ok(
                    ProviderResultWorkerOutcome::Published
                    | ProviderResultWorkerOutcome::Retried
                    | ProviderResultWorkerOutcome::Failed,
                )
                | Err(ProviderResultWorkerError::ClaimExpired) => {}
                Ok(ProviderResultWorkerOutcome::Idle)
                | Err(ProviderResultWorkerError::Clock | ProviderResultWorkerError::Unavailable) => {
                    if sleep_or_shutdown(self.retry_duration(), &shutdown).await {
                        return Ok(());
                    }
                }
                Err(error) => return Err(error),
            }
        }
    }

    async fn publish(
        &self,
        context: &ProviderRuntimeContext,
        claimed: &ClaimedProviderResult,
    ) -> Result<
        (
            ResultDisposition,
            automata_ci_provider::ProviderResultClaimFence,
        ),
        ProviderResultWorkerError,
    > {
        let provider_type = context.provider().manifest().provider_type();
        let Some(registered) = self.adapters.adapter(provider_type) else {
            return Ok((
                ResultDisposition::Fail(ProviderResultFailureKind::Unsupported),
                claimed.claim(),
            ));
        };
        if registered.capability_digest != context.provider().manifest().capability_digest() {
            return Ok((
                ResultDisposition::Fail(ProviderResultFailureKind::Conflict),
                claimed.claim(),
            ));
        }
        let mut fence = claimed.claim();
        let (lease_updates, lease_view) = watch::channel(fence);
        let lease = ProviderResultLease::new(lease_view);
        let publication = registered.adapter.publish_result(context, claimed, &lease);
        tokio::pin!(publication);
        let heartbeat = Duration::from_millis((self.config.lease_millis / 3).max(1));
        loop {
            tokio::select! {
                outcome = &mut publication => {
                    let disposition = match outcome {
                        Ok(observation) => ResultDisposition::Observed {
                            observation,
                            model: registered.publication_model,
                        },
                        Err(ResultPublisherError::Unavailable) => ResultDisposition::Retry(None),
                        Err(ResultPublisherError::RateLimited { retry_after }) => {
                            ResultDisposition::Retry(
                                retry_after.map(
                                    automata_ci_provider::ProviderResultRetryAfter::millis,
                                ),
                            )
                        }
                        Err(ResultPublisherError::Unauthorized) => {
                            ResultDisposition::Fail(ProviderResultFailureKind::Unauthorized)
                        }
                        Err(ResultPublisherError::Forbidden) => {
                            ResultDisposition::Fail(ProviderResultFailureKind::Forbidden)
                        }
                        Err(ResultPublisherError::InvalidResponse) => {
                            ResultDisposition::Fail(ProviderResultFailureKind::InvalidResponse)
                        }
                        Err(ResultPublisherError::Unsupported) => {
                            ResultDisposition::Fail(ProviderResultFailureKind::Unsupported)
                        }
                        Err(ResultPublisherError::Conflict) => {
                            ResultDisposition::Fail(ProviderResultFailureKind::Conflict)
                        }
                    };
                    return Ok((disposition, fence));
                }
                () = sleep(heartbeat) => {
                    let renewal = RenewProviderResult::new(
                        fence,
                        self.now()?,
                        self.config.lease_millis,
                    )
                    .map_err(|_| ProviderResultWorkerError::ClaimExpired)?;
                    let renewed = self.repository
                        .renew_result(renewal)
                        .await
                        .map_err(repository_error)?;
                    if !valid_result_renewal(fence, renewed) {
                        return Err(ProviderResultWorkerError::Repository);
                    }
                    fence = renewed;
                    lease_updates.send_replace(fence);
                }
            }
        }
    }

    async fn apply_disposition(
        &self,
        claimed: &ClaimedProviderResult,
        disposition: ResultDisposition,
    ) -> Result<ProviderResultWorkerOutcome, ProviderResultWorkerError> {
        let finished_at = self.now()?;
        match disposition {
            ResultDisposition::Observed { .. } => Err(ProviderResultWorkerError::Repository),
            ResultDisposition::Complete(evidence) => {
                let request = CompleteProviderResult::new(claimed.claim(), evidence)
                    .map_err(|_| ProviderResultWorkerError::Repository)?;
                self.repository
                    .complete_result(request)
                    .await
                    .map_err(repository_error)?;
                Ok(ProviderResultWorkerOutcome::Published)
            }
            ResultDisposition::Retry(retry_millis)
                if claimed.attempts()
                    < automata_ci_provider::MAX_PROVIDER_RESULT_PUBLICATION_ATTEMPTS =>
            {
                let delay = retry_millis.unwrap_or(self.config.retry_millis);
                let retry_at = finished_at
                    .get()
                    .checked_add(
                        i64::try_from(delay).map_err(|_| ProviderResultWorkerError::Clock)?,
                    )
                    .map(UnixMillis::new)
                    .ok_or(ProviderResultWorkerError::Clock)?;
                let request = RetryProviderResult::new(claimed.claim(), finished_at, retry_at)
                    .map_err(|_| ProviderResultWorkerError::ClaimExpired)?;
                self.repository
                    .retry_result(request)
                    .await
                    .map_err(repository_error)?;
                Ok(ProviderResultWorkerOutcome::Retried)
            }
            ResultDisposition::Retry(_) => {
                self.fail(
                    claimed,
                    finished_at,
                    ProviderResultFailureKind::AttemptLimit,
                )
                .await
            }
            ResultDisposition::Fail(kind) => self.fail(claimed, finished_at, kind).await,
        }
    }

    async fn fail(
        &self,
        claimed: &ClaimedProviderResult,
        failed_at: UnixMillis,
        kind: ProviderResultFailureKind,
    ) -> Result<ProviderResultWorkerOutcome, ProviderResultWorkerError> {
        let request = FailProviderResult::new(claimed.claim(), failed_at, kind)
            .map_err(|_| ProviderResultWorkerError::ClaimExpired)?;
        self.repository
            .fail_result(request)
            .await
            .map_err(repository_error)?;
        Ok(ProviderResultWorkerOutcome::Failed)
    }

    fn now(&self) -> Result<UnixMillis, ProviderResultWorkerError> {
        self.clock
            .now()
            .map_err(|_| ProviderResultWorkerError::Clock)
    }

    fn retry_duration(&self) -> Duration {
        Duration::from_millis(self.config.retry_millis)
    }
}

impl fmt::Debug for ProviderResultWorker {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProviderResultWorker")
            .field("connection_id", &self.connection_id)
            .field("worker_id", &self.worker_id)
            .field("repository", &self.repository)
            .field("contexts", &self.contexts)
            .field("adapters", &self.adapters)
            .field("clock", &self.clock)
            .field("config", &self.config)
            .finish()
    }
}

enum ResultDisposition {
    Observed {
        observation: ProviderResultObservation,
        model: ProviderResultPublicationModel,
    },
    Complete(ProviderResultPublicationEvidence),
    Retry(Option<u64>),
    Fail(ProviderResultFailureKind),
}

fn valid_result_renewal(
    prior: automata_ci_provider::ProviderResultClaimFence,
    renewed: automata_ci_provider::ProviderResultClaimFence,
) -> bool {
    renewed.subject_id() == prior.subject_id()
        && renewed.generation() == prior.generation()
        && renewed.worker_id() == prior.worker_id()
        && renewed.fence() == prior.fence()
        && renewed.claimed_at() == prior.claimed_at()
        && renewed.expires_at() > prior.expires_at()
}

async fn sleep_or_shutdown(duration: Duration, shutdown: &CancellationToken) -> bool {
    tokio::select! {
        () = shutdown.cancelled() => true,
        () = sleep(duration) => false,
    }
}

const fn repository_error(error: ProviderResultRepositoryError) -> ProviderResultWorkerError {
    match error {
        ProviderResultRepositoryError::Unavailable => ProviderResultWorkerError::Unavailable,
        ProviderResultRepositoryError::StaleClaim => ProviderResultWorkerError::ClaimExpired,
        ProviderResultRepositoryError::Conflict
        | ProviderResultRepositoryError::NotFound
        | ProviderResultRepositoryError::Corrupt => ProviderResultWorkerError::Repository,
    }
}

/// Result of one bounded result-worker pass.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProviderResultWorkerOutcome {
    /// No eligible desired generation existed for the connection.
    Idle,
    /// One generation was reconciled and durably completed.
    Published,
    /// One transient failure was scheduled for retry.
    Retried,
    /// One generation failed terminally.
    Failed,
}

/// Sanitized result-worker failure.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum ProviderResultWorkerError {
    /// Timing policy violates common result bounds.
    #[error("provider result worker configuration is invalid")]
    InvalidConfiguration,
    /// Trusted time could not be obtained or represented.
    #[error("provider result worker clock is unavailable")]
    Clock,
    /// Publication outlived, lost, or was superseded beyond its claim fence.
    #[error("provider result worker claim expired")]
    ClaimExpired,
    /// Durable result storage is temporarily unavailable.
    #[error("provider result repository is unavailable")]
    Unavailable,
    /// Durable result state violated queue invariants.
    #[error("provider result repository rejected the operation")]
    Repository,
}

/// Invalid result-adapter registry construction.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum ProviderResultAdapterRegistryError {
    /// Registry was empty or exceeded its hard bound.
    #[error("provider result adapter registry size is invalid")]
    InvalidSize,
    /// Two adapters registered the same provider type.
    #[error("provider result adapter type is duplicated")]
    Duplicate,
    /// An adapter declared a different identity during construction.
    #[error("provider result adapter identity is inconsistent")]
    Inconsistent,
    /// The selected publication model is absent from the adapter capability set.
    #[error("provider result adapter capabilities are inconsistent")]
    InvalidCapabilities,
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use automata_ci_provider::{ProviderCapability, RichCheckCapability};

    use super::*;

    #[derive(Debug)]
    struct Adapter {
        first: ProviderTypeId,
        subsequent: ProviderTypeId,
        capabilities: ProviderCapabilities,
        calls: AtomicUsize,
    }

    #[async_trait]
    impl ProviderResultAdapter for Adapter {
        fn provider_type(&self) -> &ProviderTypeId {
            if self.calls.fetch_add(1, Ordering::SeqCst) == 0 {
                &self.first
            } else {
                &self.subsequent
            }
        }

        fn publication_model(&self) -> ProviderResultPublicationModel {
            ProviderResultPublicationModel::MutableRichCheck
        }

        fn capabilities(&self) -> &ProviderCapabilities {
            &self.capabilities
        }

        async fn publish_result(
            &self,
            _context: &ProviderRuntimeContext,
            _claimed: &ClaimedProviderResult,
            _lease: &ProviderResultLease,
        ) -> Result<ProviderResultObservation, ResultPublisherError> {
            unreachable!("registry construction never publishes results")
        }
    }

    fn adapter(first: &str, subsequent: &str) -> Arc<dyn ProviderResultAdapter> {
        Arc::new(Adapter {
            first: ProviderTypeId::new(first).expect("provider type"),
            subsequent: ProviderTypeId::new(subsequent).expect("provider type"),
            capabilities: ProviderCapabilities::new([ProviderCapability::RichChecks(
                RichCheckCapability::new(true, false, false).expect("rich checks"),
            )])
            .expect("capabilities"),
            calls: AtomicUsize::new(0),
        })
    }

    fn adapter_without_rich_checks(provider_type: &str) -> Arc<dyn ProviderResultAdapter> {
        Arc::new(Adapter {
            first: ProviderTypeId::new(provider_type).expect("provider type"),
            subsequent: ProviderTypeId::new(provider_type).expect("provider type"),
            capabilities: ProviderCapabilities::new([ProviderCapability::DeviceAuthorizationLogin])
                .expect("capabilities"),
            calls: AtomicUsize::new(0),
        })
    }

    #[test]
    fn registry_rejects_empty_duplicate_excessive_and_inconsistent_adapters() {
        assert!(matches!(
            ProviderResultAdapterRegistry::new([]),
            Err(ProviderResultAdapterRegistryError::InvalidSize)
        ));
        assert!(matches!(
            ProviderResultAdapterRegistry::new([
                adapter("github", "github"),
                adapter("github", "github")
            ]),
            Err(ProviderResultAdapterRegistryError::Duplicate)
        ));
        let excessive = (0..=MAX_PROVIDER_RESULT_ADAPTERS)
            .map(|index| adapter(&format!("provider-{index}"), &format!("provider-{index}")))
            .collect::<Vec<_>>();
        assert!(matches!(
            ProviderResultAdapterRegistry::new(excessive),
            Err(ProviderResultAdapterRegistryError::InvalidSize)
        ));
        assert!(matches!(
            ProviderResultAdapterRegistry::new([adapter("github", "forgejo")]),
            Err(ProviderResultAdapterRegistryError::Inconsistent)
        ));
        assert!(matches!(
            ProviderResultAdapterRegistry::new([adapter_without_rich_checks("github")]),
            Err(ProviderResultAdapterRegistryError::InvalidCapabilities)
        ));
    }

    #[test]
    fn timing_policy_is_bounded() {
        assert!(ProviderResultWorkerConfig::new(1, 1).is_ok());
        assert!(ProviderResultWorkerConfig::new(0, 1).is_err());
        assert!(ProviderResultWorkerConfig::new(1, 0).is_err());
        assert!(
            ProviderResultWorkerConfig::new(
                automata_ci_provider::MAX_PROVIDER_RESULT_LEASE_MILLIS + 1,
                1,
            )
            .is_err()
        );
    }
}
