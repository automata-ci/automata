//! Provider-neutral dispatch into statically registered provider runtimes.

use std::{collections::BTreeMap, fmt, sync::Arc};

use async_trait::async_trait;
use automata_ci_provider::{
    ClaimedProviderProcessing, ExternalRepositoryIdentity, ProviderConnectionManifest,
    ProviderDeliveryEvidence, ProviderDeliveryId, ProviderInstanceRecord, ProviderLifecycleState,
    ProviderManifestRepository, ProviderProcessingFailure, ProviderProcessingInput,
    ProviderRepositoryError, ProviderResultSubject, ProviderTypeId,
    VerifiedProviderControlDelivery, VerifiedProviderTriggerDelivery,
};
use thiserror::Error;

use crate::{ProviderProcessingLease, ProviderProcessingOutcome, ProviderProcessingProcessor};

const MAX_PROVIDER_RUNTIME_ADAPTERS: usize = 32;

/// Terminal or retry disposition returned by one provider trigger runtime.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProviderTriggerOutcome {
    /// All idempotent workflow-admission work completed.
    Complete,
    /// A transient dependency failure should use the common retry policy.
    Retry(ProviderProcessingFailure),
    /// Policy or evidence terminally rejects this trigger.
    Fail(ProviderProcessingFailure),
}

/// Exact durable provider and repository configuration for one invocation.
pub struct ProviderRuntimeContext {
    provider: ProviderInstanceRecord,
    connection: ProviderConnectionManifest,
}

impl ProviderRuntimeContext {
    /// Returns the exact decrypted provider revision selected at ingress.
    #[must_use]
    pub const fn provider(&self) -> &ProviderInstanceRecord {
        &self.provider
    }

    /// Returns the exact repository connection revision selected at ingress.
    #[must_use]
    pub const fn connection(&self) -> &ProviderConnectionManifest {
        &self.connection
    }
}

impl fmt::Debug for ProviderRuntimeContext {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProviderRuntimeContext")
            .field("provider", &self.provider)
            .field("connection", &self.connection)
            .finish()
    }
}

/// Resolves exact immutable provider configuration for processing and publication.
#[derive(Clone)]
pub struct ProviderRuntimeContextResolver {
    manifests: Arc<dyn ProviderManifestRepository>,
}

impl ProviderRuntimeContextResolver {
    /// Binds the resolver to the canonical provider manifest repository.
    #[must_use]
    pub fn new(manifests: Arc<dyn ProviderManifestRepository>) -> Self {
        Self { manifests }
    }

    /// Resolves the exact provider and connection revisions authenticated at ingress.
    ///
    /// # Errors
    ///
    /// Returns unavailable for transient storage or secret-custody failure and
    /// invalid evidence for absent, inactive, or inconsistent configuration.
    pub async fn resolve_delivery(
        &self,
        evidence: &ProviderDeliveryEvidence,
        repository: &ExternalRepositoryIdentity,
    ) -> Result<ProviderRuntimeContext, ProviderRuntimeContextError> {
        let provider = self
            .manifests
            .load_instance(evidence.instance_id(), evidence.provider_revision())
            .await
            .map_err(context_repository_error)?
            .ok_or(ProviderRuntimeContextError::InvalidEvidence)?;
        let connection = self
            .manifests
            .load_connection(evidence.connection_id(), evidence.connection_revision())
            .await
            .map_err(context_repository_error)?
            .ok_or(ProviderRuntimeContextError::InvalidEvidence)?;
        if !valid_context(&provider, &connection, repository)
            || provider.manifest().instance_id() != evidence.instance_id()
            || provider.manifest().revision() != evidence.provider_revision()
            || provider.manifest().provider_type() != evidence.provider_type()
            || connection.connection_id() != evidence.connection_id()
            || connection.revision() != evidence.connection_revision()
        {
            return Err(ProviderRuntimeContextError::InvalidEvidence);
        }
        Ok(ProviderRuntimeContext {
            provider,
            connection,
        })
    }

    /// Resolves the exact provider configuration bound to one durable result subject.
    ///
    /// # Errors
    ///
    /// Returns unavailable for transient storage or secret-custody failure and
    /// invalid evidence for absent, inactive, or inconsistent configuration.
    pub async fn resolve_result(
        &self,
        subject: &ProviderResultSubject,
    ) -> Result<ProviderRuntimeContext, ProviderRuntimeContextError> {
        let connection = self
            .manifests
            .load_connection(subject.connection_id(), subject.connection_revision())
            .await
            .map_err(context_repository_error)?
            .ok_or(ProviderRuntimeContextError::InvalidEvidence)?;
        let configuration = connection.configuration();
        let provider = self
            .manifests
            .load_instance(
                configuration.repository().instance_id(),
                configuration.provider_revision(),
            )
            .await
            .map_err(context_repository_error)?
            .ok_or(ProviderRuntimeContextError::InvalidEvidence)?;
        if subject.connection_digest() != connection.digest()
            || subject.repository() != configuration.repository()
            || !valid_context(&provider, &connection, subject.repository())
        {
            return Err(ProviderRuntimeContextError::InvalidEvidence);
        }
        Ok(ProviderRuntimeContext {
            provider,
            connection,
        })
    }
}

impl fmt::Debug for ProviderRuntimeContextResolver {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProviderRuntimeContextResolver")
            .field("manifests", &self.manifests)
            .finish()
    }
}

fn valid_context(
    provider: &ProviderInstanceRecord,
    connection: &ProviderConnectionManifest,
    repository: &ExternalRepositoryIdentity,
) -> bool {
    let manifest = provider.manifest();
    let configuration = connection.configuration();
    manifest.state() == ProviderLifecycleState::Active
        && connection.state() == ProviderLifecycleState::Active
        && configuration.repository() == repository
        && configuration.provider_revision() == manifest.revision()
        && configuration.provider_configuration_digest() == manifest.configuration().digest()
        && configuration.capability_digest() == manifest.capability_digest()
}

/// Sanitized exact-context resolution failure.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum ProviderRuntimeContextError {
    /// Manifest persistence or secret custody is temporarily unavailable.
    #[error("provider runtime context is unavailable")]
    Unavailable,
    /// Durable configuration or evidence is missing, inactive, or inconsistent.
    #[error("provider runtime context evidence is invalid")]
    InvalidEvidence,
}

/// Provider-specific runtime operations behind the common processing worker.
///
/// Implementations own provider-native source access, workflow admission, and
/// control execution. Every operation must be idempotent under the immutable
/// delivery identity because a crash may replay it before the common invocation
/// is durably completed.
#[async_trait]
pub trait ProviderRuntimeAdapter: fmt::Debug + Send + Sync {
    /// Returns the exact provider type handled by this runtime adapter.
    fn provider_type(&self) -> &ProviderTypeId;

    /// Processes one authenticated normalized trigger under its live lease.
    async fn process_trigger(
        &self,
        context: &ProviderRuntimeContext,
        trigger: &VerifiedProviderTriggerDelivery,
        invocation: &ClaimedProviderProcessing,
        lease: &ProviderProcessingLease,
    ) -> ProviderTriggerOutcome;

    /// Reauthorizes and idempotently executes one authenticated control.
    ///
    /// Returns the originating trigger delivery when one exists. That identity
    /// is retained only as audit provenance; its admission is never replayed.
    async fn handle_control(
        &self,
        context: &ProviderRuntimeContext,
        control: &VerifiedProviderControlDelivery,
        invocation: &ClaimedProviderProcessing,
        lease: &ProviderProcessingLease,
    ) -> Result<Option<ProviderDeliveryId>, ProviderControlHandlingError>;
}

/// Exact duplicate-free registry of statically linked provider runtimes.
#[derive(Clone)]
pub struct ProviderRuntimeAdapterRegistry {
    adapters: BTreeMap<ProviderTypeId, Arc<dyn ProviderRuntimeAdapter>>,
}

impl ProviderRuntimeAdapterRegistry {
    /// Builds a bounded nonempty runtime registry.
    ///
    /// # Errors
    ///
    /// Rejects an empty, excessive, duplicate, or self-inconsistent adapter set.
    pub fn new(
        adapters: impl IntoIterator<Item = Arc<dyn ProviderRuntimeAdapter>>,
    ) -> Result<Self, ProviderRuntimeAdapterRegistryError> {
        let mut values = BTreeMap::new();
        for adapter in adapters {
            let key = adapter.provider_type().clone();
            if values.insert(key, adapter).is_some() {
                return Err(ProviderRuntimeAdapterRegistryError::Duplicate);
            }
        }
        if values.is_empty() || values.len() > MAX_PROVIDER_RUNTIME_ADAPTERS {
            return Err(ProviderRuntimeAdapterRegistryError::InvalidSize);
        }
        if values
            .iter()
            .any(|(key, adapter)| adapter.provider_type() != key)
        {
            return Err(ProviderRuntimeAdapterRegistryError::Inconsistent);
        }
        Ok(Self { adapters: values })
    }

    fn adapter(&self, provider_type: &ProviderTypeId) -> Option<&dyn ProviderRuntimeAdapter> {
        self.adapters.get(provider_type).map(Arc::as_ref)
    }
}

impl fmt::Debug for ProviderRuntimeAdapterRegistry {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProviderRuntimeAdapterRegistry")
            .field("provider_types", &self.adapters.keys().collect::<Vec<_>>())
            .finish()
    }
}

/// Processing dispatcher for provider-specific triggers and controls.
pub struct ProviderProcessingDispatcher {
    runtimes: ProviderRuntimeAdapterRegistry,
    contexts: ProviderRuntimeContextResolver,
}

impl ProviderProcessingDispatcher {
    /// Composes the exact provider runtime registry.
    #[must_use]
    pub fn new(
        runtimes: ProviderRuntimeAdapterRegistry,
        manifests: Arc<dyn ProviderManifestRepository>,
    ) -> Self {
        Self {
            runtimes,
            contexts: ProviderRuntimeContextResolver::new(manifests),
        }
    }
}

impl fmt::Debug for ProviderProcessingDispatcher {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProviderProcessingDispatcher")
            .field("runtimes", &self.runtimes)
            .field("contexts", &self.contexts)
            .finish()
    }
}

#[async_trait]
impl ProviderProcessingProcessor for ProviderProcessingDispatcher {
    async fn process(
        &self,
        invocation: &ClaimedProviderProcessing,
        lease: &ProviderProcessingLease,
    ) -> ProviderProcessingOutcome {
        match invocation.input() {
            ProviderProcessingInput::Trigger(trigger) => {
                // A control adapter has already performed its idempotent
                // operation. A bound trigger is audit provenance only and its
                // original admission side effects must never be replayed.
                let Some(source_delivery_id) = invocation.receipt().source_delivery_id() else {
                    return ProviderProcessingOutcome::Fail(
                        ProviderProcessingFailure::InvalidEvidence,
                    );
                };
                if invocation.receipt().cause_delivery_id() != source_delivery_id {
                    return ProviderProcessingOutcome::Complete;
                }
                let Some(runtime) = self.runtimes.adapter(trigger.evidence().provider_type())
                else {
                    return ProviderProcessingOutcome::Fail(
                        ProviderProcessingFailure::InvalidEvidence,
                    );
                };
                let context = match self
                    .contexts
                    .resolve_delivery(
                        trigger.evidence(),
                        trigger.trigger().trigger().target_repository().identity(),
                    )
                    .await
                {
                    Ok(context) => context,
                    Err(error) => return context_processing_outcome(error),
                };
                match runtime
                    .process_trigger(&context, trigger, invocation, lease)
                    .await
                {
                    ProviderTriggerOutcome::Complete => ProviderProcessingOutcome::Complete,
                    ProviderTriggerOutcome::Retry(failure) => {
                        ProviderProcessingOutcome::Retry(failure)
                    }
                    ProviderTriggerOutcome::Fail(failure) => {
                        ProviderProcessingOutcome::Fail(failure)
                    }
                }
            }
            ProviderProcessingInput::Control(control) => {
                let Some(runtime) = self.runtimes.adapter(control.evidence().provider_type())
                else {
                    return ProviderProcessingOutcome::Fail(
                        ProviderProcessingFailure::InvalidEvidence,
                    );
                };
                let context = match self
                    .contexts
                    .resolve_delivery(control.evidence(), control.control().repository())
                    .await
                {
                    Ok(context) => context,
                    Err(error) => return context_processing_outcome(error),
                };
                match runtime
                    .handle_control(&context, control, invocation, lease)
                    .await
                {
                    Ok(Some(source_delivery_id)) => {
                        ProviderProcessingOutcome::ResolveControl(source_delivery_id)
                    }
                    Ok(None) => ProviderProcessingOutcome::Complete,
                    Err(ProviderControlHandlingError::Unavailable) => {
                        ProviderProcessingOutcome::Retry(
                            ProviderProcessingFailure::DependencyUnavailable,
                        )
                    }
                    Err(
                        ProviderControlHandlingError::Unauthorized
                        | ProviderControlHandlingError::NotFound
                        | ProviderControlHandlingError::Conflict,
                    ) => ProviderProcessingOutcome::Fail(ProviderProcessingFailure::PolicyRejected),
                    Err(ProviderControlHandlingError::InvalidEvidence) => {
                        ProviderProcessingOutcome::Fail(ProviderProcessingFailure::InvalidEvidence)
                    }
                }
            }
        }
    }
}

const fn context_repository_error(error: ProviderRepositoryError) -> ProviderRuntimeContextError {
    match error {
        ProviderRepositoryError::Unavailable | ProviderRepositoryError::SecretCustody => {
            ProviderRuntimeContextError::Unavailable
        }
        ProviderRepositoryError::Conflict
        | ProviderRepositoryError::NotFound
        | ProviderRepositoryError::Corrupt => ProviderRuntimeContextError::InvalidEvidence,
    }
}

const fn context_processing_outcome(
    error: ProviderRuntimeContextError,
) -> ProviderProcessingOutcome {
    match error {
        ProviderRuntimeContextError::Unavailable => {
            ProviderProcessingOutcome::Retry(ProviderProcessingFailure::DependencyUnavailable)
        }
        ProviderRuntimeContextError::InvalidEvidence => {
            ProviderProcessingOutcome::Fail(ProviderProcessingFailure::InvalidEvidence)
        }
    }
}

/// Sanitized provider-native control handling failure.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum ProviderControlHandlingError {
    /// Provider or durable handling dependencies were unavailable.
    #[error("provider control handling is unavailable")]
    Unavailable,
    /// The authenticated actor lacks current Automata authority.
    #[error("provider control actor is unauthorized")]
    Unauthorized,
    /// No exact Automata result subject matched the native target.
    #[error("provider control target was not found")]
    NotFound,
    /// Native identity matched conflicting Automata result evidence.
    #[error("provider control target is ambiguous")]
    Conflict,
    /// Adapter evidence violated the registered control schema.
    #[error("provider control evidence is invalid")]
    InvalidEvidence,
}

/// Invalid provider-runtime registry construction.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum ProviderRuntimeAdapterRegistryError {
    /// Registry was empty or exceeded its hard bound.
    #[error("provider runtime registry size is invalid")]
    InvalidSize,
    /// Two runtime adapters registered the same provider type.
    #[error("provider runtime adapter type is duplicated")]
    Duplicate,
    /// An adapter declared a different identity during construction.
    #[error("provider runtime adapter identity is inconsistent")]
    Inconsistent,
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use super::*;

    #[derive(Debug)]
    struct Adapter {
        first: ProviderTypeId,
        subsequent: ProviderTypeId,
        calls: AtomicUsize,
    }

    #[async_trait]
    impl ProviderRuntimeAdapter for Adapter {
        fn provider_type(&self) -> &ProviderTypeId {
            if self.calls.fetch_add(1, Ordering::SeqCst) == 0 {
                &self.first
            } else {
                &self.subsequent
            }
        }

        async fn process_trigger(
            &self,
            _context: &ProviderRuntimeContext,
            _trigger: &VerifiedProviderTriggerDelivery,
            _invocation: &ClaimedProviderProcessing,
            _lease: &ProviderProcessingLease,
        ) -> ProviderTriggerOutcome {
            unreachable!("registry construction never dispatches triggers")
        }

        async fn handle_control(
            &self,
            _context: &ProviderRuntimeContext,
            _control: &VerifiedProviderControlDelivery,
            _invocation: &ClaimedProviderProcessing,
            _lease: &ProviderProcessingLease,
        ) -> Result<Option<ProviderDeliveryId>, ProviderControlHandlingError> {
            unreachable!("registry construction never dispatches controls")
        }
    }

    fn adapter(first: &str, subsequent: &str) -> Arc<dyn ProviderRuntimeAdapter> {
        Arc::new(Adapter {
            first: ProviderTypeId::new(first).expect("first provider type"),
            subsequent: ProviderTypeId::new(subsequent).expect("subsequent provider type"),
            calls: AtomicUsize::new(0),
        })
    }

    #[test]
    fn registry_rejects_empty_duplicate_oversized_and_changing_identities() {
        assert!(matches!(
            ProviderRuntimeAdapterRegistry::new([]),
            Err(ProviderRuntimeAdapterRegistryError::InvalidSize)
        ));
        assert!(matches!(
            ProviderRuntimeAdapterRegistry::new([
                adapter("github", "github"),
                adapter("github", "github"),
            ]),
            Err(ProviderRuntimeAdapterRegistryError::Duplicate)
        ));
        let oversized = (0..=MAX_PROVIDER_RUNTIME_ADAPTERS)
            .map(|index| {
                let provider_type = format!("provider-{index}");
                adapter(&provider_type, &provider_type)
            })
            .collect::<Vec<_>>();
        assert!(matches!(
            ProviderRuntimeAdapterRegistry::new(oversized),
            Err(ProviderRuntimeAdapterRegistryError::InvalidSize)
        ));
        assert!(matches!(
            ProviderRuntimeAdapterRegistry::new([adapter("github", "forgejo")]),
            Err(ProviderRuntimeAdapterRegistryError::Inconsistent)
        ));
    }
}
