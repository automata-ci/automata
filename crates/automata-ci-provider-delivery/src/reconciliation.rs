//! Complete provider desired-state reconciliation through registered adapters.

use std::{collections::BTreeMap, fmt, sync::Arc};

use automata_ci_core::{UnixMillis, WorkspaceId};
use automata_ci_key_management::SecretBytes;
use automata_ci_provider::{
    ExternalRepositoryId, MAX_PROVIDER_SECRET_BINDINGS, MAX_PROVIDER_WEBHOOK_CONNECTIONS,
    MAX_PROVIDER_WEBHOOK_SECRET_CANDIDATES, ProviderArchiveLimits, ProviderConfigurationDocument,
    ProviderConfigurationError, ProviderConfigurationRevision, ProviderConnectionDraft,
    ProviderConnectionError, ProviderConnectionId, ProviderConnectionManifest,
    ProviderConnectionPolicyDocument, ProviderConnectionRevision, ProviderDefaultBranch,
    ProviderDeliveryRepositoryError, ProviderDescriptor, ProviderFactoryRegistry,
    ProviderFactoryRegistryError, ProviderInstanceDraft, ProviderInstanceId,
    ProviderInstanceRecord, ProviderLifecycleState, ProviderManifestRepository, ProviderOrigins,
    ProviderRepositoryError, ProviderRunnerPolicyBinding, ProviderSaveOutcome, ProviderSecret,
    ProviderSecretGeneration, ProviderSecretName, ProviderTypeId, ProviderWebhookEndpointId,
    ProviderWebhookEndpointManifest, ProviderWebhookEndpointRepository,
    ProviderWebhookEndpointRevision, ProviderWebhookEndpointState, ProviderWebhookError,
    ProviderWebhookSecretReference, ProviderWorkflowSource, RepositoryVisibility,
};
use thiserror::Error;

/// Complete desired configuration for one provider instance generation.
pub struct ProviderInstanceDesiredState {
    instance_id: ProviderInstanceId,
    provider_type: ProviderTypeId,
    revision: ProviderConfigurationRevision,
    state: ProviderLifecycleState,
    origins: ProviderOrigins,
    configuration: ProviderConfigurationDocument,
    secrets: BTreeMap<ProviderSecretName, SecretBytes>,
    observed_at: UnixMillis,
}

impl ProviderInstanceDesiredState {
    /// Creates one authoritative provider-instance generation.
    ///
    /// # Errors
    ///
    /// Rejects a negative observation time, duplicate secret names, or more
    /// than the common secret bound.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        instance_id: ProviderInstanceId,
        provider_type: ProviderTypeId,
        revision: ProviderConfigurationRevision,
        state: ProviderLifecycleState,
        origins: ProviderOrigins,
        configuration: ProviderConfigurationDocument,
        secrets: impl IntoIterator<Item = (ProviderSecretName, SecretBytes)>,
        observed_at: UnixMillis,
    ) -> Result<Self, ProviderDesiredStateError> {
        if observed_at.get() < 0 {
            return Err(ProviderDesiredStateError::InvalidTimestamp);
        }
        let mut indexed = BTreeMap::new();
        for (name, value) in secrets {
            if indexed.len() == MAX_PROVIDER_SECRET_BINDINGS {
                return Err(ProviderDesiredStateError::TooManySecrets);
            }
            if indexed.insert(name, value).is_some() {
                return Err(ProviderDesiredStateError::DuplicateSecret);
            }
        }
        Ok(Self {
            instance_id,
            provider_type,
            revision,
            state,
            origins,
            configuration,
            secrets: indexed,
            observed_at,
        })
    }

    /// Returns the stable provider-instance identity.
    #[must_use]
    pub const fn instance_id(&self) -> ProviderInstanceId {
        self.instance_id
    }

    /// Returns the authoritative complete-set generation.
    #[must_use]
    pub const fn revision(&self) -> ProviderConfigurationRevision {
        self.revision
    }

    /// Returns the registered adapter type.
    #[must_use]
    pub const fn provider_type(&self) -> &ProviderTypeId {
        &self.provider_type
    }

    /// Returns the desired provider lifecycle state.
    #[must_use]
    pub const fn state(&self) -> ProviderLifecycleState {
        self.state
    }
}

impl fmt::Debug for ProviderInstanceDesiredState {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProviderInstanceDesiredState")
            .field("instance_id", &self.instance_id)
            .field("provider_type", &self.provider_type)
            .field("revision", &self.revision)
            .field("state", &self.state)
            .field("origins", &self.origins)
            .field("configuration", &self.configuration)
            .field("secret_names", &self.secrets.keys().collect::<Vec<_>>())
            .field("observed_at", &self.observed_at)
            .finish()
    }
}

/// Desired active repository connection within one complete provider set.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProviderConnectionDesiredState {
    connection_id: ProviderConnectionId,
    workspace_id: WorkspaceId,
    external_repository_id: ExternalRepositoryId,
    visibility: RepositoryVisibility,
    default_branch: ProviderDefaultBranch,
    workflow_source: ProviderWorkflowSource,
    runner_policy: ProviderRunnerPolicyBinding,
    archive_limits: ProviderArchiveLimits,
    adapter_policy: ProviderConnectionPolicyDocument,
    observed_at: UnixMillis,
}

impl ProviderConnectionDesiredState {
    /// Creates one active provider-neutral repository connection.
    ///
    /// # Errors
    ///
    /// Rejects a negative observation time.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        connection_id: ProviderConnectionId,
        workspace_id: WorkspaceId,
        external_repository_id: ExternalRepositoryId,
        visibility: RepositoryVisibility,
        default_branch: ProviderDefaultBranch,
        workflow_source: ProviderWorkflowSource,
        runner_policy: ProviderRunnerPolicyBinding,
        archive_limits: ProviderArchiveLimits,
        adapter_policy: ProviderConnectionPolicyDocument,
        observed_at: UnixMillis,
    ) -> Result<Self, ProviderDesiredStateError> {
        if observed_at.get() < 0 {
            return Err(ProviderDesiredStateError::InvalidTimestamp);
        }
        Ok(Self {
            connection_id,
            workspace_id,
            external_repository_id,
            visibility,
            default_branch,
            workflow_source,
            runner_policy,
            archive_limits,
            adapter_policy,
            observed_at,
        })
    }

    /// Returns the stable connection identity.
    #[must_use]
    pub const fn connection_id(&self) -> ProviderConnectionId {
        self.connection_id
    }

    /// Returns the provider-scoped external repository identity.
    #[must_use]
    pub const fn external_repository_id(&self) -> &ExternalRepositoryId {
        &self.external_repository_id
    }
}

/// Desired public webhook policy for one provider instance.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProviderWebhookEndpointDesiredState {
    endpoint_id: ProviderWebhookEndpointId,
    body_limit: u64,
    raw_retention_millis: u64,
    secret_names: Vec<ProviderSecretName>,
}

impl ProviderWebhookEndpointDesiredState {
    /// Creates one endpoint policy selecting current named provider secrets.
    ///
    /// # Errors
    ///
    /// Rejects empty, duplicate, or excessive candidate names. Exact body and
    /// retention limits are validated when the common endpoint is materialized.
    pub fn new(
        endpoint_id: ProviderWebhookEndpointId,
        body_limit: u64,
        raw_retention_millis: u64,
        mut secret_names: Vec<ProviderSecretName>,
    ) -> Result<Self, ProviderDesiredStateError> {
        secret_names.sort();
        if secret_names.is_empty() || secret_names.len() > MAX_PROVIDER_WEBHOOK_SECRET_CANDIDATES {
            return Err(ProviderDesiredStateError::InvalidSecretCandidates);
        }
        if secret_names.windows(2).any(|pair| pair[0] == pair[1]) {
            return Err(ProviderDesiredStateError::DuplicateSecret);
        }
        Ok(Self {
            endpoint_id,
            body_limit,
            raw_retention_millis,
            secret_names,
        })
    }

    /// Returns the stable opaque endpoint identity.
    #[must_use]
    pub const fn endpoint_id(&self) -> ProviderWebhookEndpointId {
        self.endpoint_id
    }
}

/// One authoritative complete provider instance, connection set, and endpoint.
#[derive(Debug)]
pub struct ProviderDesiredState {
    instance: ProviderInstanceDesiredState,
    connections: Vec<ProviderConnectionDesiredState>,
    endpoint: ProviderWebhookEndpointDesiredState,
}

impl ProviderDesiredState {
    /// Creates a canonical complete desired set.
    ///
    /// # Errors
    ///
    /// Rejects duplicate connection or external repository identities, too many
    /// repositories, or active repositories beneath a non-active instance.
    pub fn new(
        instance: ProviderInstanceDesiredState,
        mut connections: Vec<ProviderConnectionDesiredState>,
        endpoint: ProviderWebhookEndpointDesiredState,
    ) -> Result<Self, ProviderDesiredStateError> {
        if connections.len() > MAX_PROVIDER_WEBHOOK_CONNECTIONS
            || (instance.state != ProviderLifecycleState::Active && !connections.is_empty())
        {
            return Err(ProviderDesiredStateError::InvalidConnectionSet);
        }
        connections.sort_by_key(ProviderConnectionDesiredState::connection_id);
        if connections
            .windows(2)
            .any(|pair| pair[0].connection_id == pair[1].connection_id)
        {
            return Err(ProviderDesiredStateError::DuplicateConnection);
        }
        let mut external = connections
            .iter()
            .map(|connection| connection.external_repository_id.clone())
            .collect::<Vec<_>>();
        external.sort();
        if external.windows(2).any(|pair| pair[0] == pair[1]) {
            return Err(ProviderDesiredStateError::DuplicateRepository);
        }
        Ok(Self {
            instance,
            connections,
            endpoint,
        })
    }

    /// Returns the desired provider-instance generation.
    #[must_use]
    pub const fn instance(&self) -> &ProviderInstanceDesiredState {
        &self.instance
    }

    /// Returns active connections in stable identity order.
    #[must_use]
    pub fn connections(&self) -> &[ProviderConnectionDesiredState] {
        &self.connections
    }

    /// Returns the desired webhook endpoint policy.
    #[must_use]
    pub const fn endpoint(&self) -> &ProviderWebhookEndpointDesiredState {
        &self.endpoint
    }
}

/// Convergent application result for one complete provider desired set.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProviderReconciliationReport {
    instance: ProviderSaveOutcome,
    connections_inserted: usize,
    connections_unchanged: usize,
    connections_disabled: usize,
    endpoint: ProviderSaveOutcome,
}

struct ConnectionReconciliation {
    inserted: usize,
    unchanged: usize,
    disabled: usize,
    active: usize,
}

struct ReconciliationContext {
    provider_type: ProviderTypeId,
    instance_id: ProviderInstanceId,
    provider_state: ProviderLifecycleState,
    observed_at: UnixMillis,
}

impl ProviderReconciliationReport {
    /// Returns the provider-instance persistence outcome.
    #[must_use]
    pub const fn instance(self) -> ProviderSaveOutcome {
        self.instance
    }

    /// Returns the number of inserted active connection revisions.
    #[must_use]
    pub const fn connections_inserted(self) -> usize {
        self.connections_inserted
    }

    /// Returns the number of active connections already matching the generation.
    #[must_use]
    pub const fn connections_unchanged(self) -> usize {
        self.connections_unchanged
    }

    /// Returns the number of omitted connections disabled or retired.
    #[must_use]
    pub const fn connections_disabled(self) -> usize {
        self.connections_disabled
    }

    /// Returns the endpoint persistence outcome.
    #[must_use]
    pub const fn endpoint(self) -> ProviderSaveOutcome {
        self.endpoint
    }
}

/// Provider-neutral convergent desired-state application service.
pub struct ProviderReconciliationService {
    factories: ProviderFactoryRegistry,
    manifests: Arc<dyn ProviderManifestRepository>,
    endpoints: Arc<dyn ProviderWebhookEndpointRepository>,
}

impl ProviderReconciliationService {
    /// Composes the static adapter registry with durable manifest and endpoint ports.
    #[must_use]
    pub fn new(
        factories: ProviderFactoryRegistry,
        manifests: Arc<dyn ProviderManifestRepository>,
        endpoints: Arc<dyn ProviderWebhookEndpointRepository>,
    ) -> Self {
        Self {
            factories,
            manifests,
            endpoints,
        }
    }

    /// Reconciles one authoritative complete provider generation.
    ///
    /// Each individual revision is atomic. The ordered operation is convergent:
    /// retries first make the instance current, then all selected connections,
    /// then disable omissions, and finally expose the endpoint.
    ///
    /// # Errors
    ///
    /// Fails closed on a stale or skipped provider generation, invalid adapter
    /// policy, lifecycle conflict, missing endpoint secret, or durable failure.
    pub async fn reconcile(
        &self,
        desired: ProviderDesiredState,
    ) -> Result<ProviderReconciliationReport, ProviderReconciliationError> {
        let ProviderDesiredState {
            instance,
            connections,
            endpoint,
        } = desired;
        let context = ReconciliationContext {
            instance_id: instance.instance_id,
            provider_type: instance.provider_type.clone(),
            provider_state: instance.state,
            observed_at: instance.observed_at,
        };
        let (descriptor, instance_outcome) = self.reconcile_instance(instance).await?;
        let connection_report = self
            .reconcile_connections(&context, connections, &descriptor)
            .await?;
        let endpoint_outcome = self
            .reconcile_endpoint(&context, endpoint, &descriptor, connection_report.active)
            .await?;
        Ok(ProviderReconciliationReport {
            instance: instance_outcome,
            connections_inserted: connection_report.inserted,
            connections_unchanged: connection_report.unchanged,
            connections_disabled: connection_report.disabled,
            endpoint: endpoint_outcome,
        })
    }

    async fn reconcile_instance(
        &self,
        instance: ProviderInstanceDesiredState,
    ) -> Result<(ProviderDescriptor, ProviderSaveOutcome), ProviderReconciliationError> {
        let instance_id = instance.instance_id;
        let provider_state = instance.state;
        let observed_at = instance.observed_at;
        let current = self
            .manifests
            .current_instance(instance_id)
            .await
            .map_err(ProviderReconciliationError::ManifestRepository)?;
        validate_provider_revision(current.as_ref(), instance.revision)?;
        let secrets = self
            .materialize_secrets(instance_id, current.as_ref(), instance.secrets)
            .await?;
        let created_at = current
            .as_ref()
            .map_or(observed_at, |record| record.manifest().created_at());
        let activated_at = current
            .as_ref()
            .and_then(|record| record.manifest().activated_at())
            .or((provider_state == ProviderLifecycleState::Active).then_some(observed_at));
        let retired_at = current
            .as_ref()
            .and_then(|record| record.manifest().retired_at())
            .or((provider_state == ProviderLifecycleState::Retired).then_some(observed_at));
        let record = self
            .factories
            .materialize_instance(
                ProviderInstanceDraft::new(
                    instance_id,
                    instance.provider_type,
                    instance.revision,
                    provider_state,
                    instance.origins,
                    instance.configuration,
                    secrets,
                    created_at,
                    activated_at,
                    retired_at,
                )
                .map_err(ProviderReconciliationError::Configuration)?,
            )
            .map_err(ProviderReconciliationError::Factory)?;
        let descriptor = self
            .factories
            .build_descriptor(record.manifest().clone(), record.secrets())
            .map_err(ProviderReconciliationError::Factory)?;
        let instance_outcome = self
            .manifests
            .save_instance(record)
            .await
            .map_err(ProviderReconciliationError::ManifestRepository)?;
        Ok((descriptor, instance_outcome))
    }

    async fn reconcile_connections(
        &self,
        context: &ReconciliationContext,
        desired: Vec<ProviderConnectionDesiredState>,
        descriptor: &ProviderDescriptor,
    ) -> Result<ConnectionReconciliation, ProviderReconciliationError> {
        let mut current_connections = self
            .manifests
            .current_connections(context.instance_id)
            .await
            .map_err(ProviderReconciliationError::ManifestRepository)?
            .into_iter()
            .map(|connection| (connection.connection_id(), connection))
            .collect::<BTreeMap<_, _>>();
        let mut connections_inserted = 0;
        let mut connections_unchanged = 0;
        for desired_connection in desired {
            let current = current_connections.remove(&desired_connection.connection_id);
            if self
                .reconcile_connection(descriptor, desired_connection, current.as_ref())
                .await?
                == ProviderSaveOutcome::Unchanged
            {
                connections_unchanged += 1;
            } else {
                connections_inserted += 1;
            }
        }
        let omitted_state = if context.provider_state == ProviderLifecycleState::Retired {
            ProviderLifecycleState::Retired
        } else {
            ProviderLifecycleState::Disabled
        };
        let mut connections_disabled = 0;
        for current in current_connections.into_values() {
            if current.state() == ProviderLifecycleState::Retired
                || (current.state() == ProviderLifecycleState::Disabled
                    && omitted_state == ProviderLifecycleState::Disabled)
            {
                continue;
            }
            self.disable_connection(current, omitted_state, context.observed_at)
                .await?;
            connections_disabled += 1;
        }
        Ok(ConnectionReconciliation {
            inserted: connections_inserted,
            unchanged: connections_unchanged,
            disabled: connections_disabled,
            active: connections_inserted + connections_unchanged,
        })
    }

    async fn reconcile_connection(
        &self,
        descriptor: &ProviderDescriptor,
        desired: ProviderConnectionDesiredState,
        current: Option<&ProviderConnectionManifest>,
    ) -> Result<ProviderSaveOutcome, ProviderReconciliationError> {
        let revision = next_connection_revision(current)?;
        let created_at =
            current.map_or(desired.observed_at, ProviderConnectionManifest::created_at);
        let activated_at = current
            .and_then(ProviderConnectionManifest::activated_at)
            .or(Some(desired.observed_at));
        let candidate = self
            .factories
            .materialize_connection(
                descriptor,
                ProviderConnectionDraft::new(
                    desired.connection_id,
                    revision,
                    ProviderLifecycleState::Active,
                    desired.workspace_id,
                    desired.external_repository_id,
                    desired.visibility,
                    desired.default_branch,
                    desired.workflow_source,
                    desired.runner_policy,
                    desired.archive_limits,
                    desired.adapter_policy,
                    created_at,
                    activated_at,
                    None,
                )
                .map_err(ProviderReconciliationError::Connection)?,
            )
            .map_err(ProviderReconciliationError::Factory)?;
        if current.is_some_and(|current| same_connection_configuration(current, &candidate)) {
            return Ok(ProviderSaveOutcome::Unchanged);
        }
        self.manifests
            .save_connection(candidate)
            .await
            .map_err(ProviderReconciliationError::ManifestRepository)
    }

    async fn disable_connection(
        &self,
        current: ProviderConnectionManifest,
        state: ProviderLifecycleState,
        observed_at: UnixMillis,
    ) -> Result<(), ProviderReconciliationError> {
        let retired_at = (state == ProviderLifecycleState::Retired).then_some(observed_at);
        let successor = ProviderConnectionManifest::new(
            current.connection_id(),
            next_connection_revision(Some(&current))?,
            state,
            current.configuration().clone(),
            current.created_at(),
            current.activated_at(),
            retired_at,
        )
        .map_err(ProviderReconciliationError::Connection)?;
        self.manifests
            .save_connection(successor)
            .await
            .map_err(ProviderReconciliationError::ManifestRepository)?;
        Ok(())
    }

    async fn reconcile_endpoint(
        &self,
        context: &ReconciliationContext,
        endpoint: ProviderWebhookEndpointDesiredState,
        descriptor: &ProviderDescriptor,
        active_connections: usize,
    ) -> Result<ProviderSaveOutcome, ProviderReconciliationError> {
        let endpoint_state = match context.provider_state {
            ProviderLifecycleState::Active if active_connections > 0 => {
                ProviderWebhookEndpointState::Active
            }
            ProviderLifecycleState::Retired => ProviderWebhookEndpointState::Retired,
            ProviderLifecycleState::Active | ProviderLifecycleState::Disabled => {
                ProviderWebhookEndpointState::Disabled
            }
        };
        let current_endpoint = self
            .endpoints
            .current_endpoint_manifest(endpoint.endpoint_id)
            .await
            .map_err(ProviderReconciliationError::EndpointRepository)?;
        let endpoint_revision = next_endpoint_revision(current_endpoint.as_ref())?;
        let endpoint_created_at = current_endpoint.as_ref().map_or(
            context.observed_at,
            ProviderWebhookEndpointManifest::created_at,
        );
        let endpoint_retired_at = current_endpoint
            .as_ref()
            .and_then(ProviderWebhookEndpointManifest::retired_at)
            .or((endpoint_state == ProviderWebhookEndpointState::Retired)
                .then_some(context.observed_at));
        let references = endpoint
            .secret_names
            .into_iter()
            .map(|name| {
                descriptor
                    .manifest()
                    .secrets()
                    .get(&name)
                    .map(|binding| {
                        ProviderWebhookSecretReference::new(
                            descriptor.manifest().revision(),
                            name,
                            binding.generation(),
                        )
                    })
                    .ok_or(ProviderReconciliationError::MissingEndpointSecret)
            })
            .collect::<Result<Vec<_>, _>>()?;
        let endpoint_candidate = ProviderWebhookEndpointManifest::new(
            endpoint.endpoint_id,
            endpoint_revision,
            endpoint_state,
            context.provider_type.clone(),
            context.instance_id,
            descriptor.manifest().revision(),
            endpoint.body_limit,
            endpoint.raw_retention_millis,
            references,
            endpoint_created_at,
            endpoint_retired_at,
        )
        .map_err(ProviderReconciliationError::Webhook)?;
        if current_endpoint
            .as_ref()
            .is_some_and(|current| same_endpoint_configuration(current, &endpoint_candidate))
        {
            Ok(ProviderSaveOutcome::Unchanged)
        } else {
            self.endpoints
                .save_endpoint(endpoint_candidate)
                .await
                .map_err(ProviderReconciliationError::EndpointRepository)
        }
    }

    async fn materialize_secrets(
        &self,
        instance_id: ProviderInstanceId,
        current: Option<&ProviderInstanceRecord>,
        desired: BTreeMap<ProviderSecretName, SecretBytes>,
    ) -> Result<Vec<ProviderSecret>, ProviderReconciliationError> {
        let mut secrets = Vec::with_capacity(desired.len());
        for (name, value) in desired {
            let current_binding = current.and_then(|record| record.manifest().secrets().get(&name));
            let generation = match current_binding {
                Some(binding)
                    if current
                        .and_then(|record| record.secrets().get(&name))
                        .is_some_and(|current| {
                            current.expose_secret() == value.expose_secret()
                        }) =>
                {
                    binding.generation()
                }
                Some(binding) => increment_secret_generation(binding.generation())?,
                None => match self
                    .manifests
                    .latest_secret_generation(instance_id, name.clone())
                    .await
                    .map_err(ProviderReconciliationError::ManifestRepository)?
                {
                    Some(generation) => increment_secret_generation(generation)?,
                    None => ProviderSecretGeneration::new(1)
                        .map_err(ProviderReconciliationError::Configuration)?,
                },
            };
            secrets.push(ProviderSecret::new(name, generation, value));
        }
        Ok(secrets)
    }
}

impl fmt::Debug for ProviderReconciliationService {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProviderReconciliationService")
            .field("factories", &self.factories)
            .field("manifests", &self.manifests)
            .field("endpoints", &self.endpoints)
            .finish()
    }
}

fn validate_provider_revision(
    current: Option<&ProviderInstanceRecord>,
    desired: ProviderConfigurationRevision,
) -> Result<(), ProviderReconciliationError> {
    // The provider-neutral registry may be empty when it is first introduced
    // alongside an already-established provider configuration.  In that
    // bootstrap case the durable provider configuration revision is the
    // authoritative starting point and need not be replayed from revision 1.
    // Once a neutral manifest exists, every subsequent observation remains
    // strictly idempotent or contiguous.
    let valid = current.is_none_or(|current| {
        let current = current.manifest().revision().get();
        desired.get() == current || current.checked_add(1) == Some(desired.get())
    });
    if valid {
        Ok(())
    } else {
        Err(ProviderReconciliationError::RevisionConflict)
    }
}

fn increment_secret_generation(
    current: ProviderSecretGeneration,
) -> Result<ProviderSecretGeneration, ProviderReconciliationError> {
    current
        .get()
        .checked_add(1)
        .ok_or(ProviderReconciliationError::RevisionConflict)
        .and_then(|generation| {
            ProviderSecretGeneration::new(generation)
                .map_err(ProviderReconciliationError::Configuration)
        })
}

fn next_connection_revision(
    current: Option<&ProviderConnectionManifest>,
) -> Result<ProviderConnectionRevision, ProviderReconciliationError> {
    let revision = current.map_or(Some(1), |current| current.revision().get().checked_add(1));
    ProviderConnectionRevision::new(revision.ok_or(ProviderReconciliationError::RevisionConflict)?)
        .map_err(ProviderReconciliationError::Connection)
}

fn next_endpoint_revision(
    current: Option<&ProviderWebhookEndpointManifest>,
) -> Result<ProviderWebhookEndpointRevision, ProviderReconciliationError> {
    let revision = current.map_or(Some(1), |current| current.revision().get().checked_add(1));
    ProviderWebhookEndpointRevision::new(
        revision.ok_or(ProviderReconciliationError::RevisionConflict)?,
    )
    .map_err(ProviderReconciliationError::Webhook)
}

fn same_connection_configuration(
    current: &ProviderConnectionManifest,
    candidate: &ProviderConnectionManifest,
) -> bool {
    current.state() == candidate.state()
        && current.configuration() == candidate.configuration()
        && current.created_at() == candidate.created_at()
        && current.activated_at() == candidate.activated_at()
        && current.retired_at() == candidate.retired_at()
}

fn same_endpoint_configuration(
    current: &ProviderWebhookEndpointManifest,
    candidate: &ProviderWebhookEndpointManifest,
) -> bool {
    current.state() == candidate.state()
        && current.provider_type() == candidate.provider_type()
        && current.instance_id() == candidate.instance_id()
        && current.provider_revision() == candidate.provider_revision()
        && current.body_limit() == candidate.body_limit()
        && current.raw_retention_millis() == candidate.raw_retention_millis()
        && current.secret_references() == candidate.secret_references()
        && current.created_at() == candidate.created_at()
        && current.retired_at() == candidate.retired_at()
}

/// Invalid complete provider desired-state input.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum ProviderDesiredStateError {
    /// A desired-state observation time was negative.
    #[error("provider desired-state timestamp is invalid")]
    InvalidTimestamp,
    /// More secrets were supplied than the common bound.
    #[error("too many provider desired-state secrets were supplied")]
    TooManySecrets,
    /// A provider secret name appeared more than once.
    #[error("a provider desired-state secret was duplicated")]
    DuplicateSecret,
    /// An endpoint had no candidates or exceeded the common candidate bound.
    #[error("provider webhook desired-state candidates are invalid")]
    InvalidSecretCandidates,
    /// A connection identity appeared more than once.
    #[error("a provider desired-state connection was duplicated")]
    DuplicateConnection,
    /// An external repository appeared more than once within the instance.
    #[error("a provider desired-state repository was duplicated")]
    DuplicateRepository,
    /// The complete connection set exceeded its bound or contradicted lifecycle state.
    #[error("provider desired-state connections are invalid")]
    InvalidConnectionSet,
}

/// Sanitized complete provider reconciliation failure.
#[derive(Debug, Error)]
pub enum ProviderReconciliationError {
    /// The desired provider generation was stale or noncontiguous.
    #[error("provider desired-state revision conflicts with durable state")]
    RevisionConflict,
    /// Common provider configuration evidence was invalid.
    #[error("provider desired-state configuration is invalid")]
    Configuration(#[source] ProviderConfigurationError),
    /// Common connection evidence was invalid.
    #[error("provider desired-state connection is invalid")]
    Connection(#[source] ProviderConnectionError),
    /// Common webhook evidence was invalid.
    #[error("provider desired-state webhook is invalid")]
    Webhook(#[source] ProviderWebhookError),
    /// The selected adapter rejected provider-specific configuration.
    #[error("provider desired-state adapter validation failed")]
    Factory(#[source] ProviderFactoryRegistryError),
    /// A requested endpoint secret name was absent from the instance generation.
    #[error("provider desired-state endpoint secret is missing")]
    MissingEndpointSecret,
    /// Durable provider manifest storage failed.
    #[error("provider desired-state manifest repository failed")]
    ManifestRepository(#[source] ProviderRepositoryError),
    /// Durable webhook endpoint storage failed.
    #[error("provider desired-state endpoint repository failed")]
    EndpointRepository(#[source] ProviderDeliveryRepositoryError),
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use automata_ci_core::{GitObjectAlgorithm, Sha256Digest};
    use automata_ci_provider::{
        ProviderCapabilities, ProviderCapability, ProviderConfigurationFactory,
        ProviderConnectionFactoryRequest, ProviderDeliveryFuture, ProviderFactoryRequest,
        ProviderFactoryValidationError, ProviderInstanceManifest, ProviderRepositoryFuture,
        ProviderRepositoryPath, ProviderSecretSet, ProviderWebhookEndpointRecord,
        SourceReadCapability,
    };

    use super::*;

    #[derive(Debug)]
    struct TestFactory {
        provider_type: ProviderTypeId,
    }

    impl ProviderConfigurationFactory for TestFactory {
        fn provider_type(&self) -> &ProviderTypeId {
            &self.provider_type
        }

        fn validate_instance(
            &self,
            request: ProviderFactoryRequest<'_>,
        ) -> Result<ProviderCapabilities, ProviderFactoryValidationError> {
            let secret = ProviderSecretName::new("control-token").expect("secret name");
            if request.provider_type() != &self.provider_type
                || request.secrets().get(&secret).is_none()
            {
                return Err(ProviderFactoryValidationError::InvalidSecrets);
            }
            ProviderCapabilities::new([ProviderCapability::SourceRead(
                SourceReadCapability::new([GitObjectAlgorithm::Sha1])
                    .map_err(|_| ProviderFactoryValidationError::InvalidCapabilities)?,
            )])
            .map_err(|_| ProviderFactoryValidationError::InvalidCapabilities)
        }

        fn validate_connection(
            &self,
            _request: ProviderConnectionFactoryRequest<'_>,
        ) -> Result<(), ProviderFactoryValidationError> {
            Ok(())
        }
    }

    struct StoredSecret {
        name: ProviderSecretName,
        generation: ProviderSecretGeneration,
        value: Vec<u8>,
    }

    struct StoredInstance {
        manifest: ProviderInstanceManifest,
        secrets: Vec<StoredSecret>,
    }

    impl StoredInstance {
        fn record(&self) -> Result<ProviderInstanceRecord, ProviderRepositoryError> {
            let secrets = self
                .secrets
                .iter()
                .map(|secret| {
                    SecretBytes::new(secret.value.clone())
                        .map(|value| {
                            ProviderSecret::new(secret.name.clone(), secret.generation, value)
                        })
                        .map_err(|_| ProviderRepositoryError::Corrupt)
                })
                .collect::<Result<Vec<_>, _>>()?;
            let set = ProviderSecretSet::new(self.manifest.secrets(), secrets)
                .map_err(|_| ProviderRepositoryError::Corrupt)?;
            ProviderInstanceRecord::new(self.manifest.clone(), set)
        }
    }

    #[derive(Default)]
    struct RepositoryState {
        instance: Option<StoredInstance>,
        generations: BTreeMap<ProviderSecretName, ProviderSecretGeneration>,
        connections: BTreeMap<ProviderConnectionId, ProviderConnectionManifest>,
        endpoint: Option<ProviderWebhookEndpointManifest>,
    }

    #[derive(Default)]
    struct MemoryRepository {
        state: Mutex<RepositoryState>,
    }

    impl fmt::Debug for MemoryRepository {
        fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str("MemoryRepository([REDACTED])")
        }
    }

    impl ProviderManifestRepository for MemoryRepository {
        fn save_instance(
            &self,
            record: ProviderInstanceRecord,
        ) -> ProviderRepositoryFuture<'_, ProviderSaveOutcome> {
            Box::pin(async move {
                let (manifest, secrets) = record.into_parts();
                let mut state = self.state.lock().expect("repository state");
                if let Some(current) = &state.instance {
                    if manifest.revision() == current.manifest.revision() {
                        return if manifest.digest() == current.manifest.digest() {
                            Ok(ProviderSaveOutcome::Unchanged)
                        } else {
                            Err(ProviderRepositoryError::Conflict)
                        };
                    }
                    manifest
                        .validate_successor(&current.manifest)
                        .map_err(|_| ProviderRepositoryError::Conflict)?;
                }
                let stored = secrets
                    .into_secrets()
                    .map(|secret| {
                        let (name, generation, value) = secret.into_parts();
                        state.generations.insert(name.clone(), generation);
                        StoredSecret {
                            name,
                            generation,
                            value: value.expose_secret().to_vec(),
                        }
                    })
                    .collect();
                state.instance = Some(StoredInstance {
                    manifest,
                    secrets: stored,
                });
                Ok(ProviderSaveOutcome::Inserted)
            })
        }

        fn load_instance(
            &self,
            instance_id: ProviderInstanceId,
            revision: ProviderConfigurationRevision,
        ) -> ProviderRepositoryFuture<'_, Option<ProviderInstanceRecord>> {
            Box::pin(async move {
                let state = self.state.lock().expect("repository state");
                state
                    .instance
                    .as_ref()
                    .filter(|stored| {
                        stored.manifest.instance_id() == instance_id
                            && stored.manifest.revision() == revision
                    })
                    .map(StoredInstance::record)
                    .transpose()
            })
        }

        fn current_instance(
            &self,
            instance_id: ProviderInstanceId,
        ) -> ProviderRepositoryFuture<'_, Option<ProviderInstanceRecord>> {
            Box::pin(async move {
                let state = self.state.lock().expect("repository state");
                state
                    .instance
                    .as_ref()
                    .filter(|stored| stored.manifest.instance_id() == instance_id)
                    .map(StoredInstance::record)
                    .transpose()
            })
        }

        fn latest_secret_generation(
            &self,
            _instance_id: ProviderInstanceId,
            name: ProviderSecretName,
        ) -> ProviderRepositoryFuture<'_, Option<ProviderSecretGeneration>> {
            Box::pin(async move {
                Ok(self
                    .state
                    .lock()
                    .expect("repository state")
                    .generations
                    .get(&name)
                    .copied())
            })
        }

        fn save_connection(
            &self,
            manifest: ProviderConnectionManifest,
        ) -> ProviderRepositoryFuture<'_, ProviderSaveOutcome> {
            Box::pin(async move {
                let mut state = self.state.lock().expect("repository state");
                if let Some(current) = state.connections.get(&manifest.connection_id()) {
                    if manifest.revision() == current.revision() {
                        return if manifest.digest() == current.digest() {
                            Ok(ProviderSaveOutcome::Unchanged)
                        } else {
                            Err(ProviderRepositoryError::Conflict)
                        };
                    }
                    manifest
                        .validate_successor(current)
                        .map_err(|_| ProviderRepositoryError::Conflict)?;
                } else if manifest.revision().get() != 1 {
                    return Err(ProviderRepositoryError::Conflict);
                }
                state.connections.insert(manifest.connection_id(), manifest);
                Ok(ProviderSaveOutcome::Inserted)
            })
        }

        fn load_connection(
            &self,
            connection_id: ProviderConnectionId,
            revision: ProviderConnectionRevision,
        ) -> ProviderRepositoryFuture<'_, Option<ProviderConnectionManifest>> {
            Box::pin(async move {
                Ok(self
                    .state
                    .lock()
                    .expect("repository state")
                    .connections
                    .get(&connection_id)
                    .filter(|connection| connection.revision() == revision)
                    .cloned())
            })
        }

        fn current_connection(
            &self,
            connection_id: ProviderConnectionId,
        ) -> ProviderRepositoryFuture<'_, Option<ProviderConnectionManifest>> {
            Box::pin(async move {
                Ok(self
                    .state
                    .lock()
                    .expect("repository state")
                    .connections
                    .get(&connection_id)
                    .cloned())
            })
        }

        fn current_connections(
            &self,
            instance_id: ProviderInstanceId,
        ) -> ProviderRepositoryFuture<'_, Vec<ProviderConnectionManifest>> {
            Box::pin(async move {
                Ok(self
                    .state
                    .lock()
                    .expect("repository state")
                    .connections
                    .values()
                    .filter(|connection| {
                        connection.configuration().repository().instance_id() == instance_id
                    })
                    .cloned()
                    .collect())
            })
        }
    }

    impl ProviderWebhookEndpointRepository for MemoryRepository {
        fn save_endpoint(
            &self,
            endpoint: ProviderWebhookEndpointManifest,
        ) -> ProviderDeliveryFuture<'_, ProviderSaveOutcome> {
            Box::pin(async move {
                let mut state = self.state.lock().expect("repository state");
                if let Some(current) = &state.endpoint {
                    if endpoint.revision() == current.revision() {
                        return if endpoint == *current {
                            Ok(ProviderSaveOutcome::Unchanged)
                        } else {
                            Err(ProviderDeliveryRepositoryError::EndpointConflict)
                        };
                    }
                    endpoint
                        .validate_successor(current)
                        .map_err(|_| ProviderDeliveryRepositoryError::EndpointConflict)?;
                } else if endpoint.revision().get() != 1 {
                    return Err(ProviderDeliveryRepositoryError::EndpointConflict);
                }
                state.endpoint = Some(endpoint);
                Ok(ProviderSaveOutcome::Inserted)
            })
        }

        fn current_endpoint_manifest(
            &self,
            endpoint_id: ProviderWebhookEndpointId,
        ) -> ProviderDeliveryFuture<'_, Option<ProviderWebhookEndpointManifest>> {
            Box::pin(async move {
                Ok(self
                    .state
                    .lock()
                    .expect("repository state")
                    .endpoint
                    .as_ref()
                    .filter(|endpoint| endpoint.endpoint_id() == endpoint_id)
                    .cloned())
            })
        }

        fn resolve_endpoint(
            &self,
            _endpoint_id: ProviderWebhookEndpointId,
        ) -> ProviderDeliveryFuture<'_, Option<ProviderWebhookEndpointRecord>> {
            Box::pin(async { Err(ProviderDeliveryRepositoryError::Unavailable) })
        }

        fn load_endpoint(
            &self,
            _endpoint_id: ProviderWebhookEndpointId,
            _revision: ProviderWebhookEndpointRevision,
        ) -> ProviderDeliveryFuture<'_, Option<ProviderWebhookEndpointRecord>> {
            Box::pin(async { Err(ProviderDeliveryRepositoryError::Unavailable) })
        }
    }

    fn desired(
        instance_id: ProviderInstanceId,
        connection_id: ProviderConnectionId,
        endpoint_id: ProviderWebhookEndpointId,
        revision: u64,
        secret: &[u8],
        with_connection: bool,
    ) -> ProviderDesiredState {
        let instance = ProviderInstanceDesiredState::new(
            instance_id,
            ProviderTypeId::new("forgejo").expect("provider type"),
            ProviderConfigurationRevision::new(revision).expect("provider revision"),
            ProviderLifecycleState::Active,
            ProviderOrigins::new("https://code.example/", "https://code.example/api/v1/")
                .expect("origins"),
            ProviderConfigurationDocument::new(
                automata_ci_provider::ProviderSchemaVersion::new(1).expect("schema"),
                b"{}".to_vec(),
            )
            .expect("configuration"),
            [(
                ProviderSecretName::new("control-token").expect("secret name"),
                SecretBytes::new(secret.to_vec()).expect("secret"),
            )],
            UnixMillis::new(i64::try_from(revision).expect("time") * 1_000),
        )
        .expect("instance desired state");
        let connections = with_connection
            .then(|| {
                ProviderConnectionDesiredState::new(
                    connection_id,
                    WorkspaceId::parse("11111111-1111-4111-8111-111111111111").expect("workspace"),
                    ExternalRepositoryId::new("42").expect("external repository"),
                    RepositoryVisibility::Private,
                    ProviderDefaultBranch::new("main").expect("default branch"),
                    ProviderWorkflowSource::Directory(
                        ProviderRepositoryPath::new(".ci/workflows").expect("workflow root"),
                    ),
                    ProviderRunnerPolicyBinding::new(
                        automata_ci_provider::ProviderSchemaVersion::new(2).expect("runner schema"),
                        Sha256Digest::from_bytes([7; 32]),
                    ),
                    ProviderArchiveLimits::new(1_024, 8_192, 100, 1_024, 10, 1_024)
                        .expect("archive limits"),
                    ProviderConnectionPolicyDocument::new(
                        automata_ci_provider::ProviderSchemaVersion::new(1).expect("policy schema"),
                        b"{}".to_vec(),
                    )
                    .expect("connection policy"),
                    UnixMillis::new(1_000),
                )
                .expect("connection desired state")
            })
            .into_iter()
            .collect();
        let endpoint = ProviderWebhookEndpointDesiredState::new(
            endpoint_id,
            1_048_576,
            30 * 24 * 60 * 60 * 1_000,
            vec![ProviderSecretName::new("control-token").expect("secret name")],
        )
        .expect("endpoint desired state");
        ProviderDesiredState::new(instance, connections, endpoint).expect("provider desired state")
    }

    #[tokio::test]
    async fn complete_sets_are_idempotent_and_connections_have_independent_revisions() {
        let repository = Arc::new(MemoryRepository::default());
        let factory = Arc::new(TestFactory {
            provider_type: ProviderTypeId::new("forgejo").expect("provider type"),
        }) as Arc<dyn ProviderConfigurationFactory>;
        let manifests: Arc<dyn ProviderManifestRepository> = repository.clone();
        let endpoints: Arc<dyn ProviderWebhookEndpointRepository> = repository.clone();
        let service = ProviderReconciliationService::new(
            ProviderFactoryRegistry::new([factory]).expect("registry"),
            manifests,
            endpoints,
        );
        let instance_id = ProviderInstanceId::new();
        let connection_id = ProviderConnectionId::new();
        let endpoint_id = ProviderWebhookEndpointId::new();

        let first = service
            .reconcile(desired(
                instance_id,
                connection_id,
                endpoint_id,
                1,
                b"first-secret",
                true,
            ))
            .await
            .expect("initial reconciliation");
        assert_eq!(first.instance(), ProviderSaveOutcome::Inserted);
        assert_eq!(first.connections_inserted(), 1);
        assert_eq!(first.endpoint(), ProviderSaveOutcome::Inserted);

        let repeated = service
            .reconcile(desired(
                instance_id,
                connection_id,
                endpoint_id,
                1,
                b"first-secret",
                true,
            ))
            .await
            .expect("idempotent reconciliation");
        assert_eq!(repeated.instance(), ProviderSaveOutcome::Unchanged);
        assert_eq!(repeated.connections_unchanged(), 1);
        assert_eq!(repeated.endpoint(), ProviderSaveOutcome::Unchanged);

        let removed = service
            .reconcile(desired(
                instance_id,
                connection_id,
                endpoint_id,
                2,
                b"second-secret",
                false,
            ))
            .await
            .expect("removal reconciliation");
        assert_eq!(removed.connections_disabled(), 1);
        let state = repository.state.lock().expect("repository state");
        let instance = state.instance.as_ref().expect("instance");
        assert_eq!(instance.manifest.revision().get(), 2);
        assert_eq!(
            instance
                .manifest
                .secrets()
                .iter()
                .next()
                .expect("binding")
                .generation()
                .get(),
            2
        );
        let connection = state.connections.get(&connection_id).expect("connection");
        assert_eq!(connection.revision().get(), 2);
        assert_eq!(connection.state(), ProviderLifecycleState::Disabled);
        let endpoint = state.endpoint.as_ref().expect("endpoint");
        assert_eq!(endpoint.revision().get(), 2);
        assert_eq!(endpoint.provider_revision().get(), 2);
        assert_eq!(endpoint.state(), ProviderWebhookEndpointState::Disabled);
    }

    #[tokio::test]
    async fn first_observation_bootstraps_an_existing_provider_revision() {
        let repository = Arc::new(MemoryRepository::default());
        let factory = Arc::new(TestFactory {
            provider_type: ProviderTypeId::new("forgejo").expect("provider type"),
        }) as Arc<dyn ProviderConfigurationFactory>;
        let service = ProviderReconciliationService::new(
            ProviderFactoryRegistry::new([factory]).expect("registry"),
            repository.clone(),
            repository,
        );

        let report = service
            .reconcile(desired(
                ProviderInstanceId::new(),
                ProviderConnectionId::new(),
                ProviderWebhookEndpointId::new(),
                2,
                b"bootstrap-secret",
                false,
            ))
            .await
            .expect("first observation with an existing durable revision");
        assert_eq!(report.instance(), ProviderSaveOutcome::Inserted);
        assert_eq!(report.endpoint(), ProviderSaveOutcome::Inserted);
    }
}
