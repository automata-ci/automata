//! mTLS-only managed-secret delivery after durable exact authority reservation.
//!
//! This module never participates in runner-command serialization.  The
//! runner constructs a fresh one-shot bearer only after lease acceptance; this
//! handler records its keyed verifier, resolves only the built-in provider
//! after the Store atomically reserves the exact operation, and acknowledges
//! only an explicit post-custody request from the same mTLS machine.

use std::{fmt, sync::Arc};

use async_trait::async_trait;
use automata_ci_auth::{machine::AuthenticatedMachine, time::Clock};
use automata_ci_core::{
    AttemptId, FencingToken, JobId, Lease, LeaseId, RunId, RunnerId, RunnerSessionId, UnixMillis,
};
use automata_ci_protocol::ManagedSecretBindingOverlay;
use automata_ci_runner_control::{
    ControlPortError, ManagedSecretBindingIssuer, RuntimeAuthorityIssueRequest,
};
use automata_ci_runner_transport::{
    ApplicationError, ApplicationErrorKind, AuthenticatedRunnerEphemeralRequest,
    EphemeralHandlerFuture, MANAGED_SECRET_DELIVERY_CREDENTIAL_KEY_ID,
    ManagedSecretDeliveryCoordinates, ManagedSecretDeliveryOperation, ManagedSecretDeliveryRequest,
    ManagedSecretDeliveryResponse, ManagedSecretDeliveryValue, RunnerEphemeralHandler,
    RunnerEphemeralReply,
};
use automata_ci_secret::{
    EnvironmentScopeId, ProviderOperationContext, ProviderRequestId, ProviderSecretLocator,
    ProviderVersionId, RepositoryScopeId, ResolveSecretVersionRequest, SecretDescriptor, SecretId,
    SecretName, SecretProvider, SecretScope, TenantScopeId, WorkloadContext, WorkloadId,
};
use automata_ci_store::{
    AcknowledgeManagedSecretDelivery, BUILTIN_SECRET_PROVIDER_ID, IssueLeasedJobSecretGrants,
    ManagedSecretAuthorityBinding, ManagedSecretAuthorityReceipt, ManagedSecretAuthorityRepository,
    ManagedSecretAuthorityStoreError, ManagedSecretBinding, ManagedSecretBindingSet,
    ManagedSecretDeliveryMachine, ManagedSecretDeliveryOperationId, ManagedSecretDeliveryProposal,
    ManagedSecretExecutionScope, ManagedSecretGrantMode, ManagedSecretScope,
    ProtectedEnvironmentRepository, ProtectedEnvironmentStoreError, RepositorySecretVersionId,
    ResolveManagedSecretAuthority, ResolveManagedSecretDeliverySession,
    ResolveManagedSecretExecutionScope, RunnerSessionFence, SecretWorkloadGrantId,
    StableRunnerSlot, StoreError, TenantScope,
};
use sha2::{Digest as _, Sha256};
use uuid::Uuid;

use super::secret_custody::SecretCustodyVerifier;

/// Post-lease adapter that derives only value-free secret grant locators.
pub(crate) struct LeasedManagedSecretBindingIssuer {
    repository: Arc<dyn ProtectedEnvironmentRepository>,
    tenant: TenantScope,
}

impl LeasedManagedSecretBindingIssuer {
    #[must_use]
    pub(crate) const fn new(
        repository: Arc<dyn ProtectedEnvironmentRepository>,
        tenant: TenantScope,
    ) -> Self {
        Self { repository, tenant }
    }
}

impl fmt::Debug for LeasedManagedSecretBindingIssuer {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LeasedManagedSecretBindingIssuer")
            .field("repository", &"ProtectedEnvironmentRepository(..)")
            .field("tenant", &"[REDACTED]")
            .finish()
    }
}

#[async_trait]
impl ManagedSecretBindingIssuer for LeasedManagedSecretBindingIssuer {
    async fn issue(
        &self,
        request: RuntimeAuthorityIssueRequest<'_>,
    ) -> Result<ManagedSecretBindingOverlay, ControlPortError> {
        let lease = request.lease();
        let issued = self
            .repository
            .issue_leased_job_secret_grants(
                IssueLeasedJobSecretGrants::new(
                    self.tenant.clone(),
                    lease.attempt_id(),
                    lease.lease_id(),
                    lease.fencing_token(),
                    lease.issued_at(),
                    lease.expires_at(),
                )
                .map_err(|_| ControlPortError::Corrupt)?,
            )
            .await
            .map_err(protected_environment_port_error)?;
        ManagedSecretBindingOverlay::new(
            lease,
            issued
                .into_iter()
                .map(|entry| (entry.canonical_name().to_owned(), entry.binding().clone())),
        )
        .map_err(|_| ControlPortError::Corrupt)
    }
}

fn protected_environment_port_error(error: ProtectedEnvironmentStoreError) -> ControlPortError {
    match error {
        ProtectedEnvironmentStoreError::Operation(StoreError::Operation(_)) => {
            ControlPortError::Unavailable
        }
        ProtectedEnvironmentStoreError::NotFound
        | ProtectedEnvironmentStoreError::AuthorityRejected
        | ProtectedEnvironmentStoreError::Conflict => ControlPortError::Conflict,
        ProtectedEnvironmentStoreError::Operation(_)
        | ProtectedEnvironmentStoreError::CorruptData => ControlPortError::Corrupt,
    }
}

/// Converts an exact private wire request into Store authority evidence.
///
/// It is intentionally independent of [`automata_ci_runner_control::RuntimeAuthorityIssuer`]:
/// that issuer's credentials are serialized to the durable command outbox,
/// whereas this object receives no bearer until the mTLS exchange itself.
pub(crate) struct ManagedSecretRuntimeAuthorityIssuer {
    repository: Arc<dyn ManagedSecretAuthorityRepository>,
    clock: Arc<dyn Clock>,
}

impl ManagedSecretRuntimeAuthorityIssuer {
    /// Constructs a value-free exact-authority issuer.
    #[must_use]
    pub(crate) const fn new(
        repository: Arc<dyn ManagedSecretAuthorityRepository>,
        clock: Arc<dyn Clock>,
    ) -> Self {
        Self { repository, clock }
    }

    async fn issue(
        &self,
        request: &ManagedSecretDeliveryRequest,
        machine: &AuthenticatedMachine,
    ) -> Result<ResolveManagedSecretAuthority, ManagedSecretAuthorityStoreError> {
        let observed_at = current_millis(self.clock.as_ref())
            .ok_or(ManagedSecretAuthorityStoreError::Unavailable)?;
        let (lease, runner_id, session_id, slot, run_id, job_id, digest, overlay_digest) =
            execution_coordinates(request.coordinates())
                .ok_or(ManagedSecretAuthorityStoreError::Unauthorized)?;
        let authenticated_machine = ManagedSecretDeliveryMachine::new(
            machine.external_identity().as_str(),
            automata_ci_core::Sha256Digest::from_bytes(*machine.certificate_sha256()),
        )
        .map_err(|_| ManagedSecretAuthorityStoreError::Unauthorized)?;
        let session = self
            .repository
            .resolve_managed_secret_delivery_session(
                ResolveManagedSecretDeliverySession::new(
                    session_id,
                    authenticated_machine.clone(),
                    observed_at,
                )
                .map_err(|_| ManagedSecretAuthorityStoreError::Unauthorized)?,
            )
            .await?
            .ok_or(ManagedSecretAuthorityStoreError::Unauthorized)?;
        if session.runner_id() != runner_id {
            return Err(ManagedSecretAuthorityStoreError::Unauthorized);
        }
        let scope_request = ResolveManagedSecretExecutionScope::new(
            run_id,
            job_id,
            lease.clone(),
            session,
            slot,
            digest,
            observed_at,
        )
        .map_err(|_| ManagedSecretAuthorityStoreError::Unauthorized)?;
        let scope = self
            .repository
            .resolve_managed_secret_execution_scope(scope_request)
            .await?;
        let bindings =
            managed_bindings(request).ok_or(ManagedSecretAuthorityStoreError::Unauthorized)?;
        let operation_id = derived_operation_id(
            &scope,
            run_id,
            job_id,
            &lease,
            session,
            slot,
            digest,
            overlay_digest,
            &bindings,
        )
        .ok_or(ManagedSecretAuthorityStoreError::Unauthorized)?;
        let verifier = automata_ci_core::Sha256Digest::from_bytes(
            Sha256::digest(request.expose_bearer()).into(),
        );
        let delivery =
            ManagedSecretDeliveryProposal::new(operation_id, request.credential_key_id(), verifier)
                .map_err(|_| ManagedSecretAuthorityStoreError::Unauthorized)?;
        ResolveManagedSecretAuthority::new(
            scope.tenant().clone(),
            scope.repository_id(),
            run_id,
            job_id,
            lease,
            session,
            slot,
            digest,
            bindings,
            observed_at,
        )
        .map(|authority| {
            authority
                .with_delivery(delivery)
                .with_authenticated_machine(authenticated_machine)
        })
        .map_err(|_| ManagedSecretAuthorityStoreError::Unauthorized)
    }

    async fn reserve(
        &self,
        request: &ManagedSecretDeliveryRequest,
        machine: &AuthenticatedMachine,
    ) -> Result<
        (ResolveManagedSecretAuthority, ManagedSecretAuthorityReceipt),
        ManagedSecretAuthorityStoreError,
    > {
        let authority = self.issue(request, machine).await?;
        let receipt = self
            .repository
            .resolve_managed_secret_authority(authority.clone())
            .await?;
        Ok((authority, receipt))
    }
}

impl fmt::Debug for ManagedSecretRuntimeAuthorityIssuer {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ManagedSecretRuntimeAuthorityIssuer")
            .field("repository", &"ManagedSecretAuthorityRepository(..)")
            .field("clock", &self.clock)
            .finish()
    }
}

/// Built-in-only mTLS handler for value-bearing managed-secret delivery.
///
/// Constructing it requires an operational custody verifier and one provider
/// whose ID is exactly `builtin`; no provider registry/default or generic
/// proxy is accepted at this boundary.
pub(crate) struct ManagedSecretRunnerHandler {
    authority: ManagedSecretRuntimeAuthorityIssuer,
    provider: Arc<dyn SecretProvider>,
    custody: Arc<SecretCustodyVerifier>,
}

impl ManagedSecretRunnerHandler {
    /// Creates the handler only for the operational built-in provider.
    pub(crate) fn new(
        repository: Arc<dyn ManagedSecretAuthorityRepository>,
        provider: Arc<dyn SecretProvider>,
        custody: Arc<SecretCustodyVerifier>,
        clock: Arc<dyn Clock>,
    ) -> Option<Self> {
        (provider.provider_id().as_str() == BUILTIN_SECRET_PROVIDER_ID).then_some(Self {
            authority: ManagedSecretRuntimeAuthorityIssuer::new(repository, clock),
            provider,
            custody,
        })
    }

    async fn fetch(
        &self,
        request: &ManagedSecretDeliveryRequest,
        machine: &AuthenticatedMachine,
    ) -> Result<ManagedSecretDeliveryResponse, ApplicationError> {
        if request.credential_key_id() != MANAGED_SECRET_DELIVERY_CREDENTIAL_KEY_ID {
            return Err(forbidden());
        }
        let (_authority, receipt) = self
            .authority
            .reserve(request, machine)
            .await
            .map_err(map_store_error)?;
        self.custody.verify().await.map_err(|_| unavailable())?;
        let mut values = Vec::with_capacity(receipt.bindings().len());
        for binding in receipt.bindings() {
            values.push(self.resolve_builtin(&receipt, binding).await?);
        }
        exact_values(request, &values)
            .then_some(ManagedSecretDeliveryResponse::Values(values))
            .ok_or_else(forbidden)
    }

    async fn acknowledge(
        &self,
        request: &ManagedSecretDeliveryRequest,
        machine: &AuthenticatedMachine,
    ) -> Result<ManagedSecretDeliveryResponse, ApplicationError> {
        if request.credential_key_id() != MANAGED_SECRET_DELIVERY_CREDENTIAL_KEY_ID {
            return Err(forbidden());
        }
        self.custody.verify().await.map_err(|_| unavailable())?;
        let authority = self
            .authority
            .issue(request, machine)
            .await
            .map_err(map_store_error)?;
        let acknowledgement =
            AcknowledgeManagedSecretDelivery::new(authority).map_err(|_| forbidden())?;
        self.authority
            .repository
            .acknowledge_managed_secret_delivery(acknowledgement)
            .await
            .map_err(map_store_error)?;
        Ok(ManagedSecretDeliveryResponse::Acknowledged)
    }

    async fn resolve_builtin(
        &self,
        receipt: &ManagedSecretAuthorityReceipt,
        binding: &ManagedSecretAuthorityBinding,
    ) -> Result<ManagedSecretDeliveryValue, ApplicationError> {
        if binding.provider_id().as_str() != BUILTIN_SECRET_PROVIDER_ID
            || binding.mode() != ManagedSecretGrantMode::ReadableSecret
            || binding.provider_supports_dynamic_leases()
        {
            return Err(forbidden());
        }
        let tenant =
            TenantScopeId::new(receipt.tenant().as_str().to_owned()).map_err(|_| forbidden())?;
        let repository =
            RepositoryScopeId::new(receipt.repository_id().as_uuid().hyphenated().to_string())
                .map_err(|_| forbidden())?;
        let secret_scope = match binding.scope() {
            ManagedSecretScope::Tenant => SecretScope::tenant(tenant.clone()),
            ManagedSecretScope::Repository => {
                SecretScope::repository(tenant.clone(), repository.clone())
            }
            ManagedSecretScope::Environment { environment_id } => SecretScope::environment(
                tenant.clone(),
                repository.clone(),
                EnvironmentScopeId::new(environment_id.hyphenated().to_string())
                    .map_err(|_| forbidden())?,
            ),
        };
        let workload_scope = match &secret_scope {
            SecretScope::Environment { .. } => secret_scope.clone(),
            SecretScope::Tenant { .. } | SecretScope::Repository { .. } => {
                SecretScope::repository(tenant.clone(), repository)
            }
        };
        let descriptor = SecretDescriptor::new(
            SecretId::new(binding.secret_id().as_uuid().hyphenated().to_string())
                .map_err(|_| forbidden())?,
            SecretName::new(binding.canonical_name()).map_err(|_| forbidden())?,
            secret_scope,
        );
        let request_id = ProviderRequestId::new(format!(
            "managed-delivery:{}:{}",
            receipt.operation_id().as_uuid().hyphenated(),
            binding.grant_id().as_uuid().hyphenated(),
        ))
        .map_err(|_| forbidden())?;
        let workload = WorkloadContext::new(
            WorkloadId::new(format!(
                "managed-delivery:{}",
                receipt.lease().attempt_id().as_uuid().hyphenated(),
            ))
            .map_err(|_| forbidden())?,
            workload_scope,
        )
        .map_err(|_| forbidden())?;
        let provider_request = ResolveSecretVersionRequest::new(
            ProviderOperationContext::new(tenant, request_id),
            workload,
            descriptor,
            ProviderSecretLocator::new(binding.secret_id().as_uuid().hyphenated().to_string())
                .map_err(|_| forbidden())?,
            ProviderVersionId::new(binding.version_id().as_uuid().hyphenated().to_string())
                .map_err(|_| forbidden())?,
        )
        .map_err(|_| forbidden())?;
        let resolved = self
            .provider
            .resolve_version(provider_request)
            .await
            .map_err(|_| unavailable())?;
        if resolved.version().as_str() != binding.version_id().as_uuid().hyphenated().to_string()
            || resolved.lease().is_some()
        {
            return Err(forbidden());
        }
        let value = std::str::from_utf8(resolved.value().expose_secret())
            .map_err(|_| forbidden())?
            .as_bytes()
            .to_vec();
        ManagedSecretDeliveryValue::new(
            binding.grant_id().as_uuid().hyphenated().to_string(),
            binding.version_id().as_uuid().hyphenated().to_string(),
            value,
        )
        .map_err(|_| forbidden())
    }
}

impl fmt::Debug for ManagedSecretRunnerHandler {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ManagedSecretRunnerHandler")
            .field("authority", &self.authority)
            .field("provider", &"builtin")
            .field("custody", &self.custody)
            .finish()
    }
}

impl RunnerEphemeralHandler for ManagedSecretRunnerHandler {
    fn handle(&self, request: AuthenticatedRunnerEphemeralRequest) -> EphemeralHandlerFuture<'_> {
        Box::pin(async move {
            if request.cancellation_token().is_cancelled() {
                return Err(unavailable());
            }
            let decoded = ManagedSecretDeliveryRequest::decode(request.expose_body())
                .map_err(|_| forbidden())?;
            let response = match decoded.operation() {
                ManagedSecretDeliveryOperation::Fetch => {
                    self.fetch(&decoded, request.machine()).await?
                }
                ManagedSecretDeliveryOperation::Acknowledge => {
                    self.acknowledge(&decoded, request.machine()).await?
                }
            };
            if request.cancellation_token().is_cancelled() {
                return Err(unavailable());
            }
            let body = response.encode().map_err(|_| forbidden())?;
            RunnerEphemeralReply::new(body)
        })
    }
}

fn execution_coordinates(
    value: ManagedSecretDeliveryCoordinates,
) -> Option<(
    Lease,
    RunnerId,
    RunnerSessionId,
    StableRunnerSlot,
    RunId,
    JobId,
    automata_ci_core::Sha256Digest,
    automata_ci_core::Sha256Digest,
)> {
    let runner = RunnerId::from_uuid(Uuid::from_bytes(value.runner_id));
    let session = RunnerSessionId::from_uuid(Uuid::from_bytes(value.session_id));
    let lease = Lease::new(
        LeaseId::from_uuid(Uuid::from_bytes(value.lease_id)),
        AttemptId::from_uuid(Uuid::from_bytes(value.attempt_id)),
        runner,
        FencingToken::new(value.fencing_token).ok()?,
        UnixMillis::new(value.lease_issued_at_ms),
        UnixMillis::new(value.lease_expires_at_ms),
    )
    .ok()?;
    Some((
        lease,
        runner,
        session,
        StableRunnerSlot::new(value.slot).ok()?,
        RunId::from_uuid(Uuid::from_bytes(value.run_id)),
        JobId::from_uuid(Uuid::from_bytes(value.job_id)),
        automata_ci_core::Sha256Digest::from_bytes(value.runtime_context_digest),
        automata_ci_core::Sha256Digest::from_bytes(value.binding_overlay_digest),
    ))
}

/// Derives a retry-stable delivery identity after the Store owns the live
/// session generation and epoch. The runner never supplies this identity;
/// every component is either the exact lease/context binding or server-derived
/// session/scope evidence that the Store rechecks while reserving the row.
#[allow(clippy::too_many_arguments)]
fn derived_operation_id(
    scope: &ManagedSecretExecutionScope,
    run_id: RunId,
    job_id: JobId,
    lease: &Lease,
    session: RunnerSessionFence,
    slot: StableRunnerSlot,
    runtime_context_digest: automata_ci_core::Sha256Digest,
    binding_overlay_digest: automata_ci_core::Sha256Digest,
    bindings: &ManagedSecretBindingSet,
) -> Option<ManagedSecretDeliveryOperationId> {
    let mut digest = Sha256::new();
    digest.update(b"automata/server/managed-secret-delivery-operation:v2\0");
    let tenant = scope.tenant().as_str().as_bytes();
    digest.update(u16::try_from(tenant.len()).ok()?.to_be_bytes());
    digest.update(tenant);
    digest.update(scope.repository_id().as_uuid().as_bytes());
    digest.update(run_id.as_uuid().as_bytes());
    digest.update(job_id.as_uuid().as_bytes());
    digest.update(lease.attempt_id().as_uuid().as_bytes());
    digest.update(lease.lease_id().as_uuid().as_bytes());
    digest.update(lease.runner_id().as_uuid().as_bytes());
    digest.update(lease.fencing_token().get().to_be_bytes());
    digest.update(lease.issued_at().get().to_be_bytes());
    digest.update(lease.expires_at().get().to_be_bytes());
    digest.update(session.runner_id().as_uuid().as_bytes());
    digest.update(session.session_id().as_uuid().as_bytes());
    digest.update(session.runner_generation().get().to_be_bytes());
    digest.update(session.session_epoch().get().to_be_bytes());
    digest.update(slot.get().to_be_bytes());
    digest.update(runtime_context_digest.as_bytes());
    digest.update(binding_overlay_digest.as_bytes());
    for (grant_id, version_id) in bindings.entries() {
        digest.update(grant_id.as_uuid().as_bytes());
        digest.update(version_id.as_uuid().as_bytes());
    }
    let mut bytes: [u8; 16] = digest.finalize()[..16].try_into().ok()?;
    // `ManagedSecretDeliveryOperationId` reserves nil only as a sentinel.
    // Avoid a digest/sentinel collision without reintroducing a caller-owned
    // operation identity.
    bytes[0] |= 1;
    ManagedSecretDeliveryOperationId::from_uuid(Uuid::from_bytes(bytes)).ok()
}

fn managed_bindings(request: &ManagedSecretDeliveryRequest) -> Option<ManagedSecretBindingSet> {
    request
        .bindings()
        .iter()
        .map(|binding| {
            Some(ManagedSecretBinding::new(
                SecretWorkloadGrantId::from_uuid(Uuid::parse_str(binding.binding_id()).ok()?)
                    .ok()?,
                RepositorySecretVersionId::from_uuid(Uuid::parse_str(binding.version_id()).ok()?)
                    .ok()?,
            ))
        })
        .collect::<Option<Vec<_>>>()
        .and_then(|bindings| ManagedSecretBindingSet::new(bindings).ok())
}

fn exact_values(
    request: &ManagedSecretDeliveryRequest,
    values: &[ManagedSecretDeliveryValue],
) -> bool {
    request.bindings().len() == values.len()
        && request
            .bindings()
            .iter()
            .zip(values)
            .all(|(binding, value)| {
                binding.binding_id() == value.binding_id()
                    && binding.version_id() == value.version_id()
            })
}

fn current_millis(clock: &dyn Clock) -> Option<UnixMillis> {
    i64::try_from(clock.now().as_seconds())
        .ok()?
        .checked_mul(1_000)
        .map(UnixMillis::new)
}

const fn forbidden() -> ApplicationError {
    ApplicationError::new(ApplicationErrorKind::Forbidden)
}

const fn unavailable() -> ApplicationError {
    ApplicationError::new(ApplicationErrorKind::Unavailable)
}

const fn map_store_error(error: ManagedSecretAuthorityStoreError) -> ApplicationError {
    match error {
        ManagedSecretAuthorityStoreError::Unauthorized => forbidden(),
        ManagedSecretAuthorityStoreError::Indeterminate
        | ManagedSecretAuthorityStoreError::ResourceExhausted
        | ManagedSecretAuthorityStoreError::CorruptData
        | ManagedSecretAuthorityStoreError::Unavailable => unavailable(),
    }
}
