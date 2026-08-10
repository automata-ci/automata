//! Product orchestration for encrypted repository-secret mutations.
//!
//! The durable repository commits a value-free intent before this service
//! crosses the provider plaintext boundary. A fresh actor timestamp is then
//! used to reauthorize the exact, value-free provider receipt.

use std::{fmt, sync::Arc};

use async_trait::async_trait;
use automata_ci_auth::{management::ManagementActor, time::Clock};
use automata_ci_core::RunId;
use automata_ci_secret::{
    CreateSecretVersionRequest, CreatedSecretVersion, ExistingSecretVersion, ProviderCapability,
    ProviderErrorKind, ProviderOperationContext, ProviderRequestId, ProviderSecretLocator,
    ProviderVersionId, ReconcileCreateSecretVersionOutcome, ReconcileCreateSecretVersionRequest,
    RepositoryScopeId, SecretAtRestProtection, SecretDescriptor, SecretId, SecretName,
    SecretProvider, SecretProviderId, SecretProviderRegistry, SecretScope, SecretValue,
    TenantScopeId,
};
use automata_ci_store::{
    ActivateBuiltinSecretProvider, ActivateBuiltinSecretProviderOutcome,
    BUILTIN_SECRET_PROVIDER_ID, BuiltinRepositorySecretVersion,
    ConfirmRepositorySecretVersionMutation, ConfirmRepositorySecretVersionMutationOutcome,
    DeleteRepositorySecret, DeleteRepositorySecretOutcome, ListRepositorySecrets,
    ListRepositorySecretsOutcome, ManagedSecretProviderId, RepositoryId, RepositorySecretId,
    RepositorySecretManagementRepository, RepositorySecretMutationKind, RepositorySecretName,
    RepositorySecretProviderMutationResult, RepositorySecretVersionId,
    RepositorySecretVersionMutationReceipt, ReserveRepositorySecretVersionMutation,
    ReserveRepositorySecretVersionMutationOutcome, SECRET_MUTATION_CONFIRMATION_TTL_MILLIS,
    SecretManagementRepositoryError,
};

use crate::app::secret_api::{
    RepositorySecretApiBackend, RepositorySecretMutationOutcome, SecretApiBackendError,
    SecretIngressValue,
};
use crate::server::secret_custody::SecretCustodyVerifier;

/// Operational composition of durable management and one exact provider registry.
pub(crate) struct OperationalRepositorySecretBackend {
    repository: Arc<dyn RepositorySecretManagementRepository>,
    providers: Arc<SecretProviderRegistry>,
    custody: Arc<SecretCustodyVerifier>,
    clock: Arc<dyn Clock>,
}

impl OperationalRepositorySecretBackend {
    /// Constructs the service only for the exact encrypted built-in registry contract.
    pub(crate) fn new(
        repository: Arc<dyn RepositorySecretManagementRepository>,
        providers: Arc<SecretProviderRegistry>,
        custody: Arc<SecretCustodyVerifier>,
        clock: Arc<dyn Clock>,
    ) -> Result<Self, SecretApiBackendError> {
        if !valid_builtin_registry(&providers) {
            return Err(SecretApiBackendError::InvalidRequest);
        }
        Ok(Self {
            repository,
            providers,
            custody,
            clock,
        })
    }

    fn fresh_actor(&self, actor: &ManagementActor) -> ManagementActor {
        ManagementActor::new(
            actor.tenant_id().clone(),
            actor.principal_id().clone(),
            actor.session_id().clone(),
            actor.authorization_revision(),
            actor.request_id().cloned(),
            self.clock.now(),
        )
    }

    async fn create_provider_version(
        &self,
        actor: &ManagementActor,
        reservation: &automata_ci_store::RepositorySecretVersionMutationReservation,
        value: SecretIngressValue,
    ) -> Result<ProviderCreateAttempt, ProviderCallError> {
        let provider = exact_provider(&self.providers, reservation.provider_id())?;
        self.custody
            .verify()
            .await
            .map_err(|_| ProviderCallError::Unavailable)?;
        let intent = ProviderCreateIntent::new(
            actor.tenant_id().as_str(),
            reservation.provider_create_request_id(),
            reservation.secret_id(),
            reservation.repository_id(),
            reservation.name(),
            reservation.expected_predecessor(),
        )?;
        let value = SecretValue::new(value.into_bytes()).map_err(|_| ProviderCallError::Invalid)?;
        let request = intent.into_create(value)?;
        let created = match provider.create_version(request).await {
            Ok(value) => value,
            Err(error) if error.kind() == ProviderErrorKind::Conflict => {
                return Ok(ProviderCreateAttempt::CasLost);
            }
            Err(error) => {
                return Ok(ProviderCreateAttempt::ReconcileRequired(
                    provider_call_error(error.kind()),
                ));
            }
        };
        match created_builtin_target(
            reservation.secret_id(),
            reservation.reserved_version_number(),
            &created,
        ) {
            Ok(target) => Ok(ProviderCreateAttempt::Created(target)),
            Err(error) => Ok(ProviderCreateAttempt::ReconcileRequired(error)),
        }
    }

    async fn reconcile_provider_version(
        &self,
        actor: &ManagementActor,
        reservation: &automata_ci_store::RepositorySecretVersionMutationReservation,
    ) -> Result<Option<BuiltinRepositorySecretVersion>, ProviderCallError> {
        let provider = exact_provider(&self.providers, reservation.provider_id())?;
        self.custody
            .verify()
            .await
            .map_err(|_| ProviderCallError::Unavailable)?;
        let request = ProviderCreateIntent::new(
            actor.tenant_id().as_str(),
            reservation.provider_create_request_id(),
            reservation.secret_id(),
            reservation.repository_id(),
            reservation.name(),
            reservation.expected_predecessor(),
        )?
        .into_reconcile()?;
        match provider.reconcile_create_version(request).await {
            Ok(ReconcileCreateSecretVersionOutcome::AlreadyCommitted(created)) => {
                created_builtin_target(
                    reservation.secret_id(),
                    reservation.reserved_version_number(),
                    &created,
                )
                .map(Some)
            }
            Ok(ReconcileCreateSecretVersionOutcome::DefinitivelyNotCommitted) => Ok(None),
            Err(error) => Err(provider_call_error(error.kind())),
        }
    }
}

/// Reconstructs the original create and reconciliation requests from one exact durable intent.
pub(crate) struct ProviderCreateIntent {
    context: ProviderOperationContext,
    descriptor: SecretDescriptor,
    expected_predecessor: Option<ExistingSecretVersion>,
}

impl ProviderCreateIntent {
    /// Builds one value-free intent shared by create and reconciliation.
    pub(crate) fn new(
        tenant_id: &str,
        request_id: &str,
        secret_id: RepositorySecretId,
        repository_id: RepositoryId,
        name: &RepositorySecretName,
        expected_predecessor: Option<BuiltinRepositorySecretVersion>,
    ) -> Result<Self, ProviderCallError> {
        let tenant =
            TenantScopeId::new(tenant_id.to_owned()).map_err(|_| ProviderCallError::CorruptData)?;
        let request_id = ProviderRequestId::new(request_id.to_owned())
            .map_err(|_| ProviderCallError::CorruptData)?;
        let context = ProviderOperationContext::new(tenant.clone(), request_id);
        let repository = RepositoryScopeId::new(repository_id.as_uuid().hyphenated().to_string())
            .map_err(|_| ProviderCallError::CorruptData)?;
        let scope = SecretScope::repository(tenant, repository);
        let provider_secret_id = SecretId::new(secret_id.as_uuid().hyphenated().to_string())
            .map_err(|_| ProviderCallError::CorruptData)?;
        let name = SecretName::new(name.as_str()).map_err(|_| ProviderCallError::CorruptData)?;
        let descriptor = SecretDescriptor::new(provider_secret_id, name, scope);
        let expected_predecessor = expected_predecessor
            .map(|predecessor| {
                Ok(ExistingSecretVersion::new(
                    ProviderSecretLocator::new(
                        predecessor.secret_id().as_uuid().hyphenated().to_string(),
                    )
                    .map_err(|_| ProviderCallError::CorruptData)?,
                    ProviderVersionId::new(
                        predecessor.version_id().as_uuid().hyphenated().to_string(),
                    )
                    .map_err(|_| ProviderCallError::CorruptData)?,
                ))
            })
            .transpose()?;
        Ok(Self {
            context,
            descriptor,
            expected_predecessor,
        })
    }

    fn into_create(
        self,
        value: SecretValue,
    ) -> Result<CreateSecretVersionRequest, ProviderCallError> {
        CreateSecretVersionRequest::new(
            self.context,
            self.descriptor,
            self.expected_predecessor,
            value,
        )
        .map_err(|_| ProviderCallError::CorruptData)
    }

    /// Consumes the shared intent as the value-free reconciliation request.
    pub(crate) fn into_reconcile(
        self,
    ) -> Result<ReconcileCreateSecretVersionRequest, ProviderCallError> {
        ReconcileCreateSecretVersionRequest::new(
            self.context,
            self.descriptor,
            self.expected_predecessor,
        )
        .map_err(|_| ProviderCallError::CorruptData)
    }
}

/// Looks up the exact durable provider without consulting the registry default.
pub(crate) fn exact_provider(
    providers: &SecretProviderRegistry,
    provider_id: &ManagedSecretProviderId,
) -> Result<Arc<dyn SecretProvider>, ProviderCallError> {
    let provider_id = SecretProviderId::new(provider_id.as_str().to_owned())
        .map_err(|_| ProviderCallError::CorruptData)?;
    providers
        .provider(&provider_id)
        .ok_or(ProviderCallError::Unavailable)
}

/// Validates the current one-provider built-in runtime contract.
pub(crate) fn valid_builtin_registry(providers: &SecretProviderRegistry) -> bool {
    let Ok(builtin_id) = SecretProviderId::new(BUILTIN_SECRET_PROVIDER_ID) else {
        return false;
    };
    if providers.len() != 1 || providers.default_provider_id() != &builtin_id {
        return false;
    }
    let Some(provider) = providers.provider(&builtin_id) else {
        return false;
    };
    provider.provider_id() == &builtin_id
        && provider.at_rest_protection() == SecretAtRestProtection::AutomataEnvelope
        && [
            ProviderCapability::CreateVersion,
            ProviderCapability::ReconcileCreateVersion,
            ProviderCapability::DestroyVersion,
        ]
        .into_iter()
        .all(|capability| provider.capabilities().supports(capability))
}

/// Converts one provider result into the exact built-in durable identity.
pub(crate) fn created_builtin_target(
    expected_secret_id: RepositorySecretId,
    reserved_version_number: u64,
    created: &CreatedSecretVersion,
) -> Result<BuiltinRepositorySecretVersion, ProviderCallError> {
    let locator =
        canonical_uuid(created.locator().as_str()).ok_or(ProviderCallError::CorruptData)?;
    if locator.as_uuid() != expected_secret_id.as_uuid() {
        return Err(ProviderCallError::CorruptData);
    }
    let version =
        canonical_uuid(created.version().as_str()).ok_or(ProviderCallError::CorruptData)?;
    let version_id = RepositorySecretVersionId::from_uuid(version.as_uuid())
        .map_err(|_| ProviderCallError::CorruptData)?;
    BuiltinRepositorySecretVersion::new(expected_secret_id, version_id, reserved_version_number)
        .map_err(|_| ProviderCallError::CorruptData)
}

const fn provider_call_error(kind: ProviderErrorKind) -> ProviderCallError {
    match kind {
        ProviderErrorKind::RateLimited | ProviderErrorKind::Unavailable => {
            ProviderCallError::Unavailable
        }
        ProviderErrorKind::InvalidRequest => ProviderCallError::Invalid,
        ProviderErrorKind::Unsupported
        | ProviderErrorKind::Unauthorized
        | ProviderErrorKind::Forbidden
        | ProviderErrorKind::NotFound
        | ProviderErrorKind::Conflict
        | ProviderErrorKind::IntegrityFailure
        | ProviderErrorKind::InvalidResponse => ProviderCallError::CorruptData,
    }
}

impl fmt::Debug for OperationalRepositorySecretBackend {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OperationalRepositorySecretBackend")
            .field("repository", &self.repository)
            .field("providers", &self.providers)
            .field("custody", &self.custody)
            .field("clock", &self.clock)
            .finish()
    }
}

#[async_trait]
impl RepositorySecretApiBackend for OperationalRepositorySecretBackend {
    async fn list(
        &self,
        request: ListRepositorySecrets,
    ) -> Result<ListRepositorySecretsOutcome, SecretApiBackendError> {
        let repository_id = request.repository_id();
        let after = request.after();
        let limit = request.limit().get();
        let outcome = self
            .repository
            .list_repository_secrets(request)
            .await
            .map_err(map_repository_error)?;
        if let ListRepositorySecretsOutcome::Found(page) = &outcome
            && !metadata_page_matches(repository_id, after, limit, page)
        {
            return Err(SecretApiBackendError::CorruptData);
        }
        Ok(outcome)
    }

    async fn mutate(
        &self,
        request: ReserveRepositorySecretVersionMutation,
        value: SecretIngressValue,
    ) -> Result<RepositorySecretMutationOutcome, SecretApiBackendError> {
        self.custody
            .verify()
            .await
            .map_err(|_| SecretApiBackendError::Unavailable)?;
        let actor = request.actor().clone();
        let mutation_id = request.mutation_id();
        let expected_reservation = request.clone();
        let reservation_outcome = self
            .repository
            .reserve_repository_secret_version_mutation(request)
            .await
            .map_err(map_repository_error)?;
        let prepared = match prepare_provider_mutation(&expected_reservation, reservation_outcome)?
        {
            PreparedRepositorySecretMutation::Create(reservation) => {
                PreparedProviderOperation::Create(reservation, value)
            }
            PreparedRepositorySecretMutation::Reconcile(reservation) => {
                drop(value);
                PreparedProviderOperation::Reconcile(reservation)
            }
            PreparedRepositorySecretMutation::Complete(outcome) => return Ok(outcome),
        };
        let reservation = prepared.reservation();
        let provider_actor = self.fresh_actor(&actor);
        let provider_now_ms = actor_millis(&provider_actor)?;
        if provider_now_ms >= reservation.confirmation_deadline().get() {
            return Ok(RepositorySecretMutationOutcome::Cancelled);
        }
        let provider_result = match prepared {
            PreparedProviderOperation::Create(reservation, value) => {
                match self
                    .create_provider_version(&provider_actor, &reservation, value)
                    .await
                {
                    Ok(ProviderCreateAttempt::Created(target)) => {
                        RepositorySecretProviderMutationResult::BuiltinCreated(target)
                    }
                    Ok(ProviderCreateAttempt::CasLost) => {
                        RepositorySecretProviderMutationResult::CasLost
                    }
                    Ok(ProviderCreateAttempt::ReconcileRequired(original_failure)) => {
                        match self
                            .reconcile_provider_version(&provider_actor, &reservation)
                            .await
                        {
                            Ok(Some(target)) => {
                                RepositorySecretProviderMutationResult::BuiltinCreated(target)
                            }
                            Ok(None) => {
                                return open_reservation_failure(original_failure);
                            }
                            Err(error) => return open_reservation_failure(error),
                        }
                    }
                    Err(error) => return open_reservation_failure(error),
                }
            }
            PreparedProviderOperation::Reconcile(reservation) => {
                match self
                    .reconcile_provider_version(&provider_actor, &reservation)
                    .await
                {
                    Ok(Some(target)) => {
                        RepositorySecretProviderMutationResult::BuiltinCreated(target)
                    }
                    Ok(None) => {
                        return Ok(RepositorySecretMutationOutcome::ProviderUnavailable);
                    }
                    Err(error) => return open_reservation_failure(error),
                }
            }
        };
        let confirm = ConfirmRepositorySecretVersionMutation::new(
            self.fresh_actor(&actor),
            mutation_id,
            provider_result,
        );
        self.custody
            .verify()
            .await
            .map_err(|_| SecretApiBackendError::Unavailable)?;
        let outcome = self
            .repository
            .confirm_repository_secret_version_mutation(confirm)
            .await
            .map_err(map_repository_error)?;
        confirmed_mutation_outcome(mutation_id, provider_result, &outcome)
    }

    async fn delete(
        &self,
        request: DeleteRepositorySecret,
    ) -> Result<DeleteRepositorySecretOutcome, SecretApiBackendError> {
        self.custody
            .verify()
            .await
            .map_err(|_| SecretApiBackendError::Unavailable)?;
        let secret_id = request.secret_id();
        let outcome = self
            .repository
            .delete_repository_secret(request)
            .await
            .map_err(map_repository_error)?;
        if let DeleteRepositorySecretOutcome::Deleted(receipt) = &outcome
            && receipt.secret_id() != secret_id
        {
            return Err(SecretApiBackendError::CorruptData);
        }
        Ok(outcome)
    }

    async fn activate_builtin(
        &self,
        request: ActivateBuiltinSecretProvider,
    ) -> Result<ActivateBuiltinSecretProviderOutcome, SecretApiBackendError> {
        self.custody
            .verify()
            .await
            .map_err(|_| SecretApiBackendError::Unavailable)?;
        // Construction has already proved the runtime encryption/capability
        // contract. Provider health is durable-state aware and is necessarily
        // unavailable while the seeded row is still unconfigured, so probing
        // it here would make first activation circular.
        let actor = request.actor().clone();
        let expected_revision = request.expected_revision();
        let request =
            ActivateBuiltinSecretProvider::new(self.fresh_actor(&actor), expected_revision);
        let outcome = self
            .repository
            .activate_builtin_secret_provider(request)
            .await
            .map_err(map_repository_error)?;
        if !activation_outcome_matches(expected_revision, &outcome) {
            return Err(SecretApiBackendError::CorruptData);
        }
        Ok(outcome)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ProviderCallError {
    Invalid,
    Unavailable,
    CorruptData,
}

enum ProviderCreateAttempt {
    Created(BuiltinRepositorySecretVersion),
    CasLost,
    ReconcileRequired(ProviderCallError),
}

enum PreparedRepositorySecretMutation {
    Create(automata_ci_store::RepositorySecretVersionMutationReservation),
    Reconcile(automata_ci_store::RepositorySecretVersionMutationReservation),
    Complete(RepositorySecretMutationOutcome),
}

enum PreparedProviderOperation {
    Create(
        automata_ci_store::RepositorySecretVersionMutationReservation,
        SecretIngressValue,
    ),
    Reconcile(automata_ci_store::RepositorySecretVersionMutationReservation),
}

impl PreparedProviderOperation {
    fn reservation(&self) -> &automata_ci_store::RepositorySecretVersionMutationReservation {
        match self {
            Self::Create(reservation, _) | Self::Reconcile(reservation) => reservation,
        }
    }
}

fn open_reservation_failure(
    error: ProviderCallError,
) -> Result<RepositorySecretMutationOutcome, SecretApiBackendError> {
    match error {
        ProviderCallError::Unavailable => Ok(RepositorySecretMutationOutcome::ProviderUnavailable),
        ProviderCallError::Invalid => Err(SecretApiBackendError::InvalidRequest),
        ProviderCallError::CorruptData => Err(SecretApiBackendError::CorruptData),
    }
}

fn prepare_provider_mutation(
    request: &ReserveRepositorySecretVersionMutation,
    outcome: ReserveRepositorySecretVersionMutationOutcome,
) -> Result<PreparedRepositorySecretMutation, SecretApiBackendError> {
    let reservation = match outcome {
        ReserveRepositorySecretVersionMutationOutcome::FreshReservation(value) => {
            if value.provider_id().as_str() != BUILTIN_SECRET_PROVIDER_ID {
                return Ok(completed_mutation(
                    RepositorySecretMutationOutcome::ProviderUnavailable,
                ));
            }
            if !reservation_matches_request(request, &value) {
                return Err(SecretApiBackendError::CorruptData);
            }
            return Ok(PreparedRepositorySecretMutation::Create(value));
        }
        ReserveRepositorySecretVersionMutationOutcome::ReconcileRequired(value) => value,
        ReserveRepositorySecretVersionMutationOutcome::Applied(receipt)
            if replay_receipt_matches(request, receipt) =>
        {
            return Ok(PreparedRepositorySecretMutation::Complete(
                RepositorySecretMutationOutcome::Applied,
            ));
        }
        ReserveRepositorySecretVersionMutationOutcome::AppliedThenSuperseded(receipt)
            if replay_receipt_matches(request, receipt) =>
        {
            return Ok(PreparedRepositorySecretMutation::Complete(
                RepositorySecretMutationOutcome::AppliedThenSuperseded,
            ));
        }
        ReserveRepositorySecretVersionMutationOutcome::AppliedThenDeleted(receipt)
            if replay_receipt_matches(request, receipt) =>
        {
            return Ok(PreparedRepositorySecretMutation::Complete(
                RepositorySecretMutationOutcome::AppliedThenDeleted,
            ));
        }
        ReserveRepositorySecretVersionMutationOutcome::Applied(_)
        | ReserveRepositorySecretVersionMutationOutcome::AppliedThenSuperseded(_)
        | ReserveRepositorySecretVersionMutationOutcome::AppliedThenDeleted(_) => {
            return Err(SecretApiBackendError::CorruptData);
        }
        ReserveRepositorySecretVersionMutationOutcome::CasLost => {
            return Ok(completed_mutation(RepositorySecretMutationOutcome::CasLost));
        }
        ReserveRepositorySecretVersionMutationOutcome::Cancelled
        | ReserveRepositorySecretVersionMutationOutcome::Expired => {
            return Ok(completed_mutation(
                RepositorySecretMutationOutcome::Cancelled,
            ));
        }
        ReserveRepositorySecretVersionMutationOutcome::Forbidden => {
            return Ok(completed_mutation(
                RepositorySecretMutationOutcome::Forbidden,
            ));
        }
        ReserveRepositorySecretVersionMutationOutcome::SessionStale => {
            return Ok(completed_mutation(
                RepositorySecretMutationOutcome::SessionStale,
            ));
        }
        ReserveRepositorySecretVersionMutationOutcome::NotFound => {
            return Ok(completed_mutation(
                RepositorySecretMutationOutcome::NotFound,
            ));
        }
        ReserveRepositorySecretVersionMutationOutcome::Conflict => {
            return Ok(completed_mutation(
                RepositorySecretMutationOutcome::Conflict,
            ));
        }
        ReserveRepositorySecretVersionMutationOutcome::RevisionConflict { .. } => {
            return Ok(completed_mutation(
                RepositorySecretMutationOutcome::RevisionConflict,
            ));
        }
        ReserveRepositorySecretVersionMutationOutcome::ProviderUnavailable => {
            return Ok(completed_mutation(
                RepositorySecretMutationOutcome::ProviderUnavailable,
            ));
        }
    };
    if reservation.provider_id().as_str() != BUILTIN_SECRET_PROVIDER_ID {
        return Ok(completed_mutation(
            RepositorySecretMutationOutcome::ProviderUnavailable,
        ));
    }
    if !reservation_matches_request(request, &reservation) {
        return Err(SecretApiBackendError::CorruptData);
    }
    Ok(PreparedRepositorySecretMutation::Reconcile(reservation))
}

fn completed_mutation(
    outcome: RepositorySecretMutationOutcome,
) -> PreparedRepositorySecretMutation {
    PreparedRepositorySecretMutation::Complete(outcome)
}

fn confirmed_mutation_outcome(
    mutation_id: automata_ci_store::RepositorySecretMutationId,
    provider_result: RepositorySecretProviderMutationResult,
    outcome: &ConfirmRepositorySecretVersionMutationOutcome,
) -> Result<RepositorySecretMutationOutcome, SecretApiBackendError> {
    match outcome {
        ConfirmRepositorySecretVersionMutationOutcome::Applied(receipt)
            if confirmation_receipt_matches(mutation_id, provider_result, *receipt) =>
        {
            Ok(RepositorySecretMutationOutcome::Applied)
        }
        ConfirmRepositorySecretVersionMutationOutcome::AppliedThenSuperseded(receipt)
            if confirmation_receipt_matches(mutation_id, provider_result, *receipt) =>
        {
            Ok(RepositorySecretMutationOutcome::AppliedThenSuperseded)
        }
        ConfirmRepositorySecretVersionMutationOutcome::AppliedThenDeleted(receipt)
            if confirmation_receipt_matches(mutation_id, provider_result, *receipt) =>
        {
            Ok(RepositorySecretMutationOutcome::AppliedThenDeleted)
        }
        ConfirmRepositorySecretVersionMutationOutcome::CasLost
            if provider_result == RepositorySecretProviderMutationResult::CasLost =>
        {
            Ok(RepositorySecretMutationOutcome::CasLost)
        }
        ConfirmRepositorySecretVersionMutationOutcome::Applied(_)
        | ConfirmRepositorySecretVersionMutationOutcome::AppliedThenSuperseded(_)
        | ConfirmRepositorySecretVersionMutationOutcome::AppliedThenDeleted(_)
        | ConfirmRepositorySecretVersionMutationOutcome::CasLost => {
            Err(SecretApiBackendError::CorruptData)
        }
        ConfirmRepositorySecretVersionMutationOutcome::Cancelled
        | ConfirmRepositorySecretVersionMutationOutcome::Expired => {
            Ok(RepositorySecretMutationOutcome::Cancelled)
        }
        ConfirmRepositorySecretVersionMutationOutcome::Forbidden => {
            Ok(RepositorySecretMutationOutcome::Forbidden)
        }
        ConfirmRepositorySecretVersionMutationOutcome::SessionStale => {
            Ok(RepositorySecretMutationOutcome::SessionStale)
        }
        ConfirmRepositorySecretVersionMutationOutcome::NotFound => {
            Ok(RepositorySecretMutationOutcome::NotFound)
        }
        ConfirmRepositorySecretVersionMutationOutcome::Conflict => {
            Ok(RepositorySecretMutationOutcome::Conflict)
        }
        ConfirmRepositorySecretVersionMutationOutcome::ProviderUnavailable => {
            Ok(RepositorySecretMutationOutcome::ProviderUnavailable)
        }
    }
}

fn metadata_page_matches(
    repository_id: automata_ci_store::RepositoryId,
    after: Option<automata_ci_store::RepositorySecretId>,
    limit: u16,
    page: &automata_ci_store::RepositorySecretMetadataPage,
) -> bool {
    let records = page.records();
    if records.len() > usize::from(limit)
        || records.iter().any(|record| {
            record.repository_id() != repository_id
                || after.is_some_and(|after| record.id() <= after)
                || record.created_at().get() < 0
                || record.updated_at() < record.created_at()
                || match record.state() {
                    automata_ci_store::RepositorySecretState::Provisioning => {
                        record.current_version_number().is_some()
                    }
                    automata_ci_store::RepositorySecretState::Active
                    | automata_ci_store::RepositorySecretState::Disabled => record
                        .current_version_number()
                        .is_none_or(|version| version == 0),
                }
        })
        || records.windows(2).any(|pair| pair[0].id() >= pair[1].id())
    {
        return false;
    }
    page.next_after().is_none_or(|cursor| {
        records.len() == usize::from(limit)
            && records.last().is_some_and(|record| record.id() == cursor)
    })
}

fn replay_receipt_matches(
    request: &ReserveRepositorySecretVersionMutation,
    receipt: RepositorySecretVersionMutationReceipt,
) -> bool {
    let committed = receipt.committed();
    receipt.mutation_id() == request.mutation_id()
        && committed.secret_id() == request.secret_id()
        && request
            .provider_id()
            .is_none_or(|provider| provider.as_str() == BUILTIN_SECRET_PROVIDER_ID)
        && (request.kind() != RepositorySecretMutationKind::Create
            || committed.version_number() == 1)
}

fn confirmation_receipt_matches(
    mutation_id: automata_ci_store::RepositorySecretMutationId,
    provider_result: RepositorySecretProviderMutationResult,
    receipt: RepositorySecretVersionMutationReceipt,
) -> bool {
    receipt.mutation_id() == mutation_id
        && match provider_result {
            RepositorySecretProviderMutationResult::BuiltinCreated(expected) => {
                receipt.committed() == expected
            }
            RepositorySecretProviderMutationResult::CasLost => false,
        }
}

fn activation_outcome_matches(
    expected_revision: automata_ci_auth::management::ManagementRevision,
    outcome: &ActivateBuiltinSecretProviderOutcome,
) -> bool {
    match outcome {
        ActivateBuiltinSecretProviderOutcome::Activated(metadata) => {
            metadata.state() == automata_ci_store::BuiltinSecretProviderState::Active
                && expected_revision
                    .value()
                    .checked_add(1)
                    .is_some_and(|revision| revision == metadata.revision().value())
                && metadata.updated_at().get() >= 0
        }
        ActivateBuiltinSecretProviderOutcome::AlreadyActive(metadata) => {
            metadata.state() == automata_ci_store::BuiltinSecretProviderState::Active
                && metadata.revision() == expected_revision
                && metadata.updated_at().get() >= 0
        }
        ActivateBuiltinSecretProviderOutcome::Forbidden
        | ActivateBuiltinSecretProviderOutcome::SessionStale
        | ActivateBuiltinSecretProviderOutcome::NotFound
        | ActivateBuiltinSecretProviderOutcome::RevisionConflict { .. } => true,
    }
}

fn reservation_matches_request(
    request: &ReserveRepositorySecretVersionMutation,
    reservation: &automata_ci_store::RepositorySecretVersionMutationReservation,
) -> bool {
    if reservation.mutation_id() != request.mutation_id()
        || reservation.secret_id() != request.secret_id()
        || reservation.repository_id() != request.repository_id()
        || reservation.name() != request.name()
        || reservation.kind() != request.kind()
        || request
            .provider_id()
            .is_some_and(|provider| provider != reservation.provider_id())
        || reservation.provider_create_request_id()
            != format!(
                "secret-version:{}",
                request.mutation_id().as_uuid().hyphenated()
            )
        || actor_millis(request.actor()).ok().and_then(|reserved_at| {
            reserved_at.checked_add(i64::try_from(SECRET_MUTATION_CONFIRMATION_TTL_MILLIS).ok()?)
        }) != Some(reservation.confirmation_deadline().get())
    {
        return false;
    }

    match request.kind() {
        RepositorySecretMutationKind::Create => {
            request.expected_revision().is_none()
                && reservation.reserved_revision().value() == 1
                && reservation.reserved_version_number() == 1
                && reservation.expected_predecessor().is_none()
        }
        RepositorySecretMutationKind::Replace => {
            request.expected_revision() == Some(reservation.reserved_revision())
                && reservation
                    .expected_predecessor()
                    .is_some_and(|predecessor| {
                        predecessor.secret_id() == request.secret_id()
                            && reservation.reserved_version_number() > predecessor.version_number()
                    })
        }
    }
}

fn actor_millis(actor: &ManagementActor) -> Result<i64, SecretApiBackendError> {
    actor
        .now()
        .as_seconds()
        .checked_mul(1_000)
        .and_then(|value| i64::try_from(value).ok())
        .ok_or(SecretApiBackendError::CorruptData)
}

fn map_repository_error(error: SecretManagementRepositoryError) -> SecretApiBackendError {
    match error {
        SecretManagementRepositoryError::InvalidRequest => SecretApiBackendError::InvalidRequest,
        SecretManagementRepositoryError::Unavailable => SecretApiBackendError::Unavailable,
        SecretManagementRepositoryError::CorruptData => SecretApiBackendError::CorruptData,
    }
}

fn canonical_uuid(value: &str) -> Option<RunId> {
    let parsed = value.parse::<RunId>().ok()?;
    (!parsed.as_uuid().is_nil() && parsed.to_string() == value).then_some(parsed)
}

#[cfg(test)]
mod tests {
    use std::sync::{
        Mutex,
        atomic::{AtomicU64, Ordering},
    };

    use automata_ci_auth::{
        human::{PrincipalId, TenantId},
        management::{ManagementRequestId, ManagementRevision},
        session::SessionId,
        time::UnixTimestamp,
    };
    use automata_ci_secret::{
        CreatedSecretVersion, DestroySecretVersionRequest, ProviderCapabilities, ProviderError,
        ProviderHealth, ProviderSecretLocator, ReconcileCreateSecretVersionRequest,
        ResolveSecretVersionRequest, ResolvedSecretVersion, SecretProviderId,
    };
    use automata_ci_store::{
        BuiltinSecretProviderMetadata, RepositoryId, RepositorySecretId, RepositorySecretMetadata,
        RepositorySecretMetadataPage, RepositorySecretMutationId, RepositorySecretName,
        RepositorySecretState, RepositorySecretVersionMutationReceipt,
        RepositorySecretVersionMutationReservation,
    };

    use super::*;

    const TENANT: &str = "tenant-a";
    const PRINCIPAL: &str = "10000000-0000-4000-8000-000000000001";
    const SESSION: &str = "20000000-0000-4000-8000-000000000002";
    const REPOSITORY: &str = "30000000-0000-4000-8000-000000000003";
    const SECRET: &str = "40000000-0000-4000-8000-000000000004";
    const MUTATION: &str = "50000000-0000-4000-8000-000000000005";
    const VERSION: &str = "60000000-0000-4000-8000-000000000006";
    const SECRET_VALUE: &[u8] = b"provider-bound-secret";

    #[derive(Debug)]
    struct MutableClock(Arc<AtomicU64>);

    impl Clock for MutableClock {
        fn now(&self) -> UnixTimestamp {
            UnixTimestamp::from_seconds(self.0.load(Ordering::SeqCst))
        }
    }

    #[derive(Debug)]
    struct FakeRepository {
        activation_time: AtomicU64,
        reserve_time: AtomicU64,
        confirm_time: AtomicU64,
        reservation_override: Mutex<Option<RepositorySecretVersionMutationReservation>>,
        replay_reservation: bool,
        confirmed: Mutex<Option<BuiltinRepositorySecretVersion>>,
    }

    impl Default for FakeRepository {
        fn default() -> Self {
            Self {
                activation_time: AtomicU64::new(0),
                reserve_time: AtomicU64::new(0),
                confirm_time: AtomicU64::new(0),
                reservation_override: Mutex::new(None),
                replay_reservation: false,
                confirmed: Mutex::new(None),
            }
        }
    }

    impl FakeRepository {
        fn with_reservation(reservation: RepositorySecretVersionMutationReservation) -> Self {
            Self {
                reservation_override: Mutex::new(Some(reservation)),
                ..Self::default()
            }
        }

        fn with_replay_reservation(
            reservation: RepositorySecretVersionMutationReservation,
        ) -> Self {
            Self {
                reservation_override: Mutex::new(Some(reservation)),
                replay_reservation: true,
                ..Self::default()
            }
        }
    }

    #[async_trait]
    impl RepositorySecretManagementRepository for FakeRepository {
        async fn activate_builtin_secret_provider(
            &self,
            request: ActivateBuiltinSecretProvider,
        ) -> Result<ActivateBuiltinSecretProviderOutcome, SecretManagementRepositoryError> {
            self.activation_time
                .store(request.actor().now().as_seconds(), Ordering::SeqCst);
            Ok(ActivateBuiltinSecretProviderOutcome::Activated(
                BuiltinSecretProviderMetadata::new(
                    automata_ci_store::BuiltinSecretProviderState::Active,
                    ManagementRevision::new(2).expect("revision"),
                    automata_ci_core::UnixMillis::new(20_000),
                ),
            ))
        }

        async fn list_repository_secrets(
            &self,
            _request: ListRepositorySecrets,
        ) -> Result<ListRepositorySecretsOutcome, SecretManagementRepositoryError> {
            Ok(ListRepositorySecretsOutcome::Found(
                RepositorySecretMetadataPage::new(Vec::new(), None),
            ))
        }

        async fn reserve_repository_secret_version_mutation(
            &self,
            request: ReserveRepositorySecretVersionMutation,
        ) -> Result<ReserveRepositorySecretVersionMutationOutcome, SecretManagementRepositoryError>
        {
            self.reserve_time
                .store(request.actor().now().as_seconds(), Ordering::SeqCst);
            if let Some(reservation) = self
                .reservation_override
                .lock()
                .expect("reservation override lock")
                .clone()
            {
                return Ok(if self.replay_reservation {
                    ReserveRepositorySecretVersionMutationOutcome::ReconcileRequired(reservation)
                } else {
                    ReserveRepositorySecretVersionMutationOutcome::FreshReservation(reservation)
                });
            }
            Ok(
                ReserveRepositorySecretVersionMutationOutcome::FreshReservation(
                    RepositorySecretVersionMutationReservation::new(
                        request.mutation_id(),
                        request.secret_id(),
                        request.repository_id(),
                        request.name().clone(),
                        automata_ci_store::ManagedSecretProviderId::new("builtin")
                            .expect("provider"),
                        request.kind(),
                        ManagementRevision::new(1).expect("revision"),
                        1,
                        automata_ci_core::UnixMillis::new(610_000),
                        None,
                        format!(
                            "secret-version:{}",
                            request.mutation_id().as_uuid().hyphenated()
                        ),
                    ),
                ),
            )
        }

        async fn confirm_repository_secret_version_mutation(
            &self,
            request: ConfirmRepositorySecretVersionMutation,
        ) -> Result<ConfirmRepositorySecretVersionMutationOutcome, SecretManagementRepositoryError>
        {
            self.confirm_time
                .store(request.actor().now().as_seconds(), Ordering::SeqCst);
            let RepositorySecretProviderMutationResult::BuiltinCreated(target) =
                request.provider_result()
            else {
                return Ok(ConfirmRepositorySecretVersionMutationOutcome::CasLost);
            };
            *self.confirmed.lock().expect("confirmed lock") = Some(target);
            Ok(ConfirmRepositorySecretVersionMutationOutcome::Applied(
                RepositorySecretVersionMutationReceipt::new(request.mutation_id(), target),
            ))
        }

        async fn delete_repository_secret(
            &self,
            _request: DeleteRepositorySecret,
        ) -> Result<DeleteRepositorySecretOutcome, SecretManagementRepositoryError> {
            Ok(DeleteRepositorySecretOutcome::AlreadyDeleted)
        }
    }

    #[derive(Debug)]
    struct FakeProvider {
        id: SecretProviderId,
        capabilities: ProviderCapabilities,
        clock: Arc<AtomicU64>,
        health_calls: AtomicU64,
        create_calls: AtomicU64,
        reconcile_calls: AtomicU64,
        create_error: Option<ProviderErrorKind>,
        reconcile_not_committed: bool,
    }

    impl FakeProvider {
        fn new(clock: Arc<AtomicU64>) -> Self {
            Self {
                id: SecretProviderId::new("builtin").expect("provider ID"),
                capabilities: ProviderCapabilities::new([
                    ProviderCapability::CreateVersion,
                    ProviderCapability::ReconcileCreateVersion,
                    ProviderCapability::DestroyVersion,
                ])
                .expect("capabilities"),
                clock,
                health_calls: AtomicU64::new(0),
                create_calls: AtomicU64::new(0),
                reconcile_calls: AtomicU64::new(0),
                create_error: None,
                reconcile_not_committed: false,
            }
        }

        fn with_create_error(mut self, kind: ProviderErrorKind) -> Self {
            self.create_error = Some(kind);
            self
        }

        fn with_definitive_absence(mut self) -> Self {
            self.reconcile_not_committed = true;
            self
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
            SecretAtRestProtection::AutomataEnvelope
        }

        async fn health(
            &self,
            _context: &ProviderOperationContext,
        ) -> Result<ProviderHealth, ProviderError> {
            self.health_calls.fetch_add(1, Ordering::SeqCst);
            Ok(ProviderHealth::Unavailable)
        }

        async fn create_version(
            &self,
            request: CreateSecretVersionRequest,
        ) -> Result<CreatedSecretVersion, ProviderError> {
            self.create_calls.fetch_add(1, Ordering::SeqCst);
            assert_eq!(request.value().expose_secret(), SECRET_VALUE);
            assert_eq!(
                request.context().request_id().as_str(),
                format!("secret-version:{MUTATION}")
            );
            assert!(request.expected_existing_version().is_none());
            self.clock.store(20, Ordering::SeqCst);
            if let Some(kind) = self.create_error {
                return Err(ProviderError::new(kind));
            }
            Ok(CreatedSecretVersion::new(
                ProviderSecretLocator::new(request.secret().id().as_str().to_owned())
                    .expect("locator"),
                ProviderVersionId::new(VERSION).expect("version"),
            ))
        }

        async fn reconcile_create_version(
            &self,
            request: ReconcileCreateSecretVersionRequest,
        ) -> Result<ReconcileCreateSecretVersionOutcome, ProviderError> {
            self.reconcile_calls.fetch_add(1, Ordering::SeqCst);
            assert_eq!(
                request.context().request_id().as_str(),
                format!("secret-version:{MUTATION}")
            );
            assert_eq!(request.secret().id().as_str(), SECRET);
            assert!(request.expected_existing_version().is_none());
            if self.reconcile_not_committed {
                return Ok(ReconcileCreateSecretVersionOutcome::DefinitivelyNotCommitted);
            }
            Ok(ReconcileCreateSecretVersionOutcome::AlreadyCommitted(
                CreatedSecretVersion::new(
                    ProviderSecretLocator::new(SECRET).expect("locator"),
                    ProviderVersionId::new(VERSION).expect("version"),
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

    fn actor(now: u64) -> ManagementActor {
        ManagementActor::new(
            TenantId::new(TENANT).expect("tenant"),
            PrincipalId::new(PRINCIPAL).expect("principal"),
            SessionId::new(SESSION).expect("session"),
            ManagementRevision::new(7).expect("revision"),
            Some(ManagementRequestId::new("request-1").expect("request ID")),
            UnixTimestamp::from_seconds(now),
        )
    }

    fn mutation_request() -> ReserveRepositorySecretVersionMutation {
        let repository = REPOSITORY.parse::<RunId>().expect("repository");
        let secret = SECRET.parse::<RunId>().expect("secret");
        let mutation = MUTATION.parse::<RunId>().expect("mutation");
        let secret_id = RepositorySecretId::from_uuid(secret.as_uuid()).expect("secret ID");
        ReserveRepositorySecretVersionMutation::create(
            actor(10),
            RepositorySecretMutationId::from_uuid(mutation.as_uuid(), secret_id)
                .expect("mutation ID"),
            secret_id,
            RepositoryId::from_uuid(repository.as_uuid()),
            RepositorySecretName::new("DEPLOY_TOKEN").expect("name"),
            None,
        )
        .expect("mutation")
    }

    fn create_reservation(
        request: &ReserveRepositorySecretVersionMutation,
        reserved_version_number: u64,
        confirmation_deadline_ms: i64,
    ) -> RepositorySecretVersionMutationReservation {
        RepositorySecretVersionMutationReservation::new(
            request.mutation_id(),
            request.secret_id(),
            request.repository_id(),
            request.name().clone(),
            automata_ci_store::ManagedSecretProviderId::new(BUILTIN_SECRET_PROVIDER_ID)
                .expect("provider"),
            RepositorySecretMutationKind::Create,
            ManagementRevision::new(1).expect("revision"),
            reserved_version_number,
            automata_ci_core::UnixMillis::new(confirmation_deadline_ms),
            None,
            format!(
                "secret-version:{}",
                request.mutation_id().as_uuid().hyphenated()
            ),
        )
    }

    fn replacement_request() -> ReserveRepositorySecretVersionMutation {
        let mut request = mutation_request();
        request = ReserveRepositorySecretVersionMutation::replace(
            request.actor().clone(),
            request.mutation_id(),
            request.secret_id(),
            request.repository_id(),
            request.name().clone(),
            ManagementRevision::new(2).expect("revision"),
        )
        .expect("replacement mutation");
        request
    }

    fn replacement_reservation(
        request: &ReserveRepositorySecretVersionMutation,
        reserved_version_number: u64,
    ) -> RepositorySecretVersionMutationReservation {
        let predecessor = BuiltinRepositorySecretVersion::new(
            request.secret_id(),
            RepositorySecretVersionId::from_uuid(
                VERSION.parse::<RunId>().expect("predecessor").as_uuid(),
            )
            .expect("predecessor version ID"),
            5,
        )
        .expect("predecessor");
        RepositorySecretVersionMutationReservation::new(
            request.mutation_id(),
            request.secret_id(),
            request.repository_id(),
            request.name().clone(),
            automata_ci_store::ManagedSecretProviderId::new(BUILTIN_SECRET_PROVIDER_ID)
                .expect("provider"),
            RepositorySecretMutationKind::Replace,
            ManagementRevision::new(2).expect("revision"),
            reserved_version_number,
            automata_ci_core::UnixMillis::new(610_000),
            Some(predecessor),
            format!(
                "secret-version:{}",
                request.mutation_id().as_uuid().hyphenated()
            ),
        )
    }

    fn provider_registry(provider: &Arc<FakeProvider>) -> Arc<SecretProviderRegistry> {
        let provider: Arc<dyn SecretProvider> = provider.clone();
        Arc::new(
            SecretProviderRegistry::new(provider.provider_id().clone(), [provider])
                .expect("provider registry"),
        )
    }

    fn backend_with_reservation(
        reservation: RepositorySecretVersionMutationReservation,
        now_seconds: u64,
    ) -> (OperationalRepositorySecretBackend, Arc<FakeProvider>) {
        let time = Arc::new(AtomicU64::new(now_seconds));
        let repository: Arc<dyn RepositorySecretManagementRepository> =
            Arc::new(FakeRepository::with_reservation(reservation));
        let provider = Arc::new(FakeProvider::new(Arc::clone(&time)));
        let clock: Arc<dyn Clock> = Arc::new(MutableClock(time));
        (
            OperationalRepositorySecretBackend::new(
                repository,
                provider_registry(&provider),
                SecretCustodyVerifier::verified_for_tests(),
                clock,
            )
            .expect("backend"),
            provider,
        )
    }

    fn backend_with_custody(
        custody: Arc<SecretCustodyVerifier>,
    ) -> (
        OperationalRepositorySecretBackend,
        Arc<FakeRepository>,
        Arc<FakeProvider>,
    ) {
        let time = Arc::new(AtomicU64::new(10));
        let repository = Arc::new(FakeRepository::default());
        let provider = Arc::new(FakeProvider::new(Arc::clone(&time)));
        let repository_port: Arc<dyn RepositorySecretManagementRepository> = repository.clone();
        let clock: Arc<dyn Clock> = Arc::new(MutableClock(time));
        (
            OperationalRepositorySecretBackend::new(
                repository_port,
                provider_registry(&provider),
                custody,
                clock,
            )
            .expect("backend"),
            repository,
            provider,
        )
    }

    #[tokio::test]
    async fn intent_provider_and_fresh_confirmation_are_exactly_ordered() {
        let time = Arc::new(AtomicU64::new(10));
        let repository = Arc::new(FakeRepository::default());
        let provider = Arc::new(FakeProvider::new(Arc::clone(&time)));
        let repository_port: Arc<dyn RepositorySecretManagementRepository> = repository.clone();
        let clock: Arc<dyn Clock> = Arc::new(MutableClock(time));
        let backend = OperationalRepositorySecretBackend::new(
            repository_port,
            provider_registry(&provider),
            SecretCustodyVerifier::verified_for_tests(),
            clock,
        )
        .expect("backend");

        let outcome = backend
            .mutate(
                mutation_request(),
                SecretIngressValue::new(SECRET_VALUE.to_vec()).expect("secret value"),
            )
            .await
            .expect("mutation outcome");
        assert_eq!(outcome, RepositorySecretMutationOutcome::Applied);
        assert_eq!(repository.reserve_time.load(Ordering::SeqCst), 10);
        assert_eq!(repository.confirm_time.load(Ordering::SeqCst), 20);
        assert_eq!(provider.create_calls.load(Ordering::SeqCst), 1);
        let confirmed = repository
            .confirmed
            .lock()
            .expect("confirmed lock")
            .expect("confirmed target");
        assert_eq!(
            confirmed.secret_id().as_uuid().hyphenated().to_string(),
            SECRET
        );
        assert_eq!(
            confirmed.version_id().as_uuid().hyphenated().to_string(),
            VERSION
        );
        assert_eq!(confirmed.version_number(), 1);
    }

    #[tokio::test]
    async fn exact_reservation_replay_reconciles_without_a_second_create() {
        let request = mutation_request();
        let reservation = create_reservation(&request, 1, 610_000);
        let time = Arc::new(AtomicU64::new(10));
        let repository = Arc::new(FakeRepository::with_replay_reservation(reservation));
        let provider = Arc::new(FakeProvider::new(Arc::clone(&time)));
        let backend = OperationalRepositorySecretBackend::new(
            repository.clone(),
            provider_registry(&provider),
            SecretCustodyVerifier::verified_for_tests(),
            Arc::new(MutableClock(time)),
        )
        .expect("backend");

        assert_eq!(
            backend
                .mutate(
                    request,
                    SecretIngressValue::new(SECRET_VALUE.to_vec()).expect("secret value"),
                )
                .await,
            Ok(RepositorySecretMutationOutcome::Applied)
        );
        assert_eq!(provider.create_calls.load(Ordering::SeqCst), 0);
        assert_eq!(provider.reconcile_calls.load(Ordering::SeqCst), 1);
        assert_eq!(repository.confirm_time.load(Ordering::SeqCst), 10);
    }

    #[tokio::test]
    async fn ambiguous_fresh_create_reconciles_without_retrying_create() {
        let time = Arc::new(AtomicU64::new(10));
        let repository = Arc::new(FakeRepository::default());
        let provider = Arc::new(
            FakeProvider::new(Arc::clone(&time)).with_create_error(ProviderErrorKind::Unavailable),
        );
        let backend = OperationalRepositorySecretBackend::new(
            repository.clone(),
            provider_registry(&provider),
            SecretCustodyVerifier::verified_for_tests(),
            Arc::new(MutableClock(time)),
        )
        .expect("backend");

        assert_eq!(
            backend
                .mutate(
                    mutation_request(),
                    SecretIngressValue::new(SECRET_VALUE.to_vec()).expect("secret value"),
                )
                .await,
            Ok(RepositorySecretMutationOutcome::Applied)
        );
        assert_eq!(provider.create_calls.load(Ordering::SeqCst), 1);
        assert_eq!(provider.reconcile_calls.load(Ordering::SeqCst), 1);
        assert_eq!(repository.confirm_time.load(Ordering::SeqCst), 20);
    }

    #[tokio::test]
    async fn definitive_replay_absence_leaves_the_reservation_open() {
        let request = mutation_request();
        let reservation = create_reservation(&request, 1, 610_000);
        let time = Arc::new(AtomicU64::new(10));
        let repository = Arc::new(FakeRepository::with_replay_reservation(reservation));
        let provider = Arc::new(FakeProvider::new(Arc::clone(&time)).with_definitive_absence());
        let backend = OperationalRepositorySecretBackend::new(
            repository.clone(),
            provider_registry(&provider),
            SecretCustodyVerifier::verified_for_tests(),
            Arc::new(MutableClock(time)),
        )
        .expect("backend");

        assert_eq!(
            backend
                .mutate(
                    request,
                    SecretIngressValue::new(SECRET_VALUE.to_vec()).expect("secret value"),
                )
                .await,
            Ok(RepositorySecretMutationOutcome::ProviderUnavailable)
        );
        assert_eq!(provider.create_calls.load(Ordering::SeqCst), 0);
        assert_eq!(provider.reconcile_calls.load(Ordering::SeqCst), 1);
        assert_eq!(repository.confirm_time.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn ambiguous_create_with_definitive_absence_stays_open_without_recreation() {
        let time = Arc::new(AtomicU64::new(10));
        let repository = Arc::new(FakeRepository::default());
        let provider = Arc::new(
            FakeProvider::new(Arc::clone(&time))
                .with_create_error(ProviderErrorKind::Unavailable)
                .with_definitive_absence(),
        );
        let backend = OperationalRepositorySecretBackend::new(
            repository.clone(),
            provider_registry(&provider),
            SecretCustodyVerifier::verified_for_tests(),
            Arc::new(MutableClock(time)),
        )
        .expect("backend");

        assert_eq!(
            backend
                .mutate(
                    mutation_request(),
                    SecretIngressValue::new(SECRET_VALUE.to_vec()).expect("secret value"),
                )
                .await,
            Ok(RepositorySecretMutationOutcome::ProviderUnavailable)
        );
        assert_eq!(provider.create_calls.load(Ordering::SeqCst), 1);
        assert_eq!(provider.reconcile_calls.load(Ordering::SeqCst), 1);
        assert_eq!(repository.confirm_time.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn custody_is_refreshed_before_replay_reconciliation() {
        let request = mutation_request();
        let reservation = create_reservation(&request, 1, 610_000);
        let time = Arc::new(AtomicU64::new(10));
        let repository = Arc::new(FakeRepository::with_replay_reservation(reservation));
        let provider = Arc::new(FakeProvider::new(Arc::clone(&time)));
        let backend = OperationalRepositorySecretBackend::new(
            repository.clone(),
            provider_registry(&provider),
            SecretCustodyVerifier::available_then_unavailable_for_tests(1),
            Arc::new(MutableClock(time)),
        )
        .expect("backend");

        assert_eq!(
            backend
                .mutate(
                    request,
                    SecretIngressValue::new(SECRET_VALUE.to_vec()).expect("secret value"),
                )
                .await,
            Ok(RepositorySecretMutationOutcome::ProviderUnavailable)
        );
        assert_eq!(provider.create_calls.load(Ordering::SeqCst), 0);
        assert_eq!(provider.reconcile_calls.load(Ordering::SeqCst), 0);
        assert_eq!(repository.confirm_time.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn custody_failure_precedes_intent_and_plaintext_provider_io() {
        let time = Arc::new(AtomicU64::new(10));
        let repository = Arc::new(FakeRepository::default());
        let repository_port: Arc<dyn RepositorySecretManagementRepository> = repository.clone();
        let provider = Arc::new(FakeProvider::new(Arc::clone(&time)));
        let clock: Arc<dyn Clock> = Arc::new(MutableClock(time));
        let backend = OperationalRepositorySecretBackend::new(
            repository_port,
            provider_registry(&provider),
            SecretCustodyVerifier::unavailable_for_tests(),
            clock,
        )
        .expect("backend");

        assert_eq!(
            backend
                .mutate(
                    mutation_request(),
                    SecretIngressValue::new(SECRET_VALUE.to_vec()).expect("secret value"),
                )
                .await,
            Err(SecretApiBackendError::Unavailable)
        );
        assert_eq!(repository.reserve_time.load(Ordering::SeqCst), 0);
        assert_eq!(provider.create_calls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn custody_failure_after_reservation_precedes_plaintext_provider_io() {
        let (backend, repository, provider) = backend_with_custody(
            SecretCustodyVerifier::available_then_unavailable_for_tests(1),
        );

        assert_eq!(
            backend
                .mutate(
                    mutation_request(),
                    SecretIngressValue::new(SECRET_VALUE.to_vec()).expect("secret value"),
                )
                .await,
            Ok(RepositorySecretMutationOutcome::ProviderUnavailable)
        );
        assert_eq!(repository.reserve_time.load(Ordering::SeqCst), 10);
        assert_eq!(provider.create_calls.load(Ordering::SeqCst), 0);
        assert_eq!(repository.confirm_time.load(Ordering::SeqCst), 0);
        assert!(
            repository
                .confirmed
                .lock()
                .expect("confirmed lock")
                .is_none()
        );
    }

    #[tokio::test]
    async fn custody_failure_after_provider_write_precedes_confirmation() {
        let (backend, repository, provider) = backend_with_custody(
            SecretCustodyVerifier::available_then_unavailable_for_tests(2),
        );

        assert_eq!(
            backend
                .mutate(
                    mutation_request(),
                    SecretIngressValue::new(SECRET_VALUE.to_vec()).expect("secret value"),
                )
                .await,
            Err(SecretApiBackendError::Unavailable)
        );
        assert_eq!(repository.reserve_time.load(Ordering::SeqCst), 10);
        assert_eq!(provider.create_calls.load(Ordering::SeqCst), 1);
        assert_eq!(repository.confirm_time.load(Ordering::SeqCst), 0);
        assert!(
            repository
                .confirmed
                .lock()
                .expect("confirmed lock")
                .is_none()
        );
    }

    #[tokio::test]
    async fn corrupt_ordinal_or_deadline_never_crosses_the_plaintext_provider_boundary() {
        let create = mutation_request();
        let replace = replacement_request();
        for (request, reservation) in [
            (create.clone(), create_reservation(&create, 2, 610_000)),
            (create.clone(), create_reservation(&create, 1, 610_001)),
            (replace.clone(), replacement_reservation(&replace, 5)),
        ] {
            let (backend, provider) = backend_with_reservation(reservation, 10);
            assert_eq!(
                backend
                    .mutate(
                        request,
                        SecretIngressValue::new(SECRET_VALUE.to_vec()).expect("secret value"),
                    )
                    .await,
                Err(SecretApiBackendError::CorruptData)
            );
            assert_eq!(provider.create_calls.load(Ordering::SeqCst), 0);
        }
    }

    #[tokio::test]
    async fn durable_provider_selection_never_falls_back_to_the_registry_default() {
        let request = mutation_request();
        let reservation = RepositorySecretVersionMutationReservation::new(
            request.mutation_id(),
            request.secret_id(),
            request.repository_id(),
            request.name().clone(),
            automata_ci_store::ManagedSecretProviderId::new("external-vault").expect("provider ID"),
            request.kind(),
            ManagementRevision::new(1).expect("revision"),
            1,
            automata_ci_core::UnixMillis::new(610_000),
            None,
            format!(
                "secret-version:{}",
                request.mutation_id().as_uuid().hyphenated()
            ),
        );
        let (backend, provider) = backend_with_reservation(reservation, 10);

        assert_eq!(
            backend
                .mutate(
                    request,
                    SecretIngressValue::new(SECRET_VALUE.to_vec()).expect("secret value"),
                )
                .await,
            Ok(RepositorySecretMutationOutcome::ProviderUnavailable)
        );
        assert_eq!(provider.create_calls.load(Ordering::SeqCst), 0);
        assert_eq!(provider.reconcile_calls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn clock_expiry_immediately_before_provider_io_never_exposes_plaintext() {
        let request = mutation_request();
        let reservation = create_reservation(&request, 1, 610_000);
        let (backend, provider) = backend_with_reservation(reservation, 610);
        assert_eq!(
            backend
                .mutate(
                    request,
                    SecretIngressValue::new(SECRET_VALUE.to_vec()).expect("secret value"),
                )
                .await,
            Ok(RepositorySecretMutationOutcome::Cancelled)
        );
        assert_eq!(provider.create_calls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn activation_uses_fresh_reauthorization_without_a_circular_health_probe() {
        let time = Arc::new(AtomicU64::new(20));
        let repository = Arc::new(FakeRepository::default());
        let provider = Arc::new(FakeProvider::new(Arc::clone(&time)));
        let repository_port: Arc<dyn RepositorySecretManagementRepository> = repository.clone();
        let clock: Arc<dyn Clock> = Arc::new(MutableClock(time));
        let backend = OperationalRepositorySecretBackend::new(
            repository_port,
            provider_registry(&provider),
            SecretCustodyVerifier::verified_for_tests(),
            clock,
        )
        .expect("backend");

        let outcome = backend
            .activate_builtin(ActivateBuiltinSecretProvider::new(
                actor(10),
                ManagementRevision::new(1).expect("revision"),
            ))
            .await
            .expect("activation outcome");

        assert!(matches!(
            outcome,
            ActivateBuiltinSecretProviderOutcome::Activated(_)
        ));
        assert_eq!(repository.activation_time.load(Ordering::SeqCst), 20);
        assert_eq!(provider.health_calls.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn provider_handoff_must_match_the_exact_reserved_intent() {
        let request = mutation_request();
        let exact = RepositorySecretVersionMutationReservation::new(
            request.mutation_id(),
            request.secret_id(),
            request.repository_id(),
            request.name().clone(),
            automata_ci_store::ManagedSecretProviderId::new(BUILTIN_SECRET_PROVIDER_ID)
                .expect("provider"),
            request.kind(),
            ManagementRevision::new(1).expect("revision"),
            1,
            automata_ci_core::UnixMillis::new(610_000),
            None,
            format!(
                "secret-version:{}",
                request.mutation_id().as_uuid().hyphenated()
            ),
        );
        assert!(reservation_matches_request(&request, &exact));

        let mismatched = RepositorySecretVersionMutationReservation::new(
            request.mutation_id(),
            request.secret_id(),
            RepositoryId::from_uuid(
                "70000000-0000-4000-8000-000000000007"
                    .parse::<RunId>()
                    .expect("repository")
                    .as_uuid(),
            ),
            request.name().clone(),
            automata_ci_store::ManagedSecretProviderId::new(BUILTIN_SECRET_PROVIDER_ID)
                .expect("provider"),
            request.kind(),
            ManagementRevision::new(1).expect("revision"),
            1,
            automata_ci_core::UnixMillis::new(610_000),
            None,
            exact.provider_create_request_id().to_owned(),
        );
        assert!(!reservation_matches_request(&request, &mismatched));

        let mismatched = RepositorySecretVersionMutationReservation::new(
            request.mutation_id(),
            request.secret_id(),
            request.repository_id(),
            request.name().clone(),
            automata_ci_store::ManagedSecretProviderId::new(BUILTIN_SECRET_PROVIDER_ID)
                .expect("provider"),
            request.kind(),
            ManagementRevision::new(1).expect("revision"),
            1,
            automata_ci_core::UnixMillis::new(610_000),
            None,
            "secret-version:80000000-0000-4000-8000-000000000008".to_owned(),
        );
        assert!(!reservation_matches_request(&request, &mismatched));
    }

    #[test]
    fn value_free_adapter_outputs_remain_exactly_scope_and_intent_bound() {
        let request = mutation_request();
        let version = VERSION.parse::<RunId>().expect("version");
        let target = BuiltinRepositorySecretVersion::new(
            request.secret_id(),
            RepositorySecretVersionId::from_uuid(version.as_uuid()).expect("version ID"),
            1,
        )
        .expect("target");
        let receipt = RepositorySecretVersionMutationReceipt::new(request.mutation_id(), target);
        assert!(replay_receipt_matches(&request, receipt));
        assert!(confirmation_receipt_matches(
            request.mutation_id(),
            RepositorySecretProviderMutationResult::BuiltinCreated(target),
            receipt,
        ));
        assert!(!confirmation_receipt_matches(
            request.mutation_id(),
            RepositorySecretProviderMutationResult::CasLost,
            receipt,
        ));

        let metadata = RepositorySecretMetadata::from_durable_parts(
            request.secret_id(),
            request.repository_id(),
            request.name().clone(),
            automata_ci_store::ManagedSecretProviderId::new(BUILTIN_SECRET_PROVIDER_ID)
                .expect("provider"),
            RepositorySecretState::Active,
            Some(1),
            ManagementRevision::new(1).expect("revision"),
            automata_ci_core::UnixMillis::new(1_000),
            automata_ci_core::UnixMillis::new(2_000),
        );
        let page =
            RepositorySecretMetadataPage::new(vec![metadata.clone()], Some(request.secret_id()));
        assert!(metadata_page_matches(
            request.repository_id(),
            None,
            1,
            &page,
        ));

        let foreign_repository = RepositoryId::from_uuid(
            "70000000-0000-4000-8000-000000000007"
                .parse::<RunId>()
                .expect("repository")
                .as_uuid(),
        );
        let foreign_page = RepositorySecretMetadataPage::new(
            vec![RepositorySecretMetadata::from_durable_parts(
                metadata.id(),
                foreign_repository,
                metadata.name().clone(),
                metadata.provider_id().clone(),
                metadata.state(),
                metadata.current_version_number(),
                metadata.revision(),
                metadata.created_at(),
                metadata.updated_at(),
            )],
            None,
        );
        assert!(!metadata_page_matches(
            request.repository_id(),
            None,
            1,
            &foreign_page,
        ));
    }

    #[test]
    fn external_provider_composition_fails_closed() {
        let time = Arc::new(AtomicU64::new(10));
        let repository: Arc<dyn RepositorySecretManagementRepository> =
            Arc::new(FakeRepository::default());
        let mut provider = FakeProvider::new(Arc::clone(&time));
        provider.id = SecretProviderId::new("external-vault").expect("provider ID");
        let provider: Arc<dyn SecretProvider> = Arc::new(provider);
        let providers = Arc::new(
            SecretProviderRegistry::new(provider.provider_id().clone(), [provider])
                .expect("provider registry"),
        );
        let clock: Arc<dyn Clock> = Arc::new(MutableClock(time));

        assert_eq!(
            OperationalRepositorySecretBackend::new(
                repository,
                providers,
                SecretCustodyVerifier::verified_for_tests(),
                clock,
            )
            .expect_err("external provider must remain uncomposed"),
            SecretApiBackendError::InvalidRequest
        );
    }
}
