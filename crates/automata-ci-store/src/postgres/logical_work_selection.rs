use async_trait::async_trait;
use automata_ci_core::{RunId, Sha256Digest, UnixMillis};
use sqlx::{Postgres, Row as _, Transaction, postgres::PgRow};
use uuid::Uuid;

use super::{
    PostgresStore,
    durable_schema::current_durable_schemas,
    logical_activation::{
        claim_logical_job_activation_in_transaction, consume_selected_activation_in_transaction,
    },
    logical_activation_preparation::{
        claim_logical_activation_preparation_in_transaction,
        consume_selected_preparation_in_transaction,
    },
    logical_materialization::{
        claim_logical_instance_materialization_in_transaction,
        consume_selected_materialization_in_transaction,
    },
};
use crate::{
    ClaimLogicalActivationPreparation, ClaimLogicalInstanceMaterialization,
    ClaimLogicalJobActivation, ClaimNextLogicalInstanceMaterialization,
    ClaimNextLogicalJobOrchestration, ConsumeSelectedLogicalInstanceMaterialization,
    ConsumeSelectedLogicalJobOrchestration, ConsumedLogicalJobOrchestrationAuthority,
    ConsumedSelectedLogicalInstanceMaterialization, ConsumedSelectedLogicalJobOrchestration,
    LogicalActivationPreparationClaimOutcome, LogicalActivationPreparationStoreError,
    LogicalActivationPreparationTarget, LogicalActivationStoreError,
    LogicalInstanceMaterializationClaimOutcome, LogicalInstanceMaterializationSelectionOutcome,
    LogicalInstanceMaterializationTarget, LogicalJobOrchestrationAuthorityKind,
    LogicalJobOrchestrationSelectionOutcome, LogicalMaterializationStoreError,
    LogicalWorkQuarantineKind, LogicalWorkQuarantineOutcome, LogicalWorkSelectionGeneration,
    LogicalWorkSelectionRepository, LogicalWorkSelectionStoreError, LogicalWorkflowInstanceId,
    LogicalWorkflowInvocationId, LogicalWorkflowJobId, MAX_LOGICAL_WORK_DISCOVERY_CANDIDATES,
    MIN_LOGICAL_WORK_SELECTION_HANDOFF_MILLIS, QuarantineLogicalInstanceMaterialization,
    QuarantineLogicalJobOrchestration, RepositoryId, SelectedLogicalInstanceMaterialization,
    SelectedLogicalJobOrchestration, StoreError, TenantScope, WorkflowRuntimePolicyPin,
    WorkflowRuntimePolicyRevision,
};

const MAX_SELECTION_CLOCK_SKEW_MILLIS: i64 = 60_000;
const CLEANUP_BATCH_SIZE: i64 = 1_024;
const DISCOVERY_BATCH_SIZE: usize = 64;

#[derive(Clone, Copy)]
struct SelectionAdmission {
    database_now: i64,
    replay_floor: i64,
    previous_floor: i64,
    previous_updated_at: i64,
}

struct LockedSelectionHorizon {
    replay_floor: i64,
    activation_cursor: Option<ActivationDiscoveryCursor>,
    materialization_cursor: Option<MaterializationDiscoveryCursor>,
}

enum DiscoveryCursorUpdate {
    Activation(Option<ActivationDiscoveryCursor>),
    Materialization(Option<MaterializationDiscoveryCursor>),
}

#[derive(Clone, Copy)]
struct ActivationDiscoveryCursor {
    ready_at: i64,
    run_id: Uuid,
    invocation_id: Uuid,
    source_order: i32,
    logical_job_id: Uuid,
}

impl ActivationDiscoveryCursor {
    fn decode(row: &PgRow) -> Result<Self, LogicalWorkSelectionStoreError> {
        Ok(Self {
            ready_at: row.try_get("ready_at_ms").map_err(operation_error)?,
            run_id: row.try_get("run_id").map_err(operation_error)?,
            invocation_id: row.try_get("invocation_id").map_err(operation_error)?,
            source_order: row.try_get("source_order").map_err(operation_error)?,
            logical_job_id: row.try_get("logical_job_id").map_err(operation_error)?,
        })
    }

    fn decode_horizon(row: &PgRow) -> Result<Option<Self>, LogicalWorkSelectionStoreError> {
        let ready_at: Option<i64> = row.try_get("cursor_ready_at_ms").map_err(operation_error)?;
        let Some(ready_at) = ready_at else {
            return Ok(None);
        };
        Ok(Some(Self {
            ready_at,
            run_id: required_cursor_column(row, "cursor_run_id")?,
            invocation_id: required_cursor_column(row, "cursor_invocation_id")?,
            source_order: required_cursor_column(row, "cursor_source_order")?,
            logical_job_id: required_cursor_column(row, "cursor_target_id")?,
        }))
    }
}

#[derive(Clone, Copy)]
struct MaterializationDiscoveryCursor {
    ready_at: i64,
    run_id: Uuid,
    invocation_id: Uuid,
    source_order: i32,
    matrix_index: i32,
    instance_id: Uuid,
}

impl MaterializationDiscoveryCursor {
    fn decode(row: &PgRow) -> Result<Self, LogicalWorkSelectionStoreError> {
        Ok(Self {
            ready_at: row.try_get("ready_at_ms").map_err(operation_error)?,
            run_id: row.try_get("run_id").map_err(operation_error)?,
            invocation_id: row.try_get("invocation_id").map_err(operation_error)?,
            source_order: row.try_get("source_order").map_err(operation_error)?,
            matrix_index: row.try_get("matrix_index").map_err(operation_error)?,
            instance_id: row.try_get("instance_id").map_err(operation_error)?,
        })
    }

    fn decode_horizon(row: &PgRow) -> Result<Option<Self>, LogicalWorkSelectionStoreError> {
        let ready_at: Option<i64> = row.try_get("cursor_ready_at_ms").map_err(operation_error)?;
        let Some(ready_at) = ready_at else {
            return Ok(None);
        };
        Ok(Some(Self {
            ready_at,
            run_id: required_cursor_column(row, "cursor_run_id")?,
            invocation_id: required_cursor_column(row, "cursor_invocation_id")?,
            source_order: required_cursor_column(row, "cursor_source_order")?,
            matrix_index: required_cursor_column(row, "cursor_matrix_index")?,
            instance_id: required_cursor_column(row, "cursor_target_id")?,
        }))
    }
}

fn required_cursor_column<T>(
    row: &PgRow,
    column: &'static str,
) -> Result<T, LogicalWorkSelectionStoreError>
where
    T: for<'decode> sqlx::Decode<'decode, Postgres> + sqlx::Type<Postgres>,
{
    row.try_get::<Option<T>, _>(column)
        .map_err(operation_error)?
        .ok_or_else(|| StoreError::corrupt_data("logical work cursor is incomplete").into())
}

#[allow(clippy::too_many_lines)] // Selection keeps each bounded lock/scan/transition proof atomic.
#[async_trait]
impl LogicalWorkSelectionRepository for PostgresStore {
    async fn claim_next_logical_job_orchestration(
        &self,
        request: ClaimNextLogicalJobOrchestration,
    ) -> Result<LogicalJobOrchestrationSelectionOutcome, LogicalWorkSelectionStoreError> {
        let mut transaction = begin_read_committed(self).await?;
        if let Some(row) = lock_activation_receipt(&mut transaction, &request).await? {
            let outcome = replay_activation(&mut transaction, &request, &row).await?;
            transaction.commit().await.map_err(operation_error)?;
            return Ok(outcome);
        }
        if !reserve_activation_selection(&mut transaction, &request).await? {
            let row = lock_activation_receipt(&mut transaction, &request)
                .await?
                .ok_or_else(|| StoreError::corrupt_data("activation reservation disappeared"))?;
            let outcome = replay_activation(&mut transaction, &request, &row).await?;
            transaction.commit().await.map_err(operation_error)?;
            return Ok(outcome);
        }
        let horizon = lock_selection_horizon(&mut transaction, "activation").await?;
        cleanup_receipts(&mut transaction, "activation", horizon.replay_floor).await?;
        let mut can_wrap = horizon.activation_cursor.is_some();
        let mut discovery_cursor = horizon.activation_cursor;
        let mut scanned_candidates = 0_usize;
        let mut saw_contention = false;
        let (scan_exhausted, cursor_after_scan) = loop {
            let remaining_candidates =
                MAX_LOGICAL_WORK_DISCOVERY_CANDIDATES.saturating_sub(scanned_candidates);
            if remaining_candidates == 0 {
                break (false, discovery_cursor);
            }
            let discovery_limit = remaining_candidates.min(DISCOVERY_BATCH_SIZE);
            let candidates = discover_activation_candidates(
                &mut transaction,
                discovery_cursor.as_ref(),
                i64::try_from(discovery_limit).map_err(|_| {
                    StoreError::corrupt_data("activation discovery limit is invalid")
                })?,
            )
            .await?;
            let discovered = candidates.len();
            scanned_candidates = scanned_candidates.saturating_add(discovered);
            let next_cursor = candidates
                .last()
                .map(ActivationDiscoveryCursor::decode)
                .transpose()?;
            for candidate in candidates {
                let candidate_cursor = ActivationDiscoveryCursor::decode(&candidate)?;
                begin_candidate_savepoint(&mut transaction).await?;
                if !lock_activation_eligibility_graph(&mut transaction, &candidate).await? {
                    saw_contention = true;
                    rollback_candidate_savepoint(&mut transaction).await?;
                    continue;
                }
                let admission = lock_selection_admission(
                    &mut transaction,
                    "activation",
                    request.observed_at(),
                    request.duration_ms(),
                )
                .await?;
                let now = admission.database_now;
                if !activation_candidate_is_eligible(&mut transaction, &candidate, now).await? {
                    rollback_candidate_savepoint(&mut transaction).await?;
                    continue;
                }
                advance_selection_horizon(
                    &mut transaction,
                    "activation",
                    admission,
                    DiscoveryCursorUpdate::Activation(Some(candidate_cursor)),
                )
                .await?;
                let expires_at = checked_expiration(now, request.duration_ms())?;
                let selected = match claim_activation_candidate(
                    &mut transaction,
                    &request,
                    &candidate,
                    now,
                    expires_at,
                )
                .await
                {
                    Ok(selected) => selected,
                    Err(LogicalWorkSelectionStoreError::GenerationExhausted) => {
                        quarantine_activation_generation_poison(
                            &mut transaction,
                            &request,
                            &candidate,
                            now,
                            expires_at,
                        )
                        .await?;
                        release_candidate_savepoint(&mut transaction).await?;
                        transaction.commit().await.map_err(operation_error)?;
                        return Ok(LogicalJobOrchestrationSelectionOutcome::Quarantined);
                    }
                    Err(error) => return Err(error),
                };
                require_selection_handoff_budget(&mut transaction, selected.expires_at()).await?;
                insert_activation_selected(&mut transaction, &request, &selected).await?;
                release_candidate_savepoint(&mut transaction).await?;
                transaction.commit().await.map_err(operation_error)?;
                return Ok(LogicalJobOrchestrationSelectionOutcome::Selected(selected));
            }
            if discovered < discovery_limit {
                if can_wrap && scanned_candidates < MAX_LOGICAL_WORK_DISCOVERY_CANDIDATES {
                    can_wrap = false;
                    discovery_cursor = None;
                    continue;
                }
                break (
                    !saw_contention,
                    if saw_contention { next_cursor } else { None },
                );
            }
            if scanned_candidates >= MAX_LOGICAL_WORK_DISCOVERY_CANDIDATES {
                break (false, next_cursor);
            }
            discovery_cursor = next_cursor;
        };
        let admission = lock_selection_admission(
            &mut transaction,
            "activation",
            request.observed_at(),
            request.duration_ms(),
        )
        .await?;
        advance_selection_horizon(
            &mut transaction,
            "activation",
            admission,
            DiscoveryCursorUpdate::Activation(cursor_after_scan),
        )
        .await?;
        let expires_at = checked_expiration(admission.database_now, request.duration_ms())?;
        require_selection_handoff_budget(&mut transaction, UnixMillis::new(expires_at)).await?;
        if scan_exhausted {
            insert_activation_idle(
                &mut transaction,
                &request,
                admission.database_now,
                expires_at,
            )
            .await?;
        } else {
            insert_activation_contended(
                &mut transaction,
                &request,
                admission.database_now,
                expires_at,
            )
            .await?;
        }
        transaction.commit().await.map_err(operation_error)?;
        Ok(if scan_exhausted {
            LogicalJobOrchestrationSelectionOutcome::Idle
        } else {
            LogicalJobOrchestrationSelectionOutcome::Contended
        })
    }

    async fn claim_next_logical_instance_materialization(
        &self,
        request: ClaimNextLogicalInstanceMaterialization,
    ) -> Result<LogicalInstanceMaterializationSelectionOutcome, LogicalWorkSelectionStoreError>
    {
        let mut transaction = begin_read_committed(self).await?;
        if let Some(row) = lock_materialization_receipt(&mut transaction, &request).await? {
            let outcome = replay_materialization(&mut transaction, &request, &row).await?;
            transaction.commit().await.map_err(operation_error)?;
            return Ok(outcome);
        }
        if !reserve_materialization_selection(&mut transaction, &request).await? {
            let row = lock_materialization_receipt(&mut transaction, &request)
                .await?
                .ok_or_else(|| {
                    StoreError::corrupt_data("materialization reservation disappeared")
                })?;
            let outcome = replay_materialization(&mut transaction, &request, &row).await?;
            transaction.commit().await.map_err(operation_error)?;
            return Ok(outcome);
        }
        let horizon = lock_selection_horizon(&mut transaction, "materialization").await?;
        cleanup_receipts(&mut transaction, "materialization", horizon.replay_floor).await?;
        let mut can_wrap = horizon.materialization_cursor.is_some();
        let mut discovery_cursor = horizon.materialization_cursor;
        let mut scanned_candidates = 0_usize;
        let mut saw_contention = false;
        let (scan_exhausted, cursor_after_scan) = loop {
            let remaining_candidates =
                MAX_LOGICAL_WORK_DISCOVERY_CANDIDATES.saturating_sub(scanned_candidates);
            if remaining_candidates == 0 {
                break (false, discovery_cursor);
            }
            let discovery_limit = remaining_candidates.min(DISCOVERY_BATCH_SIZE);
            let candidates = discover_materialization_candidates(
                &mut transaction,
                discovery_cursor.as_ref(),
                i64::try_from(discovery_limit).map_err(|_| {
                    StoreError::corrupt_data("materialization discovery limit is invalid")
                })?,
            )
            .await?;
            let discovered = candidates.len();
            scanned_candidates = scanned_candidates.saturating_add(discovered);
            let next_cursor = candidates
                .last()
                .map(MaterializationDiscoveryCursor::decode)
                .transpose()?;
            for candidate in candidates {
                let candidate_cursor = MaterializationDiscoveryCursor::decode(&candidate)?;
                begin_candidate_savepoint(&mut transaction).await?;
                if !lock_materialization_eligibility_graph(&mut transaction, &candidate).await? {
                    saw_contention = true;
                    rollback_candidate_savepoint(&mut transaction).await?;
                    continue;
                }
                let admission = lock_selection_admission(
                    &mut transaction,
                    "materialization",
                    request.observed_at(),
                    request.duration_ms(),
                )
                .await?;
                let now = admission.database_now;
                if !materialization_candidate_is_eligible(&mut transaction, &candidate, now).await?
                {
                    rollback_candidate_savepoint(&mut transaction).await?;
                    continue;
                }
                advance_selection_horizon(
                    &mut transaction,
                    "materialization",
                    admission,
                    DiscoveryCursorUpdate::Materialization(Some(candidate_cursor)),
                )
                .await?;
                let expires_at = checked_expiration(now, request.duration_ms())?;
                let selected = match claim_materialization_candidate(
                    &mut transaction,
                    &request,
                    &candidate,
                    now,
                    expires_at,
                )
                .await
                {
                    Ok(selected) => selected,
                    Err(LogicalWorkSelectionStoreError::GenerationExhausted) => {
                        quarantine_materialization_generation_poison(
                            &mut transaction,
                            &request,
                            &candidate,
                            now,
                            expires_at,
                        )
                        .await?;
                        release_candidate_savepoint(&mut transaction).await?;
                        transaction.commit().await.map_err(operation_error)?;
                        return Ok(LogicalInstanceMaterializationSelectionOutcome::Quarantined);
                    }
                    Err(error) => return Err(error),
                };
                require_selection_handoff_budget(&mut transaction, selected.expires_at()).await?;
                insert_materialization_selected(&mut transaction, &request, &selected).await?;
                release_candidate_savepoint(&mut transaction).await?;
                transaction.commit().await.map_err(operation_error)?;
                return Ok(LogicalInstanceMaterializationSelectionOutcome::Selected(
                    selected,
                ));
            }
            if discovered < discovery_limit {
                if can_wrap && scanned_candidates < MAX_LOGICAL_WORK_DISCOVERY_CANDIDATES {
                    can_wrap = false;
                    discovery_cursor = None;
                    continue;
                }
                break (
                    !saw_contention,
                    if saw_contention { next_cursor } else { None },
                );
            }
            if scanned_candidates >= MAX_LOGICAL_WORK_DISCOVERY_CANDIDATES {
                break (false, next_cursor);
            }
            discovery_cursor = next_cursor;
        };
        let admission = lock_selection_admission(
            &mut transaction,
            "materialization",
            request.observed_at(),
            request.duration_ms(),
        )
        .await?;
        advance_selection_horizon(
            &mut transaction,
            "materialization",
            admission,
            DiscoveryCursorUpdate::Materialization(cursor_after_scan),
        )
        .await?;
        let expires_at = checked_expiration(admission.database_now, request.duration_ms())?;
        require_selection_handoff_budget(&mut transaction, UnixMillis::new(expires_at)).await?;
        if scan_exhausted {
            insert_materialization_idle(
                &mut transaction,
                &request,
                admission.database_now,
                expires_at,
            )
            .await?;
        } else {
            insert_materialization_contended(
                &mut transaction,
                &request,
                admission.database_now,
                expires_at,
            )
            .await?;
        }
        transaction.commit().await.map_err(operation_error)?;
        Ok(if scan_exhausted {
            LogicalInstanceMaterializationSelectionOutcome::Idle
        } else {
            LogicalInstanceMaterializationSelectionOutcome::Contended
        })
    }

    async fn consume_selected_logical_job_orchestration(
        &self,
        request: ConsumeSelectedLogicalJobOrchestration,
    ) -> Result<ConsumedSelectedLogicalJobOrchestration, LogicalWorkSelectionStoreError> {
        let selected = request.selected();
        let mut transaction = begin_read_committed(self).await?;
        let receipt = lock_activation_receipt_for_selected(&mut transaction, selected)
            .await?
            .ok_or(LogicalWorkSelectionStoreError::SelectionExpired)?;
        if !activation_quarantine_receipt_matches(&receipt, selected)? {
            return Err(LogicalWorkSelectionStoreError::SelectionConflict);
        }
        lock_quarantine_horizon(&mut transaction, "activation").await?;
        if lock_activation_quarantine(&mut transaction, selected)
            .await?
            .is_some()
        {
            return Err(LogicalWorkSelectionStoreError::SelectionQuarantined);
        }
        require_active_consume_graph(&mut transaction, selected.target()).await?;
        let consumed = match selected.authority_kind() {
            LogicalJobOrchestrationAuthorityKind::Preparation => {
                consume_selected_preparation_in_transaction(&mut transaction, selected)
                    .await
                    .map_err(map_preparation_consume_error)?
                    .map(ConsumedLogicalJobOrchestrationAuthority::Preparation)
            }
            LogicalJobOrchestrationAuthorityKind::Activation => {
                consume_selected_activation_in_transaction(&mut transaction, selected)
                    .await
                    .map_err(map_activation_consume_error)?
                    .map(ConsumedLogicalJobOrchestrationAuthority::Activation)
            }
        }
        .ok_or(LogicalWorkSelectionStoreError::SelectionExpired)?;
        let expires_at = match &consumed {
            ConsumedLogicalJobOrchestrationAuthority::Preparation(claimed) => {
                claimed.claim().expires_at()
            }
            ConsumedLogicalJobOrchestrationAuthority::Activation(claimed) => {
                claimed.claim().expires_at()
            }
        };
        let validated_at = require_selection_handoff_budget(&mut transaction, expires_at).await?;
        let consumed = ConsumedSelectedLogicalJobOrchestration::new_repository_verified(
            selected.clone(),
            consumed,
            validated_at,
        )
        .map_err(|_| {
            StoreError::corrupt_data(
                "consumed orchestration authority disagrees with its selection receipt",
            )
        })?;
        transaction.commit().await.map_err(operation_error)?;
        Ok(consumed)
    }

    async fn consume_selected_logical_instance_materialization(
        &self,
        request: ConsumeSelectedLogicalInstanceMaterialization,
    ) -> Result<ConsumedSelectedLogicalInstanceMaterialization, LogicalWorkSelectionStoreError>
    {
        let selected = request.selected();
        let mut transaction = begin_read_committed(self).await?;
        let receipt = lock_materialization_receipt_for_selected(&mut transaction, selected)
            .await?
            .ok_or(LogicalWorkSelectionStoreError::SelectionExpired)?;
        if !materialization_quarantine_receipt_matches(&receipt, selected)? {
            return Err(LogicalWorkSelectionStoreError::SelectionConflict);
        }
        lock_quarantine_horizon(&mut transaction, "materialization").await?;
        if lock_materialization_quarantine(&mut transaction, selected)
            .await?
            .is_some()
        {
            return Err(LogicalWorkSelectionStoreError::SelectionQuarantined);
        }
        require_active_materialization_consume_graph(&mut transaction, selected.target()).await?;
        let consumed = consume_selected_materialization_in_transaction(&mut transaction, selected)
            .await
            .map_err(map_materialization_consume_error)?
            .ok_or(LogicalWorkSelectionStoreError::SelectionExpired)?;
        let validated_at =
            require_selection_handoff_budget(&mut transaction, consumed.claim().expires_at())
                .await?;
        let consumed = ConsumedSelectedLogicalInstanceMaterialization::new_repository_verified(
            selected.clone(),
            consumed,
            validated_at,
        )
        .map_err(|_| {
            StoreError::corrupt_data(
                "consumed materialization authority disagrees with its selection receipt",
            )
        })?;
        transaction.commit().await.map_err(operation_error)?;
        Ok(consumed)
    }

    async fn quarantine_logical_job_orchestration(
        &self,
        request: QuarantineLogicalJobOrchestration,
    ) -> Result<LogicalWorkQuarantineOutcome, LogicalWorkSelectionStoreError> {
        let mut transaction = begin_read_committed(self).await?;
        let outcome = quarantine_activation_authority(&mut transaction, &request).await?;
        transaction.commit().await.map_err(operation_error)?;
        Ok(outcome)
    }

    async fn quarantine_logical_instance_materialization(
        &self,
        request: QuarantineLogicalInstanceMaterialization,
    ) -> Result<LogicalWorkQuarantineOutcome, LogicalWorkSelectionStoreError> {
        let mut transaction = begin_read_committed(self).await?;
        let outcome = quarantine_materialization_authority(&mut transaction, &request).await?;
        transaction.commit().await.map_err(operation_error)?;
        Ok(outcome)
    }
}

async fn begin_read_committed(
    store: &PostgresStore,
) -> Result<Transaction<'_, Postgres>, LogicalWorkSelectionStoreError> {
    let mut transaction = store.pool.begin().await.map_err(operation_error)?;
    sqlx::query("SET TRANSACTION ISOLATION LEVEL READ COMMITTED")
        .execute(&mut *transaction)
        .await
        .map_err(operation_error)?;
    Ok(transaction)
}

async fn require_active_consume_graph(
    transaction: &mut Transaction<'_, Postgres>,
    target: &LogicalActivationPreparationTarget,
) -> Result<(), LogicalWorkSelectionStoreError> {
    require_active_consume_graph_ids(
        transaction,
        target.tenant(),
        target.run_id().as_uuid(),
        target.invocation_id().as_uuid(),
    )
    .await
}

async fn require_active_materialization_consume_graph(
    transaction: &mut Transaction<'_, Postgres>,
    target: &LogicalInstanceMaterializationTarget,
) -> Result<(), LogicalWorkSelectionStoreError> {
    require_active_consume_graph_ids(
        transaction,
        target.tenant(),
        target.run_id().as_uuid(),
        target.invocation_id().as_uuid(),
    )
    .await
}

async fn require_active_consume_graph_ids(
    transaction: &mut Transaction<'_, Postgres>,
    tenant: &TenantScope,
    run_id: Uuid,
    invocation_id: Uuid,
) -> Result<(), LogicalWorkSelectionStoreError> {
    let schemas = current_durable_schemas();
    let run_active: Option<bool> = sqlx::query_scalar(
        r"
        SELECT run.status IN ('queued', 'in_progress')
               AND run.admission_epoch = $3 AND run.plan_schema = $3
        FROM workflow_runs AS run
        JOIN repositories AS repository ON repository.id = run.repository_id
        WHERE repository.tenant_id = $1 AND run.id = $2
        FOR SHARE OF run
        ",
    )
    .bind(tenant.as_str())
    .bind(run_id)
    .bind(schemas.workflow_plan_i32)
    .fetch_optional(&mut **transaction)
    .await
    .map_err(operation_error)?;
    if run_active != Some(true) {
        return Err(LogicalWorkSelectionStoreError::SelectionExpired);
    }
    let marker_active: Option<bool> = sqlx::query_scalar(
        r"
        SELECT marker.state IN ('pending', 'active')
               AND marker.orchestration_schema = $3
               AND marker.admission_graph_sealed_at_ms IS NOT NULL
               AND automata_logical_workflow_invocation_published(
                   marker.run_id, $2
               )
        FROM logical_workflow_runs AS marker
        WHERE marker.run_id = $1
        FOR SHARE OF marker
        ",
    )
    .bind(run_id)
    .bind(invocation_id)
    .bind(schemas.logical_orchestration_i16)
    .fetch_optional(&mut **transaction)
    .await
    .map_err(operation_error)?;
    if marker_active != Some(true) {
        return Err(LogicalWorkSelectionStoreError::SelectionExpired);
    }
    let invocation_active: Option<bool> = sqlx::query_scalar(
        r"
        SELECT invocation.state IN ('pending', 'active')
               AND invocation.plan_schema = $3
        FROM logical_workflow_invocations AS invocation
        WHERE invocation.run_id = $1 AND invocation.id = $2
        FOR SHARE OF invocation
        ",
    )
    .bind(run_id)
    .bind(invocation_id)
    .bind(schemas.workflow_plan_i16)
    .fetch_optional(&mut **transaction)
    .await
    .map_err(operation_error)?;
    if invocation_active != Some(true) {
        return Err(LogicalWorkSelectionStoreError::SelectionExpired);
    }
    Ok(())
}

async fn database_now_ms(
    transaction: &mut Transaction<'_, Postgres>,
) -> Result<i64, LogicalWorkSelectionStoreError> {
    sqlx::query_scalar("SELECT floor(extract(epoch FROM clock_timestamp()) * 1000)::bigint")
        .fetch_one(&mut **transaction)
        .await
        .map_err(operation_error)
}

async fn require_selection_handoff_budget(
    transaction: &mut Transaction<'_, Postgres>,
    expires_at: UnixMillis,
) -> Result<UnixMillis, LogicalWorkSelectionStoreError> {
    let now = database_now_ms(transaction).await?;
    if expires_at.get().saturating_sub(now) < MIN_LOGICAL_WORK_SELECTION_HANDOFF_MILLIS {
        return Err(LogicalWorkSelectionStoreError::SelectionExpired);
    }
    Ok(UnixMillis::new(now))
}

async fn reserve_activation_selection(
    transaction: &mut Transaction<'_, Postgres>,
    request: &ClaimNextLogicalJobOrchestration,
) -> Result<bool, LogicalWorkSelectionStoreError> {
    let rows = sqlx::query(
        r"
        INSERT INTO logical_workflow_activation_work_selections (
            selection_id, owner_id, requested_at_ms, duration_ms, outcome
        ) VALUES ($1,$2,$3,$4,'selecting')
        ON CONFLICT (selection_id) DO NOTHING
        ",
    )
    .bind(request.selection_id().as_uuid())
    .bind(request.owner().as_uuid())
    .bind(request.observed_at().get())
    .bind(request.duration_ms())
    .execute(&mut **transaction)
    .await
    .map_err(operation_error)?
    .rows_affected();
    match rows {
        0 => Ok(false),
        1 => Ok(true),
        _ => Err(StoreError::corrupt_data(
            "activation selection reservation inserted an invalid row count",
        )
        .into()),
    }
}

async fn reserve_materialization_selection(
    transaction: &mut Transaction<'_, Postgres>,
    request: &ClaimNextLogicalInstanceMaterialization,
) -> Result<bool, LogicalWorkSelectionStoreError> {
    let rows = sqlx::query(
        r"
        INSERT INTO logical_workflow_materialization_work_selections (
            selection_id, owner_id, requested_at_ms, duration_ms, outcome
        ) VALUES ($1,$2,$3,$4,'selecting')
        ON CONFLICT (selection_id) DO NOTHING
        ",
    )
    .bind(request.selection_id().as_uuid())
    .bind(request.owner().as_uuid())
    .bind(request.observed_at().get())
    .bind(request.duration_ms())
    .execute(&mut **transaction)
    .await
    .map_err(operation_error)?
    .rows_affected();
    match rows {
        0 => Ok(false),
        1 => Ok(true),
        _ => Err(StoreError::corrupt_data(
            "materialization selection reservation inserted an invalid row count",
        )
        .into()),
    }
}

async fn lock_selection_horizon(
    transaction: &mut Transaction<'_, Postgres>,
    queue: &'static str,
) -> Result<LockedSelectionHorizon, LogicalWorkSelectionStoreError> {
    let row = sqlx::query(
        r"
        SELECT replay_floor_ms, updated_at_ms, cursor_ready_at_ms,
               cursor_run_id, cursor_invocation_id, cursor_source_order,
               cursor_matrix_index, cursor_target_id
        FROM logical_workflow_work_selection_replay_horizons
        WHERE queue_name = $1
        FOR UPDATE
        ",
    )
    .bind(queue)
    .fetch_optional(&mut **transaction)
    .await
    .map_err(operation_error)?
    .ok_or_else(|| StoreError::corrupt_data("logical work replay horizon is absent"))?;
    let replay_floor: i64 = row.try_get("replay_floor_ms").map_err(operation_error)?;
    let updated_at: i64 = row.try_get("updated_at_ms").map_err(operation_error)?;
    if replay_floor < 0 || replay_floor > updated_at {
        return Err(StoreError::corrupt_data("logical work replay horizon is malformed").into());
    }
    let activation_cursor = if queue == "activation" {
        ActivationDiscoveryCursor::decode_horizon(&row)?
    } else {
        None
    };
    let materialization_cursor = if queue == "materialization" {
        MaterializationDiscoveryCursor::decode_horizon(&row)?
    } else {
        None
    };
    Ok(LockedSelectionHorizon {
        replay_floor,
        activation_cursor,
        materialization_cursor,
    })
}

async fn lock_selection_admission(
    transaction: &mut Transaction<'_, Postgres>,
    queue: &'static str,
    observed_at: UnixMillis,
    duration_ms: i64,
) -> Result<SelectionAdmission, LogicalWorkSelectionStoreError> {
    let row = sqlx::query(
        r"
        SELECT replay_floor_ms, updated_at_ms,
               floor(extract(epoch FROM clock_timestamp()) * 1000)::bigint AS database_now
        FROM logical_workflow_work_selection_replay_horizons
        WHERE queue_name = $1
        FOR UPDATE
        ",
    )
    .bind(queue)
    .fetch_one(&mut **transaction)
    .await
    .map_err(operation_error)?;
    let floor: i64 = row.try_get("replay_floor_ms").map_err(operation_error)?;
    let updated_at: i64 = row.try_get("updated_at_ms").map_err(operation_error)?;
    let now: i64 = row.try_get("database_now").map_err(operation_error)?;
    if floor < 0 || floor > updated_at || updated_at > now {
        return Err(StoreError::corrupt_data("logical work replay horizon is malformed").into());
    }
    if observed_at.get() < now.saturating_sub(MAX_SELECTION_CLOCK_SKEW_MILLIS)
        || observed_at.get() > now.saturating_add(MAX_SELECTION_CLOCK_SKEW_MILLIS)
    {
        return Err(LogicalWorkSelectionStoreError::SelectionClockSkew);
    }
    if checked_expiration(now, duration_ms)? <= now {
        return Err(LogicalWorkSelectionStoreError::SelectionExpired);
    }
    let elapsed = now
        .checked_sub(updated_at)
        .ok_or_else(|| StoreError::corrupt_data("logical work replay horizon moved into future"))?;
    let time_floor = now.saturating_sub(MAX_SELECTION_CLOCK_SKEW_MILLIS);
    let next_floor = floor.saturating_add(elapsed).min(time_floor).max(floor);
    if observed_at.get() <= next_floor {
        return Err(LogicalWorkSelectionStoreError::SelectionExpired);
    }
    Ok(SelectionAdmission {
        database_now: now,
        replay_floor: next_floor,
        previous_floor: floor,
        previous_updated_at: updated_at,
    })
}

async fn advance_selection_horizon(
    transaction: &mut Transaction<'_, Postgres>,
    queue: &'static str,
    admission: SelectionAdmission,
    cursor: DiscoveryCursorUpdate,
) -> Result<(), LogicalWorkSelectionStoreError> {
    let (ready_at, run_id, invocation_id, source_order, matrix_index, target_id) = match cursor {
        DiscoveryCursorUpdate::Activation(cursor) => {
            cursor.map_or((None, None, None, None, None, None), |cursor| {
                (
                    Some(cursor.ready_at),
                    Some(cursor.run_id),
                    Some(cursor.invocation_id),
                    Some(cursor.source_order),
                    None,
                    Some(cursor.logical_job_id),
                )
            })
        }
        DiscoveryCursorUpdate::Materialization(cursor) => {
            cursor.map_or((None, None, None, None, None, None), |cursor| {
                (
                    Some(cursor.ready_at),
                    Some(cursor.run_id),
                    Some(cursor.invocation_id),
                    Some(cursor.source_order),
                    Some(cursor.matrix_index),
                    Some(cursor.instance_id),
                )
            })
        }
    };
    let rows = sqlx::query(
        r"
        UPDATE logical_workflow_work_selection_replay_horizons
        SET replay_floor_ms = $2, updated_at_ms = $3,
            cursor_ready_at_ms = $6, cursor_run_id = $7,
            cursor_invocation_id = $8, cursor_source_order = $9,
            cursor_matrix_index = $10, cursor_target_id = $11
        WHERE queue_name = $1 AND replay_floor_ms = $4 AND updated_at_ms = $5
        ",
    )
    .bind(queue)
    .bind(admission.replay_floor)
    .bind(admission.database_now)
    .bind(admission.previous_floor)
    .bind(admission.previous_updated_at)
    .bind(ready_at)
    .bind(run_id)
    .bind(invocation_id)
    .bind(source_order)
    .bind(matrix_index)
    .bind(target_id)
    .execute(&mut **transaction)
    .await
    .map_err(operation_error)?
    .rows_affected();
    exact_one(rows, "logical work replay horizon lost its lock")
}

async fn cleanup_receipts(
    transaction: &mut Transaction<'_, Postgres>,
    queue: &'static str,
    replay_floor: i64,
) -> Result<(), LogicalWorkSelectionStoreError> {
    let query = match queue {
        "activation" => sqlx::query(
            r"
            WITH expired AS (
                SELECT selection_id
                FROM logical_workflow_activation_work_selections AS receipt
                WHERE expires_at_ms <= $1 AND requested_at_ms < $1
                  AND NOT EXISTS (
                      SELECT 1
                      FROM logical_workflow_activation_preparation_claims AS preparation
                      WHERE receipt.authority_kind = 'preparation'
                        AND preparation.logical_job_id = receipt.logical_job_id
                        AND preparation.origin_selection_id = receipt.selection_id
                        AND preparation.generation >= receipt.generation
                        AND preparation.descriptor_digest = receipt.authority_digest
                        AND preparation.state = 'preparing'
                  )
                  AND NOT EXISTS (
                      SELECT 1
                      FROM logical_workflow_jobs AS job
                      WHERE receipt.authority_kind = 'activation'
                        AND job.id = receipt.logical_job_id
                        AND job.activation_origin_selection_id = receipt.selection_id
                        AND job.activation_fence >= receipt.generation
                        AND job.activation_input_digest = receipt.authority_digest
                        AND job.state = 'activating'
                  )
                  AND NOT EXISTS (
                      SELECT 1
                      FROM logical_workflow_activation_work_quarantines AS quarantine
                      WHERE quarantine.selection_id = receipt.selection_id
                  )
                ORDER BY expires_at_ms, selection_id
                FOR UPDATE SKIP LOCKED
                LIMIT $2
            )
            DELETE FROM logical_workflow_activation_work_selections AS receipt
            USING expired
            WHERE receipt.selection_id = expired.selection_id
            ",
        ),
        "materialization" => sqlx::query(
            r"
            WITH expired AS (
                SELECT selection_id
                FROM logical_workflow_materialization_work_selections AS receipt
                WHERE expires_at_ms <= $1 AND requested_at_ms < $1
                  AND NOT EXISTS (
                      SELECT 1
                      FROM logical_workflow_materialization_claims AS claim
                      WHERE claim.instance_id = receipt.instance_id
                        AND claim.origin_selection_id = receipt.selection_id
                        AND claim.generation >= receipt.generation
                        AND claim.descriptor_digest = receipt.authority_digest
                        AND claim.state = 'materializing'
                  )
                  AND NOT EXISTS (
                      SELECT 1
                      FROM logical_workflow_materialization_work_quarantines AS quarantine
                      WHERE quarantine.selection_id = receipt.selection_id
                  )
                ORDER BY expires_at_ms, selection_id
                FOR UPDATE SKIP LOCKED
                LIMIT $2
            )
            DELETE FROM logical_workflow_materialization_work_selections AS receipt
            USING expired
            WHERE receipt.selection_id = expired.selection_id
            ",
        ),
        _ => return Err(StoreError::corrupt_data("unknown work-selection queue").into()),
    };
    query
        .bind(replay_floor)
        .bind(CLEANUP_BATCH_SIZE)
        .execute(&mut **transaction)
        .await
        .map_err(operation_error)?;
    Ok(())
}

async fn begin_candidate_savepoint(
    transaction: &mut Transaction<'_, Postgres>,
) -> Result<(), LogicalWorkSelectionStoreError> {
    sqlx::query("SAVEPOINT automata_work_candidate")
        .execute(&mut **transaction)
        .await
        .map_err(operation_error)?;
    Ok(())
}

async fn rollback_candidate_savepoint(
    transaction: &mut Transaction<'_, Postgres>,
) -> Result<(), LogicalWorkSelectionStoreError> {
    sqlx::query("ROLLBACK TO SAVEPOINT automata_work_candidate")
        .execute(&mut **transaction)
        .await
        .map_err(operation_error)?;
    release_candidate_savepoint(transaction).await
}

async fn release_candidate_savepoint(
    transaction: &mut Transaction<'_, Postgres>,
) -> Result<(), LogicalWorkSelectionStoreError> {
    sqlx::query("RELEASE SAVEPOINT automata_work_candidate")
        .execute(&mut **transaction)
        .await
        .map_err(operation_error)?;
    Ok(())
}

async fn discover_activation_candidates(
    transaction: &mut Transaction<'_, Postgres>,
    cursor: Option<&ActivationDiscoveryCursor>,
    limit: i64,
) -> Result<Vec<PgRow>, LogicalWorkSelectionStoreError> {
    let schemas = current_durable_schemas();
    sqlx::query(
        r"
        SELECT repository.tenant_id, repository.id AS repository_id,
               job.run_id, job.invocation_id,
               job.id AS logical_job_id, job.source_order,
               job.created_at_ms AS ready_at_ms,
               job.state AS job_state, job.activation_fence,
               job.activation_owner_id, job.activation_claimed_at_ms,
               job.activation_expires_at_ms, job.activation_input_digest,
               pin.policy_revision, pin.policy_digest,
               preparation_claim.state AS preparation_state,
               preparation_claim.owner_id AS preparation_owner_id,
               preparation_claim.generation AS preparation_generation,
               preparation_claim.descriptor_digest AS preparation_descriptor_digest,
               preparation_claim.claimed_at_ms AS preparation_claimed_at_ms,
               preparation_claim.expires_at_ms AS preparation_expires_at_ms,
               preparation.activation_input_digest AS prepared_input_digest
        FROM logical_workflow_jobs AS job
        JOIN logical_workflow_invocations AS invocation
          ON invocation.run_id = job.run_id AND invocation.id = job.invocation_id
        JOIN logical_workflow_runs AS marker ON marker.run_id = job.run_id
        JOIN workflow_runs AS run ON run.id = marker.run_id
        JOIN repositories AS repository ON repository.id = run.repository_id
        JOIN logical_workflow_runtime_policy_pins AS pin ON pin.run_id = job.run_id
        LEFT JOIN logical_workflow_activation_preparation_claims AS preparation_claim
          ON preparation_claim.logical_job_id = job.id
        LEFT JOIN logical_workflow_activation_preparations AS preparation
          ON preparation.logical_job_id = job.id
        LEFT JOIN logical_workflow_activation_work_quarantines AS quarantine
          ON quarantine.logical_job_id = job.id
        CROSS JOIN LATERAL (
            SELECT floor(extract(epoch FROM clock_timestamp()) * 1000)::BIGINT AS now_ms
        ) AS database_clock
        WHERE job.execution_kind = 'steps'
          AND automata_logical_workflow_invocation_published(
              marker.run_id, invocation.id
          )
          AND invocation.plan_schema = $7
          AND invocation.state IN ('pending', 'active')
          AND marker.orchestration_schema = $8
          AND marker.admission_graph_sealed_at_ms IS NOT NULL
          AND marker.state IN ('pending', 'active')
          AND run.status IN ('queued', 'in_progress')
          AND run.admission_epoch = $9 AND run.plan_schema = $9
          AND (
              (job.state = 'pending' AND (
                  preparation_claim.logical_job_id IS NULL
                  OR preparation_claim.state = 'prepared'
                  OR (preparation_claim.state = 'preparing'
                      AND preparation_claim.expires_at_ms <= database_clock.now_ms)
              ))
              OR (job.state = 'activating'
                  AND job.activation_expires_at_ms <= database_clock.now_ms)
          )
          AND quarantine.logical_job_id IS NULL
          AND NOT EXISTS (
              SELECT 1
              FROM logical_workflow_dependencies AS dependency
              LEFT JOIN logical_workflow_effective_job_results AS result
                ON result.logical_job_id = dependency.prerequisite_job_id
               AND result.run_id = dependency.run_id
               AND result.invocation_id = dependency.invocation_id
               AND result.claim_state = 'finalized'
              WHERE dependency.run_id = job.run_id
                AND dependency.invocation_id = job.invocation_id
                AND dependency.logical_job_id = job.id
                AND result.logical_job_id IS NULL
          )
          AND ($1::BIGINT IS NULL OR
               (job.created_at_ms, job.run_id, job.invocation_id,
                job.source_order, job.id) > ($1,$2,$3,$4,$5))
        ORDER BY job.created_at_ms, job.run_id, job.invocation_id,
                 job.source_order, job.id
        LIMIT $6
        ",
    )
    .bind(cursor.map(|value| value.ready_at))
    .bind(cursor.map(|value| value.run_id))
    .bind(cursor.map(|value| value.invocation_id))
    .bind(cursor.map(|value| value.source_order))
    .bind(cursor.map(|value| value.logical_job_id))
    .bind(limit)
    .bind(schemas.workflow_plan_i16)
    .bind(schemas.logical_orchestration_i16)
    .bind(schemas.workflow_plan_i32)
    .fetch_all(&mut **transaction)
    .await
    .map_err(operation_error)
}

async fn discover_materialization_candidates(
    transaction: &mut Transaction<'_, Postgres>,
    cursor: Option<&MaterializationDiscoveryCursor>,
    limit: i64,
) -> Result<Vec<PgRow>, LogicalWorkSelectionStoreError> {
    let schemas = current_durable_schemas();
    sqlx::query(
        r"
        SELECT repository.tenant_id, repository.id AS repository_id,
               instance.run_id, instance.invocation_id,
               instance.logical_job_id, instance.id AS instance_id,
               logical_job.source_order, instance.matrix_index,
               publication.published_at_ms AS ready_at_ms,
               pin.policy_revision, pin.policy_digest,
               claim.state AS claim_state, claim.owner_id AS claim_owner_id,
               claim.generation AS claim_generation,
               claim.descriptor_digest AS claim_descriptor_digest,
               claim.claimed_at_ms AS claim_claimed_at_ms,
               claim.expires_at_ms AS claim_expires_at_ms
        FROM logical_workflow_instances AS instance
        JOIN logical_workflow_activation_publications AS publication
          ON publication.run_id = instance.run_id
         AND publication.invocation_id = instance.invocation_id
         AND publication.logical_job_id = instance.logical_job_id
        JOIN logical_workflow_jobs AS logical_job
          ON logical_job.run_id = instance.run_id
         AND logical_job.invocation_id = instance.invocation_id
         AND logical_job.id = instance.logical_job_id
        JOIN logical_workflow_invocations AS invocation
          ON invocation.run_id = instance.run_id
         AND invocation.id = instance.invocation_id
        JOIN logical_workflow_runs AS marker ON marker.run_id = instance.run_id
        JOIN workflow_runs AS run ON run.id = marker.run_id
        JOIN repositories AS repository ON repository.id = run.repository_id
        JOIN logical_workflow_runtime_policy_pins AS pin ON pin.run_id = instance.run_id
        LEFT JOIN logical_workflow_materialization_claims AS claim
          ON claim.instance_id = instance.id
        LEFT JOIN logical_workflow_materialization_work_quarantines AS quarantine
          ON quarantine.instance_id = instance.id
        CROSS JOIN LATERAL (
            SELECT floor(extract(epoch FROM clock_timestamp()) * 1000)::BIGINT AS now_ms
        ) AS database_clock
        WHERE instance.job_ir_version = $8
          AND instance.runtime_context_schema = $9
          AND instance.runtime_policy_revision = pin.policy_revision
          AND instance.runtime_policy_digest = pin.policy_digest
          AND publication.runtime_policy_revision = pin.policy_revision
          AND publication.runtime_policy_digest = pin.policy_digest
          AND publication.condition_matched
          AND publication.instance_count > 0
          AND logical_job.execution_kind = 'steps'
          AND logical_job.state = 'activated'
          AND automata_logical_workflow_invocation_published(
              marker.run_id, invocation.id
          )
          AND invocation.plan_schema = $10
          AND invocation.state IN ('pending', 'active')
          AND marker.orchestration_schema = $11
          AND marker.admission_graph_sealed_at_ms IS NOT NULL
          AND marker.state IN ('pending', 'active')
          AND run.status IN ('queued', 'in_progress')
          AND run.admission_epoch = $12 AND run.plan_schema = $12
          AND (claim.instance_id IS NULL
               OR (claim.state = 'materializing'
                   AND claim.expires_at_ms <= database_clock.now_ms))
          AND quarantine.instance_id IS NULL
          AND ($1::BIGINT IS NULL OR
               (publication.published_at_ms, instance.run_id,
                instance.invocation_id, logical_job.source_order,
                instance.matrix_index, instance.id) > ($1,$2,$3,$4,$5,$6))
        ORDER BY publication.published_at_ms, instance.run_id,
                 instance.invocation_id, logical_job.source_order,
                 instance.matrix_index, instance.id
        LIMIT $7
        ",
    )
    .bind(cursor.map(|value| value.ready_at))
    .bind(cursor.map(|value| value.run_id))
    .bind(cursor.map(|value| value.invocation_id))
    .bind(cursor.map(|value| value.source_order))
    .bind(cursor.map(|value| value.matrix_index))
    .bind(cursor.map(|value| value.instance_id))
    .bind(limit)
    .bind(schemas.job_ir_i16)
    .bind(schemas.runtime_context_i16)
    .bind(schemas.workflow_plan_i16)
    .bind(schemas.logical_orchestration_i16)
    .bind(schemas.workflow_plan_i32)
    .fetch_all(&mut **transaction)
    .await
    .map_err(operation_error)
}

#[allow(clippy::too_many_lines)] // Canonical lock order is intentionally visible in one function.
async fn lock_activation_eligibility_graph(
    transaction: &mut Transaction<'_, Postgres>,
    row: &PgRow,
) -> Result<bool, LogicalWorkSelectionStoreError> {
    let run_id: Uuid = row.try_get("run_id").map_err(operation_error)?;
    let invocation_id: Uuid = row.try_get("invocation_id").map_err(operation_error)?;
    let logical_job_id: Uuid = row.try_get("logical_job_id").map_err(operation_error)?;
    if sqlx::query("SELECT id FROM workflow_runs WHERE id = $1 FOR UPDATE SKIP LOCKED")
        .bind(run_id)
        .fetch_optional(&mut **transaction)
        .await
        .map_err(operation_error)?
        .is_none()
    {
        return Ok(false);
    }
    if sqlx::query(
        "SELECT run_id FROM logical_workflow_runs WHERE run_id = $1 FOR UPDATE SKIP LOCKED",
    )
    .bind(run_id)
    .fetch_optional(&mut **transaction)
    .await
    .map_err(operation_error)?
    .is_none()
    {
        return Ok(false);
    }
    if sqlx::query(
        "SELECT id FROM logical_workflow_invocations WHERE run_id = $1 AND id = $2 FOR UPDATE SKIP LOCKED",
    )
    .bind(run_id)
    .bind(invocation_id)
    .fetch_optional(&mut **transaction)
    .await
    .map_err(operation_error)?
    .is_none()
    {
        return Ok(false);
    }
    if sqlx::query(
        "SELECT id FROM logical_workflow_jobs WHERE run_id = $1 AND invocation_id = $2 AND id = $3 FOR UPDATE SKIP LOCKED",
    )
    .bind(run_id)
    .bind(invocation_id)
    .bind(logical_job_id)
    .fetch_optional(&mut **transaction)
    .await
    .map_err(operation_error)?
    .is_none()
    {
        return Ok(false);
    }
    let preparation_locked = sqlx::query(
        "SELECT logical_job_id FROM logical_workflow_activation_preparation_claims WHERE logical_job_id = $1 FOR UPDATE SKIP LOCKED",
    )
    .bind(logical_job_id)
    .fetch_optional(&mut **transaction)
    .await
    .map_err(operation_error)?;
    if preparation_locked.is_none()
        && sqlx::query_scalar::<_, bool>(
            "SELECT EXISTS (SELECT 1 FROM logical_workflow_activation_preparation_claims WHERE logical_job_id = $1)",
        )
        .bind(logical_job_id)
        .fetch_one(&mut **transaction)
        .await
        .map_err(operation_error)?
    {
        return Ok(false);
    }
    if sqlx::query(
        "SELECT run_id FROM logical_workflow_runtime_policy_pins WHERE run_id = $1 FOR SHARE SKIP LOCKED",
    )
    .bind(run_id)
    .fetch_optional(&mut **transaction)
    .await
    .map_err(operation_error)?
    .is_none()
    {
        return Ok(false);
    }
    let dependency_count: i64 = sqlx::query_scalar(
        r"
        SELECT count(*)::BIGINT
        FROM logical_workflow_dependencies
        WHERE run_id = $1 AND invocation_id = $2 AND logical_job_id = $3
        ",
    )
    .bind(run_id)
    .bind(invocation_id)
    .bind(logical_job_id)
    .fetch_one(&mut **transaction)
    .await
    .map_err(operation_error)?;
    let dependencies = sqlx::query(
        r"
        SELECT dependency.prerequisite_job_id
        FROM logical_workflow_dependencies AS dependency
        WHERE dependency.run_id = $1 AND dependency.invocation_id = $2
          AND dependency.logical_job_id = $3
        ORDER BY dependency.prerequisite_job_id
        FOR SHARE OF dependency SKIP LOCKED
        ",
    )
    .bind(run_id)
    .bind(invocation_id)
    .bind(logical_job_id)
    .fetch_all(&mut **transaction)
    .await
    .map_err(operation_error)?;
    if i64::try_from(dependencies.len()).ok() != Some(dependency_count) {
        return Ok(false);
    }
    let prerequisite_jobs = sqlx::query(
        r"
        SELECT prerequisite.id
        FROM logical_workflow_dependencies AS dependency
        JOIN logical_workflow_jobs AS prerequisite
          ON prerequisite.id = dependency.prerequisite_job_id
         AND prerequisite.run_id = dependency.run_id
         AND prerequisite.invocation_id = dependency.invocation_id
        WHERE dependency.run_id = $1 AND dependency.invocation_id = $2
          AND dependency.logical_job_id = $3
        ORDER BY prerequisite.id
        FOR SHARE OF prerequisite SKIP LOCKED
        ",
    )
    .bind(run_id)
    .bind(invocation_id)
    .bind(logical_job_id)
    .fetch_all(&mut **transaction)
    .await
    .map_err(operation_error)?;
    if prerequisite_jobs.len() != dependencies.len() {
        return Ok(false);
    }
    let finalized_result_count: i64 = sqlx::query_scalar(
        r"
        SELECT count(*)::BIGINT
        FROM logical_workflow_dependencies AS dependency
        JOIN logical_workflow_effective_job_results AS result
          ON result.logical_job_id = dependency.prerequisite_job_id
         AND result.run_id = dependency.run_id
         AND result.invocation_id = dependency.invocation_id
         AND result.claim_state = 'finalized'
        WHERE dependency.run_id = $1 AND dependency.invocation_id = $2
          AND dependency.logical_job_id = $3
        ",
    )
    .bind(run_id)
    .bind(invocation_id)
    .bind(logical_job_id)
    .fetch_one(&mut **transaction)
    .await
    .map_err(operation_error)?;
    if usize::try_from(finalized_result_count).ok() != Some(dependencies.len()) {
        return Ok(false);
    }
    Ok(true)
}

#[allow(clippy::too_many_lines)] // Canonical lock order is intentionally visible in one function.
async fn lock_materialization_eligibility_graph(
    transaction: &mut Transaction<'_, Postgres>,
    row: &PgRow,
) -> Result<bool, LogicalWorkSelectionStoreError> {
    let instance_id: Uuid = row.try_get("instance_id").map_err(operation_error)?;
    let run_id: Uuid = row.try_get("run_id").map_err(operation_error)?;
    let invocation_id: Uuid = row.try_get("invocation_id").map_err(operation_error)?;
    let logical_job_id: Uuid = row.try_get("logical_job_id").map_err(operation_error)?;
    if sqlx::query("SELECT id FROM workflow_runs WHERE id = $1 FOR UPDATE SKIP LOCKED")
        .bind(run_id)
        .fetch_optional(&mut **transaction)
        .await
        .map_err(operation_error)?
        .is_none()
    {
        return Ok(false);
    }
    if sqlx::query(
        "SELECT run_id FROM logical_workflow_runs WHERE run_id = $1 FOR UPDATE SKIP LOCKED",
    )
    .bind(run_id)
    .fetch_optional(&mut **transaction)
    .await
    .map_err(operation_error)?
    .is_none()
    {
        return Ok(false);
    }
    if sqlx::query(
        "SELECT id FROM logical_workflow_invocations WHERE run_id = $1 AND id = $2 FOR UPDATE SKIP LOCKED",
    )
    .bind(run_id)
    .bind(invocation_id)
    .fetch_optional(&mut **transaction)
    .await
    .map_err(operation_error)?
    .is_none()
    {
        return Ok(false);
    }
    if sqlx::query(
        "SELECT id FROM logical_workflow_instances WHERE run_id = $1 AND invocation_id = $2 AND logical_job_id = $3 AND id = $4 FOR UPDATE SKIP LOCKED",
    )
    .bind(run_id)
    .bind(invocation_id)
    .bind(logical_job_id)
    .bind(instance_id)
    .fetch_optional(&mut **transaction)
    .await
    .map_err(operation_error)?
    .is_none()
    {
        return Ok(false);
    }
    let claim_locked = sqlx::query(
        "SELECT instance_id FROM logical_workflow_materialization_claims WHERE instance_id = $1 FOR UPDATE SKIP LOCKED",
    )
    .bind(instance_id)
    .fetch_optional(&mut **transaction)
    .await
    .map_err(operation_error)?;
    if claim_locked.is_none()
        && sqlx::query_scalar::<_, bool>(
            "SELECT EXISTS (SELECT 1 FROM logical_workflow_materialization_claims WHERE instance_id = $1)",
        )
        .bind(instance_id)
        .fetch_one(&mut **transaction)
        .await
        .map_err(operation_error)?
    {
        return Ok(false);
    }
    if sqlx::query(
        "SELECT id FROM logical_workflow_jobs WHERE run_id = $1 AND invocation_id = $2 AND id = $3 FOR UPDATE SKIP LOCKED",
    )
    .bind(run_id)
    .bind(invocation_id)
    .bind(logical_job_id)
    .fetch_optional(&mut **transaction)
    .await
    .map_err(operation_error)?
    .is_none()
    {
        return Ok(false);
    }
    if sqlx::query(
        r"
        SELECT logical_job_id
        FROM logical_workflow_activation_publications
        WHERE run_id = $1 AND invocation_id = $2 AND logical_job_id = $3
        FOR SHARE SKIP LOCKED
        ",
    )
    .bind(run_id)
    .bind(invocation_id)
    .bind(logical_job_id)
    .fetch_optional(&mut **transaction)
    .await
    .map_err(operation_error)?
    .is_none()
    {
        return Ok(false);
    }
    if sqlx::query(
        "SELECT run_id FROM logical_workflow_runtime_policy_pins WHERE run_id = $1 FOR SHARE SKIP LOCKED",
    )
    .bind(run_id)
    .fetch_optional(&mut **transaction)
    .await
    .map_err(operation_error)?
    .is_none()
    {
        return Ok(false);
    }
    Ok(true)
}

async fn activation_candidate_is_eligible(
    transaction: &mut Transaction<'_, Postgres>,
    row: &PgRow,
    now: i64,
) -> Result<bool, LogicalWorkSelectionStoreError> {
    let schemas = current_durable_schemas();
    sqlx::query_scalar(
        r"
        SELECT EXISTS (
            SELECT 1
            FROM logical_workflow_jobs AS job
            JOIN logical_workflow_invocations AS invocation
              ON invocation.run_id = job.run_id AND invocation.id = job.invocation_id
            JOIN logical_workflow_runs AS marker ON marker.run_id = job.run_id
            JOIN workflow_runs AS run ON run.id = marker.run_id
            LEFT JOIN logical_workflow_activation_preparation_claims AS preparation
              ON preparation.logical_job_id = job.id
            LEFT JOIN logical_workflow_activation_work_quarantines AS quarantine
              ON quarantine.logical_job_id = job.id
            WHERE job.id = $1 AND job.run_id = $2 AND job.invocation_id = $3
              AND job.execution_kind = 'steps'
              AND automata_logical_workflow_invocation_published(
                  marker.run_id, invocation.id
              )
              AND invocation.plan_schema = $5
              AND invocation.state IN ('pending', 'active')
              AND marker.orchestration_schema = $6
              AND marker.admission_graph_sealed_at_ms IS NOT NULL
              AND marker.state IN ('pending', 'active')
              AND run.status IN ('queued', 'in_progress')
              AND run.admission_epoch = $7 AND run.plan_schema = $7
              AND quarantine.logical_job_id IS NULL
              AND (
                  (job.state = 'pending' AND (
                      preparation.logical_job_id IS NULL
                      OR preparation.state = 'prepared'
                      OR (preparation.state = 'preparing' AND preparation.expires_at_ms <= $4)
                  ))
                  OR (job.state = 'activating' AND job.activation_expires_at_ms <= $4)
              )
              AND NOT EXISTS (
                  SELECT 1
                  FROM logical_workflow_dependencies AS dependency
                  LEFT JOIN logical_workflow_effective_job_results AS result
                    ON result.logical_job_id = dependency.prerequisite_job_id
                   AND result.run_id = dependency.run_id
                   AND result.invocation_id = dependency.invocation_id
                   AND result.claim_state = 'finalized'
                  WHERE dependency.run_id = job.run_id
                    AND dependency.invocation_id = job.invocation_id
                    AND dependency.logical_job_id = job.id
                    AND result.logical_job_id IS NULL
              )
        )
        ",
    )
    .bind(
        row.try_get::<Uuid, _>("logical_job_id")
            .map_err(operation_error)?,
    )
    .bind(row.try_get::<Uuid, _>("run_id").map_err(operation_error)?)
    .bind(
        row.try_get::<Uuid, _>("invocation_id")
            .map_err(operation_error)?,
    )
    .bind(now)
    .bind(schemas.workflow_plan_i16)
    .bind(schemas.logical_orchestration_i16)
    .bind(schemas.workflow_plan_i32)
    .fetch_one(&mut **transaction)
    .await
    .map_err(operation_error)
}

async fn materialization_candidate_is_eligible(
    transaction: &mut Transaction<'_, Postgres>,
    row: &PgRow,
    now: i64,
) -> Result<bool, LogicalWorkSelectionStoreError> {
    let schemas = current_durable_schemas();
    sqlx::query_scalar(
        r"
        SELECT EXISTS (
            SELECT 1
            FROM logical_workflow_instances AS instance
            JOIN logical_workflow_activation_publications AS publication
              ON publication.run_id = instance.run_id
             AND publication.invocation_id = instance.invocation_id
             AND publication.logical_job_id = instance.logical_job_id
            JOIN logical_workflow_jobs AS job
              ON job.run_id = instance.run_id
             AND job.invocation_id = instance.invocation_id
             AND job.id = instance.logical_job_id
            JOIN logical_workflow_invocations AS invocation
              ON invocation.run_id = instance.run_id AND invocation.id = instance.invocation_id
            JOIN logical_workflow_runs AS marker ON marker.run_id = instance.run_id
            JOIN workflow_runs AS run ON run.id = marker.run_id
            JOIN logical_workflow_runtime_policy_pins AS pin ON pin.run_id = instance.run_id
            LEFT JOIN logical_workflow_materialization_claims AS claim
              ON claim.instance_id = instance.id
            LEFT JOIN logical_workflow_materialization_work_quarantines AS quarantine
              ON quarantine.instance_id = instance.id
            WHERE instance.id = $1 AND instance.run_id = $2
              AND instance.invocation_id = $3 AND instance.logical_job_id = $4
              AND instance.job_ir_version = $6 AND instance.runtime_context_schema = $7
              AND instance.runtime_policy_revision = pin.policy_revision
              AND instance.runtime_policy_digest = pin.policy_digest
              AND publication.runtime_policy_revision = pin.policy_revision
              AND publication.runtime_policy_digest = pin.policy_digest
              AND publication.condition_matched AND publication.instance_count > 0
              AND job.execution_kind = 'steps' AND job.state = 'activated'
              AND automata_logical_workflow_invocation_published(
                  marker.run_id, invocation.id
              )
              AND invocation.plan_schema = $8
              AND invocation.state IN ('pending', 'active')
              AND marker.orchestration_schema = $9
              AND marker.admission_graph_sealed_at_ms IS NOT NULL
              AND marker.state IN ('pending', 'active')
              AND run.status IN ('queued', 'in_progress')
              AND run.admission_epoch = $10 AND run.plan_schema = $10
              AND (claim.instance_id IS NULL
                   OR (claim.state = 'materializing' AND claim.expires_at_ms <= $5))
              AND quarantine.instance_id IS NULL
        )
        ",
    )
    .bind(
        row.try_get::<Uuid, _>("instance_id")
            .map_err(operation_error)?,
    )
    .bind(row.try_get::<Uuid, _>("run_id").map_err(operation_error)?)
    .bind(
        row.try_get::<Uuid, _>("invocation_id")
            .map_err(operation_error)?,
    )
    .bind(
        row.try_get::<Uuid, _>("logical_job_id")
            .map_err(operation_error)?,
    )
    .bind(now)
    .bind(schemas.job_ir_i16)
    .bind(schemas.runtime_context_i16)
    .bind(schemas.workflow_plan_i16)
    .bind(schemas.logical_orchestration_i16)
    .bind(schemas.workflow_plan_i32)
    .fetch_one(&mut **transaction)
    .await
    .map_err(operation_error)
}

async fn claim_activation_candidate(
    transaction: &mut Transaction<'_, Postgres>,
    request: &ClaimNextLogicalJobOrchestration,
    row: &PgRow,
    now: i64,
    expires_at: i64,
) -> Result<SelectedLogicalJobOrchestration, LogicalWorkSelectionStoreError> {
    let target = decode_activation_target(row)?;
    let prepared_input = optional_digest(row, "prepared_input_digest")?;
    let durable_input = optional_digest(row, "activation_input_digest")?;
    if let Some(input_digest) = prepared_input.or(durable_input) {
        let tenant = target.tenant().clone();
        let revision = decode_policy_revision(row)?;
        let policy_digest = decode_digest(row, "policy_digest")?;
        let repository_id =
            RepositoryId::from_uuid(row.try_get("repository_id").map_err(operation_error)?);
        let claim_request = ClaimLogicalJobActivation::new(
            tenant.clone(),
            target.run_id(),
            target.invocation_id(),
            target.logical_job_id(),
            request.owner(),
            WorkflowRuntimePolicyPin::new(tenant, repository_id, revision, policy_digest),
            input_digest,
            UnixMillis::new(now),
            UnixMillis::new(expires_at),
        )
        .map_err(corrupt_value)?;
        let claimed = claim_logical_job_activation_in_transaction(
            transaction,
            &claim_request,
            request.selection_id().as_uuid(),
        )
        .await
        .map_err(map_activation_claim_error)?
        .ok_or_else(|| {
            StoreError::corrupt_data("locked activation candidate ceased to be claimable")
        })?;
        let claim = claimed.claim();
        return SelectedLogicalJobOrchestration::new(
            request.selection_id(),
            target,
            request.owner(),
            decode_selection_generation(claim.generation().get())?,
            LogicalJobOrchestrationAuthorityKind::Activation,
            claim.input_digest(),
            claim.claimed_at(),
            claim.expires_at(),
        )
        .map_err(corrupt_value);
    }

    let claim_request = ClaimLogicalActivationPreparation::new(
        target.clone(),
        request.owner(),
        UnixMillis::new(now),
        UnixMillis::new(expires_at),
    )
    .map_err(corrupt_value)?;
    let outcome = claim_logical_activation_preparation_in_transaction(
        transaction,
        &claim_request,
        request.selection_id().as_uuid(),
    )
    .await
    .map_err(map_preparation_claim_error)?;
    let claimed = match outcome {
        LogicalActivationPreparationClaimOutcome::Claimed(claimed) => claimed,
        LogicalActivationPreparationClaimOutcome::NotReady
        | LogicalActivationPreparationClaimOutcome::Busy
        | LogicalActivationPreparationClaimOutcome::Prepared(_) => {
            return Err(StoreError::corrupt_data(
                "locked preparation candidate ceased to be claimable",
            )
            .into());
        }
    };
    let claim = claimed.claim();
    SelectedLogicalJobOrchestration::new(
        request.selection_id(),
        target,
        request.owner(),
        decode_selection_generation(claim.generation().get())?,
        LogicalJobOrchestrationAuthorityKind::Preparation,
        claim.descriptor_digest(),
        claim.claimed_at(),
        claim.expires_at(),
    )
    .map_err(corrupt_value)
}

async fn claim_materialization_candidate(
    transaction: &mut Transaction<'_, Postgres>,
    request: &ClaimNextLogicalInstanceMaterialization,
    row: &PgRow,
    now: i64,
    expires_at: i64,
) -> Result<SelectedLogicalInstanceMaterialization, LogicalWorkSelectionStoreError> {
    let target = decode_materialization_target(row)?;
    let claim_request = ClaimLogicalInstanceMaterialization::new(
        target.clone(),
        request.owner(),
        UnixMillis::new(now),
        UnixMillis::new(expires_at),
    )
    .map_err(corrupt_value)?;
    let outcome = claim_logical_instance_materialization_in_transaction(
        transaction,
        &claim_request,
        request.selection_id().as_uuid(),
    )
    .await
    .map_err(map_materialization_claim_error)?;
    let claimed = match outcome {
        LogicalInstanceMaterializationClaimOutcome::Claimed(claimed) => claimed,
        LogicalInstanceMaterializationClaimOutcome::Busy
        | LogicalInstanceMaterializationClaimOutcome::Materialized(_) => {
            return Err(StoreError::corrupt_data(
                "locked materialization candidate ceased to be claimable",
            )
            .into());
        }
    };
    let claim = claimed.claim();
    SelectedLogicalInstanceMaterialization::new(
        request.selection_id(),
        target,
        request.owner(),
        decode_selection_generation(claim.generation().get())?,
        claim.descriptor_digest(),
        claim.claimed_at(),
        claim.expires_at(),
    )
    .map_err(corrupt_value)
}

struct GenerationPoisonEvidence {
    owner: Uuid,
    generation: i64,
    digest: Sha256Digest,
    claimed_at: i64,
    expires_at: i64,
}

async fn quarantine_activation_generation_poison(
    transaction: &mut Transaction<'_, Postgres>,
    request: &ClaimNextLogicalJobOrchestration,
    row: &PgRow,
    selection_claimed_at: i64,
    selection_expires_at: i64,
) -> Result<(), LogicalWorkSelectionStoreError> {
    let target = decode_activation_target(row)?;
    let (authority_kind, evidence) =
        load_locked_activation_generation_poison(transaction, &target).await?;
    require_max_generation_poison(&evidence, selection_claimed_at)?;
    let rows = sqlx::query(
        r"
        INSERT INTO logical_workflow_activation_work_quarantines (
            logical_job_id, tenant_id, run_id, invocation_id,
            selection_id, selection_owner_id,
            selection_requested_at_ms, selection_duration_ms,
            selection_generation, selection_claimed_at_ms,
            selection_expires_at_ms, authority_kind, authority_digest,
            authority_owner_id, authority_generation,
            authority_claimed_at_ms, authority_expires_at_ms,
            failure_kind, quarantined_at_ms
        ) VALUES (
            $1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,
            'generation_exhausted',$10
        )
        ",
    )
    .bind(target.logical_job_id().as_uuid())
    .bind(target.tenant().as_str())
    .bind(target.run_id().as_uuid())
    .bind(target.invocation_id().as_uuid())
    .bind(request.selection_id().as_uuid())
    .bind(request.owner().as_uuid())
    .bind(request.observed_at().get())
    .bind(request.duration_ms())
    .bind(evidence.generation)
    .bind(selection_claimed_at)
    .bind(selection_expires_at)
    .bind(authority_kind_name(authority_kind))
    .bind(evidence.digest.as_bytes().as_slice())
    .bind(evidence.owner)
    .bind(evidence.generation)
    .bind(evidence.claimed_at)
    .bind(evidence.expires_at)
    .execute(&mut **transaction)
    .await
    .map_err(operation_error)?
    .rows_affected();
    exact_one(rows, "activation generation poison was not quarantined")?;

    let rows = sqlx::query(
        r"
        UPDATE logical_workflow_activation_work_selections
        SET claimed_at_ms = $2, expires_at_ms = $3, outcome = 'quarantined',
            tenant_id = $4, run_id = $5, invocation_id = $6,
            logical_job_id = $7, generation = $8,
            authority_kind = $9, authority_digest = $10
        WHERE selection_id = $1 AND owner_id = $11
          AND requested_at_ms = $12 AND duration_ms = $13
          AND outcome = 'selecting'
        ",
    )
    .bind(request.selection_id().as_uuid())
    .bind(selection_claimed_at)
    .bind(selection_expires_at)
    .bind(target.tenant().as_str())
    .bind(target.run_id().as_uuid())
    .bind(target.invocation_id().as_uuid())
    .bind(target.logical_job_id().as_uuid())
    .bind(evidence.generation)
    .bind(authority_kind_name(authority_kind))
    .bind(evidence.digest.as_bytes().as_slice())
    .bind(request.owner().as_uuid())
    .bind(request.observed_at().get())
    .bind(request.duration_ms())
    .execute(&mut **transaction)
    .await
    .map_err(operation_error)?
    .rows_affected();
    exact_one(
        rows,
        "activation generation poison receipt was not finalized",
    )
}

async fn quarantine_materialization_generation_poison(
    transaction: &mut Transaction<'_, Postgres>,
    request: &ClaimNextLogicalInstanceMaterialization,
    row: &PgRow,
    selection_claimed_at: i64,
    selection_expires_at: i64,
) -> Result<(), LogicalWorkSelectionStoreError> {
    let target = decode_materialization_target(row)?;
    let evidence = load_locked_materialization_generation_poison(transaction, &target).await?;
    require_max_generation_poison(&evidence, selection_claimed_at)?;
    let rows = sqlx::query(
        r"
        INSERT INTO logical_workflow_materialization_work_quarantines (
            instance_id, tenant_id, run_id, invocation_id, logical_job_id,
            selection_id, selection_owner_id,
            selection_requested_at_ms, selection_duration_ms,
            selection_generation, selection_claimed_at_ms,
            selection_expires_at_ms, authority_digest,
            authority_owner_id, authority_generation,
            authority_claimed_at_ms, authority_expires_at_ms,
            failure_kind, quarantined_at_ms
        ) VALUES (
            $1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,
            'generation_exhausted',$11
        )
        ",
    )
    .bind(target.instance_id().as_uuid())
    .bind(target.tenant().as_str())
    .bind(target.run_id().as_uuid())
    .bind(target.invocation_id().as_uuid())
    .bind(target.logical_job_id().as_uuid())
    .bind(request.selection_id().as_uuid())
    .bind(request.owner().as_uuid())
    .bind(request.observed_at().get())
    .bind(request.duration_ms())
    .bind(evidence.generation)
    .bind(selection_claimed_at)
    .bind(selection_expires_at)
    .bind(evidence.digest.as_bytes().as_slice())
    .bind(evidence.owner)
    .bind(evidence.generation)
    .bind(evidence.claimed_at)
    .bind(evidence.expires_at)
    .execute(&mut **transaction)
    .await
    .map_err(operation_error)?
    .rows_affected();
    exact_one(
        rows,
        "materialization generation poison was not quarantined",
    )?;

    let rows = sqlx::query(
        r"
        UPDATE logical_workflow_materialization_work_selections
        SET claimed_at_ms = $2, expires_at_ms = $3, outcome = 'quarantined',
            tenant_id = $4, run_id = $5, invocation_id = $6,
            logical_job_id = $7, instance_id = $8, generation = $9,
            authority_digest = $10
        WHERE selection_id = $1 AND owner_id = $11
          AND requested_at_ms = $12 AND duration_ms = $13
          AND outcome = 'selecting'
        ",
    )
    .bind(request.selection_id().as_uuid())
    .bind(selection_claimed_at)
    .bind(selection_expires_at)
    .bind(target.tenant().as_str())
    .bind(target.run_id().as_uuid())
    .bind(target.invocation_id().as_uuid())
    .bind(target.logical_job_id().as_uuid())
    .bind(target.instance_id().as_uuid())
    .bind(evidence.generation)
    .bind(evidence.digest.as_bytes().as_slice())
    .bind(request.owner().as_uuid())
    .bind(request.observed_at().get())
    .bind(request.duration_ms())
    .execute(&mut **transaction)
    .await
    .map_err(operation_error)?
    .rows_affected();
    exact_one(
        rows,
        "materialization generation poison receipt was not finalized",
    )
}

async fn load_locked_activation_generation_poison(
    transaction: &mut Transaction<'_, Postgres>,
    target: &LogicalActivationPreparationTarget,
) -> Result<
    (
        LogicalJobOrchestrationAuthorityKind,
        GenerationPoisonEvidence,
    ),
    LogicalWorkSelectionStoreError,
> {
    let job = sqlx::query(
        r"
        SELECT state, activation_owner_id, activation_fence,
               activation_input_digest, activation_claimed_at_ms,
               activation_expires_at_ms
        FROM logical_workflow_jobs
        WHERE run_id = $1 AND invocation_id = $2 AND id = $3
        ",
    )
    .bind(target.run_id().as_uuid())
    .bind(target.invocation_id().as_uuid())
    .bind(target.logical_job_id().as_uuid())
    .fetch_optional(&mut **transaction)
    .await
    .map_err(operation_error)?
    .ok_or_else(|| StoreError::corrupt_data("locked activation poison target disappeared"))?;
    match job
        .try_get::<String, _>("state")
        .map_err(operation_error)?
        .as_str()
    {
        "activating" => Ok((
            LogicalJobOrchestrationAuthorityKind::Activation,
            generation_poison_evidence(
                &job,
                "activation_owner_id",
                "activation_fence",
                "activation_input_digest",
                "activation_claimed_at_ms",
                "activation_expires_at_ms",
            )?,
        )),
        "pending" => {
            let preparation = sqlx::query(
                r"
                SELECT state, owner_id, generation, descriptor_digest,
                       claimed_at_ms, expires_at_ms
                FROM logical_workflow_activation_preparation_claims
                WHERE logical_job_id = $1
                ",
            )
            .bind(target.logical_job_id().as_uuid())
            .fetch_optional(&mut **transaction)
            .await
            .map_err(operation_error)?
            .ok_or_else(|| {
                StoreError::corrupt_data("locked preparation poison authority disappeared")
            })?;
            if preparation
                .try_get::<String, _>("state")
                .map_err(operation_error)?
                != "preparing"
            {
                return Err(StoreError::corrupt_data(
                    "generation exhaustion lacks one active preparation authority",
                )
                .into());
            }
            Ok((
                LogicalJobOrchestrationAuthorityKind::Preparation,
                generation_poison_evidence(
                    &preparation,
                    "owner_id",
                    "generation",
                    "descriptor_digest",
                    "claimed_at_ms",
                    "expires_at_ms",
                )?,
            ))
        }
        _ => Err(StoreError::corrupt_data(
            "generation exhaustion lacks one active orchestration authority",
        )
        .into()),
    }
}

async fn load_locked_materialization_generation_poison(
    transaction: &mut Transaction<'_, Postgres>,
    target: &LogicalInstanceMaterializationTarget,
) -> Result<GenerationPoisonEvidence, LogicalWorkSelectionStoreError> {
    let claim = sqlx::query(
        r"
        SELECT state, owner_id, generation, descriptor_digest,
               claimed_at_ms, expires_at_ms
        FROM logical_workflow_materialization_claims
        WHERE instance_id = $1
        ",
    )
    .bind(target.instance_id().as_uuid())
    .fetch_optional(&mut **transaction)
    .await
    .map_err(operation_error)?
    .ok_or_else(|| StoreError::corrupt_data("locked materialization poison claim disappeared"))?;
    if claim
        .try_get::<String, _>("state")
        .map_err(operation_error)?
        != "materializing"
    {
        return Err(StoreError::corrupt_data(
            "generation exhaustion lacks one active materialization authority",
        )
        .into());
    }
    generation_poison_evidence(
        &claim,
        "owner_id",
        "generation",
        "descriptor_digest",
        "claimed_at_ms",
        "expires_at_ms",
    )
}

fn generation_poison_evidence(
    row: &PgRow,
    owner_column: &str,
    generation_column: &str,
    digest_column: &str,
    claimed_at_column: &str,
    expires_at_column: &str,
) -> Result<GenerationPoisonEvidence, LogicalWorkSelectionStoreError> {
    Ok(GenerationPoisonEvidence {
        owner: row
            .try_get::<Option<Uuid>, _>(owner_column)
            .map_err(operation_error)?
            .ok_or_else(|| StoreError::corrupt_data("generation poison owner is absent"))?,
        generation: row
            .try_get::<Option<i64>, _>(generation_column)
            .map_err(operation_error)?
            .ok_or_else(|| StoreError::corrupt_data("generation poison fence is absent"))?,
        digest: optional_digest(row, digest_column)?
            .ok_or_else(|| StoreError::corrupt_data("generation poison digest is absent"))?,
        claimed_at: row
            .try_get::<Option<i64>, _>(claimed_at_column)
            .map_err(operation_error)?
            .ok_or_else(|| StoreError::corrupt_data("generation poison claim start is absent"))?,
        expires_at: row
            .try_get::<Option<i64>, _>(expires_at_column)
            .map_err(operation_error)?
            .ok_or_else(|| StoreError::corrupt_data("generation poison expiry is absent"))?,
    })
}

fn require_max_generation_poison(
    evidence: &GenerationPoisonEvidence,
    database_now: i64,
) -> Result<(), LogicalWorkSelectionStoreError> {
    if evidence.generation != i64::MAX || evidence.expires_at > database_now {
        return Err(StoreError::corrupt_data(
            "generation exhaustion lacks one exact expired maximum fence",
        )
        .into());
    }
    Ok(())
}

async fn insert_activation_idle(
    transaction: &mut Transaction<'_, Postgres>,
    request: &ClaimNextLogicalJobOrchestration,
    now: i64,
    expires_at: i64,
) -> Result<(), LogicalWorkSelectionStoreError> {
    insert_activation_receipt(
        transaction,
        request,
        now,
        expires_at,
        "idle",
        None,
        None,
        None,
        None,
    )
    .await
}

async fn insert_activation_contended(
    transaction: &mut Transaction<'_, Postgres>,
    request: &ClaimNextLogicalJobOrchestration,
    now: i64,
    expires_at: i64,
) -> Result<(), LogicalWorkSelectionStoreError> {
    insert_activation_receipt(
        transaction,
        request,
        now,
        expires_at,
        "contended",
        None,
        None,
        None,
        None,
    )
    .await
}

async fn insert_activation_selected(
    transaction: &mut Transaction<'_, Postgres>,
    request: &ClaimNextLogicalJobOrchestration,
    selected: &SelectedLogicalJobOrchestration,
) -> Result<(), LogicalWorkSelectionStoreError> {
    insert_activation_receipt(
        transaction,
        request,
        selected.claimed_at().get(),
        selected.expires_at().get(),
        "claimed",
        Some(selected.target()),
        Some(selected.generation()),
        Some(selected.authority_kind()),
        Some(selected.authority_digest()),
    )
    .await
}

#[allow(clippy::too_many_arguments)] // The transition binds one closed evidence tuple.
async fn insert_activation_receipt(
    transaction: &mut Transaction<'_, Postgres>,
    request: &ClaimNextLogicalJobOrchestration,
    now: i64,
    expires_at: i64,
    outcome: &'static str,
    target: Option<&LogicalActivationPreparationTarget>,
    generation: Option<LogicalWorkSelectionGeneration>,
    authority_kind: Option<LogicalJobOrchestrationAuthorityKind>,
    authority_digest: Option<Sha256Digest>,
) -> Result<(), LogicalWorkSelectionStoreError> {
    let rows = sqlx::query(
        r"
        UPDATE logical_workflow_activation_work_selections
        SET claimed_at_ms = $5, expires_at_ms = $6, outcome = $7,
            tenant_id = $8, run_id = $9, invocation_id = $10,
            logical_job_id = $11, generation = $12,
            authority_kind = $13, authority_digest = $14
        WHERE selection_id = $1 AND owner_id = $2
          AND requested_at_ms = $3 AND duration_ms = $4
          AND outcome = 'selecting'
        ",
    )
    .bind(request.selection_id().as_uuid())
    .bind(request.owner().as_uuid())
    .bind(request.observed_at().get())
    .bind(request.duration_ms())
    .bind(now)
    .bind(expires_at)
    .bind(outcome)
    .bind(target.map(|target| target.tenant().as_str()))
    .bind(target.map(|target| target.run_id().as_uuid()))
    .bind(target.map(|target| target.invocation_id().as_uuid()))
    .bind(target.map(|target| target.logical_job_id().as_uuid()))
    .bind(generation.map(LogicalWorkSelectionGeneration::as_i64))
    .bind(authority_kind.map(authority_kind_name))
    .bind(authority_digest.map(|digest| digest.as_bytes().to_vec()))
    .execute(&mut **transaction)
    .await
    .map_err(operation_error)?
    .rows_affected();
    exact_one(rows, "activation work selection was not recorded")
}

async fn insert_materialization_idle(
    transaction: &mut Transaction<'_, Postgres>,
    request: &ClaimNextLogicalInstanceMaterialization,
    now: i64,
    expires_at: i64,
) -> Result<(), LogicalWorkSelectionStoreError> {
    insert_materialization_receipt(
        transaction,
        request,
        now,
        expires_at,
        "idle",
        None,
        None,
        None,
    )
    .await
}

async fn insert_materialization_contended(
    transaction: &mut Transaction<'_, Postgres>,
    request: &ClaimNextLogicalInstanceMaterialization,
    now: i64,
    expires_at: i64,
) -> Result<(), LogicalWorkSelectionStoreError> {
    insert_materialization_receipt(
        transaction,
        request,
        now,
        expires_at,
        "contended",
        None,
        None,
        None,
    )
    .await
}

async fn insert_materialization_selected(
    transaction: &mut Transaction<'_, Postgres>,
    request: &ClaimNextLogicalInstanceMaterialization,
    selected: &SelectedLogicalInstanceMaterialization,
) -> Result<(), LogicalWorkSelectionStoreError> {
    insert_materialization_receipt(
        transaction,
        request,
        selected.claimed_at().get(),
        selected.expires_at().get(),
        "claimed",
        Some(selected.target()),
        Some(selected.generation()),
        Some(selected.authority_digest()),
    )
    .await
}

#[allow(clippy::too_many_arguments)] // The transition binds one closed evidence tuple.
async fn insert_materialization_receipt(
    transaction: &mut Transaction<'_, Postgres>,
    request: &ClaimNextLogicalInstanceMaterialization,
    now: i64,
    expires_at: i64,
    outcome: &'static str,
    target: Option<&LogicalInstanceMaterializationTarget>,
    generation: Option<LogicalWorkSelectionGeneration>,
    authority_digest: Option<Sha256Digest>,
) -> Result<(), LogicalWorkSelectionStoreError> {
    let rows = sqlx::query(
        r"
        UPDATE logical_workflow_materialization_work_selections
        SET claimed_at_ms = $5, expires_at_ms = $6, outcome = $7,
            tenant_id = $8, run_id = $9, invocation_id = $10,
            logical_job_id = $11, instance_id = $12, generation = $13,
            authority_digest = $14
        WHERE selection_id = $1 AND owner_id = $2
          AND requested_at_ms = $3 AND duration_ms = $4
          AND outcome = 'selecting'
        ",
    )
    .bind(request.selection_id().as_uuid())
    .bind(request.owner().as_uuid())
    .bind(request.observed_at().get())
    .bind(request.duration_ms())
    .bind(now)
    .bind(expires_at)
    .bind(outcome)
    .bind(target.map(|target| target.tenant().as_str()))
    .bind(target.map(|target| target.run_id().as_uuid()))
    .bind(target.map(|target| target.invocation_id().as_uuid()))
    .bind(target.map(|target| target.logical_job_id().as_uuid()))
    .bind(target.map(|target| target.instance_id().as_uuid()))
    .bind(generation.map(LogicalWorkSelectionGeneration::as_i64))
    .bind(authority_digest.map(|digest| digest.as_bytes().to_vec()))
    .execute(&mut **transaction)
    .await
    .map_err(operation_error)?
    .rows_affected();
    exact_one(rows, "materialization work selection was not recorded")
}

async fn lock_activation_receipt(
    transaction: &mut Transaction<'_, Postgres>,
    request: &ClaimNextLogicalJobOrchestration,
) -> Result<Option<PgRow>, LogicalWorkSelectionStoreError> {
    sqlx::query(
        r"
        SELECT owner_id, requested_at_ms, duration_ms, claimed_at_ms,
               expires_at_ms, outcome, tenant_id, run_id, invocation_id,
               logical_job_id, generation, authority_kind, authority_digest
        FROM logical_workflow_activation_work_selections
        WHERE selection_id = $1 FOR UPDATE
        ",
    )
    .bind(request.selection_id().as_uuid())
    .fetch_optional(&mut **transaction)
    .await
    .map_err(operation_error)
}

async fn lock_materialization_receipt(
    transaction: &mut Transaction<'_, Postgres>,
    request: &ClaimNextLogicalInstanceMaterialization,
) -> Result<Option<PgRow>, LogicalWorkSelectionStoreError> {
    sqlx::query(
        r"
        SELECT owner_id, requested_at_ms, duration_ms, claimed_at_ms,
               expires_at_ms, outcome, tenant_id, run_id, invocation_id,
               logical_job_id, instance_id, generation, authority_digest
        FROM logical_workflow_materialization_work_selections
        WHERE selection_id = $1 FOR UPDATE
        ",
    )
    .bind(request.selection_id().as_uuid())
    .fetch_optional(&mut **transaction)
    .await
    .map_err(operation_error)
}

async fn replay_activation(
    transaction: &mut Transaction<'_, Postgres>,
    request: &ClaimNextLogicalJobOrchestration,
    row: &PgRow,
) -> Result<LogicalJobOrchestrationSelectionOutcome, LogicalWorkSelectionStoreError> {
    verify_activation_request(row, request)?;
    match row
        .try_get::<String, _>("outcome")
        .map_err(operation_error)?
        .as_str()
    {
        "idle" => Ok(LogicalJobOrchestrationSelectionOutcome::Idle),
        "contended" => Ok(LogicalJobOrchestrationSelectionOutcome::Contended),
        "quarantined" => {
            let selected = selected_activation_from_receipt(request, row)?;
            require_activation_quarantine_replay(transaction, request, row, &selected, true)
                .await?;
            Ok(LogicalJobOrchestrationSelectionOutcome::Quarantined)
        }
        "claimed" => {
            let selected = selected_activation_from_receipt(request, row)?;
            if require_activation_quarantine_replay(transaction, request, row, &selected, false)
                .await?
            {
                return Ok(LogicalJobOrchestrationSelectionOutcome::Quarantined);
            }
            require_active_consume_graph(transaction, selected.target()).await?;
            let expires_at = match selected.authority_kind() {
                LogicalJobOrchestrationAuthorityKind::Preparation => {
                    consume_selected_preparation_in_transaction(transaction, &selected)
                        .await
                        .map_err(map_preparation_consume_error)?
                        .ok_or(LogicalWorkSelectionStoreError::SelectionExpired)?
                        .claim()
                        .expires_at()
                }
                LogicalJobOrchestrationAuthorityKind::Activation => {
                    consume_selected_activation_in_transaction(transaction, &selected)
                        .await
                        .map_err(map_activation_consume_error)?
                        .ok_or(LogicalWorkSelectionStoreError::SelectionExpired)?
                        .claim()
                        .expires_at()
                }
            };
            require_selection_handoff_budget(transaction, expires_at).await?;
            Ok(LogicalJobOrchestrationSelectionOutcome::Selected(selected))
        }
        _ => Err(StoreError::corrupt_data("activation selection outcome is unknown").into()),
    }
}

async fn replay_materialization(
    transaction: &mut Transaction<'_, Postgres>,
    request: &ClaimNextLogicalInstanceMaterialization,
    row: &PgRow,
) -> Result<LogicalInstanceMaterializationSelectionOutcome, LogicalWorkSelectionStoreError> {
    verify_materialization_request(row, request)?;
    match row
        .try_get::<String, _>("outcome")
        .map_err(operation_error)?
        .as_str()
    {
        "idle" => Ok(LogicalInstanceMaterializationSelectionOutcome::Idle),
        "contended" => Ok(LogicalInstanceMaterializationSelectionOutcome::Contended),
        "quarantined" => {
            let selected = selected_materialization_from_receipt(request, row)?;
            require_materialization_quarantine_replay(transaction, request, row, &selected, true)
                .await?;
            Ok(LogicalInstanceMaterializationSelectionOutcome::Quarantined)
        }
        "claimed" => {
            let selected = selected_materialization_from_receipt(request, row)?;
            if require_materialization_quarantine_replay(
                transaction,
                request,
                row,
                &selected,
                false,
            )
            .await?
            {
                return Ok(LogicalInstanceMaterializationSelectionOutcome::Quarantined);
            }
            require_active_materialization_consume_graph(transaction, selected.target()).await?;
            let consumed = consume_selected_materialization_in_transaction(transaction, &selected)
                .await
                .map_err(map_materialization_consume_error)?
                .ok_or(LogicalWorkSelectionStoreError::SelectionExpired)?;
            require_selection_handoff_budget(transaction, consumed.claim().expires_at()).await?;
            Ok(LogicalInstanceMaterializationSelectionOutcome::Selected(
                selected,
            ))
        }
        _ => Err(StoreError::corrupt_data("materialization selection outcome is unknown").into()),
    }
}

async fn require_activation_quarantine_replay(
    transaction: &mut Transaction<'_, Postgres>,
    request: &ClaimNextLogicalJobOrchestration,
    receipt: &PgRow,
    selected: &SelectedLogicalJobOrchestration,
    required: bool,
) -> Result<bool, LogicalWorkSelectionStoreError> {
    lock_quarantine_horizon(transaction, "activation").await?;
    let quarantines = lock_activation_replay_quarantines(transaction, selected).await?;
    let Some(quarantine) = exact_replay_quarantine(
        &quarantines,
        selected.selection_id().as_uuid(),
        required,
        "activation",
    )?
    else {
        return Ok(false);
    };
    require_quarantine_replay_graph(
        transaction,
        selected.target().tenant(),
        selected.target().run_id().as_uuid(),
        selected.target().invocation_id().as_uuid(),
    )
    .await?;
    let authority = lock_activation_replay_authority(transaction, selected)
        .await?
        .ok_or_else(|| StoreError::corrupt_data("activation quarantine authority is absent"))?;
    if !activation_replay_quarantine_matches(
        quarantine, receipt, request, selected, &authority, required,
    )? {
        return Err(
            StoreError::corrupt_data("activation quarantine evidence is inconsistent").into(),
        );
    }
    Ok(true)
}

async fn require_materialization_quarantine_replay(
    transaction: &mut Transaction<'_, Postgres>,
    request: &ClaimNextLogicalInstanceMaterialization,
    receipt: &PgRow,
    selected: &SelectedLogicalInstanceMaterialization,
    required: bool,
) -> Result<bool, LogicalWorkSelectionStoreError> {
    lock_quarantine_horizon(transaction, "materialization").await?;
    let quarantines = lock_materialization_replay_quarantines(transaction, selected).await?;
    let Some(quarantine) = exact_replay_quarantine(
        &quarantines,
        selected.selection_id().as_uuid(),
        required,
        "materialization",
    )?
    else {
        return Ok(false);
    };
    require_quarantine_replay_graph(
        transaction,
        selected.target().tenant(),
        selected.target().run_id().as_uuid(),
        selected.target().invocation_id().as_uuid(),
    )
    .await?;
    let authority = lock_materialization_replay_authority(transaction, selected)
        .await?
        .ok_or_else(|| {
            StoreError::corrupt_data("materialization quarantine authority is absent")
        })?;
    if !materialization_replay_quarantine_matches(
        quarantine, receipt, request, selected, &authority, required,
    )? {
        return Err(StoreError::corrupt_data(
            "materialization quarantine evidence is inconsistent",
        )
        .into());
    }
    Ok(true)
}

fn exact_replay_quarantine<'row>(
    quarantines: &'row [PgRow],
    selection_id: Uuid,
    required: bool,
    queue: &'static str,
) -> Result<Option<&'row PgRow>, LogicalWorkSelectionStoreError> {
    let [quarantine] = quarantines else {
        if quarantines.is_empty() {
            return if required {
                Err(StoreError::corrupt_data(format!(
                    "quarantined {queue} selection lacks immutable evidence"
                ))
                .into())
            } else {
                Ok(None)
            };
        }
        return Err(StoreError::corrupt_data(format!(
            "{queue} quarantine evidence is not one-to-one"
        ))
        .into());
    };
    let quarantine_selection_id = quarantine
        .try_get::<Uuid, _>("selection_id")
        .map_err(operation_error)?;
    if quarantine_selection_id != selection_id {
        return if required {
            Err(StoreError::corrupt_data(format!(
                "quarantined {queue} selection lacks its exact evidence"
            ))
            .into())
        } else {
            Err(LogicalWorkSelectionStoreError::SelectionExpired)
        };
    }
    Ok(Some(quarantine))
}

fn verify_activation_request(
    row: &PgRow,
    request: &ClaimNextLogicalJobOrchestration,
) -> Result<(), LogicalWorkSelectionStoreError> {
    if row
        .try_get::<Uuid, _>("owner_id")
        .map_err(operation_error)?
        != request.owner().as_uuid()
        || row
            .try_get::<i64, _>("requested_at_ms")
            .map_err(operation_error)?
            != request.observed_at().get()
        || row
            .try_get::<i64, _>("duration_ms")
            .map_err(operation_error)?
            != request.duration_ms()
    {
        return Err(LogicalWorkSelectionStoreError::SelectionConflict);
    }
    Ok(())
}

fn verify_materialization_request(
    row: &PgRow,
    request: &ClaimNextLogicalInstanceMaterialization,
) -> Result<(), LogicalWorkSelectionStoreError> {
    if row
        .try_get::<Uuid, _>("owner_id")
        .map_err(operation_error)?
        != request.owner().as_uuid()
        || row
            .try_get::<i64, _>("requested_at_ms")
            .map_err(operation_error)?
            != request.observed_at().get()
        || row
            .try_get::<i64, _>("duration_ms")
            .map_err(operation_error)?
            != request.duration_ms()
    {
        return Err(LogicalWorkSelectionStoreError::SelectionConflict);
    }
    Ok(())
}

fn selected_activation_from_receipt(
    request: &ClaimNextLogicalJobOrchestration,
    row: &PgRow,
) -> Result<SelectedLogicalJobOrchestration, LogicalWorkSelectionStoreError> {
    let target = LogicalActivationPreparationTarget::new(
        decode_optional_tenant(row)?,
        RunId::from_uuid(required_uuid(row, "run_id")?),
        LogicalWorkflowInvocationId::from_uuid(required_uuid(row, "invocation_id")?)
            .map_err(corrupt_value)?,
        LogicalWorkflowJobId::from_uuid(required_uuid(row, "logical_job_id")?)
            .map_err(corrupt_value)?,
    )
    .map_err(corrupt_value)?;
    SelectedLogicalJobOrchestration::new(
        request.selection_id(),
        target,
        request.owner(),
        decode_generation(required_i64(row, "generation")?)?,
        decode_authority_kind(&required_string(row, "authority_kind")?)?,
        required_digest(row, "authority_digest")?,
        UnixMillis::new(required_i64(row, "claimed_at_ms")?),
        UnixMillis::new(required_i64(row, "expires_at_ms")?),
    )
    .map_err(corrupt_value)
}

fn selected_materialization_from_receipt(
    request: &ClaimNextLogicalInstanceMaterialization,
    row: &PgRow,
) -> Result<SelectedLogicalInstanceMaterialization, LogicalWorkSelectionStoreError> {
    let target = LogicalInstanceMaterializationTarget::new(
        decode_optional_tenant(row)?,
        RunId::from_uuid(required_uuid(row, "run_id")?),
        LogicalWorkflowInvocationId::from_uuid(required_uuid(row, "invocation_id")?)
            .map_err(corrupt_value)?,
        LogicalWorkflowJobId::from_uuid(required_uuid(row, "logical_job_id")?)
            .map_err(corrupt_value)?,
        LogicalWorkflowInstanceId::from_uuid(required_uuid(row, "instance_id")?)
            .map_err(corrupt_value)?,
    )
    .map_err(corrupt_value)?;
    SelectedLogicalInstanceMaterialization::new(
        request.selection_id(),
        target,
        request.owner(),
        decode_generation(required_i64(row, "generation")?)?,
        required_digest(row, "authority_digest")?,
        UnixMillis::new(required_i64(row, "claimed_at_ms")?),
        UnixMillis::new(required_i64(row, "expires_at_ms")?),
    )
    .map_err(corrupt_value)
}

#[allow(clippy::too_many_lines)] // Isolation proves and writes one complete custody transition.
async fn quarantine_activation_authority(
    transaction: &mut Transaction<'_, Postgres>,
    request: &QuarantineLogicalJobOrchestration,
) -> Result<LogicalWorkQuarantineOutcome, LogicalWorkSelectionStoreError> {
    let selected = request.selected();
    let Some(receipt) = lock_activation_receipt_for_selected(transaction, selected).await? else {
        return Ok(LogicalWorkQuarantineOutcome::FenceRejected);
    };
    if !activation_quarantine_receipt_matches(&receipt, selected)? {
        return Ok(LogicalWorkQuarantineOutcome::FenceRejected);
    }
    lock_quarantine_horizon(transaction, "activation").await?;
    if let Some(existing) = lock_activation_quarantine(transaction, selected).await? {
        return if quarantine_row_matches(&existing, request, &receipt)? {
            Ok(LogicalWorkQuarantineOutcome::AlreadyQuarantined)
        } else {
            Ok(LogicalWorkQuarantineOutcome::FenceRejected)
        };
    }
    match require_active_consume_graph(transaction, selected.target()).await {
        Ok(()) => {}
        Err(LogicalWorkSelectionStoreError::SelectionExpired) => {
            return Ok(LogicalWorkQuarantineOutcome::FenceRejected);
        }
        Err(error) => return Err(error),
    }
    let row = match selected.authority_kind() {
        LogicalJobOrchestrationAuthorityKind::Preparation => sqlx::query(
            r"
            SELECT repository.tenant_id, job.run_id, job.invocation_id,
                   claim.owner_id AS authority_owner_id,
                   claim.generation AS authority_generation,
                   claim.descriptor_digest AS authority_digest,
                   claim.claimed_at_ms AS authority_claimed_at_ms,
                   claim.expires_at_ms AS authority_expires_at_ms,
                   claim.state AS authority_state,
                   claim.origin_selection_id
            FROM logical_workflow_jobs AS job
            JOIN workflow_runs AS run ON run.id = job.run_id
            JOIN repositories AS repository ON repository.id = run.repository_id
            JOIN logical_workflow_activation_preparation_claims AS claim
              ON claim.logical_job_id = job.id
            WHERE job.id = $1
            FOR UPDATE OF job, claim
            ",
        )
        .bind(selected.target().logical_job_id().as_uuid())
        .fetch_optional(&mut **transaction)
        .await
        .map_err(operation_error)?,
        LogicalJobOrchestrationAuthorityKind::Activation => sqlx::query(
            r"
            SELECT repository.tenant_id, job.run_id, job.invocation_id,
                   job.activation_owner_id AS authority_owner_id,
                   job.activation_fence AS authority_generation,
                   job.activation_input_digest AS authority_digest,
                   job.activation_claimed_at_ms AS authority_claimed_at_ms,
                   job.activation_expires_at_ms AS authority_expires_at_ms,
                   job.state AS authority_state,
                   job.activation_origin_selection_id AS origin_selection_id
            FROM logical_workflow_jobs AS job
            JOIN workflow_runs AS run ON run.id = job.run_id
            JOIN repositories AS repository ON repository.id = run.repository_id
            WHERE job.id = $1
            FOR UPDATE OF job
            ",
        )
        .bind(selected.target().logical_job_id().as_uuid())
        .fetch_optional(&mut **transaction)
        .await
        .map_err(operation_error)?,
    };
    let Some(row) = row else {
        return Ok(LogicalWorkQuarantineOutcome::FenceRejected);
    };
    let now = database_now_ms(transaction).await?;
    if !activation_quarantine_authority_matches(&row, selected)?
        || !activation_captured_authority_matches(&row, request)?
    {
        return Ok(LogicalWorkQuarantineOutcome::FenceRejected);
    }
    let (
        authority_owner,
        authority_generation,
        _authority_digest,
        authority_claimed_at,
        authority_expires_at,
    ) = activation_captured_authority(request)?;
    let rows = sqlx::query(
        r"
        INSERT INTO logical_workflow_activation_work_quarantines (
            logical_job_id, tenant_id, run_id, invocation_id,
            selection_id, selection_owner_id,
            selection_requested_at_ms, selection_duration_ms,
            selection_generation, selection_claimed_at_ms,
            selection_expires_at_ms,
            authority_kind, authority_digest, authority_owner_id,
            authority_generation, authority_claimed_at_ms,
            authority_expires_at_ms, failure_kind, quarantined_at_ms
        ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19)
        ",
    )
    .bind(selected.target().logical_job_id().as_uuid())
    .bind(selected.target().tenant().as_str())
    .bind(selected.target().run_id().as_uuid())
    .bind(selected.target().invocation_id().as_uuid())
    .bind(selected.selection_id().as_uuid())
    .bind(selected.owner().as_uuid())
    .bind(
        receipt
            .try_get::<i64, _>("requested_at_ms")
            .map_err(operation_error)?,
    )
    .bind(
        receipt
            .try_get::<i64, _>("duration_ms")
            .map_err(operation_error)?,
    )
    .bind(selected.generation().as_i64())
    .bind(selected.claimed_at().get())
    .bind(selected.expires_at().get())
    .bind(authority_kind_name(selected.authority_kind()))
    .bind(selected.authority_digest().as_bytes().as_slice())
    .bind(authority_owner)
    .bind(authority_generation)
    .bind(authority_claimed_at)
    .bind(authority_expires_at)
    .bind(quarantine_kind(request.kind()))
    .bind(now)
    .execute(&mut **transaction)
    .await
    .map_err(operation_error)?
    .rows_affected();
    exact_one(rows, "activation authority quarantine was not inserted")?;
    Ok(LogicalWorkQuarantineOutcome::Quarantined)
}

#[allow(clippy::too_many_lines)] // Isolation proves and writes one complete custody transition.
async fn quarantine_materialization_authority(
    transaction: &mut Transaction<'_, Postgres>,
    request: &QuarantineLogicalInstanceMaterialization,
) -> Result<LogicalWorkQuarantineOutcome, LogicalWorkSelectionStoreError> {
    let selected = request.selected();
    let Some(receipt) = lock_materialization_receipt_for_selected(transaction, selected).await?
    else {
        return Ok(LogicalWorkQuarantineOutcome::FenceRejected);
    };
    if !materialization_quarantine_receipt_matches(&receipt, selected)? {
        return Ok(LogicalWorkQuarantineOutcome::FenceRejected);
    }
    lock_quarantine_horizon(transaction, "materialization").await?;
    if let Some(existing) = lock_materialization_quarantine(transaction, selected).await? {
        return if materialization_quarantine_row_matches(&existing, request, &receipt)? {
            Ok(LogicalWorkQuarantineOutcome::AlreadyQuarantined)
        } else {
            Ok(LogicalWorkQuarantineOutcome::FenceRejected)
        };
    }
    match require_active_materialization_consume_graph(transaction, selected.target()).await {
        Ok(()) => {}
        Err(LogicalWorkSelectionStoreError::SelectionExpired) => {
            return Ok(LogicalWorkQuarantineOutcome::FenceRejected);
        }
        Err(error) => return Err(error),
    }
    let row = sqlx::query(
        r"
        SELECT repository.tenant_id, instance.run_id, instance.invocation_id,
               instance.logical_job_id, claim.owner_id AS authority_owner_id,
               claim.generation AS authority_generation,
               claim.descriptor_digest AS authority_digest,
               claim.claimed_at_ms AS authority_claimed_at_ms,
               claim.expires_at_ms AS authority_expires_at_ms,
               claim.state AS authority_state, claim.origin_selection_id
        FROM logical_workflow_instances AS instance
        JOIN workflow_runs AS run ON run.id = instance.run_id
        JOIN repositories AS repository ON repository.id = run.repository_id
        JOIN logical_workflow_materialization_claims AS claim
          ON claim.instance_id = instance.id
        WHERE instance.id = $1
        FOR UPDATE OF instance, claim
        ",
    )
    .bind(selected.target().instance_id().as_uuid())
    .fetch_optional(&mut **transaction)
    .await
    .map_err(operation_error)?;
    let Some(row) = row else {
        return Ok(LogicalWorkQuarantineOutcome::FenceRejected);
    };
    let now = database_now_ms(transaction).await?;
    if !materialization_quarantine_authority_matches(&row, selected)?
        || !materialization_captured_authority_matches(&row, request)?
    {
        return Ok(LogicalWorkQuarantineOutcome::FenceRejected);
    }
    let authority = request.consumed().authority().claim();
    let rows = sqlx::query(
        r"
        INSERT INTO logical_workflow_materialization_work_quarantines (
            instance_id, tenant_id, run_id, invocation_id, logical_job_id,
            selection_id, selection_owner_id,
            selection_requested_at_ms, selection_duration_ms,
            selection_generation, selection_claimed_at_ms,
            selection_expires_at_ms,
            authority_digest, authority_owner_id, authority_generation,
            authority_claimed_at_ms, authority_expires_at_ms,
            failure_kind, quarantined_at_ms
        ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19)
        ",
    )
    .bind(selected.target().instance_id().as_uuid())
    .bind(selected.target().tenant().as_str())
    .bind(selected.target().run_id().as_uuid())
    .bind(selected.target().invocation_id().as_uuid())
    .bind(selected.target().logical_job_id().as_uuid())
    .bind(selected.selection_id().as_uuid())
    .bind(selected.owner().as_uuid())
    .bind(
        receipt
            .try_get::<i64, _>("requested_at_ms")
            .map_err(operation_error)?,
    )
    .bind(
        receipt
            .try_get::<i64, _>("duration_ms")
            .map_err(operation_error)?,
    )
    .bind(selected.generation().as_i64())
    .bind(selected.claimed_at().get())
    .bind(selected.expires_at().get())
    .bind(selected.authority_digest().as_bytes().as_slice())
    .bind(authority.owner().as_uuid())
    .bind(authority.generation().as_i64())
    .bind(authority.claimed_at().get())
    .bind(authority.expires_at().get())
    .bind(quarantine_kind(request.kind()))
    .bind(now)
    .execute(&mut **transaction)
    .await
    .map_err(operation_error)?
    .rows_affected();
    exact_one(
        rows,
        "materialization authority quarantine was not inserted",
    )?;
    Ok(LogicalWorkQuarantineOutcome::Quarantined)
}

fn activation_quarantine_authority_matches(
    row: &PgRow,
    selected: &SelectedLogicalJobOrchestration,
) -> Result<bool, LogicalWorkSelectionStoreError> {
    let expected_state = match selected.authority_kind() {
        LogicalJobOrchestrationAuthorityKind::Preparation => "preparing",
        LogicalJobOrchestrationAuthorityKind::Activation => "activating",
    };
    Ok(row
        .try_get::<String, _>("tenant_id")
        .map_err(operation_error)?
        == selected.target().tenant().as_str()
        && row.try_get::<Uuid, _>("run_id").map_err(operation_error)?
            == selected.target().run_id().as_uuid()
        && row
            .try_get::<Uuid, _>("invocation_id")
            .map_err(operation_error)?
            == selected.target().invocation_id().as_uuid()
        && row
            .try_get::<Option<Uuid>, _>("origin_selection_id")
            .map_err(operation_error)?
            == Some(selected.selection_id().as_uuid())
        && row
            .try_get::<Option<Uuid>, _>("authority_owner_id")
            .map_err(operation_error)?
            == Some(selected.owner().as_uuid())
        && row
            .try_get::<Option<Vec<u8>>, _>("authority_digest")
            .map_err(operation_error)?
            .as_deref()
            == Some(selected.authority_digest().as_bytes().as_slice())
        && row
            .try_get::<String, _>("authority_state")
            .map_err(operation_error)?
            == expected_state
        && row
            .try_get::<Option<i64>, _>("authority_generation")
            .map_err(operation_error)?
            .is_some_and(|generation| generation >= selected.generation().as_i64()))
}

fn materialization_quarantine_authority_matches(
    row: &PgRow,
    selected: &SelectedLogicalInstanceMaterialization,
) -> Result<bool, LogicalWorkSelectionStoreError> {
    Ok(row
        .try_get::<String, _>("tenant_id")
        .map_err(operation_error)?
        == selected.target().tenant().as_str()
        && row.try_get::<Uuid, _>("run_id").map_err(operation_error)?
            == selected.target().run_id().as_uuid()
        && row
            .try_get::<Uuid, _>("invocation_id")
            .map_err(operation_error)?
            == selected.target().invocation_id().as_uuid()
        && row
            .try_get::<Uuid, _>("logical_job_id")
            .map_err(operation_error)?
            == selected.target().logical_job_id().as_uuid()
        && row
            .try_get::<Option<Uuid>, _>("origin_selection_id")
            .map_err(operation_error)?
            == Some(selected.selection_id().as_uuid())
        && row
            .try_get::<Option<Uuid>, _>("authority_owner_id")
            .map_err(operation_error)?
            == Some(selected.owner().as_uuid())
        && row
            .try_get::<Vec<u8>, _>("authority_digest")
            .map_err(operation_error)?
            .as_slice()
            == selected.authority_digest().as_bytes().as_slice()
        && row
            .try_get::<String, _>("authority_state")
            .map_err(operation_error)?
            == "materializing"
        && row
            .try_get::<i64, _>("authority_generation")
            .map_err(operation_error)?
            >= selected.generation().as_i64())
}

fn activation_captured_authority(
    request: &QuarantineLogicalJobOrchestration,
) -> Result<(Uuid, i64, Sha256Digest, i64, i64), LogicalWorkSelectionStoreError> {
    match request.consumed().authority() {
        ConsumedLogicalJobOrchestrationAuthority::Preparation(claimed)
            if request.selected().authority_kind()
                == LogicalJobOrchestrationAuthorityKind::Preparation =>
        {
            let claim = claimed.claim();
            Ok((
                claim.owner().as_uuid(),
                claim.generation().as_i64(),
                claim.descriptor_digest(),
                claim.claimed_at().get(),
                claim.expires_at().get(),
            ))
        }
        ConsumedLogicalJobOrchestrationAuthority::Activation(claimed)
            if request.selected().authority_kind()
                == LogicalJobOrchestrationAuthorityKind::Activation =>
        {
            let claim = claimed.claim();
            Ok((
                claim.owner().as_uuid(),
                claim.generation().as_i64(),
                claim.input_digest(),
                claim.claimed_at().get(),
                claim.expires_at().get(),
            ))
        }
        _ => Err(StoreError::corrupt_data(
            "consumed orchestration authority disagrees with selection kind",
        )
        .into()),
    }
}

fn activation_captured_authority_matches(
    row: &PgRow,
    request: &QuarantineLogicalJobOrchestration,
) -> Result<bool, LogicalWorkSelectionStoreError> {
    let (owner, generation, digest, claimed_at, expires_at) =
        activation_captured_authority(request)?;
    Ok(row
        .try_get::<Uuid, _>("authority_owner_id")
        .map_err(operation_error)?
        == owner
        && row
            .try_get::<i64, _>("authority_generation")
            .map_err(operation_error)?
            == generation
        && row
            .try_get::<Vec<u8>, _>("authority_digest")
            .map_err(operation_error)?
            .as_slice()
            == digest.as_bytes().as_slice()
        && row
            .try_get::<i64, _>("authority_claimed_at_ms")
            .map_err(operation_error)?
            == claimed_at
        && row
            .try_get::<i64, _>("authority_expires_at_ms")
            .map_err(operation_error)?
            == expires_at)
}

fn materialization_captured_authority_matches(
    row: &PgRow,
    request: &QuarantineLogicalInstanceMaterialization,
) -> Result<bool, LogicalWorkSelectionStoreError> {
    let claim = request.consumed().authority().claim();
    Ok(row
        .try_get::<Uuid, _>("authority_owner_id")
        .map_err(operation_error)?
        == claim.owner().as_uuid()
        && row
            .try_get::<i64, _>("authority_generation")
            .map_err(operation_error)?
            == claim.generation().as_i64()
        && row
            .try_get::<Vec<u8>, _>("authority_digest")
            .map_err(operation_error)?
            .as_slice()
            == claim.descriptor_digest().as_bytes().as_slice()
        && row
            .try_get::<i64, _>("authority_claimed_at_ms")
            .map_err(operation_error)?
            == claim.claimed_at().get()
        && row
            .try_get::<i64, _>("authority_expires_at_ms")
            .map_err(operation_error)?
            == claim.expires_at().get())
}

async fn lock_quarantine_horizon(
    transaction: &mut Transaction<'_, Postgres>,
    queue: &'static str,
) -> Result<(), LogicalWorkSelectionStoreError> {
    let row = sqlx::query(
        "SELECT queue_name FROM logical_workflow_work_selection_replay_horizons WHERE queue_name = $1 FOR UPDATE",
    )
    .bind(queue)
    .fetch_optional(&mut **transaction)
    .await
    .map_err(operation_error)?;
    if row.is_none() {
        return Err(StoreError::corrupt_data("work quarantine replay horizon is absent").into());
    }
    Ok(())
}

async fn lock_activation_receipt_for_selected(
    transaction: &mut Transaction<'_, Postgres>,
    selected: &SelectedLogicalJobOrchestration,
) -> Result<Option<PgRow>, LogicalWorkSelectionStoreError> {
    sqlx::query(
        r"
        SELECT selection_id, owner_id, requested_at_ms, duration_ms,
               claimed_at_ms, expires_at_ms, outcome, tenant_id, run_id,
               invocation_id, logical_job_id, generation, authority_kind,
               authority_digest
        FROM logical_workflow_activation_work_selections
        WHERE selection_id = $1
        FOR UPDATE
        ",
    )
    .bind(selected.selection_id().as_uuid())
    .fetch_optional(&mut **transaction)
    .await
    .map_err(operation_error)
}

async fn lock_materialization_receipt_for_selected(
    transaction: &mut Transaction<'_, Postgres>,
    selected: &SelectedLogicalInstanceMaterialization,
) -> Result<Option<PgRow>, LogicalWorkSelectionStoreError> {
    sqlx::query(
        r"
        SELECT selection_id, owner_id, requested_at_ms, duration_ms,
               claimed_at_ms, expires_at_ms, outcome, tenant_id, run_id,
               invocation_id, logical_job_id, instance_id, generation,
               authority_digest
        FROM logical_workflow_materialization_work_selections
        WHERE selection_id = $1
        FOR UPDATE
        ",
    )
    .bind(selected.selection_id().as_uuid())
    .fetch_optional(&mut **transaction)
    .await
    .map_err(operation_error)
}

fn activation_quarantine_receipt_matches(
    row: &PgRow,
    selected: &SelectedLogicalJobOrchestration,
) -> Result<bool, LogicalWorkSelectionStoreError> {
    Ok(row
        .try_get::<String, _>("outcome")
        .map_err(operation_error)?
        == "claimed"
        && row
            .try_get::<Uuid, _>("owner_id")
            .map_err(operation_error)?
            == selected.owner().as_uuid()
        && row
            .try_get::<String, _>("tenant_id")
            .map_err(operation_error)?
            == selected.target().tenant().as_str()
        && row.try_get::<Uuid, _>("run_id").map_err(operation_error)?
            == selected.target().run_id().as_uuid()
        && row
            .try_get::<Uuid, _>("invocation_id")
            .map_err(operation_error)?
            == selected.target().invocation_id().as_uuid()
        && row
            .try_get::<Uuid, _>("logical_job_id")
            .map_err(operation_error)?
            == selected.target().logical_job_id().as_uuid()
        && row
            .try_get::<i64, _>("generation")
            .map_err(operation_error)?
            == selected.generation().as_i64()
        && row
            .try_get::<String, _>("authority_kind")
            .map_err(operation_error)?
            == authority_kind_name(selected.authority_kind())
        && row
            .try_get::<Vec<u8>, _>("authority_digest")
            .map_err(operation_error)?
            == selected.authority_digest().as_bytes().as_slice()
        && row
            .try_get::<i64, _>("claimed_at_ms")
            .map_err(operation_error)?
            == selected.claimed_at().get()
        && row
            .try_get::<i64, _>("expires_at_ms")
            .map_err(operation_error)?
            == selected.expires_at().get())
}

fn materialization_quarantine_receipt_matches(
    row: &PgRow,
    selected: &SelectedLogicalInstanceMaterialization,
) -> Result<bool, LogicalWorkSelectionStoreError> {
    Ok(row
        .try_get::<String, _>("outcome")
        .map_err(operation_error)?
        == "claimed"
        && row
            .try_get::<Uuid, _>("owner_id")
            .map_err(operation_error)?
            == selected.owner().as_uuid()
        && row
            .try_get::<String, _>("tenant_id")
            .map_err(operation_error)?
            == selected.target().tenant().as_str()
        && row.try_get::<Uuid, _>("run_id").map_err(operation_error)?
            == selected.target().run_id().as_uuid()
        && row
            .try_get::<Uuid, _>("invocation_id")
            .map_err(operation_error)?
            == selected.target().invocation_id().as_uuid()
        && row
            .try_get::<Uuid, _>("logical_job_id")
            .map_err(operation_error)?
            == selected.target().logical_job_id().as_uuid()
        && row
            .try_get::<Uuid, _>("instance_id")
            .map_err(operation_error)?
            == selected.target().instance_id().as_uuid()
        && row
            .try_get::<i64, _>("generation")
            .map_err(operation_error)?
            == selected.generation().as_i64()
        && row
            .try_get::<Vec<u8>, _>("authority_digest")
            .map_err(operation_error)?
            == selected.authority_digest().as_bytes().as_slice()
        && row
            .try_get::<i64, _>("claimed_at_ms")
            .map_err(operation_error)?
            == selected.claimed_at().get()
        && row
            .try_get::<i64, _>("expires_at_ms")
            .map_err(operation_error)?
            == selected.expires_at().get())
}

async fn lock_activation_quarantine(
    transaction: &mut Transaction<'_, Postgres>,
    selected: &SelectedLogicalJobOrchestration,
) -> Result<Option<PgRow>, LogicalWorkSelectionStoreError> {
    sqlx::query(
        r"
        SELECT tenant_id, run_id, invocation_id, logical_job_id,
               selection_id, selection_owner_id, selection_requested_at_ms,
               selection_duration_ms, selection_generation,
               selection_claimed_at_ms, selection_expires_at_ms,
               authority_kind, authority_digest, authority_owner_id,
               authority_generation, authority_claimed_at_ms,
               authority_expires_at_ms, failure_kind
        FROM logical_workflow_activation_work_quarantines
        WHERE logical_job_id = $1 FOR UPDATE
        ",
    )
    .bind(selected.target().logical_job_id().as_uuid())
    .fetch_optional(&mut **transaction)
    .await
    .map_err(operation_error)
}

async fn lock_materialization_quarantine(
    transaction: &mut Transaction<'_, Postgres>,
    selected: &SelectedLogicalInstanceMaterialization,
) -> Result<Option<PgRow>, LogicalWorkSelectionStoreError> {
    sqlx::query(
        r"
        SELECT tenant_id, run_id, invocation_id, logical_job_id, instance_id,
               selection_id, selection_owner_id, selection_requested_at_ms,
               selection_duration_ms, selection_generation,
               selection_claimed_at_ms, selection_expires_at_ms,
               authority_digest, authority_owner_id, authority_generation,
               authority_claimed_at_ms, authority_expires_at_ms, failure_kind
        FROM logical_workflow_materialization_work_quarantines
        WHERE instance_id = $1 FOR UPDATE
        ",
    )
    .bind(selected.target().instance_id().as_uuid())
    .fetch_optional(&mut **transaction)
    .await
    .map_err(operation_error)
}

async fn lock_activation_replay_quarantines(
    transaction: &mut Transaction<'_, Postgres>,
    selected: &SelectedLogicalJobOrchestration,
) -> Result<Vec<PgRow>, LogicalWorkSelectionStoreError> {
    sqlx::query(
        r"
        SELECT tenant_id, run_id, invocation_id, logical_job_id,
               selection_id, selection_owner_id, selection_requested_at_ms,
               selection_duration_ms, selection_generation,
               selection_claimed_at_ms, selection_expires_at_ms,
               authority_kind, authority_digest, authority_owner_id,
               authority_generation, authority_claimed_at_ms,
               authority_expires_at_ms, failure_kind, quarantined_at_ms
        FROM logical_workflow_activation_work_quarantines
        WHERE logical_job_id = $1 OR selection_id = $2
        ORDER BY logical_job_id, selection_id
        FOR UPDATE
        ",
    )
    .bind(selected.target().logical_job_id().as_uuid())
    .bind(selected.selection_id().as_uuid())
    .fetch_all(&mut **transaction)
    .await
    .map_err(operation_error)
}

async fn lock_materialization_replay_quarantines(
    transaction: &mut Transaction<'_, Postgres>,
    selected: &SelectedLogicalInstanceMaterialization,
) -> Result<Vec<PgRow>, LogicalWorkSelectionStoreError> {
    sqlx::query(
        r"
        SELECT tenant_id, run_id, invocation_id, logical_job_id, instance_id,
               selection_id, selection_owner_id, selection_requested_at_ms,
               selection_duration_ms, selection_generation,
               selection_claimed_at_ms, selection_expires_at_ms,
               authority_digest, authority_owner_id, authority_generation,
               authority_claimed_at_ms, authority_expires_at_ms,
               failure_kind, quarantined_at_ms
        FROM logical_workflow_materialization_work_quarantines
        WHERE instance_id = $1 OR selection_id = $2
        ORDER BY instance_id, selection_id
        FOR UPDATE
        ",
    )
    .bind(selected.target().instance_id().as_uuid())
    .bind(selected.selection_id().as_uuid())
    .fetch_all(&mut **transaction)
    .await
    .map_err(operation_error)
}

async fn require_quarantine_replay_graph(
    transaction: &mut Transaction<'_, Postgres>,
    tenant: &TenantScope,
    run_id: Uuid,
    invocation_id: Uuid,
) -> Result<(), LogicalWorkSelectionStoreError> {
    let schemas = current_durable_schemas();
    let exact: Option<bool> = sqlx::query_scalar(
        r"
        SELECT run.admission_epoch = $4 AND run.plan_schema = $4
               AND marker.orchestration_schema = $5
               AND automata_logical_workflow_invocation_published(
                   marker.run_id, $3
               )
               AND invocation.plan_schema = $6
        FROM workflow_runs AS run
        JOIN repositories AS repository ON repository.id = run.repository_id
        JOIN logical_workflow_runs AS marker ON marker.run_id = run.id
        JOIN logical_workflow_invocations AS invocation
          ON invocation.run_id = run.id AND invocation.id = $3
        WHERE repository.tenant_id = $1 AND run.id = $2
        FOR SHARE OF repository, run, marker, invocation
        ",
    )
    .bind(tenant.as_str())
    .bind(run_id)
    .bind(invocation_id)
    .bind(schemas.workflow_plan_i32)
    .bind(schemas.logical_orchestration_i16)
    .bind(schemas.workflow_plan_i16)
    .fetch_optional(&mut **transaction)
    .await
    .map_err(operation_error)?;
    if exact != Some(true) {
        return Err(
            StoreError::corrupt_data("work quarantine replay graph is inconsistent").into(),
        );
    }
    Ok(())
}

async fn lock_activation_replay_authority(
    transaction: &mut Transaction<'_, Postgres>,
    selected: &SelectedLogicalJobOrchestration,
) -> Result<Option<PgRow>, LogicalWorkSelectionStoreError> {
    let logical_job_id = selected.target().logical_job_id().as_uuid();
    match selected.authority_kind() {
        LogicalJobOrchestrationAuthorityKind::Preparation => sqlx::query(
            r"
            SELECT repository.tenant_id, job.run_id, job.invocation_id,
                   job.id AS logical_job_id,
                   claim.origin_selection_id,
                   claim.owner_id AS authority_owner_id,
                   claim.generation AS authority_generation,
                   claim.descriptor_digest AS authority_digest,
                   claim.claimed_at_ms AS authority_claimed_at_ms,
                   claim.expires_at_ms AS authority_expires_at_ms,
                   claim.state AS authority_state
            FROM logical_workflow_activation_preparation_claims AS claim
            JOIN logical_workflow_jobs AS job ON job.id = claim.logical_job_id
            JOIN workflow_runs AS run ON run.id = job.run_id
            JOIN repositories AS repository ON repository.id = run.repository_id
            WHERE job.id = $1
            FOR UPDATE OF job, claim
            ",
        )
        .bind(logical_job_id)
        .fetch_optional(&mut **transaction)
        .await
        .map_err(operation_error),
        LogicalJobOrchestrationAuthorityKind::Activation => sqlx::query(
            r"
            SELECT repository.tenant_id, job.run_id, job.invocation_id,
                   job.id AS logical_job_id,
                   job.activation_origin_selection_id AS origin_selection_id,
                   job.activation_owner_id AS authority_owner_id,
                   job.activation_fence AS authority_generation,
                   job.activation_input_digest AS authority_digest,
                   job.activation_claimed_at_ms AS authority_claimed_at_ms,
                   job.activation_expires_at_ms AS authority_expires_at_ms,
                   job.state AS authority_state
            FROM logical_workflow_jobs AS job
            JOIN workflow_runs AS run ON run.id = job.run_id
            JOIN repositories AS repository ON repository.id = run.repository_id
            WHERE job.id = $1
            FOR UPDATE OF job
            ",
        )
        .bind(logical_job_id)
        .fetch_optional(&mut **transaction)
        .await
        .map_err(operation_error),
    }
}

async fn lock_materialization_replay_authority(
    transaction: &mut Transaction<'_, Postgres>,
    selected: &SelectedLogicalInstanceMaterialization,
) -> Result<Option<PgRow>, LogicalWorkSelectionStoreError> {
    sqlx::query(
        r"
        SELECT repository.tenant_id, instance.run_id, instance.invocation_id,
               instance.logical_job_id, instance.id AS instance_id,
               claim.origin_selection_id,
               claim.owner_id AS authority_owner_id,
               claim.generation AS authority_generation,
               claim.descriptor_digest AS authority_digest,
               claim.claimed_at_ms AS authority_claimed_at_ms,
               claim.expires_at_ms AS authority_expires_at_ms,
               claim.state AS authority_state
        FROM logical_workflow_materialization_claims AS claim
        JOIN logical_workflow_instances AS instance ON instance.id = claim.instance_id
        JOIN workflow_runs AS run ON run.id = instance.run_id
        JOIN repositories AS repository ON repository.id = run.repository_id
        WHERE instance.id = $1
        FOR UPDATE OF instance, claim
        ",
    )
    .bind(selected.target().instance_id().as_uuid())
    .fetch_optional(&mut **transaction)
    .await
    .map_err(operation_error)
}

fn activation_replay_quarantine_matches(
    quarantine: &PgRow,
    receipt: &PgRow,
    request: &ClaimNextLogicalJobOrchestration,
    selected: &SelectedLogicalJobOrchestration,
    authority: &PgRow,
    generation_poison: bool,
) -> Result<bool, LogicalWorkSelectionStoreError> {
    let selection_exact = quarantine
        .try_get::<Uuid, _>("selection_id")
        .map_err(operation_error)?
        == selected.selection_id().as_uuid()
        && quarantine
            .try_get::<Uuid, _>("selection_owner_id")
            .map_err(operation_error)?
            == selected.owner().as_uuid()
        && quarantine
            .try_get::<i64, _>("selection_requested_at_ms")
            .map_err(operation_error)?
            == request.observed_at().get()
        && quarantine
            .try_get::<i64, _>("selection_duration_ms")
            .map_err(operation_error)?
            == request.duration_ms()
        && quarantine
            .try_get::<i64, _>("selection_generation")
            .map_err(operation_error)?
            == selected.generation().as_i64()
        && quarantine
            .try_get::<i64, _>("selection_claimed_at_ms")
            .map_err(operation_error)?
            == selected.claimed_at().get()
        && quarantine
            .try_get::<i64, _>("selection_expires_at_ms")
            .map_err(operation_error)?
            == selected.expires_at().get()
        && quarantine
            .try_get::<String, _>("tenant_id")
            .map_err(operation_error)?
            == selected.target().tenant().as_str()
        && quarantine
            .try_get::<Uuid, _>("run_id")
            .map_err(operation_error)?
            == selected.target().run_id().as_uuid()
        && quarantine
            .try_get::<Uuid, _>("invocation_id")
            .map_err(operation_error)?
            == selected.target().invocation_id().as_uuid()
        && quarantine
            .try_get::<Uuid, _>("logical_job_id")
            .map_err(operation_error)?
            == selected.target().logical_job_id().as_uuid()
        && quarantine
            .try_get::<String, _>("authority_kind")
            .map_err(operation_error)?
            == authority_kind_name(selected.authority_kind())
        && quarantine
            .try_get::<Vec<u8>, _>("authority_digest")
            .map_err(operation_error)?
            .as_slice()
            == selected.authority_digest().as_bytes().as_slice();
    Ok(selection_exact
        && replay_quarantine_receipt_kind_matches(receipt, quarantine, generation_poison)?
        && replay_captured_authority_shape_matches(
            quarantine,
            selected.generation().as_i64(),
            selected.claimed_at().get(),
            selected.expires_at().get(),
            generation_poison,
        )?
        && activation_replay_authority_matches(authority, quarantine, selected, generation_poison)?)
}

fn materialization_replay_quarantine_matches(
    quarantine: &PgRow,
    receipt: &PgRow,
    request: &ClaimNextLogicalInstanceMaterialization,
    selected: &SelectedLogicalInstanceMaterialization,
    authority: &PgRow,
    generation_poison: bool,
) -> Result<bool, LogicalWorkSelectionStoreError> {
    let selection_exact = quarantine
        .try_get::<Uuid, _>("selection_id")
        .map_err(operation_error)?
        == selected.selection_id().as_uuid()
        && quarantine
            .try_get::<Uuid, _>("selection_owner_id")
            .map_err(operation_error)?
            == selected.owner().as_uuid()
        && quarantine
            .try_get::<i64, _>("selection_requested_at_ms")
            .map_err(operation_error)?
            == request.observed_at().get()
        && quarantine
            .try_get::<i64, _>("selection_duration_ms")
            .map_err(operation_error)?
            == request.duration_ms()
        && quarantine
            .try_get::<i64, _>("selection_generation")
            .map_err(operation_error)?
            == selected.generation().as_i64()
        && quarantine
            .try_get::<i64, _>("selection_claimed_at_ms")
            .map_err(operation_error)?
            == selected.claimed_at().get()
        && quarantine
            .try_get::<i64, _>("selection_expires_at_ms")
            .map_err(operation_error)?
            == selected.expires_at().get()
        && quarantine
            .try_get::<String, _>("tenant_id")
            .map_err(operation_error)?
            == selected.target().tenant().as_str()
        && quarantine
            .try_get::<Uuid, _>("run_id")
            .map_err(operation_error)?
            == selected.target().run_id().as_uuid()
        && quarantine
            .try_get::<Uuid, _>("invocation_id")
            .map_err(operation_error)?
            == selected.target().invocation_id().as_uuid()
        && quarantine
            .try_get::<Uuid, _>("logical_job_id")
            .map_err(operation_error)?
            == selected.target().logical_job_id().as_uuid()
        && quarantine
            .try_get::<Uuid, _>("instance_id")
            .map_err(operation_error)?
            == selected.target().instance_id().as_uuid()
        && quarantine
            .try_get::<Vec<u8>, _>("authority_digest")
            .map_err(operation_error)?
            .as_slice()
            == selected.authority_digest().as_bytes().as_slice();
    Ok(selection_exact
        && replay_quarantine_receipt_kind_matches(receipt, quarantine, generation_poison)?
        && replay_captured_authority_shape_matches(
            quarantine,
            selected.generation().as_i64(),
            selected.claimed_at().get(),
            selected.expires_at().get(),
            generation_poison,
        )?
        && materialization_replay_authority_matches(
            authority,
            quarantine,
            selected,
            generation_poison,
        )?)
}

fn replay_quarantine_receipt_kind_matches(
    receipt: &PgRow,
    quarantine: &PgRow,
    generation_poison: bool,
) -> Result<bool, LogicalWorkSelectionStoreError> {
    let outcome = receipt
        .try_get::<String, _>("outcome")
        .map_err(operation_error)?;
    let failure = quarantine
        .try_get::<String, _>("failure_kind")
        .map_err(operation_error)?;
    Ok(if generation_poison {
        outcome == "quarantined" && failure == "generation_exhausted"
    } else {
        outcome == "claimed"
            && matches!(
                failure.as_str(),
                "relational_evidence" | "object_evidence" | "payload_evidence"
            )
    })
}

fn replay_captured_authority_shape_matches(
    quarantine: &PgRow,
    selection_generation: i64,
    selection_claimed_at: i64,
    selection_expires_at: i64,
    generation_poison: bool,
) -> Result<bool, LogicalWorkSelectionStoreError> {
    let owner = quarantine
        .try_get::<Uuid, _>("authority_owner_id")
        .map_err(operation_error)?;
    let generation = quarantine
        .try_get::<i64, _>("authority_generation")
        .map_err(operation_error)?;
    let claimed_at = quarantine
        .try_get::<i64, _>("authority_claimed_at_ms")
        .map_err(operation_error)?;
    let expires_at = quarantine
        .try_get::<i64, _>("authority_expires_at_ms")
        .map_err(operation_error)?;
    let quarantined_at = quarantine
        .try_get::<i64, _>("quarantined_at_ms")
        .map_err(operation_error)?;
    let ordinary_base_exact = generation != selection_generation
        || (claimed_at == selection_claimed_at && expires_at == selection_expires_at);
    Ok(owner != Uuid::nil()
        && generation >= selection_generation
        && claimed_at >= 0
        && expires_at > claimed_at
        && quarantined_at >= claimed_at
        && if generation_poison {
            generation == i64::MAX
                && generation == selection_generation
                && expires_at <= quarantined_at
        } else {
            ordinary_base_exact
        })
}

fn activation_replay_authority_matches(
    authority: &PgRow,
    quarantine: &PgRow,
    selected: &SelectedLogicalJobOrchestration,
    generation_poison: bool,
) -> Result<bool, LogicalWorkSelectionStoreError> {
    let expected_state = match selected.authority_kind() {
        LogicalJobOrchestrationAuthorityKind::Preparation => "preparing",
        LogicalJobOrchestrationAuthorityKind::Activation => "activating",
    };
    let authority_owner = quarantine
        .try_get::<Uuid, _>("authority_owner_id")
        .map_err(operation_error)?;
    Ok(authority
        .try_get::<String, _>("tenant_id")
        .map_err(operation_error)?
        == selected.target().tenant().as_str()
        && authority
            .try_get::<Uuid, _>("run_id")
            .map_err(operation_error)?
            == selected.target().run_id().as_uuid()
        && authority
            .try_get::<Uuid, _>("invocation_id")
            .map_err(operation_error)?
            == selected.target().invocation_id().as_uuid()
        && authority
            .try_get::<Uuid, _>("logical_job_id")
            .map_err(operation_error)?
            == selected.target().logical_job_id().as_uuid()
        && authority
            .try_get::<String, _>("authority_state")
            .map_err(operation_error)?
            == expected_state
        && authority
            .try_get::<Option<Uuid>, _>("authority_owner_id")
            .map_err(operation_error)?
            == Some(authority_owner)
        && authority
            .try_get::<Option<i64>, _>("authority_generation")
            .map_err(operation_error)?
            == Some(
                quarantine
                    .try_get::<i64, _>("authority_generation")
                    .map_err(operation_error)?,
            )
        && authority
            .try_get::<Option<Vec<u8>>, _>("authority_digest")
            .map_err(operation_error)?
            .as_deref()
            == Some(
                quarantine
                    .try_get::<Vec<u8>, _>("authority_digest")
                    .map_err(operation_error)?
                    .as_slice(),
            )
        && authority
            .try_get::<Option<i64>, _>("authority_claimed_at_ms")
            .map_err(operation_error)?
            == Some(
                quarantine
                    .try_get::<i64, _>("authority_claimed_at_ms")
                    .map_err(operation_error)?,
            )
        && authority
            .try_get::<Option<i64>, _>("authority_expires_at_ms")
            .map_err(operation_error)?
            == Some(
                quarantine
                    .try_get::<i64, _>("authority_expires_at_ms")
                    .map_err(operation_error)?,
            )
        && (generation_poison
            || (authority_owner == selected.owner().as_uuid()
                && authority
                    .try_get::<Option<Uuid>, _>("origin_selection_id")
                    .map_err(operation_error)?
                    == Some(selected.selection_id().as_uuid()))))
}

fn materialization_replay_authority_matches(
    authority: &PgRow,
    quarantine: &PgRow,
    selected: &SelectedLogicalInstanceMaterialization,
    generation_poison: bool,
) -> Result<bool, LogicalWorkSelectionStoreError> {
    let authority_owner = quarantine
        .try_get::<Uuid, _>("authority_owner_id")
        .map_err(operation_error)?;
    Ok(authority
        .try_get::<String, _>("tenant_id")
        .map_err(operation_error)?
        == selected.target().tenant().as_str()
        && authority
            .try_get::<Uuid, _>("run_id")
            .map_err(operation_error)?
            == selected.target().run_id().as_uuid()
        && authority
            .try_get::<Uuid, _>("invocation_id")
            .map_err(operation_error)?
            == selected.target().invocation_id().as_uuid()
        && authority
            .try_get::<Uuid, _>("logical_job_id")
            .map_err(operation_error)?
            == selected.target().logical_job_id().as_uuid()
        && authority
            .try_get::<Uuid, _>("instance_id")
            .map_err(operation_error)?
            == selected.target().instance_id().as_uuid()
        && authority
            .try_get::<String, _>("authority_state")
            .map_err(operation_error)?
            == "materializing"
        && authority
            .try_get::<Option<Uuid>, _>("authority_owner_id")
            .map_err(operation_error)?
            == Some(authority_owner)
        && authority
            .try_get::<Option<i64>, _>("authority_generation")
            .map_err(operation_error)?
            == Some(
                quarantine
                    .try_get::<i64, _>("authority_generation")
                    .map_err(operation_error)?,
            )
        && authority
            .try_get::<Option<Vec<u8>>, _>("authority_digest")
            .map_err(operation_error)?
            .as_deref()
            == Some(
                quarantine
                    .try_get::<Vec<u8>, _>("authority_digest")
                    .map_err(operation_error)?
                    .as_slice(),
            )
        && authority
            .try_get::<Option<i64>, _>("authority_claimed_at_ms")
            .map_err(operation_error)?
            == Some(
                quarantine
                    .try_get::<i64, _>("authority_claimed_at_ms")
                    .map_err(operation_error)?,
            )
        && authority
            .try_get::<Option<i64>, _>("authority_expires_at_ms")
            .map_err(operation_error)?
            == Some(
                quarantine
                    .try_get::<i64, _>("authority_expires_at_ms")
                    .map_err(operation_error)?,
            )
        && (generation_poison
            || (authority_owner == selected.owner().as_uuid()
                && authority
                    .try_get::<Option<Uuid>, _>("origin_selection_id")
                    .map_err(operation_error)?
                    == Some(selected.selection_id().as_uuid()))))
}

fn quarantine_row_matches(
    row: &PgRow,
    request: &QuarantineLogicalJobOrchestration,
    receipt: &PgRow,
) -> Result<bool, LogicalWorkSelectionStoreError> {
    let selected = request.selected();
    Ok(row
        .try_get::<Uuid, _>("selection_id")
        .map_err(operation_error)?
        == selected.selection_id().as_uuid()
        && row
            .try_get::<Uuid, _>("selection_owner_id")
            .map_err(operation_error)?
            == selected.owner().as_uuid()
        && row
            .try_get::<i64, _>("selection_generation")
            .map_err(operation_error)?
            == selected.generation().as_i64()
        && row
            .try_get::<i64, _>("selection_requested_at_ms")
            .map_err(operation_error)?
            == receipt
                .try_get::<i64, _>("requested_at_ms")
                .map_err(operation_error)?
        && row
            .try_get::<i64, _>("selection_duration_ms")
            .map_err(operation_error)?
            == receipt
                .try_get::<i64, _>("duration_ms")
                .map_err(operation_error)?
        && row
            .try_get::<i64, _>("selection_claimed_at_ms")
            .map_err(operation_error)?
            == selected.claimed_at().get()
        && row
            .try_get::<i64, _>("selection_expires_at_ms")
            .map_err(operation_error)?
            == selected.expires_at().get()
        && row
            .try_get::<String, _>("tenant_id")
            .map_err(operation_error)?
            == selected.target().tenant().as_str()
        && row.try_get::<Uuid, _>("run_id").map_err(operation_error)?
            == selected.target().run_id().as_uuid()
        && row
            .try_get::<Uuid, _>("invocation_id")
            .map_err(operation_error)?
            == selected.target().invocation_id().as_uuid()
        && row
            .try_get::<Uuid, _>("logical_job_id")
            .map_err(operation_error)?
            == selected.target().logical_job_id().as_uuid()
        && row
            .try_get::<String, _>("authority_kind")
            .map_err(operation_error)?
            == authority_kind_name(selected.authority_kind())
        && row
            .try_get::<Vec<u8>, _>("authority_digest")
            .map_err(operation_error)?
            .as_slice()
            == selected.authority_digest().as_bytes().as_slice()
        && activation_captured_authority_matches(row, request)?
        && row
            .try_get::<String, _>("failure_kind")
            .map_err(operation_error)?
            == quarantine_kind(request.kind()))
}

fn materialization_quarantine_row_matches(
    row: &PgRow,
    request: &QuarantineLogicalInstanceMaterialization,
    receipt: &PgRow,
) -> Result<bool, LogicalWorkSelectionStoreError> {
    let selected = request.selected();
    Ok(row
        .try_get::<Uuid, _>("selection_id")
        .map_err(operation_error)?
        == selected.selection_id().as_uuid()
        && row
            .try_get::<Uuid, _>("selection_owner_id")
            .map_err(operation_error)?
            == selected.owner().as_uuid()
        && row
            .try_get::<i64, _>("selection_generation")
            .map_err(operation_error)?
            == selected.generation().as_i64()
        && row
            .try_get::<i64, _>("selection_requested_at_ms")
            .map_err(operation_error)?
            == receipt
                .try_get::<i64, _>("requested_at_ms")
                .map_err(operation_error)?
        && row
            .try_get::<i64, _>("selection_duration_ms")
            .map_err(operation_error)?
            == receipt
                .try_get::<i64, _>("duration_ms")
                .map_err(operation_error)?
        && row
            .try_get::<i64, _>("selection_claimed_at_ms")
            .map_err(operation_error)?
            == selected.claimed_at().get()
        && row
            .try_get::<i64, _>("selection_expires_at_ms")
            .map_err(operation_error)?
            == selected.expires_at().get()
        && row
            .try_get::<String, _>("tenant_id")
            .map_err(operation_error)?
            == selected.target().tenant().as_str()
        && row.try_get::<Uuid, _>("run_id").map_err(operation_error)?
            == selected.target().run_id().as_uuid()
        && row
            .try_get::<Uuid, _>("invocation_id")
            .map_err(operation_error)?
            == selected.target().invocation_id().as_uuid()
        && row
            .try_get::<Uuid, _>("logical_job_id")
            .map_err(operation_error)?
            == selected.target().logical_job_id().as_uuid()
        && row
            .try_get::<Uuid, _>("instance_id")
            .map_err(operation_error)?
            == selected.target().instance_id().as_uuid()
        && row
            .try_get::<Vec<u8>, _>("authority_digest")
            .map_err(operation_error)?
            .as_slice()
            == selected.authority_digest().as_bytes().as_slice()
        && materialization_captured_authority_matches(row, request)?
        && row
            .try_get::<String, _>("failure_kind")
            .map_err(operation_error)?
            == quarantine_kind(request.kind()))
}

fn decode_tenant(row: &PgRow) -> Result<TenantScope, LogicalWorkSelectionStoreError> {
    TenantScope::from_authenticated_tenant_id(
        row.try_get::<String, _>("tenant_id")
            .map_err(operation_error)?,
    )
    .map_err(corrupt_value)
}

fn decode_optional_tenant(row: &PgRow) -> Result<TenantScope, LogicalWorkSelectionStoreError> {
    TenantScope::from_authenticated_tenant_id(
        row.try_get::<Option<String>, _>("tenant_id")
            .map_err(operation_error)?
            .ok_or_else(|| StoreError::corrupt_data("selected work lacks tenant"))?,
    )
    .map_err(corrupt_value)
}

fn required_uuid(row: &PgRow, column: &str) -> Result<Uuid, LogicalWorkSelectionStoreError> {
    row.try_get::<Option<Uuid>, _>(column)
        .map_err(operation_error)?
        .ok_or_else(|| StoreError::corrupt_data("selected work lacks UUID").into())
}

fn required_i64(row: &PgRow, column: &str) -> Result<i64, LogicalWorkSelectionStoreError> {
    row.try_get::<Option<i64>, _>(column)
        .map_err(operation_error)?
        .ok_or_else(|| StoreError::corrupt_data("selected work lacks integer").into())
}

fn required_string(row: &PgRow, column: &str) -> Result<String, LogicalWorkSelectionStoreError> {
    row.try_get::<Option<String>, _>(column)
        .map_err(operation_error)?
        .ok_or_else(|| StoreError::corrupt_data("selected work lacks text").into())
}

fn required_digest(
    row: &PgRow,
    column: &str,
) -> Result<Sha256Digest, LogicalWorkSelectionStoreError> {
    let bytes = row
        .try_get::<Option<Vec<u8>>, _>(column)
        .map_err(operation_error)?
        .ok_or_else(|| StoreError::corrupt_data("selected work lacks digest"))?;
    let bytes: [u8; 32] = bytes
        .try_into()
        .map_err(|_| StoreError::corrupt_data("selected work digest is not SHA-256"))?;
    Ok(Sha256Digest::from_bytes(bytes))
}

fn decode_generation(
    value: i64,
) -> Result<LogicalWorkSelectionGeneration, LogicalWorkSelectionStoreError> {
    u64::try_from(value)
        .ok()
        .and_then(|value| LogicalWorkSelectionGeneration::new(value).ok())
        .ok_or_else(|| StoreError::corrupt_data("work-selection generation is invalid").into())
}

fn decode_selection_generation(
    value: u64,
) -> Result<LogicalWorkSelectionGeneration, LogicalWorkSelectionStoreError> {
    LogicalWorkSelectionGeneration::new(value).map_err(corrupt_value)
}

fn decode_activation_target(
    row: &PgRow,
) -> Result<LogicalActivationPreparationTarget, LogicalWorkSelectionStoreError> {
    LogicalActivationPreparationTarget::new(
        decode_tenant(row)?,
        RunId::from_uuid(row.try_get("run_id").map_err(operation_error)?),
        LogicalWorkflowInvocationId::from_uuid(
            row.try_get("invocation_id").map_err(operation_error)?,
        )
        .map_err(corrupt_value)?,
        LogicalWorkflowJobId::from_uuid(row.try_get("logical_job_id").map_err(operation_error)?)
            .map_err(corrupt_value)?,
    )
    .map_err(corrupt_value)
}

fn decode_materialization_target(
    row: &PgRow,
) -> Result<LogicalInstanceMaterializationTarget, LogicalWorkSelectionStoreError> {
    LogicalInstanceMaterializationTarget::new(
        decode_tenant(row)?,
        RunId::from_uuid(row.try_get("run_id").map_err(operation_error)?),
        LogicalWorkflowInvocationId::from_uuid(
            row.try_get("invocation_id").map_err(operation_error)?,
        )
        .map_err(corrupt_value)?,
        LogicalWorkflowJobId::from_uuid(row.try_get("logical_job_id").map_err(operation_error)?)
            .map_err(corrupt_value)?,
        LogicalWorkflowInstanceId::from_uuid(row.try_get("instance_id").map_err(operation_error)?)
            .map_err(corrupt_value)?,
    )
    .map_err(corrupt_value)
}

fn decode_digest(
    row: &PgRow,
    column: &str,
) -> Result<Sha256Digest, LogicalWorkSelectionStoreError> {
    let bytes: Vec<u8> = row.try_get(column).map_err(operation_error)?;
    let bytes: [u8; 32] = bytes
        .try_into()
        .map_err(|_| StoreError::corrupt_data("logical work digest is not SHA-256"))?;
    Ok(Sha256Digest::from_bytes(bytes))
}

fn optional_digest(
    row: &PgRow,
    column: &str,
) -> Result<Option<Sha256Digest>, LogicalWorkSelectionStoreError> {
    row.try_get::<Option<Vec<u8>>, _>(column)
        .map_err(operation_error)?
        .map(|bytes| {
            bytes
                .try_into()
                .map(Sha256Digest::from_bytes)
                .map_err(|_| StoreError::corrupt_data("logical work digest is not SHA-256").into())
        })
        .transpose()
}

fn decode_policy_revision(
    row: &PgRow,
) -> Result<WorkflowRuntimePolicyRevision, LogicalWorkSelectionStoreError> {
    let value: i64 = row.try_get("policy_revision").map_err(operation_error)?;
    u64::try_from(value)
        .ok()
        .and_then(|value| WorkflowRuntimePolicyRevision::new(value).ok())
        .ok_or_else(|| StoreError::corrupt_data("logical work policy revision is invalid").into())
}

fn map_preparation_claim_error(
    error: LogicalActivationPreparationStoreError,
) -> LogicalWorkSelectionStoreError {
    match error {
        LogicalActivationPreparationStoreError::Store(error) => error.into(),
        LogicalActivationPreparationStoreError::GenerationExhausted => {
            LogicalWorkSelectionStoreError::GenerationExhausted
        }
        LogicalActivationPreparationStoreError::InvalidTarget
        | LogicalActivationPreparationStoreError::PreparationConflict
        | LogicalActivationPreparationStoreError::ClaimRejected
        | LogicalActivationPreparationStoreError::BindConflict => {
            StoreError::corrupt_data("locked preparation authority was rejected").into()
        }
    }
}

fn map_activation_claim_error(
    error: LogicalActivationStoreError,
) -> LogicalWorkSelectionStoreError {
    match error {
        LogicalActivationStoreError::Store(error) => error.into(),
        LogicalActivationStoreError::GenerationExhausted => {
            LogicalWorkSelectionStoreError::GenerationExhausted
        }
        LogicalActivationStoreError::InvalidTarget
        | LogicalActivationStoreError::InputConflict
        | LogicalActivationStoreError::ClaimRejected
        | LogicalActivationStoreError::PublicationConflict => {
            StoreError::corrupt_data("locked activation authority was rejected").into()
        }
    }
}

fn map_materialization_claim_error(
    error: LogicalMaterializationStoreError,
) -> LogicalWorkSelectionStoreError {
    match error {
        LogicalMaterializationStoreError::Store(error) => error.into(),
        LogicalMaterializationStoreError::GenerationExhausted => {
            LogicalWorkSelectionStoreError::GenerationExhausted
        }
        LogicalMaterializationStoreError::InvalidTarget
        | LogicalMaterializationStoreError::ClaimRejected
        | LogicalMaterializationStoreError::CommitConflict => {
            StoreError::corrupt_data("locked materialization authority was rejected").into()
        }
    }
}

fn map_preparation_consume_error(
    error: LogicalActivationPreparationStoreError,
) -> LogicalWorkSelectionStoreError {
    match error {
        LogicalActivationPreparationStoreError::Store(error) => error.into(),
        LogicalActivationPreparationStoreError::GenerationExhausted => {
            LogicalWorkSelectionStoreError::GenerationExhausted
        }
        LogicalActivationPreparationStoreError::InvalidTarget
        | LogicalActivationPreparationStoreError::PreparationConflict
        | LogicalActivationPreparationStoreError::ClaimRejected
        | LogicalActivationPreparationStoreError::BindConflict => {
            LogicalWorkSelectionStoreError::SelectionExpired
        }
    }
}

fn map_activation_consume_error(
    error: LogicalActivationStoreError,
) -> LogicalWorkSelectionStoreError {
    match error {
        LogicalActivationStoreError::Store(error) => error.into(),
        LogicalActivationStoreError::GenerationExhausted => {
            LogicalWorkSelectionStoreError::GenerationExhausted
        }
        LogicalActivationStoreError::InvalidTarget
        | LogicalActivationStoreError::InputConflict
        | LogicalActivationStoreError::ClaimRejected
        | LogicalActivationStoreError::PublicationConflict => {
            LogicalWorkSelectionStoreError::SelectionExpired
        }
    }
}

fn map_materialization_consume_error(
    error: LogicalMaterializationStoreError,
) -> LogicalWorkSelectionStoreError {
    match error {
        LogicalMaterializationStoreError::Store(error) => error.into(),
        LogicalMaterializationStoreError::GenerationExhausted => {
            LogicalWorkSelectionStoreError::GenerationExhausted
        }
        LogicalMaterializationStoreError::InvalidTarget
        | LogicalMaterializationStoreError::ClaimRejected
        | LogicalMaterializationStoreError::CommitConflict => {
            LogicalWorkSelectionStoreError::SelectionExpired
        }
    }
}

fn checked_expiration(now: i64, duration_ms: i64) -> Result<i64, LogicalWorkSelectionStoreError> {
    now.checked_add(duration_ms)
        .ok_or_else(|| StoreError::corrupt_data("work-selection time overflow").into())
}

fn quarantine_kind(value: LogicalWorkQuarantineKind) -> &'static str {
    match value {
        LogicalWorkQuarantineKind::RelationalEvidence => "relational_evidence",
        LogicalWorkQuarantineKind::ObjectEvidence => "object_evidence",
        LogicalWorkQuarantineKind::PayloadEvidence => "payload_evidence",
    }
}

const fn authority_kind_name(value: LogicalJobOrchestrationAuthorityKind) -> &'static str {
    match value {
        LogicalJobOrchestrationAuthorityKind::Preparation => "preparation",
        LogicalJobOrchestrationAuthorityKind::Activation => "activation",
    }
}

fn decode_authority_kind(
    value: &str,
) -> Result<LogicalJobOrchestrationAuthorityKind, LogicalWorkSelectionStoreError> {
    match value {
        "preparation" => Ok(LogicalJobOrchestrationAuthorityKind::Preparation),
        "activation" => Ok(LogicalJobOrchestrationAuthorityKind::Activation),
        _ => Err(StoreError::corrupt_data("unknown orchestration authority kind").into()),
    }
}

fn exact_one(rows: u64, message: &'static str) -> Result<(), LogicalWorkSelectionStoreError> {
    if rows == 1 {
        Ok(())
    } else {
        Err(StoreError::corrupt_data(message).into())
    }
}

fn operation_error(error: sqlx::Error) -> LogicalWorkSelectionStoreError {
    StoreError::operation(error).into()
}

fn corrupt_value(error: impl std::fmt::Display) -> LogicalWorkSelectionStoreError {
    let _ = error;
    StoreError::corrupt_data("logical work selection value is invalid").into()
}
