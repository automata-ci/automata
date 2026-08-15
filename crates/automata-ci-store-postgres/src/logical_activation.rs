use async_trait::async_trait;
use automata_ci_core::{
    JOB_IR_SCHEMA_VERSION, JOB_RUNTIME_CONTEXT_SCHEMA_VERSION, JobAuthorityProfile, RunId,
    RunIdAlias, Sha256Digest, UnixMillis, WorkflowId, WorkflowJobKey,
};
use sqlx::{Postgres, Row as _, Transaction, postgres::PgRow};
use uuid::Uuid;

use super::{
    PostgresStore,
    durable_schema::current_durable_schemas,
    logical_activation_preparation::load_bound_preparation_for_activation_in_transaction,
    logical_graph::lock_active_logical_graph,
    pg_bigint,
    protected_environment::{
        job_event_trust_name, job_source_kind_name, reusable_secret_permission_name,
    },
};
use automata_ci_store::{
    ActivatedLogicalInstanceDescriptor, AdmissionObject, ClaimLogicalJobActivation,
    ClaimedLogicalJobActivation, LOGICAL_ACTIVATION_JOB_IR_MEDIA_TYPE,
    LOGICAL_ACTIVATION_RUNTIME_CONTEXT_MEDIA_TYPE, LogicalActivationClaimFence,
    LogicalActivationExecutionContext, LogicalActivationGeneration,
    LogicalActivationPreparationStoreError, LogicalActivationPreparationTarget,
    LogicalActivationPublicationReceipt, LogicalActivationRepository, LogicalActivationStoreError,
    LogicalJobSchedulingPolicyScope, LogicalWorkflowInvocationId,
    MIN_LOGICAL_WORK_SELECTION_HANDOFF_MILLIS, ObjectKey, PublishLogicalJobActivation,
    RenewLogicalJobActivation, RenewedLogicalJobActivation, RepositoryId,
    ResolvedLogicalJobSchedulingPolicy, ReusableWorkflowPermissionSnapshot,
    ReusableWorkflowRuntimeStoreError, SelectedLogicalJobOrchestration, StoreError, TenantScope,
    WorkflowRuntimePolicyPin, WorkflowRuntimePolicyRevision,
};

#[allow(clippy::too_many_lines)] // The trait transaction keeps its security-relevant lock order visible.
#[async_trait]
impl LogicalActivationRepository for PostgresStore {
    async fn reusable_workflow_permission_snapshot(
        &self,
        tenant: &TenantScope,
        run_id: RunId,
        invocation_id: LogicalWorkflowInvocationId,
    ) -> Result<Option<ReusableWorkflowPermissionSnapshot>, LogicalActivationStoreError> {
        super::reusable_workflow_runtime::load_published_permission_snapshot(
            self,
            tenant,
            run_id,
            invocation_id,
        )
        .await
        .map_err(|error| match error {
            ReusableWorkflowRuntimeStoreError::Store(error) => {
                LogicalActivationStoreError::Store(error)
            }
            _ => LogicalActivationStoreError::Store(StoreError::corrupt_data(
                "reusable permission lookup returned an invalid state",
            )),
        })
    }

    async fn resolved_logical_job_scheduling_policy(
        &self,
        scope: &LogicalJobSchedulingPolicyScope,
    ) -> Result<Option<ResolvedLogicalJobSchedulingPolicy>, LogicalActivationStoreError> {
        let row = sqlx::query(
            r"
            SELECT publication.scheduling_policy_schema,
                   publication.requested_max_parallel,
                   publication.effective_max_parallel,
                   publication.instance_count
            FROM logical_workflow_activation_publications AS publication
            JOIN logical_workflow_runs AS run
              ON run.run_id = publication.run_id
            WHERE run.tenant_id = $1
              AND publication.run_id = $2
              AND publication.invocation_id = $3
              AND publication.logical_job_id = $4
            ",
        )
        .bind(scope.tenant().as_str())
        .bind(scope.run_id().as_uuid())
        .bind(scope.invocation_id().as_uuid())
        .bind(scope.logical_job_id().as_uuid())
        .fetch_optional(&self.pool)
        .await
        .map_err(operation_error)?;
        row.as_ref()
            .map(|row| decode_scheduling_policy(row, scope))
            .transpose()
            .map_err(LogicalActivationStoreError::from)
    }

    async fn renew_logical_job_activation(
        &self,
        request: RenewLogicalJobActivation,
    ) -> Result<RenewedLogicalJobActivation, LogicalActivationStoreError> {
        let mut transaction = self.pool.begin().await.map_err(operation_error)?;
        let selection_is_claimed =
            lock_activation_renewal_selection_custody(&mut transaction, request.claim()).await?;
        let next_generation = request
            .claim()
            .generation()
            .get()
            .checked_add(1)
            .and_then(|value| i64::try_from(value).ok())
            .ok_or(LogicalActivationStoreError::GenerationExhausted)?;
        let next_generation_value = LogicalActivationGeneration::new(
            u64::try_from(next_generation)
                .map_err(|_| LogicalActivationStoreError::GenerationExhausted)?,
        )
        .map_err(|_| LogicalActivationStoreError::GenerationExhausted)?;
        let selection_id = request.claim().selection_origin();
        if let Some((
            receipt_generation,
            receipt_claimed_at,
            receipt_expires_at,
            receipt_validated_at,
        )) = load_exact_activation_renewal_receipt(&mut transaction, &request).await?
        {
            let acknowledgement = RenewedLogicalJobActivation::new(
                request,
                LogicalActivationGeneration::new(receipt_generation)
                    .map_err(|_| LogicalActivationStoreError::GenerationExhausted)?,
                UnixMillis::new(receipt_claimed_at),
                UnixMillis::new(receipt_expires_at),
                UnixMillis::new(receipt_validated_at),
            )
            .map_err(|_| StoreError::corrupt_data("invalid activation renewal receipt"))?;
            transaction.commit().await.map_err(operation_error)?;
            return Ok(acknowledgement);
        }
        if !selection_is_claimed {
            return Err(LogicalActivationStoreError::ClaimRejected);
        }
        lock_activation_quarantine_custody(&mut transaction, request.claim()).await?;
        if !lock_active_logical_graph(
            &mut transaction,
            request.claim().tenant(),
            request.claim().run_id(),
            request.claim().invocation_id(),
        )
        .await?
        {
            return Err(LogicalActivationStoreError::ClaimRejected);
        }
        let schemas = current_durable_schemas();
        let row = sqlx::query(claim_target_query())
            .bind(request.claim().tenant().as_str())
            .bind(request.claim().run_id().as_uuid())
            .bind(request.claim().invocation_id().as_uuid())
            .bind(request.claim().logical_job_id().as_uuid())
            .bind(schemas.workflow_plan_i16)
            .bind(schemas.logical_orchestration_i16)
            .bind(schemas.workflow_plan_i32)
            .bind(schemas.admission_epoch_i32)
            .fetch_optional(&mut *transaction)
            .await
            .map_err(operation_error)?
            .ok_or(LogicalActivationStoreError::InvalidTarget)?;
        let durable = DurableClaimState::decode(&row)?;
        require_activation_selection_origin(&row, request.claim().selection_origin())?;
        if !durable.prerequisites_ready
            || durable.prepared_input_digest != Some(request.claim().input_digest())
        {
            return Err(LogicalActivationStoreError::ClaimRejected);
        }
        if durable.state != "activating" {
            return Err(LogicalActivationStoreError::ClaimRejected);
        }
        let database_now: i64 = sqlx::query_scalar(
            "SELECT floor(extract(epoch FROM clock_timestamp()) * 1000)::BIGINT",
        )
        .fetch_one(&mut *transaction)
        .await
        .map_err(operation_error)?;
        if !durable.matches_claim(request.claim()) {
            return Err(LogicalActivationStoreError::ClaimRejected);
        }
        let durable_claimed_at = durable
            .claimed_at
            .ok_or_else(|| StoreError::corrupt_data("active activation lacks claim start"))?;
        let durable_expires_at = durable
            .expires_at
            .ok_or_else(|| StoreError::corrupt_data("active activation lacks expiration"))?;
        if database_now < durable_claimed_at || database_now >= durable_expires_at {
            return Err(LogicalActivationStoreError::ClaimRejected);
        }
        let expires_at = database_now
            .checked_add(request.duration_ms())
            .filter(|expires_at| *expires_at > durable_expires_at)
            .ok_or(LogicalActivationStoreError::ClaimRejected)?;

        let rows = sqlx::query(
            r"
            UPDATE logical_workflow_jobs
            SET activation_fence = $9,
                activation_claimed_at_ms = $10,
                activation_expires_at_ms = $11,
                updated_at_ms = $10
            WHERE run_id = $1
              AND invocation_id = $2
              AND id = $3
              AND state = 'activating'
              AND activation_owner_id = $4
              AND activation_fence = $5
              AND activation_input_digest = $6
              AND activation_claimed_at_ms = $7
              AND activation_expires_at_ms = $8
            ",
        )
        .bind(request.claim().run_id().as_uuid())
        .bind(request.claim().invocation_id().as_uuid())
        .bind(request.claim().logical_job_id().as_uuid())
        .bind(request.claim().owner().as_uuid())
        .bind(pg_bigint(request.claim().generation().get()))
        .bind(request.claim().input_digest().as_bytes().as_slice())
        .bind(request.claim().claimed_at().get())
        .bind(request.claim().expires_at().get())
        .bind(next_generation)
        .bind(database_now)
        .bind(expires_at)
        .execute(&mut *transaction)
        .await
        .map_err(operation_error)?
        .rows_affected();
        if rows != 1 {
            return Err(LogicalActivationStoreError::ClaimRejected);
        }
        let validated_at = insert_activation_renewal_receipt(
            &mut transaction,
            &request,
            next_generation,
            database_now,
            expires_at,
            selection_id.as_uuid(),
        )
        .await?;
        let acknowledgement = RenewedLogicalJobActivation::new(
            request,
            next_generation_value,
            UnixMillis::new(database_now),
            UnixMillis::new(expires_at),
            UnixMillis::new(validated_at),
        )
        .map_err(|_| StoreError::corrupt_data("invalid activation renewal receipt"))?;
        transaction.commit().await.map_err(operation_error)?;
        Ok(acknowledgement)
    }

    async fn publish_logical_job_activation(
        &self,
        request: PublishLogicalJobActivation,
    ) -> Result<LogicalActivationPublicationReceipt, LogicalActivationStoreError> {
        let mut transaction = self.pool.begin().await.map_err(operation_error)?;
        lock_activation_continuation_custody(&mut transaction, request.claim()).await?;
        if !lock_active_logical_graph(
            &mut transaction,
            request.claim().tenant(),
            request.claim().run_id(),
            request.claim().invocation_id(),
        )
        .await?
        {
            return Err(LogicalActivationStoreError::ClaimRejected);
        }
        let row = lock_publication_target(&mut transaction, &request)
            .await?
            .ok_or(LogicalActivationStoreError::InvalidTarget)?;
        let durable = DurableClaimState::decode(&row)?;
        require_activation_selection_origin(&row, request.claim().selection_origin())?;
        let authority_profile = durable.authority_profile.ok_or_else(|| {
            StoreError::corrupt_data("logical activation publication lacks authority profile")
        })?;

        if durable.state != "activating" {
            let replay =
                verify_exact_publication(&mut transaction, &request, authority_profile).await?;
            transaction.commit().await.map_err(operation_error)?;
            return replay
                .then(|| LogicalActivationPublicationReceipt::new(&request, true))
                .ok_or(LogicalActivationStoreError::ClaimRejected);
        }
        if !durable.prerequisites_ready
            || durable.prepared_input_digest != Some(request.claim().input_digest())
        {
            return Err(StoreError::corrupt_data(
                "claimed logical job lost its exact activation preparation",
            )
            .into());
        }
        validate_live_publication_fence(&durable, &request)?;
        let database_now: i64 = sqlx::query_scalar(
            "SELECT floor(extract(epoch FROM clock_timestamp()) * 1000)::BIGINT",
        )
        .fetch_one(&mut *transaction)
        .await
        .map_err(operation_error)?;
        if durable
            .claimed_at
            .is_none_or(|claimed_at| database_now < claimed_at)
            || durable
                .expires_at
                .is_none_or(|expires_at| database_now >= expires_at)
        {
            return Err(LogicalActivationStoreError::ClaimRejected);
        }

        insert_publication(&mut transaction, &request, authority_profile).await?;
        for instance in request.instances() {
            insert_instance(&mut transaction, &request, instance).await?;
        }
        let terminal_state = if request.condition_matched() {
            "activated"
        } else {
            "skipped"
        };
        let rows = sqlx::query(
            r"
            UPDATE logical_workflow_jobs
            SET state = $5,
                activation_owner_id = NULL,
                activation_claimed_at_ms = NULL,
                activation_expires_at_ms = NULL,
                updated_at_ms = $6
            WHERE run_id = $1
              AND invocation_id = $2
              AND id = $3
              AND activation_fence = $4
              AND state = 'activating'
            ",
        )
        .bind(request.claim().run_id().as_uuid())
        .bind(request.claim().invocation_id().as_uuid())
        .bind(request.claim().logical_job_id().as_uuid())
        .bind(pg_bigint(request.claim().generation().get()))
        .bind(terminal_state)
        .bind(request.published_at().get())
        .execute(&mut *transaction)
        .await
        .map_err(operation_error)?
        .rows_affected();
        if rows != 1 {
            return Err(StoreError::corrupt_data(
                "logical activation publication lost its locked claim",
            )
            .into());
        }
        transaction.commit().await.map_err(operation_error)?;
        Ok(LogicalActivationPublicationReceipt::new(&request, false))
    }
}

async fn lock_activation_selection_custody(
    transaction: &mut Transaction<'_, Postgres>,
    claim: &LogicalActivationClaimFence,
) -> Result<(), LogicalActivationStoreError> {
    let outcome = lock_activation_selection_evidence(transaction, claim).await?;
    if outcome != "claimed" {
        return Err(LogicalActivationStoreError::ClaimRejected);
    }
    Ok(())
}

async fn lock_activation_renewal_selection_custody(
    transaction: &mut Transaction<'_, Postgres>,
    claim: &LogicalActivationClaimFence,
) -> Result<bool, LogicalActivationStoreError> {
    match lock_activation_selection_evidence(transaction, claim)
        .await?
        .as_str()
    {
        "claimed" => Ok(true),
        "quarantined" => Ok(false),
        _ => Err(LogicalActivationStoreError::ClaimRejected),
    }
}

async fn lock_activation_selection_evidence(
    transaction: &mut Transaction<'_, Postgres>,
    claim: &LogicalActivationClaimFence,
) -> Result<String, LogicalActivationStoreError> {
    let selection_id = claim.selection_origin();
    let row = sqlx::query(
        r"
        SELECT outcome,
               COALESCE(owner_id = $2
               AND tenant_id = $3
               AND run_id = $4
               AND invocation_id = $5
               AND logical_job_id = $6
               AND authority_kind = 'activation'
               AND authority_digest = $7, FALSE) AS exact
        FROM logical_workflow_activation_work_selections
        WHERE selection_id = $1
        FOR UPDATE
        ",
    )
    .bind(selection_id.as_uuid())
    .bind(claim.owner().as_uuid())
    .bind(claim.tenant().as_str())
    .bind(claim.run_id().as_uuid())
    .bind(claim.invocation_id().as_uuid())
    .bind(claim.logical_job_id().as_uuid())
    .bind(claim.input_digest().as_bytes().as_slice())
    .fetch_optional(&mut **transaction)
    .await
    .map_err(operation_error)?;
    let row = row.ok_or(LogicalActivationStoreError::ClaimRejected)?;
    let exact: bool = row.try_get("exact").map_err(operation_error)?;
    if !exact {
        return Err(LogicalActivationStoreError::ClaimRejected);
    }
    let outcome: String = row.try_get("outcome").map_err(operation_error)?;
    let horizon: Option<String> = sqlx::query_scalar(
        r"
        SELECT queue_name
        FROM logical_workflow_work_selection_replay_horizons
        WHERE queue_name = 'activation'
        FOR UPDATE
        ",
    )
    .fetch_optional(&mut **transaction)
    .await
    .map_err(operation_error)?;
    if horizon.as_deref() != Some("activation") {
        return Err(
            StoreError::corrupt_data("activation selection replay horizon is absent").into(),
        );
    }
    Ok(outcome)
}

async fn lock_activation_quarantine_custody(
    transaction: &mut Transaction<'_, Postgres>,
    claim: &LogicalActivationClaimFence,
) -> Result<(), LogicalActivationStoreError> {
    let quarantine: Option<Uuid> = sqlx::query_scalar(
        r"
        SELECT logical_job_id
        FROM logical_workflow_activation_work_quarantines
        WHERE logical_job_id = $1
        FOR UPDATE
        ",
    )
    .bind(claim.logical_job_id().as_uuid())
    .fetch_optional(&mut **transaction)
    .await
    .map_err(operation_error)?;
    if quarantine.is_some() {
        return Err(LogicalActivationStoreError::ClaimRejected);
    }
    Ok(())
}

async fn lock_activation_continuation_custody(
    transaction: &mut Transaction<'_, Postgres>,
    claim: &LogicalActivationClaimFence,
) -> Result<(), LogicalActivationStoreError> {
    lock_activation_selection_custody(transaction, claim).await?;
    lock_activation_quarantine_custody(transaction, claim).await
}

async fn load_exact_activation_renewal_receipt(
    transaction: &mut Transaction<'_, Postgres>,
    request: &RenewLogicalJobActivation,
) -> Result<Option<(u64, i64, i64, i64)>, LogicalActivationStoreError> {
    let selection_id = request.claim().selection_origin();
    let row = sqlx::query(
        r"
        SELECT successor_generation, successor_claimed_at_ms,
               successor_expires_at_ms, validated_at_ms
        FROM logical_workflow_activation_renewal_receipts
        WHERE logical_job_id = $1
          AND authority_kind = 'activation'
          AND predecessor_generation = $2
          AND selection_id = $3
          AND tenant_id = $4
          AND run_id = $5
          AND invocation_id = $6
          AND owner_id = $7
          AND runtime_policy_revision = $8
          AND runtime_policy_digest = $9
          AND authority_digest = $10
          AND predecessor_claimed_at_ms = $11
          AND predecessor_expires_at_ms = $12
          AND requested_duration_ms = $13
        FOR UPDATE
        ",
    )
    .bind(request.claim().logical_job_id().as_uuid())
    .bind(pg_bigint(request.claim().generation().get()))
    .bind(selection_id.as_uuid())
    .bind(request.claim().tenant().as_str())
    .bind(request.claim().run_id().as_uuid())
    .bind(request.claim().invocation_id().as_uuid())
    .bind(request.claim().owner().as_uuid())
    .bind(pg_bigint(request.claim().runtime_policy().revision().get()))
    .bind(
        request
            .claim()
            .runtime_policy()
            .digest()
            .as_bytes()
            .as_slice(),
    )
    .bind(request.claim().input_digest().as_bytes().as_slice())
    .bind(request.claim().claimed_at().get())
    .bind(request.claim().expires_at().get())
    .bind(request.duration_ms())
    .fetch_optional(&mut **transaction)
    .await
    .map_err(operation_error)?;
    row.map(|row| {
        let generation: i64 = row
            .try_get("successor_generation")
            .map_err(operation_error)?;
        let generation = u64::try_from(generation).map_err(|_| {
            LogicalActivationStoreError::Store(StoreError::corrupt_data(
                "invalid activation renewal receipt generation",
            ))
        })?;
        let claimed_at = row
            .try_get("successor_claimed_at_ms")
            .map_err(operation_error)?;
        let expires_at = row
            .try_get("successor_expires_at_ms")
            .map_err(operation_error)?;
        let validated_at = row.try_get("validated_at_ms").map_err(operation_error)?;
        Ok((generation, claimed_at, expires_at, validated_at))
    })
    .transpose()
}

#[allow(clippy::too_many_lines)] // One bounded proof follows the complete immutable renewal chain.
async fn verify_selected_activation_renewal_lineage(
    transaction: &mut Transaction<'_, Postgres>,
    selected: &SelectedLogicalJobOrchestration,
    durable: &DurableClaimState,
    current_claimed_at: i64,
    current_expires_at: i64,
    runtime_policy_revision: i64,
    runtime_policy_digest: Sha256Digest,
) -> Result<(), LogicalActivationStoreError> {
    const MAX_RENEWAL_CHAIN_EDGES: usize = 64;

    let selection_id = selected.selection_id();
    let mut generation = pg_bigint(selected.generation().get());
    let mut claimed_at = selected.claimed_at().get();
    let mut expires_at = selected.expires_at().get();
    for _ in 0..MAX_RENEWAL_CHAIN_EDGES {
        if generation == durable.fence {
            break;
        }
        if generation > durable.fence {
            return Err(LogicalActivationStoreError::ClaimRejected);
        }
        let edge = sqlx::query(
            r"
            SELECT successor_generation, successor_claimed_at_ms,
                   successor_expires_at_ms
            FROM logical_workflow_activation_renewal_receipts
            WHERE logical_job_id = $1
              AND authority_kind = 'activation'
              AND predecessor_generation = $2
              AND selection_id = $3
              AND tenant_id = $4
              AND run_id = $5
              AND invocation_id = $6
              AND owner_id = $7
              AND runtime_policy_revision = $8
              AND runtime_policy_digest = $9
              AND authority_digest = $10
              AND predecessor_claimed_at_ms = $11
              AND predecessor_expires_at_ms = $12
            FOR UPDATE
            ",
        )
        .bind(selected.target().logical_job_id().as_uuid())
        .bind(generation)
        .bind(selection_id.as_uuid())
        .bind(selected.target().tenant().as_str())
        .bind(selected.target().run_id().as_uuid())
        .bind(selected.target().invocation_id().as_uuid())
        .bind(selected.owner().as_uuid())
        .bind(runtime_policy_revision)
        .bind(runtime_policy_digest.as_bytes().as_slice())
        .bind(selected.authority_digest().as_bytes().as_slice())
        .bind(claimed_at)
        .bind(expires_at)
        .fetch_optional(&mut **transaction)
        .await
        .map_err(operation_error)?
        .ok_or(LogicalActivationStoreError::ClaimRejected)?;
        let next_generation: i64 = edge
            .try_get("successor_generation")
            .map_err(operation_error)?;
        let next_claimed_at: i64 = edge
            .try_get("successor_claimed_at_ms")
            .map_err(operation_error)?;
        let next_expires_at: i64 = edge
            .try_get("successor_expires_at_ms")
            .map_err(operation_error)?;
        if generation.checked_add(1) != Some(next_generation)
            || next_claimed_at < claimed_at
            || next_claimed_at >= expires_at
            || next_expires_at <= expires_at
        {
            return Err(StoreError::corrupt_data(
                "logical activation renewal receipt chain is invalid",
            )
            .into());
        }
        generation = next_generation;
        claimed_at = next_claimed_at;
        expires_at = next_expires_at;
    }
    if generation != durable.fence
        || claimed_at != current_claimed_at
        || expires_at != current_expires_at
    {
        return Err(LogicalActivationStoreError::ClaimRejected);
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn insert_activation_renewal_receipt(
    transaction: &mut Transaction<'_, Postgres>,
    request: &RenewLogicalJobActivation,
    successor_generation: i64,
    successor_claimed_at: i64,
    successor_expires_at: i64,
    selection_id: Uuid,
) -> Result<i64, LogicalActivationStoreError> {
    sqlx::query_scalar(
        r"
        INSERT INTO logical_workflow_activation_renewal_receipts (
            logical_job_id, authority_kind, selection_id, tenant_id, run_id,
            invocation_id, owner_id, runtime_policy_revision,
            runtime_policy_digest, authority_digest, predecessor_generation,
            predecessor_claimed_at_ms, predecessor_expires_at_ms,
            requested_duration_ms, successor_generation,
            successor_claimed_at_ms, successor_expires_at_ms, validated_at_ms
        ) VALUES (
            $1, 'activation', $2, $3, $4, $5, $6, $7, $8, $9,
            $10, $11, $12, $13, $14, $15, $16, $15
        )
        RETURNING validated_at_ms
        ",
    )
    .bind(request.claim().logical_job_id().as_uuid())
    .bind(selection_id)
    .bind(request.claim().tenant().as_str())
    .bind(request.claim().run_id().as_uuid())
    .bind(request.claim().invocation_id().as_uuid())
    .bind(request.claim().owner().as_uuid())
    .bind(pg_bigint(request.claim().runtime_policy().revision().get()))
    .bind(
        request
            .claim()
            .runtime_policy()
            .digest()
            .as_bytes()
            .as_slice(),
    )
    .bind(request.claim().input_digest().as_bytes().as_slice())
    .bind(pg_bigint(request.claim().generation().get()))
    .bind(request.claim().claimed_at().get())
    .bind(request.claim().expires_at().get())
    .bind(request.duration_ms())
    .bind(successor_generation)
    .bind(successor_claimed_at)
    .bind(successor_expires_at)
    .fetch_one(&mut **transaction)
    .await
    .map_err(operation_error)
}

#[allow(clippy::too_many_lines)] // Claim/takeover is one atomic lock-and-transition proof.
pub(super) async fn claim_logical_job_activation_in_transaction(
    transaction: &mut Transaction<'_, Postgres>,
    request: &ClaimLogicalJobActivation,
    origin_selection_id: Uuid,
) -> Result<Option<ClaimedLogicalJobActivation>, LogicalActivationStoreError> {
    if !lock_active_logical_graph(
        transaction,
        request.tenant(),
        request.run_id(),
        request.invocation_id(),
    )
    .await?
    {
        return Ok(None);
    }
    let row = lock_claim_target(transaction, request)
        .await?
        .ok_or(LogicalActivationStoreError::InvalidTarget)?;
    reject_quarantined_activation(transaction, request.logical_job_id()).await?;
    let durable = DurableClaimState::decode(&row)?;
    let durable_origin: Option<Uuid> = row
        .try_get("activation_origin_selection_id")
        .map_err(operation_error)?;

    if durable.runtime_policy_revision != Some(pg_bigint(request.runtime_policy().revision().get()))
        || durable.runtime_policy_digest != Some(request.runtime_policy().digest())
    {
        return Err(LogicalActivationStoreError::InputConflict);
    }
    if !durable.prerequisites_ready {
        return Ok(None);
    }
    if durable.prepared_input_digest != Some(request.input_digest()) {
        return Err(LogicalActivationStoreError::InputConflict);
    }
    if let Some(input_digest) = durable.input_digest
        && input_digest != request.input_digest()
    {
        return Err(LogicalActivationStoreError::InputConflict);
    }
    // Only an unclaimed pending row may lack an origin. A live legacy claim
    // with a NULL origin cannot be replayed into selector-backed authority;
    // after expiry it follows the ordinary generation-incrementing takeover.
    if durable.state == "pending" && durable_origin.is_some() {
        return Err(StoreError::corrupt_data(
            "pending logical activation unexpectedly retains a selection origin",
        )
        .into());
    }
    let is_initial_unclaimed = durable.state == "pending" && durable_origin.is_none();
    let origin_matches = durable_origin == Some(origin_selection_id);
    if origin_matches && durable.is_exact_replay(request)? {
        return decode_claimed(
            transaction,
            request,
            &row,
            durable.generation()?,
            true,
            origin_selection_id,
        )
        .await
        .map(Some);
    }

    if !is_initial_unclaimed
        && !origin_matches
        && (durable.state != "activating"
            || durable
                .expires_at
                .is_none_or(|expires_at| expires_at > request.observed_at().get()))
    {
        return Ok(None);
    }

    let eligible = durable.state == "pending"
        || (durable.state == "activating"
            && durable
                .expires_at
                .is_some_and(|expires_at| expires_at <= request.observed_at().get()));
    if !eligible || durable.created_at > request.observed_at().get() {
        return Ok(None);
    }

    let generation = durable
        .fence
        .checked_add(1)
        .filter(|value| *value > 0)
        .ok_or(LogicalActivationStoreError::GenerationExhausted)?;
    let rows = sqlx::query(
        r"
        UPDATE logical_workflow_jobs
        SET state = 'activating',
            activation_fence = $5,
            activation_owner_id = $6,
            activation_claimed_at_ms = $7,
            activation_expires_at_ms = $8,
            activation_input_digest = $9,
            activation_origin_selection_id = $10,
            updated_at_ms = $7
        WHERE run_id = $1
          AND invocation_id = $2
          AND id = $3
          AND activation_fence = $4
        ",
    )
    .bind(request.run_id().as_uuid())
    .bind(request.invocation_id().as_uuid())
    .bind(request.logical_job_id().as_uuid())
    .bind(durable.fence)
    .bind(generation)
    .bind(request.owner().as_uuid())
    .bind(request.observed_at().get())
    .bind(request.expires_at().get())
    .bind(request.input_digest().as_bytes().as_slice())
    .bind(origin_selection_id)
    .execute(&mut **transaction)
    .await
    .map_err(operation_error)?
    .rows_affected();
    if rows != 1 {
        return Err(StoreError::corrupt_data(
            "locked logical activation claim lost its durable row",
        )
        .into());
    }

    let generation = LogicalActivationGeneration::new(
        u64::try_from(generation).map_err(|_| LogicalActivationStoreError::GenerationExhausted)?,
    )
    .map_err(|_| LogicalActivationStoreError::GenerationExhausted)?;
    decode_claimed(
        transaction,
        request,
        &row,
        generation,
        false,
        origin_selection_id,
    )
    .await
    .map(Some)
}

pub(super) async fn consume_selected_activation_in_transaction(
    transaction: &mut Transaction<'_, Postgres>,
    selected: &SelectedLogicalJobOrchestration,
) -> Result<Option<ClaimedLogicalJobActivation>, LogicalActivationStoreError> {
    let schemas = current_durable_schemas();
    let row = sqlx::query(claim_target_query())
        .bind(selected.target().tenant().as_str())
        .bind(selected.target().run_id().as_uuid())
        .bind(selected.target().invocation_id().as_uuid())
        .bind(selected.target().logical_job_id().as_uuid())
        .bind(schemas.workflow_plan_i16)
        .bind(schemas.logical_orchestration_i16)
        .bind(schemas.workflow_plan_i32)
        .bind(schemas.admission_epoch_i32)
        .fetch_optional(&mut **transaction)
        .await
        .map_err(operation_error)?;
    let Some(row) = row else {
        return Ok(None);
    };
    reject_quarantined_activation(transaction, selected.target().logical_job_id()).await?;
    let durable = DurableClaimState::decode(&row)?;
    let origin_selection_id: Option<Uuid> = row
        .try_get("activation_origin_selection_id")
        .map_err(operation_error)?;
    if durable.state != "activating"
        || origin_selection_id != Some(selected.selection_id().as_uuid())
        || durable.owner != Some(selected.owner().as_uuid())
        || durable.fence < pg_bigint(selected.generation().get())
        || durable.input_digest != Some(selected.authority_digest())
    {
        return Ok(None);
    }
    let claimed_at = durable
        .claimed_at
        .ok_or_else(|| StoreError::corrupt_data("active activation lacks claim start"))?;
    let expires_at = durable
        .expires_at
        .ok_or_else(|| StoreError::corrupt_data("active activation lacks expiration"))?;
    let now: i64 =
        sqlx::query_scalar("SELECT floor(extract(epoch FROM clock_timestamp()) * 1000)::BIGINT")
            .fetch_one(&mut **transaction)
            .await
            .map_err(operation_error)?;
    if now < claimed_at
        || expires_at.saturating_sub(now) < MIN_LOGICAL_WORK_SELECTION_HANDOFF_MILLIS
    {
        return Ok(None);
    }
    let revision = durable
        .runtime_policy_revision
        .and_then(|value| u64::try_from(value).ok())
        .and_then(|value| WorkflowRuntimePolicyRevision::new(value).ok())
        .ok_or_else(|| StoreError::corrupt_data("active activation policy revision is invalid"))?;
    let policy_digest = durable
        .runtime_policy_digest
        .ok_or_else(|| StoreError::corrupt_data("active activation policy digest is absent"))?;
    verify_selected_activation_renewal_lineage(
        transaction,
        selected,
        &durable,
        claimed_at,
        expires_at,
        pg_bigint(revision.get()),
        policy_digest,
    )
    .await?;
    let repository_id = RepositoryId::from_uuid(
        row.try_get("runtime_policy_repository_id")
            .map_err(operation_error)?,
    );
    let request = ClaimLogicalJobActivation::new(
        selected.target().tenant().clone(),
        selected.target().run_id(),
        selected.target().invocation_id(),
        selected.target().logical_job_id(),
        selected.owner(),
        WorkflowRuntimePolicyPin::new(
            selected.target().tenant().clone(),
            repository_id,
            revision,
            policy_digest,
        ),
        selected.authority_digest(),
        UnixMillis::new(claimed_at),
        UnixMillis::new(expires_at),
    )
    .map_err(|_| StoreError::corrupt_data("active activation claim is invalid"))?;
    decode_claimed(
        transaction,
        &request,
        &row,
        durable.generation()?,
        true,
        selected.selection_id().as_uuid(),
    )
    .await
    .map(Some)
}

async fn reject_quarantined_activation(
    transaction: &mut Transaction<'_, Postgres>,
    logical_job_id: automata_ci_store::LogicalWorkflowJobId,
) -> Result<(), LogicalActivationStoreError> {
    let quarantined: bool = sqlx::query_scalar(
        r"
        SELECT EXISTS (
            SELECT 1
            FROM logical_workflow_activation_work_quarantines
            WHERE logical_job_id = $1
        )
        ",
    )
    .bind(logical_job_id.as_uuid())
    .fetch_one(&mut **transaction)
    .await
    .map_err(operation_error)?;
    if quarantined {
        Err(LogicalActivationStoreError::ClaimRejected)
    } else {
        Ok(())
    }
}

async fn lock_claim_target(
    transaction: &mut Transaction<'_, Postgres>,
    request: &ClaimLogicalJobActivation,
) -> Result<Option<PgRow>, LogicalActivationStoreError> {
    let schemas = current_durable_schemas();
    sqlx::query(claim_target_query())
        .bind(request.tenant().as_str())
        .bind(request.run_id().as_uuid())
        .bind(request.invocation_id().as_uuid())
        .bind(request.logical_job_id().as_uuid())
        .bind(schemas.workflow_plan_i16)
        .bind(schemas.logical_orchestration_i16)
        .bind(schemas.workflow_plan_i32)
        .bind(schemas.admission_epoch_i32)
        .fetch_optional(&mut **transaction)
        .await
        .map_err(operation_error)
}

async fn lock_publication_target(
    transaction: &mut Transaction<'_, Postgres>,
    request: &PublishLogicalJobActivation,
) -> Result<Option<PgRow>, LogicalActivationStoreError> {
    let schemas = current_durable_schemas();
    sqlx::query(claim_target_query())
        .bind(request.claim().tenant().as_str())
        .bind(request.claim().run_id().as_uuid())
        .bind(request.claim().invocation_id().as_uuid())
        .bind(request.claim().logical_job_id().as_uuid())
        .bind(schemas.workflow_plan_i16)
        .bind(schemas.logical_orchestration_i16)
        .bind(schemas.workflow_plan_i32)
        .bind(schemas.admission_epoch_i32)
        .fetch_optional(&mut **transaction)
        .await
        .map_err(operation_error)
}

fn claim_target_query() -> &'static str {
    r"
    SELECT job.state, job.activation_fence, job.activation_owner_id,
           job.activation_claimed_at_ms, job.activation_expires_at_ms,
           job.activation_input_digest, job.activation_origin_selection_id,
           job.authority_profile,
           job.runtime_policy_revision, job.runtime_policy_digest,
           job.logical_key, job.source_order,
           job.execution_kind, job.created_at_ms,
           run.workflow_id, run.workflow_name, run.git_ref, run.event_name,
           run.actor,
           run.triggering_actor,
           run.public_run_id_alias AS run_id_alias,
           run.run_number, run.run_attempt,
           invocation.plan_digest, invocation.plan_object_key,
           invocation.plan_size_bytes, invocation.plan_media_type,
           run.event_digest, run.event_object_key, run.event_size_bytes,
           run.event_media_type, repository.id AS runtime_policy_repository_id,
           preparation.activation_input_digest AS prepared_input_digest,
           preparation.authority_profile AS prepared_authority_profile,
           preparation.runtime_policy_revision AS prepared_runtime_policy_revision,
           preparation.runtime_policy_digest AS prepared_runtime_policy_digest,
           (preparation.logical_job_id IS NOT NULL
            AND preparation_claim.state = 'prepared') AS prerequisites_ready
    FROM logical_workflow_jobs AS job
    JOIN logical_workflow_invocations AS invocation
      ON invocation.run_id = job.run_id
     AND invocation.id = job.invocation_id
    JOIN logical_workflow_runs AS marker ON marker.run_id = job.run_id
    JOIN workflow_runs AS run ON run.id = marker.run_id
    JOIN repositories AS repository ON repository.id = run.repository_id
    LEFT JOIN logical_workflow_activation_preparations AS preparation
      ON preparation.run_id = job.run_id
     AND preparation.invocation_id = job.invocation_id
     AND preparation.logical_job_id = job.id
    LEFT JOIN logical_workflow_activation_preparation_claims AS preparation_claim
      ON preparation_claim.logical_job_id = preparation.logical_job_id
    WHERE repository.tenant_id = $1
      AND job.run_id = $2
      AND job.invocation_id = $3
      AND job.id = $4
      AND job.execution_kind = 'steps'
      AND invocation.plan_schema = $5
      AND invocation.state IN ('pending', 'active')
      AND marker.orchestration_schema = $6
      AND marker.state IN ('pending', 'active')
      AND run.admission_epoch = $8
      AND run.plan_schema = $7
    FOR UPDATE OF job
    "
}

#[derive(Debug)]
struct DurableClaimState {
    state: String,
    fence: i64,
    owner: Option<Uuid>,
    claimed_at: Option<i64>,
    expires_at: Option<i64>,
    input_digest: Option<Sha256Digest>,
    prepared_input_digest: Option<Sha256Digest>,
    authority_profile: Option<JobAuthorityProfile>,
    runtime_policy_revision: Option<i64>,
    runtime_policy_digest: Option<Sha256Digest>,
    created_at: i64,
    prerequisites_ready: bool,
}

impl DurableClaimState {
    #[allow(clippy::too_many_lines)] // Decode checks one closed durable row shape.
    fn decode(row: &PgRow) -> Result<Self, LogicalActivationStoreError> {
        let state: String = row.try_get("state").map_err(operation_error)?;
        let fence: i64 = row.try_get("activation_fence").map_err(operation_error)?;
        if fence < 0 {
            return Err(StoreError::corrupt_data("logical activation fence is negative").into());
        }
        let owner = row
            .try_get::<Option<Uuid>, _>("activation_owner_id")
            .map_err(operation_error)?;
        if owner.is_some_and(|owner| owner.is_nil()) {
            return Err(
                StoreError::corrupt_data("logical activation owner is the nil UUID").into(),
            );
        }
        let claimed_at = row
            .try_get::<Option<i64>, _>("activation_claimed_at_ms")
            .map_err(operation_error)?;
        let expires_at = row
            .try_get::<Option<i64>, _>("activation_expires_at_ms")
            .map_err(operation_error)?;
        let input_digest = row
            .try_get::<Option<Vec<u8>>, _>("activation_input_digest")
            .map_err(operation_error)?
            .map(|value| decode_digest_bytes(&value, "logical activation input digest"))
            .transpose()?;
        let prepared_input_digest = row
            .try_get::<Option<Vec<u8>>, _>("prepared_input_digest")
            .map_err(operation_error)?
            .map(|value| decode_digest_bytes(&value, "prepared activation input digest"))
            .transpose()?;
        let authority_profile = row
            .try_get::<Option<String>, _>("authority_profile")
            .map_err(operation_error)?
            .as_deref()
            .map(parse_authority_profile)
            .transpose()?;
        let prepared_authority_profile = row
            .try_get::<Option<String>, _>("prepared_authority_profile")
            .map_err(operation_error)?
            .as_deref()
            .map(parse_authority_profile)
            .transpose()?;
        let runtime_policy_revision = row
            .try_get::<Option<i64>, _>("runtime_policy_revision")
            .map_err(operation_error)?;
        let runtime_policy_digest = row
            .try_get::<Option<Vec<u8>>, _>("runtime_policy_digest")
            .map_err(operation_error)?
            .map(|value| decode_digest_bytes(&value, "logical activation runtime policy"))
            .transpose()?;
        let prepared_runtime_policy_revision = row
            .try_get::<Option<i64>, _>("prepared_runtime_policy_revision")
            .map_err(operation_error)?;
        let prepared_runtime_policy_digest = row
            .try_get::<Option<Vec<u8>>, _>("prepared_runtime_policy_digest")
            .map_err(operation_error)?
            .map(|value| decode_digest_bytes(&value, "prepared activation runtime policy"))
            .transpose()?;
        let created_at: i64 = row.try_get("created_at_ms").map_err(operation_error)?;
        let prerequisites_ready: bool = row
            .try_get("prerequisites_ready")
            .map_err(operation_error)?;
        if prerequisites_ready != prepared_input_digest.is_some()
            || prerequisites_ready != prepared_authority_profile.is_some()
            || prepared_authority_profile.is_some_and(|profile| Some(profile) != authority_profile)
            || prerequisites_ready != prepared_runtime_policy_revision.is_some()
            || prerequisites_ready != prepared_runtime_policy_digest.is_some()
            || prepared_runtime_policy_revision != runtime_policy_revision
            || prepared_runtime_policy_digest != runtime_policy_digest
        {
            return Err(StoreError::corrupt_data(
                "logical activation preparation readiness is inconsistent",
            )
            .into());
        }
        let claim_fields_valid = if state == "activating" {
            fence > 0
                && owner.is_some()
                && claimed_at.is_some_and(|value| value >= created_at)
                && expires_at
                    .zip(claimed_at)
                    .is_some_and(|(expires, claimed)| expires > claimed)
        } else {
            owner.is_none() && claimed_at.is_none() && expires_at.is_none()
        };
        if !claim_fields_valid {
            return Err(StoreError::corrupt_data(
                "logical activation claim columns are inconsistent",
            )
            .into());
        }
        Ok(Self {
            state,
            fence,
            owner,
            claimed_at,
            expires_at,
            input_digest,
            prepared_input_digest,
            authority_profile,
            runtime_policy_revision,
            runtime_policy_digest,
            created_at,
            prerequisites_ready,
        })
    }

    fn generation(&self) -> Result<LogicalActivationGeneration, LogicalActivationStoreError> {
        let generation = u64::try_from(self.fence)
            .map_err(|_| StoreError::corrupt_data("invalid logical activation generation"))?;
        LogicalActivationGeneration::new(generation)
            .map_err(|_| StoreError::corrupt_data("invalid logical activation generation").into())
    }

    fn is_exact_replay(
        &self,
        request: &ClaimLogicalJobActivation,
    ) -> Result<bool, LogicalActivationStoreError> {
        if self.state != "activating" {
            return Ok(false);
        }
        let owner = self
            .owner
            .ok_or_else(|| StoreError::corrupt_data("active logical claim has no owner"))?;
        let claimed_at = self
            .claimed_at
            .ok_or_else(|| StoreError::corrupt_data("active logical claim has no start"))?;
        let expires_at = self
            .expires_at
            .ok_or_else(|| StoreError::corrupt_data("active logical claim has no expiration"))?;
        Ok(owner == request.owner().as_uuid()
            && self.input_digest == Some(request.input_digest())
            && claimed_at == request.observed_at().get()
            && expires_at == request.expires_at().get())
    }

    fn matches_claim(&self, claim: &LogicalActivationClaimFence) -> bool {
        self.state == "activating"
            && self.owner == Some(claim.owner().as_uuid())
            && self.fence == pg_bigint(claim.generation().get())
            && self.input_digest == Some(claim.input_digest())
            && self.claimed_at == Some(claim.claimed_at().get())
            && self.expires_at == Some(claim.expires_at().get())
    }
}

fn require_activation_selection_origin(
    row: &PgRow,
    expected: automata_ci_store::LogicalWorkSelectionId,
) -> Result<(), LogicalActivationStoreError> {
    let durable: Option<Uuid> = row
        .try_get("activation_origin_selection_id")
        .map_err(operation_error)?;
    if durable == Some(expected.as_uuid()) {
        Ok(())
    } else {
        Err(LogicalActivationStoreError::ClaimRejected)
    }
}

#[allow(clippy::too_many_lines)] // Rehydration validates the complete immutable claim row.
async fn decode_claimed(
    transaction: &mut Transaction<'_, Postgres>,
    request: &ClaimLogicalJobActivation,
    row: &PgRow,
    generation: LogicalActivationGeneration,
    replayed: bool,
    origin_selection_id: Uuid,
) -> Result<ClaimedLogicalJobActivation, LogicalActivationStoreError> {
    let logical_key: String = row.try_get("logical_key").map_err(operation_error)?;
    let logical_key = WorkflowJobKey::new(logical_key)
        .map_err(|_| StoreError::corrupt_data("invalid durable logical job key"))?;
    let source_order: i32 = row.try_get("source_order").map_err(operation_error)?;
    let source_order = u16::try_from(source_order)
        .map_err(|_| StoreError::corrupt_data("invalid durable logical job source order"))?;
    let execution_kind: String = row.try_get("execution_kind").map_err(operation_error)?;
    if execution_kind != "steps" {
        return Err(StoreError::corrupt_data(
            "activation claim unexpectedly selected a non-step job",
        )
        .into());
    }
    let workflow_id: Uuid = row.try_get("workflow_id").map_err(operation_error)?;
    let workflow_name: String = row.try_get("workflow_name").map_err(operation_error)?;
    let git_ref: String = row.try_get("git_ref").map_err(operation_error)?;
    let root_event_name: String = row.try_get("event_name").map_err(operation_error)?;
    let actor: Option<String> = row.try_get("actor").map_err(operation_error)?;
    let triggering_actor: Option<String> =
        row.try_get("triggering_actor").map_err(operation_error)?;
    let run_id_alias: i64 = row.try_get("run_id_alias").map_err(operation_error)?;
    let run_number: i64 = row.try_get("run_number").map_err(operation_error)?;
    let run_attempt: i32 = row.try_get("run_attempt").map_err(operation_error)?;
    let mut execution = LogicalActivationExecutionContext::new(
        WorkflowId::from_uuid(workflow_id),
        workflow_name,
        git_ref,
        root_event_name,
        actor,
        RunIdAlias::new(
            u64::try_from(run_id_alias)
                .map_err(|_| StoreError::corrupt_data("invalid durable workflow run ID alias"))?,
        )
        .map_err(|_| StoreError::corrupt_data("invalid durable workflow run ID alias"))?,
        u64::try_from(run_number)
            .map_err(|_| StoreError::corrupt_data("invalid durable workflow run number"))?,
        u32::try_from(run_attempt)
            .map_err(|_| StoreError::corrupt_data("invalid durable workflow run attempt"))?,
    )
    .map_err(|_| StoreError::corrupt_data("invalid durable activation execution metadata"))?;
    if let Some(triggering_actor) = triggering_actor {
        execution = execution
            .with_triggering_actor(triggering_actor)
            .map_err(|_| StoreError::corrupt_data("invalid durable triggering actor"))?;
    }
    let plan = decode_admission_object(
        row,
        "plan_digest",
        "plan_object_key",
        "plan_size_bytes",
        "plan_media_type",
        AdmissionObjectLimit::Standard,
    )?;
    let event = decode_admission_object(
        row,
        "event_digest",
        "event_object_key",
        "event_size_bytes",
        "event_media_type",
        AdmissionObjectLimit::ProviderEvent,
    )?;
    let selection_origin =
        automata_ci_store::LogicalWorkSelectionId::from_uuid(origin_selection_id)
            .map_err(|_| StoreError::corrupt_data("invalid durable activation selection origin"))?;
    let claim = LogicalActivationClaimFence::new_for_selection(
        request.tenant().clone(),
        request.run_id(),
        request.invocation_id(),
        request.logical_job_id(),
        request.owner(),
        request.runtime_policy().clone(),
        generation,
        request.input_digest(),
        request.observed_at(),
        request.expires_at(),
        selection_origin,
    )
    .map_err(|_| StoreError::corrupt_data("invalid durable logical activation fence"))?;
    let target = LogicalActivationPreparationTarget::new(
        request.tenant().clone(),
        request.run_id(),
        request.invocation_id(),
        request.logical_job_id(),
    )
    .map_err(|_| StoreError::corrupt_data("invalid durable preparation target"))?;
    let preparation = load_bound_preparation_for_activation_in_transaction(transaction, &target)
        .await
        .map_err(map_preparation_load_error)?;
    let exact_preparation = preparation.descriptor().logical_key() == &logical_key
        && preparation.descriptor().source_order() == source_order
        && preparation.descriptor().execution() == &execution
        && preparation.descriptor().plan() == &plan
        && preparation.descriptor().event() == &event;
    if !exact_preparation {
        return Err(StoreError::corrupt_data(
            "logical activation disagrees with immutable preparation evidence",
        )
        .into());
    }
    ClaimedLogicalJobActivation::new_with_preparation(claim, preparation, replayed)
        .map_err(|_| StoreError::corrupt_data("invalid durable logical activation evidence").into())
}

fn map_preparation_load_error(
    error: LogicalActivationPreparationStoreError,
) -> LogicalActivationStoreError {
    match error {
        LogicalActivationPreparationStoreError::Store(error) => {
            LogicalActivationStoreError::Store(error)
        }
        _ => StoreError::corrupt_data("activation claim lacks exact preparation evidence").into(),
    }
}

fn validate_live_publication_fence(
    durable: &DurableClaimState,
    request: &PublishLogicalJobActivation,
) -> Result<(), LogicalActivationStoreError> {
    let claim = request.claim();
    let exact = durable.owner == Some(claim.owner().as_uuid())
        && durable.fence == pg_bigint(claim.generation().get())
        && durable.input_digest == Some(claim.input_digest())
        && durable.prepared_input_digest == Some(claim.input_digest())
        && durable.claimed_at == Some(claim.claimed_at().get())
        && durable.expires_at == Some(claim.expires_at().get())
        && claim.claimed_at() <= request.published_at()
        && claim.expires_at() > request.published_at();
    if !exact {
        return Err(LogicalActivationStoreError::ClaimRejected);
    }
    Ok(())
}

async fn insert_publication(
    transaction: &mut Transaction<'_, Postgres>,
    request: &PublishLogicalJobActivation,
    authority_profile: JobAuthorityProfile,
) -> Result<(), LogicalActivationStoreError> {
    sqlx::query(
        r"
        INSERT INTO logical_workflow_activation_publications (
            run_id, invocation_id, logical_job_id,
            activation_input_digest, activation_output_digest, authority_profile,
            activation_owner_id, activation_generation,
            activation_claimed_at_ms, activation_expires_at_ms,
            condition_matched, instance_count, job_ir_version,
            runtime_context_schema, published_at_ms,
            runtime_policy_revision, runtime_policy_digest,
            scheduling_policy_schema, requested_max_parallel,
            effective_max_parallel
        ) VALUES (
            $1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,
            $18,$19,$20
        )
        ",
    )
    .bind(request.claim().run_id().as_uuid())
    .bind(request.claim().invocation_id().as_uuid())
    .bind(request.claim().logical_job_id().as_uuid())
    .bind(request.claim().input_digest().as_bytes().as_slice())
    .bind(request.output_digest().as_bytes().as_slice())
    .bind(authority_profile_name(authority_profile))
    .bind(request.claim().owner().as_uuid())
    .bind(pg_bigint(request.claim().generation().get()))
    .bind(request.claim().claimed_at().get())
    .bind(request.claim().expires_at().get())
    .bind(request.condition_matched())
    .bind(instance_count_i32(request.instances())?)
    .bind(i16::try_from(JOB_IR_SCHEMA_VERSION).expect("current JobIR schema fits in SMALLINT"))
    .bind(
        i16::try_from(JOB_RUNTIME_CONTEXT_SCHEMA_VERSION)
            .expect("current runtime-context schema fits in SMALLINT"),
    )
    .bind(request.published_at().get())
    .bind(pg_bigint(request.claim().runtime_policy().revision().get()))
    .bind(
        request
            .claim()
            .runtime_policy()
            .digest()
            .as_bytes()
            .as_slice(),
    )
    .bind(current_durable_schemas().logical_job_scheduling_policy_i16)
    .bind(
        request
            .scheduling_policy()
            .requested_max_parallel()
            .map(i64::from),
    )
    .bind(i32::from(
        request.scheduling_policy().effective_max_parallel(),
    ))
    .execute(&mut **transaction)
    .await
    .map_err(operation_error)?;
    Ok(())
}

pub(super) fn decode_scheduling_policy(
    row: &PgRow,
    scope: &LogicalJobSchedulingPolicyScope,
) -> Result<ResolvedLogicalJobSchedulingPolicy, StoreError> {
    let corrupt = || StoreError::corrupt_data("invalid durable logical-job scheduling policy");
    let schema = row
        .try_get::<i16, _>("scheduling_policy_schema")
        .map_err(StoreError::operation)?;
    if schema != current_durable_schemas().logical_job_scheduling_policy_i16 {
        return Err(corrupt());
    }
    let requested = row
        .try_get::<Option<i64>, _>("requested_max_parallel")
        .map_err(StoreError::operation)?
        .map(|value| u32::try_from(value).map_err(|_| corrupt()))
        .transpose()?;
    let instance_count = usize::try_from(
        row.try_get::<i32, _>("instance_count")
            .map_err(StoreError::operation)?,
    )
    .map_err(|_| corrupt())?;
    let effective = u16::try_from(
        row.try_get::<i32, _>("effective_max_parallel")
            .map_err(StoreError::operation)?,
    )
    .map_err(|_| corrupt())?;
    let policy = ResolvedLogicalJobSchedulingPolicy::new(scope.clone(), requested, instance_count)
        .map_err(|_| corrupt())?;
    if policy.effective_max_parallel() != effective {
        return Err(corrupt());
    }
    Ok(policy)
}

async fn insert_instance(
    transaction: &mut Transaction<'_, Postgres>,
    request: &PublishLogicalJobActivation,
    instance: &ActivatedLogicalInstanceDescriptor,
) -> Result<(), LogicalActivationStoreError> {
    let evidence = instance.environment_gate().ok_or_else(corrupt_instance)?;
    sqlx::query(
        r"
        INSERT INTO logical_workflow_instances (
            id, run_id, invocation_id, logical_job_id,
            matrix_index, matrix_total, matrix_digest, workspace,
            job_ir_digest, job_ir_object_key, job_ir_size_bytes,
            job_ir_media_type, job_ir_version,
            runtime_context_digest, runtime_context_object_key,
            runtime_context_size_bytes, runtime_context_media_type,
            runtime_context_schema, created_at_ms,
            runtime_policy_revision, runtime_policy_digest
        ) VALUES (
            $1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21
        )
        ",
    )
    .bind(instance.id().as_uuid())
    .bind(request.claim().run_id().as_uuid())
    .bind(request.claim().invocation_id().as_uuid())
    .bind(request.claim().logical_job_id().as_uuid())
    .bind(i32::try_from(instance.matrix_index()).map_err(|_| corrupt_instance())?)
    .bind(i32::try_from(instance.matrix_total()).map_err(|_| corrupt_instance())?)
    .bind(instance.matrix_digest().as_bytes().as_slice())
    .bind(instance.workspace())
    .bind(instance.job_ir().digest().as_bytes().as_slice())
    .bind(instance.job_ir().object_key().as_str())
    .bind(object_size_i64(instance.job_ir().encoded_size())?)
    .bind(instance.job_ir().media_type())
    .bind(i16::try_from(JOB_IR_SCHEMA_VERSION).expect("current JobIR schema fits in SMALLINT"))
    .bind(instance.runtime_context().digest().as_bytes().as_slice())
    .bind(instance.runtime_context().object_key().as_str())
    .bind(object_size_i64(instance.runtime_context().encoded_size())?)
    .bind(instance.runtime_context().media_type())
    .bind(
        i16::try_from(JOB_RUNTIME_CONTEXT_SCHEMA_VERSION)
            .expect("current runtime-context schema fits in SMALLINT"),
    )
    .bind(request.published_at().get())
    .bind(pg_bigint(request.claim().runtime_policy().revision().get()))
    .bind(
        request
            .claim()
            .runtime_policy()
            .digest()
            .as_bytes()
            .as_slice(),
    )
    .execute(&mut **transaction)
    .await
    .map_err(operation_error)?;
    sqlx::query(
        r"
        INSERT INTO logical_workflow_job_environment_evidence (
            instance_id, environment_normalized_name, event_trust,
            source_kind, reusable_secret_permission, created_at_ms
        ) VALUES ($1,$2,$3,$4,$5,$6)
        ",
    )
    .bind(instance.id().as_uuid())
    .bind(
        evidence
            .environment()
            .map(automata_ci_store::adapter_spi::deployment_environment_name),
    )
    .bind(job_event_trust_name(evidence.event_trust()))
    .bind(job_source_kind_name(evidence.source_kind()))
    .bind(reusable_secret_permission_name(
        evidence.reusable_secret_permission(),
    ))
    .bind(request.published_at().get())
    .execute(&mut **transaction)
    .await
    .map_err(operation_error)?;
    Ok(())
}

async fn verify_exact_publication(
    transaction: &mut Transaction<'_, Postgres>,
    request: &PublishLogicalJobActivation,
    authority_profile: JobAuthorityProfile,
) -> Result<bool, LogicalActivationStoreError> {
    let row = sqlx::query(
        r"
        SELECT activation_input_digest, activation_output_digest, authority_profile,
               activation_owner_id, activation_generation,
               activation_claimed_at_ms, activation_expires_at_ms,
               condition_matched, instance_count, job_ir_version,
               runtime_context_schema, published_at_ms,
               runtime_policy_revision, runtime_policy_digest,
               scheduling_policy_schema, requested_max_parallel,
               effective_max_parallel
        FROM logical_workflow_activation_publications
        WHERE run_id = $1 AND invocation_id = $2 AND logical_job_id = $3
        ",
    )
    .bind(request.claim().run_id().as_uuid())
    .bind(request.claim().invocation_id().as_uuid())
    .bind(request.claim().logical_job_id().as_uuid())
    .fetch_optional(&mut **transaction)
    .await
    .map_err(operation_error)?;
    let Some(row) = row else {
        return Ok(false);
    };

    let exact_claim = decode_digest(&row, "activation_input_digest")?
        == request.claim().input_digest()
        && row
            .try_get::<Uuid, _>("activation_owner_id")
            .map_err(operation_error)?
            == request.claim().owner().as_uuid()
        && row
            .try_get::<i64, _>("activation_generation")
            .map_err(operation_error)?
            == pg_bigint(request.claim().generation().get())
        && row
            .try_get::<i64, _>("activation_claimed_at_ms")
            .map_err(operation_error)?
            == request.claim().claimed_at().get()
        && row
            .try_get::<i64, _>("activation_expires_at_ms")
            .map_err(operation_error)?
            == request.claim().expires_at().get()
        && row
            .try_get::<i64, _>("runtime_policy_revision")
            .map_err(operation_error)?
            == pg_bigint(request.claim().runtime_policy().revision().get())
        && decode_digest(&row, "runtime_policy_digest")?
            == request.claim().runtime_policy().digest();
    if !exact_claim {
        return Err(LogicalActivationStoreError::ClaimRejected);
    }

    let exact_output = decode_digest(&row, "activation_output_digest")? == request.output_digest()
        && parse_authority_profile(
            &row.try_get::<String, _>("authority_profile")
                .map_err(operation_error)?,
        )? == authority_profile
        && row
            .try_get::<bool, _>("condition_matched")
            .map_err(operation_error)?
            == request.condition_matched()
        && row
            .try_get::<i32, _>("instance_count")
            .map_err(operation_error)?
            == instance_count_i32(request.instances())?
        && row
            .try_get::<i16, _>("job_ir_version")
            .map_err(operation_error)?
            == i16::try_from(JOB_IR_SCHEMA_VERSION).unwrap_or(i16::MAX)
        && row
            .try_get::<i16, _>("runtime_context_schema")
            .map_err(operation_error)?
            == i16::try_from(JOB_RUNTIME_CONTEXT_SCHEMA_VERSION).unwrap_or(i16::MAX)
        && row
            .try_get::<i64, _>("published_at_ms")
            .map_err(operation_error)?
            == request.published_at().get()
        && decode_scheduling_policy(&row, request.scheduling_policy().scope())?
            == *request.scheduling_policy();
    if !exact_output {
        return Err(LogicalActivationStoreError::PublicationConflict);
    }
    verify_exact_instances(transaction, request).await?;
    Ok(true)
}

async fn verify_exact_instances(
    transaction: &mut Transaction<'_, Postgres>,
    request: &PublishLogicalJobActivation,
) -> Result<(), LogicalActivationStoreError> {
    let rows = sqlx::query(
        r"
        SELECT instance.id, instance.matrix_index, instance.matrix_total,
               instance.matrix_digest, instance.workspace,
               runtime_policy_revision, runtime_policy_digest,
               job_ir_digest, job_ir_object_key, job_ir_size_bytes,
               job_ir_media_type, job_ir_version,
               runtime_context_digest, runtime_context_object_key,
               runtime_context_size_bytes, runtime_context_media_type,
               runtime_context_schema, instance.created_at_ms,
               evidence.environment_normalized_name AS gate_environment,
               evidence.event_trust AS gate_event_trust,
               evidence.source_kind AS gate_source_kind,
               evidence.reusable_secret_permission AS gate_reusable_permission,
               evidence.created_at_ms AS gate_created_at_ms
        FROM logical_workflow_instances AS instance
        LEFT JOIN logical_workflow_job_environment_evidence AS evidence
          ON evidence.instance_id = instance.id
        WHERE instance.run_id = $1 AND instance.invocation_id = $2
          AND instance.logical_job_id = $3
        ORDER BY instance.matrix_index
        ",
    )
    .bind(request.claim().run_id().as_uuid())
    .bind(request.claim().invocation_id().as_uuid())
    .bind(request.claim().logical_job_id().as_uuid())
    .fetch_all(&mut **transaction)
    .await
    .map_err(operation_error)?;
    if rows.len() != request.instances().len() {
        return Err(StoreError::corrupt_data(
            "logical activation publication has an incorrect instance count",
        )
        .into());
    }
    for (row, expected) in rows.iter().zip(request.instances()) {
        if !exact_instance_row(row, expected, request)? {
            return Err(StoreError::corrupt_data(
                "logical activation instance disagrees with its output digest",
            )
            .into());
        }
    }
    Ok(())
}

fn exact_instance_row(
    row: &PgRow,
    expected: &automata_ci_store::ActivatedLogicalInstanceDescriptor,
    request: &PublishLogicalJobActivation,
) -> Result<bool, LogicalActivationStoreError> {
    Ok(
        row.try_get::<Uuid, _>("id").map_err(operation_error)? == expected.id().as_uuid()
            && row
                .try_get::<i32, _>("matrix_index")
                .map_err(operation_error)?
                == i32::try_from(expected.matrix_index()).unwrap_or(i32::MAX)
            && row
                .try_get::<i32, _>("matrix_total")
                .map_err(operation_error)?
                == i32::try_from(expected.matrix_total()).unwrap_or(i32::MAX)
            && decode_digest(row, "matrix_digest")? == expected.matrix_digest()
            && row
                .try_get::<i64, _>("runtime_policy_revision")
                .map_err(operation_error)?
                == pg_bigint(request.claim().runtime_policy().revision().get())
            && decode_digest(row, "runtime_policy_digest")?
                == request.claim().runtime_policy().digest()
            && row
                .try_get::<String, _>("workspace")
                .map_err(operation_error)?
                == expected.workspace()
            && exact_content_reference(
                row,
                "job_ir",
                expected.job_ir(),
                LOGICAL_ACTIVATION_JOB_IR_MEDIA_TYPE,
                JOB_IR_SCHEMA_VERSION,
            )?
            && exact_content_reference(
                row,
                "runtime_context",
                expected.runtime_context(),
                LOGICAL_ACTIVATION_RUNTIME_CONTEXT_MEDIA_TYPE,
                JOB_RUNTIME_CONTEXT_SCHEMA_VERSION,
            )?
            && row
                .try_get::<i64, _>("created_at_ms")
                .map_err(operation_error)?
                == request.published_at().get()
            && exact_environment_gate_evidence(row, expected, request.published_at())?,
    )
}

fn exact_content_reference(
    row: &PgRow,
    column_prefix: &str,
    expected: &automata_ci_store::LogicalActivationObject,
    expected_media_type: &str,
    expected_schema: u16,
) -> Result<bool, LogicalActivationStoreError> {
    let digest_column = format!("{column_prefix}_digest");
    let object_key_column = format!("{column_prefix}_object_key");
    let size_column = format!("{column_prefix}_size_bytes");
    let media_type_column = format!("{column_prefix}_media_type");
    let schema_column = if column_prefix == "job_ir" {
        "job_ir_version"
    } else {
        "runtime_context_schema"
    };
    Ok(
        decode_digest(row, digest_column.as_str())? == expected.digest()
            && row
                .try_get::<String, _>(object_key_column.as_str())
                .map_err(operation_error)?
                == expected.object_key().as_str()
            && row
                .try_get::<i64, _>(size_column.as_str())
                .map_err(operation_error)?
                == object_size_i64(expected.encoded_size())?
            && row
                .try_get::<String, _>(media_type_column.as_str())
                .map_err(operation_error)?
                == expected_media_type
            && row
                .try_get::<i16, _>(schema_column)
                .map_err(operation_error)?
                == i16::try_from(expected_schema).unwrap_or(i16::MAX),
    )
}

fn exact_environment_gate_evidence(
    row: &PgRow,
    expected: &automata_ci_store::ActivatedLogicalInstanceDescriptor,
    published_at: automata_ci_core::UnixMillis,
) -> Result<bool, LogicalActivationStoreError> {
    let environment: Option<String> = row.try_get("gate_environment").map_err(operation_error)?;
    let event_trust: Option<String> = row.try_get("gate_event_trust").map_err(operation_error)?;
    let source_kind: Option<String> = row.try_get("gate_source_kind").map_err(operation_error)?;
    let reusable_permission: Option<String> = row
        .try_get("gate_reusable_permission")
        .map_err(operation_error)?;
    let created_at: Option<i64> = row.try_get("gate_created_at_ms").map_err(operation_error)?;
    let exact = match expected.environment_gate() {
        Some(evidence) => {
            environment.as_deref()
                == evidence
                    .environment()
                    .map(automata_ci_store::adapter_spi::deployment_environment_name)
                && event_trust.as_deref() == Some(job_event_trust_name(evidence.event_trust()))
                && source_kind.as_deref() == Some(job_source_kind_name(evidence.source_kind()))
                && reusable_permission.as_deref()
                    == Some(reusable_secret_permission_name(
                        evidence.reusable_secret_permission(),
                    ))
                && created_at == Some(published_at.get())
        }
        None => {
            environment.is_none()
                && event_trust.is_none()
                && source_kind.is_none()
                && reusable_permission.is_none()
                && created_at.is_none()
        }
    };
    Ok(exact)
}

fn decode_admission_object(
    row: &PgRow,
    digest_column: &str,
    key_column: &str,
    size_column: &str,
    media_column: &str,
    limit: AdmissionObjectLimit,
) -> Result<AdmissionObject, LogicalActivationStoreError> {
    let digest = decode_digest(row, digest_column)?;
    let object_key: String = row.try_get(key_column).map_err(operation_error)?;
    let encoded_size: i64 = row.try_get(size_column).map_err(operation_error)?;
    let media_type: String = row.try_get(media_column).map_err(operation_error)?;
    let object_key = ObjectKey::new(object_key)
        .map_err(|_| StoreError::corrupt_data("invalid durable activation object key"))?;
    let encoded_size = u64::try_from(encoded_size)
        .map_err(|_| StoreError::corrupt_data("invalid durable activation object size"))?;
    match limit {
        AdmissionObjectLimit::Standard => {
            AdmissionObject::new(digest, object_key, encoded_size, media_type)
        }
        AdmissionObjectLimit::ProviderEvent => {
            AdmissionObject::new_event(digest, object_key, encoded_size, media_type)
        }
    }
    .map_err(|_| StoreError::corrupt_data("invalid durable activation object descriptor").into())
}

#[derive(Clone, Copy)]
enum AdmissionObjectLimit {
    Standard,
    ProviderEvent,
}

fn decode_digest(row: &PgRow, column: &str) -> Result<Sha256Digest, LogicalActivationStoreError> {
    let value: Vec<u8> = row.try_get(column).map_err(operation_error)?;
    decode_digest_bytes(&value, column)
}

fn decode_digest_bytes(
    value: &[u8],
    field: &str,
) -> Result<Sha256Digest, LogicalActivationStoreError> {
    let bytes: [u8; 32] = value
        .try_into()
        .map_err(|_| StoreError::corrupt_data(format!("{field} is not SHA-256")))?;
    Ok(Sha256Digest::from_bytes(bytes))
}

fn parse_authority_profile(
    value: &str,
) -> Result<JobAuthorityProfile, LogicalActivationStoreError> {
    match value {
        "standard" => Ok(JobAuthorityProfile::Standard),
        "credential_free" => Ok(JobAuthorityProfile::CredentialFree),
        _ => Err(StoreError::corrupt_data("unknown logical authority profile").into()),
    }
}

const fn authority_profile_name(value: JobAuthorityProfile) -> &'static str {
    match value {
        JobAuthorityProfile::Standard => "standard",
        JobAuthorityProfile::CredentialFree => "credential_free",
    }
}

fn instance_count_i32(
    instances: &[ActivatedLogicalInstanceDescriptor],
) -> Result<i32, LogicalActivationStoreError> {
    i32::try_from(instances.len()).map_err(|_| corrupt_instance())
}

fn object_size_i64(value: u64) -> Result<i64, LogicalActivationStoreError> {
    i64::try_from(value).map_err(|_| corrupt_instance())
}

fn corrupt_instance() -> LogicalActivationStoreError {
    StoreError::corrupt_data("validated logical activation instance is not representable").into()
}

fn operation_error(error: sqlx::Error) -> LogicalActivationStoreError {
    StoreError::operation(error).into()
}
