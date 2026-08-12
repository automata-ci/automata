use async_trait::async_trait;
use std::collections::BTreeMap;

use automata_ci_core::{
    InvocationInputType, OutputSensitivity, PermissionLevel, Sha256Digest, UnixMillis,
    WorkflowJobKey, WorkflowOutputKey,
};
use sha2::{Digest as _, Sha256};
use sqlx::{Postgres, Row as _, Transaction, postgres::PgRow};

use super::PostgresStore;
use crate::{
    AdmissionObject, AdmittedReusableInputKind, CompleteReusableWorkflowCall,
    LogicalActivationPreparationStoreError, LogicalActivationPreparationTarget,
    LogicalWorkflowInvocationId, LogicalWorkflowJobId, ObjectKey, PublishReusableWorkflowCall,
    ReadyReusableWorkflowCall, ReadyReusableWorkflowCompletion, RepositoryId,
    ReusableCallOutputMapping, ReusableWorkflowCompletionReceipt,
    ReusableWorkflowInputBindingEvidence, ReusableWorkflowOperationId,
    ReusableWorkflowPermissionSnapshot, ReusableWorkflowPublicationReceipt,
    ReusableWorkflowResultOutput, ReusableWorkflowRuntimeRepository,
    ReusableWorkflowRuntimeStoreError, ReusableWorkflowSecretBindingEvidence, StoreError,
    TenantScope, WorkflowRuntimePolicyPin, WorkflowRuntimePolicyRevision,
};

const NEXT_REUSABLE_CALL_SQL: &str = r"
    SELECT repository.tenant_id, repository.id AS repository_id,
           caller.run_id, caller.invocation_id AS parent_invocation_id,
           caller.id AS caller_logical_job_id,
           planned.invocation_id AS child_invocation_id,
           planned.input_binding_count, planned.secret_binding_count,
           planned.permission_grant_count,
           permissions.default_level, permissions.permission_digest,
           catalog.plan_digest AS child_plan_digest,
           catalog.plan_object_key AS child_plan_object_key,
           catalog.plan_size_bytes AS child_plan_size_bytes,
           catalog.plan_media_type AS child_plan_media_type
    FROM workflow_plan_v2_jobs AS caller
    JOIN workflow_plan_v2_invocations AS parent
      ON parent.run_id = caller.run_id
     AND parent.id = caller.invocation_id
    JOIN workflow_plan_v2_runs AS marker ON marker.run_id = caller.run_id
    JOIN workflow_runs AS run ON run.id = marker.run_id
    JOIN repositories AS repository ON repository.id = run.repository_id
    JOIN workflow_plan_v2_reusable_invocation_expansions AS planned
      ON planned.run_id = caller.run_id
     AND planned.parent_invocation_id = caller.invocation_id
     AND planned.caller_logical_job_id = caller.id
     AND planned.depth > 0
    JOIN workflow_plan_v2_reusable_workflow_catalog AS catalog
      ON catalog.run_id = planned.run_id
     AND catalog.catalog_entry_id = planned.catalog_entry_id
    JOIN workflow_plan_v2_reusable_permission_snapshots AS permissions
      ON permissions.run_id = planned.run_id
     AND permissions.invocation_id = planned.invocation_id
    LEFT JOIN workflow_plan_v2_reusable_call_publications AS publication
      ON publication.run_id = caller.run_id
     AND publication.parent_invocation_id = caller.invocation_id
     AND publication.caller_logical_job_id = caller.id
    WHERE caller.execution_kind = 'reusable_workflow'
      AND caller.state = 'pending'
      AND caller.activation_fence = 0
      AND caller.activation_owner_id IS NULL
      AND caller.activation_claimed_at_ms IS NULL
      AND caller.activation_expires_at_ms IS NULL
      AND caller.activation_input_digest IS NULL
      AND caller.activation_origin_selection_id IS NULL
      AND parent.state IN ('pending', 'active')
      AND marker.state IN ('pending', 'active')
      AND marker.admission_graph_sealed_at_ms IS NOT NULL
      AND run.status IN ('queued', 'in_progress')
      AND run.admission_epoch = 4 AND run.plan_schema = 2
      AND publication.run_id IS NULL
      AND automata_workflow_plan_v2_invocation_published(
          caller.run_id, caller.invocation_id
      )
      AND NOT EXISTS (
          SELECT 1
          FROM workflow_plan_v2_dependencies AS dependency
          LEFT JOIN workflow_plan_v2_job_results AS result
            ON result.run_id = dependency.run_id
           AND result.invocation_id = dependency.invocation_id
           AND result.logical_job_id = dependency.prerequisite_job_id
          LEFT JOIN workflow_plan_v2_job_result_claims AS claim
            ON claim.logical_job_id = result.logical_job_id
           AND claim.state = 'finalized'
          WHERE dependency.run_id = caller.run_id
            AND dependency.invocation_id = caller.invocation_id
            AND dependency.logical_job_id = caller.id
            AND (result.logical_job_id IS NULL OR claim.logical_job_id IS NULL)
      )
      AND NOT EXISTS (
          SELECT 1 FROM workflow_plan_v2_run_result_claims AS claim
          WHERE claim.run_id = caller.run_id
      )
    ORDER BY caller.created_at_ms, caller.run_id, caller.source_order
    LIMIT 1
    FOR UPDATE OF caller SKIP LOCKED
    ";

const NEXT_REUSABLE_COMPLETION_SQL: &str = r"
    SELECT publication.tenant_id, publication.repository_id,
           publication.run_id, publication.parent_invocation_id,
           publication.caller_logical_job_id,
           publication.caller_instance_id,
           publication.child_invocation_id, publication.operation_id,
           publication.activation_input_digest,
           publication.condition_matched, publication.matrix_digest,
           publication.runtime_context_digest,
           publication.runtime_context_object_key,
           publication.runtime_context_size_bytes,
           publication.runtime_context_media_type,
           publication.permission_digest,
           publication.output_mapping_count,
           publication.output_mapping_digest,
           publication.publication_digest,
           publication.runtime_policy_revision,
           publication.runtime_policy_digest,
           publication.authority_profile,
           publication.published_at_ms,
           publication.child_graph_sealed_at_ms,
           catalog.plan_digest AS child_plan_digest,
           catalog.plan_object_key AS child_plan_object_key,
           catalog.plan_size_bytes AS child_plan_size_bytes,
           catalog.plan_media_type AS child_plan_media_type,
           greatest(
               publication.published_at_ms,
               coalesce((
                   SELECT max(result.finalized_at_ms)
                   FROM workflow_plan_v2_job_results AS result
                   JOIN workflow_plan_v2_job_result_claims AS claim
                     ON claim.logical_job_id = result.logical_job_id
                    AND claim.state = 'finalized'
                   WHERE result.run_id = publication.run_id
                     AND result.invocation_id = publication.child_invocation_id
               ), publication.published_at_ms)
           ) AS ready_at_ms
    FROM workflow_plan_v2_reusable_call_publications AS publication
    JOIN workflow_plan_v2_runs AS marker ON marker.run_id = publication.run_id
    JOIN workflow_runs AS run ON run.id = marker.run_id
    JOIN workflow_plan_v2_reusable_invocation_expansions AS expansion
      ON expansion.run_id = publication.run_id
     AND expansion.parent_invocation_id = publication.parent_invocation_id
     AND expansion.caller_logical_job_id = publication.caller_logical_job_id
     AND expansion.invocation_id = publication.child_invocation_id
    JOIN workflow_plan_v2_reusable_workflow_catalog AS catalog
      ON catalog.run_id = expansion.run_id
     AND catalog.catalog_entry_id = expansion.catalog_entry_id
    LEFT JOIN workflow_plan_v2_reusable_call_results AS completed
      ON completed.run_id = publication.run_id
     AND completed.parent_invocation_id = publication.parent_invocation_id
     AND completed.caller_logical_job_id = publication.caller_logical_job_id
    WHERE publication.child_graph_sealed_at_ms = publication.published_at_ms
      AND completed.run_id IS NULL
      AND marker.state IN ('pending', 'active')
      AND run.status IN ('queued', 'in_progress')
      AND NOT EXISTS (
          SELECT 1 FROM workflow_plan_v2_run_result_claims AS claim
          WHERE claim.run_id = publication.run_id
      )
      AND (
          NOT publication.condition_matched
          OR (
              automata_workflow_plan_v2_invocation_published(
                  publication.run_id, publication.child_invocation_id
              )
              AND NOT EXISTS (
                  SELECT 1
                  FROM workflow_plan_v2_jobs AS child_job
                  LEFT JOIN workflow_plan_v2_job_results AS result
                    ON result.run_id = child_job.run_id
                   AND result.invocation_id = child_job.invocation_id
                   AND result.logical_job_id = child_job.id
                  LEFT JOIN workflow_plan_v2_job_result_claims AS claim
                    ON claim.logical_job_id = result.logical_job_id
                   AND claim.state = 'finalized'
                  WHERE child_job.run_id = publication.run_id
                    AND child_job.invocation_id = publication.child_invocation_id
                    AND (result.logical_job_id IS NULL OR claim.logical_job_id IS NULL)
              )
          )
      )
    ORDER BY publication.published_at_ms, publication.run_id,
             publication.parent_invocation_id,
             publication.caller_logical_job_id
    LIMIT 1
    FOR UPDATE OF publication SKIP LOCKED
    ";

#[async_trait]
impl ReusableWorkflowRuntimeRepository for PostgresStore {
    async fn next_reusable_workflow_call(
        &self,
    ) -> Result<Option<ReadyReusableWorkflowCall>, ReusableWorkflowRuntimeStoreError> {
        load_next_call(self).await
    }

    async fn next_reusable_workflow_completion(
        &self,
    ) -> Result<Option<ReadyReusableWorkflowCompletion>, ReusableWorkflowRuntimeStoreError> {
        load_next_completion(self).await
    }

    async fn publish_reusable_workflow_call(
        &self,
        request: PublishReusableWorkflowCall,
    ) -> Result<ReusableWorkflowPublicationReceipt, ReusableWorkflowRuntimeStoreError> {
        let mut transaction = self.pool.begin().await.map_err(operation_error)?;
        if let Some(row) = lock_publication_replay(&mut transaction, &request).await? {
            let exact = publication_row_matches(&row, &request)?
                && output_contract_matches(&mut transaction, &request).await?;
            transaction.commit().await.map_err(operation_error)?;
            return exact
                .then(|| ReusableWorkflowPublicationReceipt::new(&request, true))
                .ok_or(ReusableWorkflowRuntimeStoreError::Conflict);
        }

        bind_output_contract(&mut transaction, &request).await?;
        insert_publication(&mut transaction, &request).await?;
        if request.condition_matched() {
            publish_child_graph(&mut transaction, &request).await?;
        }
        seal_publication(&mut transaction, &request).await?;
        activate_parent_call(&mut transaction, &request).await?;
        transaction
            .commit()
            .await
            .map_err(classify_publication_error)?;
        Ok(ReusableWorkflowPublicationReceipt::new(&request, false))
    }

    async fn complete_reusable_workflow_call(
        &self,
        request: CompleteReusableWorkflowCall,
    ) -> Result<ReusableWorkflowCompletionReceipt, ReusableWorkflowRuntimeStoreError> {
        complete_call(self, request).await
    }
}

async fn load_next_call(
    store: &PostgresStore,
) -> Result<Option<ReadyReusableWorkflowCall>, ReusableWorkflowRuntimeStoreError> {
    let mut transaction = store.pool.begin().await.map_err(operation_error)?;
    let row = sqlx::query(NEXT_REUSABLE_CALL_SQL)
        .fetch_optional(&mut *transaction)
        .await
        .map_err(operation_error)?;
    let Some(row) = row else {
        transaction.commit().await.map_err(operation_error)?;
        return Ok(None);
    };

    let target = LogicalActivationPreparationTarget::new(
        TenantScope::from_authenticated_tenant_id(
            row.try_get::<String, _>("tenant_id")
                .map_err(operation_error)?,
        )
        .map_err(|_| corrupt("reusable call tenant is invalid"))?,
        automata_ci_core::RunId::from_uuid(row.try_get("run_id").map_err(operation_error)?),
        LogicalWorkflowInvocationId::from_uuid(
            row.try_get("parent_invocation_id")
                .map_err(operation_error)?,
        )
        .map_err(|_| corrupt("reusable parent invocation ID is invalid"))?,
        LogicalWorkflowJobId::from_uuid(
            row.try_get("caller_logical_job_id")
                .map_err(operation_error)?,
        )
        .map_err(|_| corrupt("reusable caller job ID is invalid"))?,
    )
    .map_err(|_| corrupt("reusable call preparation target is invalid"))?;
    let preparation =
        super::logical_activation_preparation::load_ready_reusable_preparation_descriptor(
            &mut transaction,
            target,
        )
        .await
        .map_err(map_preparation_error)?
        .ok_or(ReusableWorkflowRuntimeStoreError::NotReady)?;
    let child_invocation_id = LogicalWorkflowInvocationId::from_uuid(
        row.try_get("child_invocation_id")
            .map_err(operation_error)?,
    )
    .map_err(|_| corrupt("reusable child invocation ID is invalid"))?;
    let inputs = load_call_inputs(
        &mut transaction,
        preparation.target().run_id(),
        child_invocation_id,
    )
    .await?;
    let secrets = load_call_secrets(
        &mut transaction,
        preparation.target().run_id(),
        child_invocation_id,
    )
    .await?;
    let permissions = load_permission_snapshot(
        &mut transaction,
        preparation.target().run_id(),
        child_invocation_id,
        &row,
    )
    .await?;
    if usize::try_from(
        row.try_get::<i32, _>("input_binding_count")
            .map_err(operation_error)?,
    )
    .ok()
        != Some(inputs.len())
        || usize::try_from(
            row.try_get::<i32, _>("secret_binding_count")
                .map_err(operation_error)?,
        )
        .ok()
            != Some(secrets.len())
        || usize::try_from(
            row.try_get::<i32, _>("permission_grant_count")
                .map_err(operation_error)?,
        )
        .ok()
            != Some(permissions.grants().len())
    {
        return Err(corrupt("reusable call boundary evidence is incomplete"));
    }
    let child_plan = admission_object(&row, "child_plan", false)?;
    let repository_id =
        RepositoryId::from_uuid(row.try_get("repository_id").map_err(operation_error)?);
    if repository_id.as_uuid().is_nil() {
        return Err(corrupt("reusable repository ID is invalid"));
    }
    transaction.commit().await.map_err(operation_error)?;
    Ok(Some(ReadyReusableWorkflowCall::new(
        repository_id,
        preparation,
        child_invocation_id,
        child_plan,
        inputs,
        secrets,
        permissions,
    )))
}

pub(super) async fn load_published_permission_snapshot(
    store: &PostgresStore,
    tenant: &TenantScope,
    run_id: automata_ci_core::RunId,
    invocation_id: LogicalWorkflowInvocationId,
) -> Result<Option<ReusableWorkflowPermissionSnapshot>, ReusableWorkflowRuntimeStoreError> {
    let mut transaction = store.pool.begin().await.map_err(operation_error)?;
    let row = sqlx::query(
        r"
        SELECT permissions.default_level, permissions.permission_digest,
               expansion.permission_grant_count
        FROM workflow_plan_v2_reusable_permission_snapshots AS permissions
        JOIN workflow_plan_v2_reusable_invocation_expansions AS expansion
          ON expansion.run_id = permissions.run_id
         AND expansion.invocation_id = permissions.invocation_id
        JOIN workflow_plan_v2_reusable_call_publications AS publication
          ON publication.run_id = expansion.run_id
         AND publication.child_invocation_id = expansion.invocation_id
         AND publication.permission_digest = permissions.permission_digest
         AND publication.child_graph_sealed_at_ms = publication.published_at_ms
        JOIN workflow_runs AS run ON run.id = publication.run_id
        JOIN repositories AS repository
          ON repository.id = run.repository_id
         AND repository.tenant_id = publication.tenant_id
         AND repository.id = publication.repository_id
        JOIN workflow_plan_v2_runs AS marker ON marker.run_id = run.id
        WHERE repository.tenant_id = $1
          AND run.id = $2
          AND expansion.invocation_id = $3
          AND publication.condition_matched
          AND marker.state IN ('pending', 'active')
          AND run.status IN ('queued', 'in_progress')
          AND automata_workflow_plan_v2_invocation_published(run.id, $3)
        FOR SHARE OF permissions, publication, run, marker
        ",
    )
    .bind(tenant.as_str())
    .bind(run_id.as_uuid())
    .bind(invocation_id.as_uuid())
    .fetch_optional(&mut *transaction)
    .await
    .map_err(operation_error)?;
    let Some(row) = row else {
        transaction.commit().await.map_err(operation_error)?;
        return Ok(None);
    };
    let snapshot = load_permission_snapshot(&mut transaction, run_id, invocation_id, &row).await?;
    if usize::try_from(
        row.try_get::<i32, _>("permission_grant_count")
            .map_err(operation_error)?,
    )
    .ok()
        != Some(snapshot.grants().len())
    {
        return Err(corrupt("reusable permission snapshot is incomplete"));
    }
    transaction.commit().await.map_err(operation_error)?;
    Ok(Some(snapshot))
}

fn map_preparation_error(
    error: LogicalActivationPreparationStoreError,
) -> ReusableWorkflowRuntimeStoreError {
    match error {
        LogicalActivationPreparationStoreError::Store(error) => error.into(),
        _ => corrupt("reusable call preparation evidence is invalid"),
    }
}

async fn load_call_inputs(
    transaction: &mut Transaction<'_, Postgres>,
    run_id: automata_ci_core::RunId,
    invocation_id: LogicalWorkflowInvocationId,
) -> Result<Vec<ReusableWorkflowInputBindingEvidence>, ReusableWorkflowRuntimeStoreError> {
    sqlx::query(
        r"
        SELECT input_key, input_type, binding_kind, value_digest
        FROM workflow_plan_v2_reusable_input_bindings
        WHERE run_id = $1 AND invocation_id = $2
        ORDER BY source_order
        ",
    )
    .bind(run_id.as_uuid())
    .bind(invocation_id.as_uuid())
    .fetch_all(&mut **transaction)
    .await
    .map_err(operation_error)?
    .into_iter()
    .map(|row| {
        let digest = row
            .try_get::<Option<Vec<u8>>, _>("value_digest")
            .map_err(operation_error)?
            .map(|value| decode_digest(&value))
            .transpose()?;
        Ok(ReusableWorkflowInputBindingEvidence::new(
            row.try_get::<String, _>("input_key")
                .map_err(operation_error)?,
            parse_input_type(
                &row.try_get::<String, _>("input_type")
                    .map_err(operation_error)?,
            )?,
            parse_input_kind(
                &row.try_get::<String, _>("binding_kind")
                    .map_err(operation_error)?,
            )?,
            digest,
        ))
    })
    .collect()
}

async fn load_call_secrets(
    transaction: &mut Transaction<'_, Postgres>,
    run_id: automata_ci_core::RunId,
    invocation_id: LogicalWorkflowInvocationId,
) -> Result<Vec<ReusableWorkflowSecretBindingEvidence>, ReusableWorkflowRuntimeStoreError> {
    sqlx::query(
        r"
        SELECT target_name, source_name
        FROM workflow_plan_v2_reusable_secret_bindings
        WHERE run_id = $1 AND invocation_id = $2
        ORDER BY source_order
        ",
    )
    .bind(run_id.as_uuid())
    .bind(invocation_id.as_uuid())
    .fetch_all(&mut **transaction)
    .await
    .map_err(operation_error)?
    .into_iter()
    .map(|row| {
        Ok(ReusableWorkflowSecretBindingEvidence::new(
            row.try_get::<String, _>("target_name")
                .map_err(operation_error)?,
            row.try_get::<String, _>("source_name")
                .map_err(operation_error)?,
        ))
    })
    .collect()
}

async fn load_permission_snapshot(
    transaction: &mut Transaction<'_, Postgres>,
    run_id: automata_ci_core::RunId,
    invocation_id: LogicalWorkflowInvocationId,
    snapshot: &PgRow,
) -> Result<ReusableWorkflowPermissionSnapshot, ReusableWorkflowRuntimeStoreError> {
    let rows = sqlx::query(
        r#"
        SELECT permission_name, permission_level
        FROM workflow_plan_v2_reusable_permission_grants
        WHERE run_id = $1 AND invocation_id = $2
        ORDER BY permission_name COLLATE "C"
        "#,
    )
    .bind(run_id.as_uuid())
    .bind(invocation_id.as_uuid())
    .fetch_all(&mut **transaction)
    .await
    .map_err(operation_error)?;
    let mut grants = BTreeMap::new();
    for row in rows {
        let name: String = row.try_get("permission_name").map_err(operation_error)?;
        let level = parse_permission_level(
            &row.try_get::<String, _>("permission_level")
                .map_err(operation_error)?,
        )?;
        if grants.insert(name, level).is_some() {
            return Err(corrupt("reusable permission grant is duplicated"));
        }
    }
    Ok(ReusableWorkflowPermissionSnapshot::new(
        parse_permission_level(
            &snapshot
                .try_get::<String, _>("default_level")
                .map_err(operation_error)?,
        )?,
        grants,
        digest_column(snapshot, "permission_digest")?,
    ))
}

async fn load_next_completion(
    store: &PostgresStore,
) -> Result<Option<ReadyReusableWorkflowCompletion>, ReusableWorkflowRuntimeStoreError> {
    let mut transaction = store.pool.begin().await.map_err(operation_error)?;
    let row = sqlx::query(NEXT_REUSABLE_COMPLETION_SQL)
        .fetch_optional(&mut *transaction)
        .await
        .map_err(operation_error)?;
    let Some(row) = row else {
        transaction.commit().await.map_err(operation_error)?;
        return Ok(None);
    };
    let tenant = TenantScope::from_authenticated_tenant_id(
        row.try_get::<String, _>("tenant_id")
            .map_err(operation_error)?,
    )
    .map_err(|_| corrupt("reusable completion tenant is invalid"))?;
    let repository_id =
        RepositoryId::from_uuid(row.try_get("repository_id").map_err(operation_error)?);
    let run_id =
        automata_ci_core::RunId::from_uuid(row.try_get("run_id").map_err(operation_error)?);
    let parent_invocation_id = LogicalWorkflowInvocationId::from_uuid(
        row.try_get("parent_invocation_id")
            .map_err(operation_error)?,
    )
    .map_err(|_| corrupt("reusable completion parent invocation is invalid"))?;
    let caller_logical_job_id = LogicalWorkflowJobId::from_uuid(
        row.try_get("caller_logical_job_id")
            .map_err(operation_error)?,
    )
    .map_err(|_| corrupt("reusable completion caller job is invalid"))?;
    let child_invocation_id = LogicalWorkflowInvocationId::from_uuid(
        row.try_get("child_invocation_id")
            .map_err(operation_error)?,
    )
    .map_err(|_| corrupt("reusable completion child invocation is invalid"))?;
    let operation_id = ReusableWorkflowOperationId::from_uuid(
        row.try_get("operation_id").map_err(operation_error)?,
    )
    .map_err(|_| corrupt("reusable publication operation is invalid"))?;
    let revision = WorkflowRuntimePolicyRevision::new(
        u64::try_from(
            row.try_get::<i64, _>("runtime_policy_revision")
                .map_err(operation_error)?,
        )
        .map_err(|_| corrupt("reusable runtime policy revision is invalid"))?,
    )
    .map_err(|_| corrupt("reusable runtime policy revision is invalid"))?;
    let pin = WorkflowRuntimePolicyPin::new(
        tenant.clone(),
        repository_id,
        revision,
        digest_column(&row, "runtime_policy_digest")?,
    );
    let mappings = load_output_mappings(&mut transaction, run_id, child_invocation_id).await?;
    let publication = PublishReusableWorkflowCall::new(
        tenant,
        repository_id,
        run_id,
        parent_invocation_id,
        caller_logical_job_id,
        child_invocation_id,
        operation_id,
        digest_column(&row, "activation_input_digest")?,
        row.try_get("condition_matched").map_err(operation_error)?,
        digest_column(&row, "matrix_digest")?,
        admission_object(&row, "runtime_context", false)?,
        digest_column(&row, "permission_digest")?,
        mappings,
        pin,
        UnixMillis::new(row.try_get("published_at_ms").map_err(operation_error)?),
    )
    .map_err(|_| corrupt("reusable publication could not be reconstructed"))?;
    if !publication_row_matches(&row, &publication)?
        || !output_contract_matches(&mut transaction, &publication).await?
    {
        return Err(corrupt(
            "reusable publication replay evidence is inconsistent",
        ));
    }
    let outputs = load_completion_outputs(&mut transaction, &publication).await?;
    let child_plan = admission_object(&row, "child_plan", false)?;
    let ready_at = UnixMillis::new(row.try_get("ready_at_ms").map_err(operation_error)?);
    transaction.commit().await.map_err(operation_error)?;
    Ok(Some(ReadyReusableWorkflowCompletion::new(
        publication,
        child_plan,
        outputs,
        ready_at,
    )))
}

async fn load_output_mappings(
    transaction: &mut Transaction<'_, Postgres>,
    run_id: automata_ci_core::RunId,
    child_invocation_id: LogicalWorkflowInvocationId,
) -> Result<Vec<ReusableCallOutputMapping>, ReusableWorkflowRuntimeStoreError> {
    sqlx::query(
        r"
        SELECT parent_output_name, child_output_name, sensitivity
        FROM workflow_plan_v2_reusable_call_output_mappings
        WHERE run_id = $1 AND child_invocation_id = $2
        ORDER BY source_order
        ",
    )
    .bind(run_id.as_uuid())
    .bind(child_invocation_id.as_uuid())
    .fetch_all(&mut **transaction)
    .await
    .map_err(operation_error)?
    .into_iter()
    .map(|row| {
        Ok(ReusableCallOutputMapping::new(
            WorkflowOutputKey::new(
                row.try_get::<String, _>("parent_output_name")
                    .map_err(operation_error)?,
            )
            .map_err(|_| corrupt("reusable parent output name is invalid"))?,
            WorkflowOutputKey::new(
                row.try_get::<String, _>("child_output_name")
                    .map_err(operation_error)?,
            )
            .map_err(|_| corrupt("reusable child output name is invalid"))?,
            parse_sensitivity(
                &row.try_get::<String, _>("sensitivity")
                    .map_err(operation_error)?,
            )?,
        ))
    })
    .collect()
}

async fn load_completion_outputs(
    transaction: &mut Transaction<'_, Postgres>,
    publication: &PublishReusableWorkflowCall,
) -> Result<Vec<ReusableWorkflowResultOutput>, ReusableWorkflowRuntimeStoreError> {
    if !publication.condition_matched() {
        return Ok(Vec::new());
    }
    sqlx::query(
        r#"
        SELECT child_job.logical_key, output.output_name,
               output.sensitivity, output.public_value
        FROM workflow_plan_v2_jobs AS child_job
        JOIN workflow_plan_v2_job_results AS result
          ON result.run_id = child_job.run_id
         AND result.invocation_id = child_job.invocation_id
         AND result.logical_job_id = child_job.id
        JOIN workflow_plan_v2_job_result_claims AS claim
          ON claim.logical_job_id = result.logical_job_id
         AND claim.state = 'finalized'
        JOIN workflow_plan_v2_job_result_outputs AS output
          ON output.logical_job_id = result.logical_job_id
        WHERE child_job.run_id = $1 AND child_job.invocation_id = $2
        ORDER BY child_job.source_order, output.output_name COLLATE "C"
        "#,
    )
    .bind(publication.run_id().as_uuid())
    .bind(publication.child_invocation_id().as_uuid())
    .fetch_all(&mut **transaction)
    .await
    .map_err(operation_error)?
    .into_iter()
    .map(|row| {
        let sensitivity = parse_sensitivity(
            &row.try_get::<String, _>("sensitivity")
                .map_err(operation_error)?,
        )?;
        let public_value: Option<String> = row.try_get("public_value").map_err(operation_error)?;
        if (sensitivity == OutputSensitivity::Public) != public_value.is_some() {
            return Err(corrupt("reusable child output sensitivity is inconsistent"));
        }
        Ok(ReusableWorkflowResultOutput::new(
            WorkflowJobKey::new(
                row.try_get::<String, _>("logical_key")
                    .map_err(operation_error)?,
            )
            .map_err(|_| corrupt("reusable child job key is invalid"))?,
            WorkflowOutputKey::new(
                row.try_get::<String, _>("output_name")
                    .map_err(operation_error)?,
            )
            .map_err(|_| corrupt("reusable child output key is invalid"))?,
            sensitivity,
            public_value,
        ))
    })
    .collect()
}

fn admission_object(
    row: &PgRow,
    prefix: &str,
    event: bool,
) -> Result<AdmissionObject, ReusableWorkflowRuntimeStoreError> {
    let digest_column_name = format!("{prefix}_digest");
    let object_key_column = format!("{prefix}_object_key");
    let size_column = format!("{prefix}_size_bytes");
    let media_type_column = format!("{prefix}_media_type");
    let digest = digest_column(row, &digest_column_name)?;
    let key = ObjectKey::new(
        row.try_get::<String, _>(object_key_column.as_str())
            .map_err(operation_error)?,
    )
    .map_err(|_| corrupt("reusable object key is invalid"))?;
    let size = u64::try_from(
        row.try_get::<i64, _>(size_column.as_str())
            .map_err(operation_error)?,
    )
    .map_err(|_| corrupt("reusable object size is invalid"))?;
    let media_type: String = row
        .try_get(media_type_column.as_str())
        .map_err(operation_error)?;
    let object = if event {
        AdmissionObject::new_event(digest, key, size, media_type)
    } else {
        AdmissionObject::new(digest, key, size, media_type)
    };
    object.map_err(|_| corrupt("reusable object descriptor is invalid"))
}

fn parse_input_type(value: &str) -> Result<InvocationInputType, ReusableWorkflowRuntimeStoreError> {
    match value {
        "boolean" => Ok(InvocationInputType::Boolean),
        "number" => Ok(InvocationInputType::Number),
        "string" => Ok(InvocationInputType::String),
        _ => Err(corrupt("reusable input type is invalid")),
    }
}

fn parse_input_kind(
    value: &str,
) -> Result<AdmittedReusableInputKind, ReusableWorkflowRuntimeStoreError> {
    match value {
        "caller" => Ok(AdmittedReusableInputKind::Caller),
        "default" => Ok(AdmittedReusableInputKind::Default),
        "implicit_default" => Ok(AdmittedReusableInputKind::ImplicitDefault),
        _ => Err(corrupt("reusable input binding kind is invalid")),
    }
}

fn parse_permission_level(
    value: &str,
) -> Result<PermissionLevel, ReusableWorkflowRuntimeStoreError> {
    match value {
        "none" => Ok(PermissionLevel::None),
        "read" => Ok(PermissionLevel::Read),
        "write" => Ok(PermissionLevel::Write),
        _ => Err(corrupt("reusable permission level is invalid")),
    }
}

fn parse_sensitivity(value: &str) -> Result<OutputSensitivity, ReusableWorkflowRuntimeStoreError> {
    match value {
        "public" => Ok(OutputSensitivity::Public),
        "secret_derived" => Ok(OutputSensitivity::SecretDerived),
        _ => Err(corrupt("reusable output sensitivity is invalid")),
    }
}

async fn lock_publication_replay(
    transaction: &mut Transaction<'_, Postgres>,
    request: &PublishReusableWorkflowCall,
) -> Result<Option<PgRow>, ReusableWorkflowRuntimeStoreError> {
    sqlx::query(
        r"
        SELECT tenant_id, repository_id, caller_instance_id,
               child_invocation_id, operation_id, activation_input_digest,
               condition_matched, matrix_digest, runtime_context_digest,
               runtime_context_object_key, runtime_context_size_bytes,
               permission_digest, output_mapping_count, output_mapping_digest,
               publication_digest, runtime_policy_revision,
               runtime_policy_digest, authority_profile, published_at_ms,
               child_graph_sealed_at_ms
        FROM workflow_plan_v2_reusable_call_publications
        WHERE run_id = $1
          AND parent_invocation_id = $2
          AND caller_logical_job_id = $3
        FOR UPDATE
        ",
    )
    .bind(request.run_id().as_uuid())
    .bind(request.parent_invocation_id().as_uuid())
    .bind(request.caller_logical_job_id().as_uuid())
    .fetch_optional(&mut **transaction)
    .await
    .map_err(operation_error)
}

fn publication_row_matches(
    row: &PgRow,
    request: &PublishReusableWorkflowCall,
) -> Result<bool, ReusableWorkflowRuntimeStoreError> {
    let context_size = i64::try_from(request.runtime_context().encoded_size())
        .map_err(|_| corrupt("runtime context size is not representable"))?;
    let mapping_count = i32::try_from(request.output_mappings().len())
        .map_err(|_| corrupt("output mapping count is not representable"))?;
    Ok(row
        .try_get::<String, _>("tenant_id")
        .map_err(operation_error)?
        == request.tenant().as_str()
        && row
            .try_get::<uuid::Uuid, _>("repository_id")
            .map_err(operation_error)?
            == request.repository_id().as_uuid()
        && row
            .try_get::<uuid::Uuid, _>("caller_instance_id")
            .map_err(operation_error)?
            == request.caller_instance_id()
        && row
            .try_get::<uuid::Uuid, _>("child_invocation_id")
            .map_err(operation_error)?
            == request.child_invocation_id().as_uuid()
        && row
            .try_get::<uuid::Uuid, _>("operation_id")
            .map_err(operation_error)?
            == request.operation_id().as_uuid()
        && digest_column(row, "activation_input_digest")? == request.activation_input_digest()
        && row
            .try_get::<bool, _>("condition_matched")
            .map_err(operation_error)?
            == request.condition_matched()
        && digest_column(row, "matrix_digest")? == request.matrix_digest()
        && digest_column(row, "runtime_context_digest")? == request.runtime_context().digest()
        && row
            .try_get::<String, _>("runtime_context_object_key")
            .map_err(operation_error)?
            == request.runtime_context().object_key().as_str()
        && row
            .try_get::<i64, _>("runtime_context_size_bytes")
            .map_err(operation_error)?
            == context_size
        && digest_column(row, "permission_digest")? == request.permission_digest()
        && row
            .try_get::<i32, _>("output_mapping_count")
            .map_err(operation_error)?
            == mapping_count
        && digest_column(row, "output_mapping_digest")? == request.output_mapping_digest()
        && digest_column(row, "publication_digest")? == request.publication_digest()
        && row
            .try_get::<i64, _>("runtime_policy_revision")
            .map_err(operation_error)?
            == request.runtime_policy().revision().as_i64()
        && digest_column(row, "runtime_policy_digest")? == request.runtime_policy().digest()
        && row
            .try_get::<String, _>("authority_profile")
            .map_err(operation_error)?
            == "credential_free"
        && row
            .try_get::<i64, _>("published_at_ms")
            .map_err(operation_error)?
            == request.published_at().get()
        && row
            .try_get::<Option<i64>, _>("child_graph_sealed_at_ms")
            .map_err(operation_error)?
            == Some(request.published_at().get()))
}

async fn bind_output_contract(
    transaction: &mut Transaction<'_, Postgres>,
    request: &PublishReusableWorkflowCall,
) -> Result<(), ReusableWorkflowRuntimeStoreError> {
    let count = i32::try_from(request.output_mappings().len())
        .map_err(|_| corrupt("output mapping count is not representable"))?;
    let inserted = sqlx::query(
        r"
        INSERT INTO workflow_plan_v2_reusable_call_output_contracts (
            run_id, child_invocation_id, mapping_count, mapping_digest,
            bound_at_ms
        ) VALUES ($1, $2, $3, $4, $5)
        ON CONFLICT (run_id, child_invocation_id) DO NOTHING
        ",
    )
    .bind(request.run_id().as_uuid())
    .bind(request.child_invocation_id().as_uuid())
    .bind(count)
    .bind(request.output_mapping_digest().as_bytes().as_slice())
    .bind(request.published_at().get())
    .execute(&mut **transaction)
    .await
    .map_err(classify_publication_error)?
    .rows_affected();

    if inserted == 1 {
        for (source_order, mapping) in request.output_mappings().iter().enumerate() {
            insert_output_mapping(transaction, request, mapping, source_order).await?;
        }
        return Ok(());
    }
    if output_contract_matches(transaction, request).await? {
        Ok(())
    } else {
        Err(ReusableWorkflowRuntimeStoreError::Conflict)
    }
}

async fn insert_output_mapping(
    transaction: &mut Transaction<'_, Postgres>,
    request: &PublishReusableWorkflowCall,
    mapping: &ReusableCallOutputMapping,
    source_order: usize,
) -> Result<(), ReusableWorkflowRuntimeStoreError> {
    let source_order = i32::try_from(source_order)
        .map_err(|_| corrupt("output mapping order is not representable"))?;
    sqlx::query(
        r"
        INSERT INTO workflow_plan_v2_reusable_call_output_mappings (
            run_id, child_invocation_id, parent_output_name,
            child_output_name, sensitivity, source_order
        ) VALUES ($1, $2, $3, $4, $5, $6)
        ",
    )
    .bind(request.run_id().as_uuid())
    .bind(request.child_invocation_id().as_uuid())
    .bind(mapping.parent_name().as_str())
    .bind(mapping.callee_name().as_str())
    .bind(sensitivity_name(mapping.sensitivity()))
    .bind(source_order)
    .execute(&mut **transaction)
    .await
    .map_err(classify_publication_error)?;
    Ok(())
}

async fn output_contract_matches(
    transaction: &mut Transaction<'_, Postgres>,
    request: &PublishReusableWorkflowCall,
) -> Result<bool, ReusableWorkflowRuntimeStoreError> {
    let row = sqlx::query(
        r"
        SELECT mapping_count, mapping_digest, bound_at_ms
        FROM workflow_plan_v2_reusable_call_output_contracts
        WHERE run_id = $1 AND child_invocation_id = $2
        ",
    )
    .bind(request.run_id().as_uuid())
    .bind(request.child_invocation_id().as_uuid())
    .fetch_optional(&mut **transaction)
    .await
    .map_err(operation_error)?;
    let Some(row) = row else {
        return Ok(false);
    };
    let count = i32::try_from(request.output_mappings().len())
        .map_err(|_| corrupt("output mapping count is not representable"))?;
    if row
        .try_get::<i32, _>("mapping_count")
        .map_err(operation_error)?
        != count
        || digest_column(&row, "mapping_digest")? != request.output_mapping_digest()
        || row
            .try_get::<i64, _>("bound_at_ms")
            .map_err(operation_error)?
            != request.published_at().get()
    {
        return Ok(false);
    }
    let rows = sqlx::query(
        r"
        SELECT parent_output_name, child_output_name, sensitivity, source_order
        FROM workflow_plan_v2_reusable_call_output_mappings
        WHERE run_id = $1 AND child_invocation_id = $2
        ORDER BY source_order
        ",
    )
    .bind(request.run_id().as_uuid())
    .bind(request.child_invocation_id().as_uuid())
    .fetch_all(&mut **transaction)
    .await
    .map_err(operation_error)?;
    if rows.len() != request.output_mappings().len() {
        return Ok(false);
    }
    rows.iter()
        .zip(request.output_mappings())
        .enumerate()
        .try_fold(true, |exact, (index, (row, mapping))| {
            let source_order = i32::try_from(index)
                .map_err(|_| corrupt("output mapping order is not representable"))?;
            Ok(exact
                && row
                    .try_get::<String, _>("parent_output_name")
                    .map_err(operation_error)?
                    == mapping.parent_name().as_str()
                && row
                    .try_get::<String, _>("child_output_name")
                    .map_err(operation_error)?
                    == mapping.callee_name().as_str()
                && row
                    .try_get::<String, _>("sensitivity")
                    .map_err(operation_error)?
                    == sensitivity_name(mapping.sensitivity())
                && row
                    .try_get::<i32, _>("source_order")
                    .map_err(operation_error)?
                    == source_order)
        })
}

async fn insert_publication(
    transaction: &mut Transaction<'_, Postgres>,
    request: &PublishReusableWorkflowCall,
) -> Result<(), ReusableWorkflowRuntimeStoreError> {
    let context_size = i64::try_from(request.runtime_context().encoded_size())
        .map_err(|_| corrupt("runtime context size is not representable"))?;
    let mapping_count = i32::try_from(request.output_mappings().len())
        .map_err(|_| corrupt("output mapping count is not representable"))?;
    sqlx::query(
        r"
        INSERT INTO workflow_plan_v2_reusable_call_publications (
            tenant_id, repository_id, run_id, parent_invocation_id,
            caller_logical_job_id, caller_instance_id, child_invocation_id,
            operation_id, activation_generation, activation_input_digest,
            condition_matched, matrix_digest, runtime_context_digest,
            runtime_context_object_key, runtime_context_size_bytes,
            runtime_context_media_type, runtime_context_schema,
            permission_digest, output_mapping_count, output_mapping_digest,
            publication_digest, runtime_policy_revision, runtime_policy_digest,
            authority_profile, published_at_ms, child_graph_sealed_at_ms
        ) VALUES (
            $1, $2, $3, $4, $5, $6, $7, $8, 1, $9, $10, $11, $12,
            $13, $14,
            'application/vnd.automata.job-runtime-context.protobuf', 2,
            $15, $16, $17, $18, $19, $20, 'credential_free', $21, NULL
        )
        ",
    )
    .bind(request.tenant().as_str())
    .bind(request.repository_id().as_uuid())
    .bind(request.run_id().as_uuid())
    .bind(request.parent_invocation_id().as_uuid())
    .bind(request.caller_logical_job_id().as_uuid())
    .bind(request.caller_instance_id())
    .bind(request.child_invocation_id().as_uuid())
    .bind(request.operation_id().as_uuid())
    .bind(request.activation_input_digest().as_bytes().as_slice())
    .bind(request.condition_matched())
    .bind(request.matrix_digest().as_bytes().as_slice())
    .bind(request.runtime_context().digest().as_bytes().as_slice())
    .bind(request.runtime_context().object_key().as_str())
    .bind(context_size)
    .bind(request.permission_digest().as_bytes().as_slice())
    .bind(mapping_count)
    .bind(request.output_mapping_digest().as_bytes().as_slice())
    .bind(request.publication_digest().as_bytes().as_slice())
    .bind(request.runtime_policy().revision().as_i64())
    .bind(request.runtime_policy().digest().as_bytes().as_slice())
    .bind(request.published_at().get())
    .execute(&mut **transaction)
    .await
    .map_err(classify_publication_error)?;
    Ok(())
}

async fn publish_child_graph(
    transaction: &mut Transaction<'_, Postgres>,
    request: &PublishReusableWorkflowCall,
) -> Result<(), ReusableWorkflowRuntimeStoreError> {
    let invocation_rows = sqlx::query(
        r"
        INSERT INTO workflow_plan_v2_invocations (
            id, run_id, plan_digest, plan_object_key, plan_size_bytes,
            plan_media_type, plan_schema, state, revision, created_at_ms,
            updated_at_ms, invocation_kind
        )
        SELECT expansion.invocation_id, expansion.run_id, catalog.plan_digest,
               catalog.plan_object_key, catalog.plan_size_bytes,
               catalog.plan_media_type, catalog.plan_schema, 'active', 1,
               $3, $3, 'reusable'
        FROM workflow_plan_v2_reusable_invocation_expansions AS expansion
        JOIN workflow_plan_v2_reusable_workflow_catalog AS catalog
          ON catalog.run_id = expansion.run_id
         AND catalog.catalog_entry_id = expansion.catalog_entry_id
        WHERE expansion.run_id = $1
          AND expansion.invocation_id = $2
          AND expansion.depth > 0
        ",
    )
    .bind(request.run_id().as_uuid())
    .bind(request.child_invocation_id().as_uuid())
    .bind(request.published_at().get())
    .execute(&mut **transaction)
    .await
    .map_err(classify_publication_error)?
    .rows_affected();
    if invocation_rows != 1 {
        return Err(ReusableWorkflowRuntimeStoreError::NotReady);
    }

    let jobs = sqlx::query(
        r"
        INSERT INTO workflow_plan_v2_jobs (
            id, run_id, invocation_id, logical_key, source_order,
            execution_kind, state, activation_fence, created_at_ms,
            updated_at_ms, runtime_policy_revision, runtime_policy_digest,
            environment_requirement_kind, environment_template_digest,
            secret_reference_names, variable_reference_names,
            credential_requirements_schema
        )
        SELECT planned.logical_job_id, planned.run_id, planned.invocation_id,
               planned.logical_key, planned.source_order,
               planned.execution_kind, 'pending', 0, $3, $3, $4, $5,
               planned.environment_requirement_kind,
               planned.environment_template_digest,
               planned.secret_reference_names,
               planned.variable_reference_names,
               planned.credential_requirements_schema
        FROM workflow_plan_v2_reusable_expanded_jobs AS planned
        WHERE planned.run_id = $1 AND planned.invocation_id = $2
        ORDER BY planned.source_order
        ",
    )
    .bind(request.run_id().as_uuid())
    .bind(request.child_invocation_id().as_uuid())
    .bind(request.published_at().get())
    .bind(request.runtime_policy().revision().as_i64())
    .bind(request.runtime_policy().digest().as_bytes().as_slice())
    .execute(&mut **transaction)
    .await
    .map_err(classify_publication_error)?
    .rows_affected();
    if jobs == 0 {
        return Err(ReusableWorkflowRuntimeStoreError::NotReady);
    }

    sqlx::query(
        r"
        INSERT INTO workflow_plan_v2_dependencies (
            run_id, invocation_id, logical_job_id, prerequisite_job_id
        )
        SELECT run_id, invocation_id, logical_job_id, prerequisite_job_id
        FROM workflow_plan_v2_reusable_expanded_dependencies
        WHERE run_id = $1 AND invocation_id = $2
        ",
    )
    .bind(request.run_id().as_uuid())
    .bind(request.child_invocation_id().as_uuid())
    .execute(&mut **transaction)
    .await
    .map_err(classify_publication_error)?;
    Ok(())
}

async fn seal_publication(
    transaction: &mut Transaction<'_, Postgres>,
    request: &PublishReusableWorkflowCall,
) -> Result<(), ReusableWorkflowRuntimeStoreError> {
    let rows = sqlx::query(
        r"
        UPDATE workflow_plan_v2_reusable_call_publications
        SET child_graph_sealed_at_ms = published_at_ms
        WHERE run_id = $1
          AND parent_invocation_id = $2
          AND caller_logical_job_id = $3
          AND operation_id = $4
          AND publication_digest = $5
          AND child_graph_sealed_at_ms IS NULL
        ",
    )
    .bind(request.run_id().as_uuid())
    .bind(request.parent_invocation_id().as_uuid())
    .bind(request.caller_logical_job_id().as_uuid())
    .bind(request.operation_id().as_uuid())
    .bind(request.publication_digest().as_bytes().as_slice())
    .execute(&mut **transaction)
    .await
    .map_err(classify_publication_error)?
    .rows_affected();
    if rows == 1 {
        Ok(())
    } else {
        Err(ReusableWorkflowRuntimeStoreError::Conflict)
    }
}

async fn activate_parent_call(
    transaction: &mut Transaction<'_, Postgres>,
    request: &PublishReusableWorkflowCall,
) -> Result<(), ReusableWorkflowRuntimeStoreError> {
    let state = if request.condition_matched() {
        "activated"
    } else {
        "skipped"
    };
    let rows = sqlx::query(
        r"
        UPDATE workflow_plan_v2_jobs
        SET state = $4,
            activation_fence = 1,
            activation_input_digest = $5,
            authority_profile = 'credential_free',
            updated_at_ms = $6
        WHERE run_id = $1
          AND invocation_id = $2
          AND id = $3
          AND execution_kind = 'reusable_workflow'
          AND state = 'pending'
          AND activation_fence = 0
          AND activation_owner_id IS NULL
          AND activation_claimed_at_ms IS NULL
          AND activation_expires_at_ms IS NULL
          AND activation_input_digest IS NULL
          AND authority_profile IS NULL
          AND activation_origin_selection_id IS NULL
        ",
    )
    .bind(request.run_id().as_uuid())
    .bind(request.parent_invocation_id().as_uuid())
    .bind(request.caller_logical_job_id().as_uuid())
    .bind(state)
    .bind(request.activation_input_digest().as_bytes().as_slice())
    .bind(request.published_at().get())
    .execute(&mut **transaction)
    .await
    .map_err(classify_publication_error)?
    .rows_affected();
    if rows == 1 {
        Ok(())
    } else {
        Err(ReusableWorkflowRuntimeStoreError::NotReady)
    }
}

async fn complete_call(
    store: &PostgresStore,
    request: CompleteReusableWorkflowCall,
) -> Result<ReusableWorkflowCompletionReceipt, ReusableWorkflowRuntimeStoreError> {
    let mut transaction = store.pool.begin().await.map_err(operation_error)?;
    let replay = sqlx::query(
        r"
        SELECT caller_instance_id, child_invocation_id,
               publication_operation_id, completion_operation_id,
               callee_plan_digest, workflow_output_evaluation_digest,
               outputs_digest, completed_at_ms, sealed_at_ms
        FROM workflow_plan_v2_reusable_call_results
        WHERE run_id = $1
          AND parent_invocation_id = $2
          AND caller_logical_job_id = $3
        FOR UPDATE
        ",
    )
    .bind(request.publication().run_id().as_uuid())
    .bind(request.publication().parent_invocation_id().as_uuid())
    .bind(request.publication().caller_logical_job_id().as_uuid())
    .fetch_optional(&mut *transaction)
    .await
    .map_err(operation_error)?;
    if let Some(row) = replay {
        let exact = row
            .try_get::<uuid::Uuid, _>("caller_instance_id")
            .map_err(operation_error)?
            == request.publication().caller_instance_id()
            && row
                .try_get::<uuid::Uuid, _>("child_invocation_id")
                .map_err(operation_error)?
                == request.publication().child_invocation_id().as_uuid()
            && row
                .try_get::<uuid::Uuid, _>("publication_operation_id")
                .map_err(operation_error)?
                == request.publication().operation_id().as_uuid()
            && row
                .try_get::<uuid::Uuid, _>("completion_operation_id")
                .map_err(operation_error)?
                == request.operation_id().as_uuid()
            && digest_column(&row, "callee_plan_digest")? == request.callee_plan_digest()
            && digest_column(&row, "workflow_output_evaluation_digest")?
                == request.workflow_output_evaluation_digest()
            && digest_column(&row, "outputs_digest")? == request.outputs_digest()
            && row
                .try_get::<i64, _>("completed_at_ms")
                .map_err(operation_error)?
                == request.completed_at().get()
            && row
                .try_get::<Option<i64>, _>("sealed_at_ms")
                .map_err(operation_error)?
                == Some(request.completed_at().get());
        transaction.commit().await.map_err(operation_error)?;
        return exact
            .then(|| ReusableWorkflowCompletionReceipt::new(&request, true))
            .ok_or(ReusableWorkflowRuntimeStoreError::Conflict);
    }

    let publication = lock_publication_replay(&mut transaction, request.publication())
        .await?
        .ok_or(ReusableWorkflowRuntimeStoreError::NotReady)?;
    if !publication_row_matches(&publication, request.publication())?
        || !output_contract_matches(&mut transaction, request.publication()).await?
    {
        return Err(ReusableWorkflowRuntimeStoreError::Conflict);
    }
    let context = load_completion_context(&mut transaction, &request).await?;
    let child_jobs = load_child_results(&mut transaction, &request, &context).await?;
    let prerequisites = load_parent_prerequisites(&mut transaction, &request).await?;
    let outputs = validate_and_map_outputs(&mut transaction, &request, &context).await?;
    let aggregate =
        CompletionAggregate::new(&request, &context, &child_jobs, &prerequisites, &outputs);

    insert_call_result(&mut transaction, &request, &context, &aggregate).await?;
    insert_call_result_jobs(&mut transaction, &request, &child_jobs).await?;
    insert_call_result_outputs(&mut transaction, &request).await?;
    seal_call_result(&mut transaction, &request).await?;
    complete_child_invocation(&mut transaction, &request, &context, &aggregate).await?;
    insert_parent_result(
        &mut transaction,
        &request,
        &context,
        &aggregate,
        &child_jobs,
        &prerequisites,
        &outputs,
    )
    .await?;
    transaction
        .commit()
        .await
        .map_err(classify_completion_error)?;
    Ok(ReusableWorkflowCompletionReceipt::new(&request, false))
}

#[derive(Debug)]
struct CompletionContext {
    condition_matched: bool,
    logical_key: String,
    source_order: i32,
    parent_plan_digest: Sha256Digest,
    parent_plan_object_key: String,
    parent_plan_size_bytes: i64,
    parent_plan_media_type: String,
    parent_plan_schema: i16,
    child_plan_digest: Sha256Digest,
    planned_child_job_count: usize,
    declared_output_count: usize,
}

#[derive(Debug)]
struct ChildResultEvidence {
    logical_job_id: uuid::Uuid,
    source_order: i32,
    descriptor_digest: Sha256Digest,
    outputs_digest: Sha256Digest,
    commit_digest: Sha256Digest,
    conclusion: String,
    closure_has_failure: bool,
    closure_has_cancelled: bool,
    closure_has_skipped: bool,
    finalized_at_ms: i64,
}

#[derive(Debug)]
struct PrerequisiteEvidence {
    logical_job_id: uuid::Uuid,
    source_order: i32,
    commit_digest: Sha256Digest,
    outputs_digest: Sha256Digest,
    conclusion: String,
    closure_has_failure: bool,
    closure_has_cancelled: bool,
    closure_has_skipped: bool,
}

#[derive(Debug)]
struct MappedParentOutput {
    name: String,
    sensitivity: OutputSensitivity,
    public_value: Option<String>,
}

#[derive(Debug)]
struct CompletionAggregate {
    conclusion: String,
    closure_has_failure: bool,
    closure_has_cancelled: bool,
    closure_has_skipped: bool,
    child_jobs_digest: Sha256Digest,
    call_descriptor_digest: Sha256Digest,
    call_commit_digest: Sha256Digest,
    parent_result_descriptor_digest: Sha256Digest,
    parent_instances_digest: Sha256Digest,
    parent_prerequisites_digest: Sha256Digest,
    parent_outputs_digest: Sha256Digest,
    parent_commit_digest: Sha256Digest,
}

impl CompletionAggregate {
    fn new(
        request: &CompleteReusableWorkflowCall,
        context: &CompletionContext,
        child_jobs: &[ChildResultEvidence],
        prerequisites: &[PrerequisiteEvidence],
        outputs: &[MappedParentOutput],
    ) -> Self {
        let conclusion = aggregate_conclusion(child_jobs, context.condition_matched).to_owned();
        let closure_has_failure = matches!(conclusion.as_str(), "failure" | "timed_out")
            || prerequisites
                .iter()
                .any(|evidence| evidence.closure_has_failure);
        let closure_has_cancelled = conclusion == "cancelled"
            || prerequisites
                .iter()
                .any(|evidence| evidence.closure_has_cancelled);
        let closure_has_skipped = conclusion == "skipped"
            || prerequisites
                .iter()
                .any(|evidence| evidence.closure_has_skipped);
        let child_jobs_digest = hash_child_jobs(child_jobs);
        let parent_prerequisites_digest = hash_prerequisites(prerequisites);
        let parent_outputs_digest = hash_parent_outputs(outputs);
        let call_descriptor_digest =
            hash_call_descriptor(request, context, child_jobs_digest, &conclusion);
        let call_commit_digest = hash_call_commit(
            request,
            call_descriptor_digest,
            request.outputs_digest(),
            &conclusion,
        );
        let parent_instances_digest = hash_parent_instances(
            request,
            context.condition_matched,
            call_descriptor_digest,
            request.outputs_digest(),
            call_commit_digest,
            &conclusion,
        );
        let parent_result_descriptor_digest = hash_parent_result_descriptor(
            request,
            context,
            parent_instances_digest,
            parent_prerequisites_digest,
        );
        let parent_commit_digest = hash_parent_commit(
            request,
            parent_result_descriptor_digest,
            parent_outputs_digest,
            &conclusion,
            closure_has_failure,
            closure_has_cancelled,
            closure_has_skipped,
        );
        Self {
            conclusion,
            closure_has_failure,
            closure_has_cancelled,
            closure_has_skipped,
            child_jobs_digest,
            call_descriptor_digest,
            call_commit_digest,
            parent_result_descriptor_digest,
            parent_instances_digest,
            parent_prerequisites_digest,
            parent_outputs_digest,
            parent_commit_digest,
        }
    }
}

async fn load_completion_context(
    transaction: &mut Transaction<'_, Postgres>,
    request: &CompleteReusableWorkflowCall,
) -> Result<CompletionContext, ReusableWorkflowRuntimeStoreError> {
    let publication = request.publication();
    let row = sqlx::query(
        r"
        SELECT call.condition_matched, caller.logical_key, caller.source_order,
               parent.plan_digest AS parent_plan_digest,
               parent.plan_object_key AS parent_plan_object_key,
               parent.plan_size_bytes AS parent_plan_size_bytes,
               parent.plan_media_type AS parent_plan_media_type,
               parent.plan_schema AS parent_plan_schema,
               catalog.plan_digest AS child_plan_digest,
               expansion.output_count AS declared_output_count,
               (SELECT count(*)
                FROM workflow_plan_v2_reusable_expanded_jobs AS planned_job
                WHERE planned_job.run_id = expansion.run_id
                  AND planned_job.invocation_id = expansion.invocation_id)
                   AS planned_child_job_count
        FROM workflow_plan_v2_reusable_call_publications AS call
        JOIN workflow_plan_v2_jobs AS caller
          ON caller.run_id = call.run_id
         AND caller.invocation_id = call.parent_invocation_id
         AND caller.id = call.caller_logical_job_id
        JOIN workflow_plan_v2_invocations AS parent
          ON parent.run_id = caller.run_id
         AND parent.id = caller.invocation_id
        JOIN workflow_plan_v2_reusable_invocation_expansions AS expansion
          ON expansion.run_id = call.run_id
         AND expansion.invocation_id = call.child_invocation_id
        JOIN workflow_plan_v2_reusable_workflow_catalog AS catalog
          ON catalog.run_id = expansion.run_id
         AND catalog.catalog_entry_id = expansion.catalog_entry_id
        WHERE call.run_id = $1
          AND call.parent_invocation_id = $2
          AND call.caller_logical_job_id = $3
          AND call.caller_instance_id = $4
          AND call.child_invocation_id = $5
          AND call.operation_id = $6
          AND call.publication_digest = $7
          AND call.child_graph_sealed_at_ms IS NOT NULL
          AND caller.execution_kind = 'reusable_workflow'
          AND caller.state = CASE WHEN call.condition_matched
              THEN 'activated' ELSE 'skipped' END
        FOR UPDATE OF call, caller, parent
        ",
    )
    .bind(publication.run_id().as_uuid())
    .bind(publication.parent_invocation_id().as_uuid())
    .bind(publication.caller_logical_job_id().as_uuid())
    .bind(publication.caller_instance_id())
    .bind(publication.child_invocation_id().as_uuid())
    .bind(publication.operation_id().as_uuid())
    .bind(publication.publication_digest().as_bytes().as_slice())
    .fetch_optional(&mut **transaction)
    .await
    .map_err(operation_error)?
    .ok_or(ReusableWorkflowRuntimeStoreError::NotReady)?;
    let planned_child_job_count: i64 = row
        .try_get("planned_child_job_count")
        .map_err(operation_error)?;
    let declared_output_count: i32 = row
        .try_get("declared_output_count")
        .map_err(operation_error)?;
    let context = CompletionContext {
        condition_matched: row.try_get("condition_matched").map_err(operation_error)?,
        logical_key: row.try_get("logical_key").map_err(operation_error)?,
        source_order: row.try_get("source_order").map_err(operation_error)?,
        parent_plan_digest: digest_column(&row, "parent_plan_digest")?,
        parent_plan_object_key: row
            .try_get("parent_plan_object_key")
            .map_err(operation_error)?,
        parent_plan_size_bytes: row
            .try_get("parent_plan_size_bytes")
            .map_err(operation_error)?,
        parent_plan_media_type: row
            .try_get("parent_plan_media_type")
            .map_err(operation_error)?,
        parent_plan_schema: row.try_get("parent_plan_schema").map_err(operation_error)?,
        child_plan_digest: digest_column(&row, "child_plan_digest")?,
        planned_child_job_count: usize::try_from(planned_child_job_count)
            .map_err(|_| corrupt("planned child job count is invalid"))?,
        declared_output_count: usize::try_from(declared_output_count)
            .map_err(|_| corrupt("declared output count is invalid"))?,
    };
    if context.child_plan_digest != request.callee_plan_digest() {
        return Err(ReusableWorkflowRuntimeStoreError::Conflict);
    }
    Ok(context)
}

async fn load_child_results(
    transaction: &mut Transaction<'_, Postgres>,
    request: &CompleteReusableWorkflowCall,
    context: &CompletionContext,
) -> Result<Vec<ChildResultEvidence>, ReusableWorkflowRuntimeStoreError> {
    if !context.condition_matched {
        return Ok(Vec::new());
    }
    let publication = request.publication();
    let rows = sqlx::query(
        r"
        SELECT child_job.id AS logical_job_id, child_job.source_order,
               child_result.descriptor_digest, child_result.outputs_digest,
               child_result.commit_digest, child_result.effective_conclusion,
               child_result.closure_has_failure,
               child_result.closure_has_cancelled,
               child_result.closure_has_skipped,
               child_result.finalized_at_ms
        FROM workflow_plan_v2_jobs AS child_job
        JOIN workflow_plan_v2_job_results AS child_result
          ON child_result.run_id = child_job.run_id
         AND child_result.invocation_id = child_job.invocation_id
         AND child_result.logical_job_id = child_job.id
        JOIN workflow_plan_v2_job_result_claims AS child_claim
          ON child_claim.logical_job_id = child_result.logical_job_id
         AND child_claim.state = 'finalized'
        WHERE child_job.run_id = $1
          AND child_job.invocation_id = $2
          AND child_result.finalized_at_ms <= $3
        ORDER BY child_job.source_order
        ",
    )
    .bind(publication.run_id().as_uuid())
    .bind(publication.child_invocation_id().as_uuid())
    .bind(request.completed_at().get())
    .fetch_all(&mut **transaction)
    .await
    .map_err(operation_error)?;
    if rows.len() != context.planned_child_job_count {
        return Err(ReusableWorkflowRuntimeStoreError::ChildResultsPending);
    }
    rows.into_iter()
        .map(|row| {
            let conclusion: String = row
                .try_get("effective_conclusion")
                .map_err(operation_error)?;
            validate_conclusion(&conclusion)?;
            Ok(ChildResultEvidence {
                logical_job_id: row.try_get("logical_job_id").map_err(operation_error)?,
                source_order: row.try_get("source_order").map_err(operation_error)?,
                descriptor_digest: digest_column(&row, "descriptor_digest")?,
                outputs_digest: digest_column(&row, "outputs_digest")?,
                commit_digest: digest_column(&row, "commit_digest")?,
                conclusion,
                closure_has_failure: row
                    .try_get("closure_has_failure")
                    .map_err(operation_error)?,
                closure_has_cancelled: row
                    .try_get("closure_has_cancelled")
                    .map_err(operation_error)?,
                closure_has_skipped: row
                    .try_get("closure_has_skipped")
                    .map_err(operation_error)?,
                finalized_at_ms: row.try_get("finalized_at_ms").map_err(operation_error)?,
            })
        })
        .collect()
}

async fn load_parent_prerequisites(
    transaction: &mut Transaction<'_, Postgres>,
    request: &CompleteReusableWorkflowCall,
) -> Result<Vec<PrerequisiteEvidence>, ReusableWorkflowRuntimeStoreError> {
    let publication = request.publication();
    let rows = sqlx::query(
        r"
        SELECT prerequisite_job.id AS logical_job_id,
               prerequisite_job.source_order, prerequisite.commit_digest,
               prerequisite.outputs_digest, prerequisite.effective_conclusion,
               prerequisite.closure_has_failure,
               prerequisite.closure_has_cancelled,
               prerequisite.closure_has_skipped
        FROM workflow_plan_v2_dependencies AS dependency
        JOIN workflow_plan_v2_jobs AS prerequisite_job
          ON prerequisite_job.run_id = dependency.run_id
         AND prerequisite_job.invocation_id = dependency.invocation_id
         AND prerequisite_job.id = dependency.prerequisite_job_id
        JOIN workflow_plan_v2_job_results AS prerequisite
          ON prerequisite.run_id = prerequisite_job.run_id
         AND prerequisite.invocation_id = prerequisite_job.invocation_id
         AND prerequisite.logical_job_id = prerequisite_job.id
        JOIN workflow_plan_v2_job_result_claims AS prerequisite_claim
          ON prerequisite_claim.logical_job_id = prerequisite.logical_job_id
         AND prerequisite_claim.state = 'finalized'
        WHERE dependency.run_id = $1
          AND dependency.invocation_id = $2
          AND dependency.logical_job_id = $3
        ORDER BY prerequisite_job.source_order
        ",
    )
    .bind(publication.run_id().as_uuid())
    .bind(publication.parent_invocation_id().as_uuid())
    .bind(publication.caller_logical_job_id().as_uuid())
    .fetch_all(&mut **transaction)
    .await
    .map_err(operation_error)?;
    let dependency_count: i64 = sqlx::query_scalar(
        r"
        SELECT count(*) FROM workflow_plan_v2_dependencies
        WHERE run_id = $1 AND invocation_id = $2 AND logical_job_id = $3
        ",
    )
    .bind(publication.run_id().as_uuid())
    .bind(publication.parent_invocation_id().as_uuid())
    .bind(publication.caller_logical_job_id().as_uuid())
    .fetch_one(&mut **transaction)
    .await
    .map_err(operation_error)?;
    if rows.len()
        != usize::try_from(dependency_count)
            .map_err(|_| corrupt("parent dependency count is invalid"))?
    {
        return Err(ReusableWorkflowRuntimeStoreError::NotReady);
    }
    rows.into_iter()
        .map(|row| {
            let conclusion: String = row
                .try_get("effective_conclusion")
                .map_err(operation_error)?;
            validate_conclusion(&conclusion)?;
            Ok(PrerequisiteEvidence {
                logical_job_id: row.try_get("logical_job_id").map_err(operation_error)?,
                source_order: row.try_get("source_order").map_err(operation_error)?,
                commit_digest: digest_column(&row, "commit_digest")?,
                outputs_digest: digest_column(&row, "outputs_digest")?,
                conclusion,
                closure_has_failure: row
                    .try_get("closure_has_failure")
                    .map_err(operation_error)?,
                closure_has_cancelled: row
                    .try_get("closure_has_cancelled")
                    .map_err(operation_error)?,
                closure_has_skipped: row
                    .try_get("closure_has_skipped")
                    .map_err(operation_error)?,
            })
        })
        .collect()
}

async fn validate_and_map_outputs(
    transaction: &mut Transaction<'_, Postgres>,
    request: &CompleteReusableWorkflowCall,
    context: &CompletionContext,
) -> Result<Vec<MappedParentOutput>, ReusableWorkflowRuntimeStoreError> {
    if !context.condition_matched {
        return request
            .outputs()
            .is_empty()
            .then(Vec::new)
            .ok_or(ReusableWorkflowRuntimeStoreError::Conflict);
    }
    if request.outputs().len() != context.declared_output_count {
        return Err(ReusableWorkflowRuntimeStoreError::Conflict);
    }
    let publication = request.publication();
    let declared = sqlx::query(
        r"
        SELECT output_key, sensitivity, source_order
        FROM workflow_plan_v2_reusable_outputs
        WHERE run_id = $1 AND invocation_id = $2
        ORDER BY source_order
        ",
    )
    .bind(publication.run_id().as_uuid())
    .bind(publication.child_invocation_id().as_uuid())
    .fetch_all(&mut **transaction)
    .await
    .map_err(operation_error)?;
    if declared.len() != request.outputs().len() {
        return Err(ReusableWorkflowRuntimeStoreError::Conflict);
    }
    for (index, (row, output)) in declared.iter().zip(request.outputs()).enumerate() {
        let name: String = row.try_get("output_key").map_err(operation_error)?;
        let sensitivity: String = row.try_get("sensitivity").map_err(operation_error)?;
        let source_order: i32 = row.try_get("source_order").map_err(operation_error)?;
        if name != output.name().as_str()
            || sensitivity != sensitivity_name(output.sensitivity())
            || source_order
                != i32::try_from(index)
                    .map_err(|_| corrupt("callee output order is not representable"))?
        {
            return Err(ReusableWorkflowRuntimeStoreError::Conflict);
        }
    }

    publication
        .output_mappings()
        .iter()
        .map(|mapping| {
            let callee = request
                .outputs()
                .iter()
                .find(|output| output.name() == mapping.callee_name())
                .ok_or(ReusableWorkflowRuntimeStoreError::Conflict)?;
            let public_value = match mapping.sensitivity() {
                OutputSensitivity::Public => callee
                    .public_value()
                    .map(ToOwned::to_owned)
                    .ok_or(ReusableWorkflowRuntimeStoreError::Conflict)?,
                OutputSensitivity::SecretDerived => String::new(),
            };
            Ok(MappedParentOutput {
                name: mapping.parent_name().as_str().to_owned(),
                sensitivity: mapping.sensitivity(),
                public_value: (mapping.sensitivity() == OutputSensitivity::Public)
                    .then_some(public_value),
            })
        })
        .collect()
}

async fn insert_call_result(
    transaction: &mut Transaction<'_, Postgres>,
    request: &CompleteReusableWorkflowCall,
    context: &CompletionContext,
    aggregate: &CompletionAggregate,
) -> Result<(), ReusableWorkflowRuntimeStoreError> {
    let publication = request.publication();
    let child_job_count = i32::try_from(if context.condition_matched {
        context.planned_child_job_count
    } else {
        0
    })
    .map_err(|_| corrupt("child job count is not representable"))?;
    let output_count = i32::try_from(request.outputs().len())
        .map_err(|_| corrupt("callee output count is not representable"))?;
    sqlx::query(
        r"
        INSERT INTO workflow_plan_v2_reusable_call_results (
            tenant_id, repository_id, run_id, parent_invocation_id,
            caller_logical_job_id, caller_instance_id, child_invocation_id,
            publication_operation_id, completion_operation_id,
            callee_plan_digest, evaluator_schema, child_job_count,
            child_jobs_digest, workflow_output_evaluation_digest,
            descriptor_digest, effective_conclusion, output_count,
            outputs_digest, commit_digest, parent_result_descriptor_digest,
            parent_instances_digest, parent_prerequisites_digest,
            parent_outputs_digest, parent_commit_digest, completed_at_ms,
            sealed_at_ms
        ) VALUES (
            $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, 1, $11, $12,
            $13, $14, $15, $16, $17, $18, $19, $20, $21, $22, $23,
            $24, NULL
        )
        ",
    )
    .bind(publication.tenant().as_str())
    .bind(publication.repository_id().as_uuid())
    .bind(publication.run_id().as_uuid())
    .bind(publication.parent_invocation_id().as_uuid())
    .bind(publication.caller_logical_job_id().as_uuid())
    .bind(publication.caller_instance_id())
    .bind(publication.child_invocation_id().as_uuid())
    .bind(publication.operation_id().as_uuid())
    .bind(request.operation_id().as_uuid())
    .bind(request.callee_plan_digest().as_bytes().as_slice())
    .bind(child_job_count)
    .bind(aggregate.child_jobs_digest.as_bytes().as_slice())
    .bind(
        request
            .workflow_output_evaluation_digest()
            .as_bytes()
            .as_slice(),
    )
    .bind(aggregate.call_descriptor_digest.as_bytes().as_slice())
    .bind(&aggregate.conclusion)
    .bind(output_count)
    .bind(request.outputs_digest().as_bytes().as_slice())
    .bind(aggregate.call_commit_digest.as_bytes().as_slice())
    .bind(
        aggregate
            .parent_result_descriptor_digest
            .as_bytes()
            .as_slice(),
    )
    .bind(aggregate.parent_instances_digest.as_bytes().as_slice())
    .bind(aggregate.parent_prerequisites_digest.as_bytes().as_slice())
    .bind(aggregate.parent_outputs_digest.as_bytes().as_slice())
    .bind(aggregate.parent_commit_digest.as_bytes().as_slice())
    .bind(request.completed_at().get())
    .execute(&mut **transaction)
    .await
    .map_err(classify_completion_error)?;
    Ok(())
}

async fn insert_call_result_jobs(
    transaction: &mut Transaction<'_, Postgres>,
    request: &CompleteReusableWorkflowCall,
    child_jobs: &[ChildResultEvidence],
) -> Result<(), ReusableWorkflowRuntimeStoreError> {
    let publication = request.publication();
    for evidence in child_jobs {
        sqlx::query(
            r"
            INSERT INTO workflow_plan_v2_reusable_call_result_jobs (
                run_id, parent_invocation_id, caller_logical_job_id,
                child_logical_job_id, source_order, descriptor_digest,
                outputs_digest, commit_digest, effective_conclusion,
                closure_has_failure, closure_has_cancelled,
                closure_has_skipped
            ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
            ",
        )
        .bind(publication.run_id().as_uuid())
        .bind(publication.parent_invocation_id().as_uuid())
        .bind(publication.caller_logical_job_id().as_uuid())
        .bind(evidence.logical_job_id)
        .bind(evidence.source_order)
        .bind(evidence.descriptor_digest.as_bytes().as_slice())
        .bind(evidence.outputs_digest.as_bytes().as_slice())
        .bind(evidence.commit_digest.as_bytes().as_slice())
        .bind(&evidence.conclusion)
        .bind(evidence.closure_has_failure)
        .bind(evidence.closure_has_cancelled)
        .bind(evidence.closure_has_skipped)
        .execute(&mut **transaction)
        .await
        .map_err(classify_completion_error)?;
    }
    Ok(())
}

async fn insert_call_result_outputs(
    transaction: &mut Transaction<'_, Postgres>,
    request: &CompleteReusableWorkflowCall,
) -> Result<(), ReusableWorkflowRuntimeStoreError> {
    let publication = request.publication();
    for (source_order, output) in request.outputs().iter().enumerate() {
        let source_order = i32::try_from(source_order)
            .map_err(|_| corrupt("callee output order is not representable"))?;
        sqlx::query(
            r"
            INSERT INTO workflow_plan_v2_reusable_call_result_outputs (
                run_id, parent_invocation_id, caller_logical_job_id,
                callee_output_name, sensitivity, public_value, source_order
            ) VALUES ($1, $2, $3, $4, $5, $6, $7)
            ",
        )
        .bind(publication.run_id().as_uuid())
        .bind(publication.parent_invocation_id().as_uuid())
        .bind(publication.caller_logical_job_id().as_uuid())
        .bind(output.name().as_str())
        .bind(sensitivity_name(output.sensitivity()))
        .bind(output.public_value())
        .bind(source_order)
        .execute(&mut **transaction)
        .await
        .map_err(classify_completion_error)?;
    }
    Ok(())
}

async fn seal_call_result(
    transaction: &mut Transaction<'_, Postgres>,
    request: &CompleteReusableWorkflowCall,
) -> Result<(), ReusableWorkflowRuntimeStoreError> {
    let publication = request.publication();
    let rows = sqlx::query(
        r"
        UPDATE workflow_plan_v2_reusable_call_results
        SET sealed_at_ms = completed_at_ms
        WHERE run_id = $1
          AND parent_invocation_id = $2
          AND caller_logical_job_id = $3
          AND completion_operation_id = $4
          AND outputs_digest = $5
          AND sealed_at_ms IS NULL
        ",
    )
    .bind(publication.run_id().as_uuid())
    .bind(publication.parent_invocation_id().as_uuid())
    .bind(publication.caller_logical_job_id().as_uuid())
    .bind(request.operation_id().as_uuid())
    .bind(request.outputs_digest().as_bytes().as_slice())
    .execute(&mut **transaction)
    .await
    .map_err(classify_completion_error)?
    .rows_affected();
    if rows == 1 {
        Ok(())
    } else {
        Err(ReusableWorkflowRuntimeStoreError::Conflict)
    }
}

async fn complete_child_invocation(
    transaction: &mut Transaction<'_, Postgres>,
    request: &CompleteReusableWorkflowCall,
    context: &CompletionContext,
    aggregate: &CompletionAggregate,
) -> Result<(), ReusableWorkflowRuntimeStoreError> {
    if !context.condition_matched {
        return Ok(());
    }
    let state = match aggregate.conclusion.as_str() {
        "success" | "skipped" => "completed",
        "cancelled" => "cancelled",
        "failure" | "timed_out" => "failed",
        _ => return Err(corrupt("unknown reusable conclusion")),
    };
    let publication = request.publication();
    let rows = sqlx::query(
        r"
        UPDATE workflow_plan_v2_invocations
        SET state = $3, revision = revision + 1, updated_at_ms = $4
        WHERE run_id = $1 AND id = $2
          AND invocation_kind = 'reusable' AND state = 'active'
        ",
    )
    .bind(publication.run_id().as_uuid())
    .bind(publication.child_invocation_id().as_uuid())
    .bind(state)
    .bind(request.completed_at().get())
    .execute(&mut **transaction)
    .await
    .map_err(classify_completion_error)?
    .rows_affected();
    if rows == 1 {
        Ok(())
    } else {
        Err(ReusableWorkflowRuntimeStoreError::Conflict)
    }
}

#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
async fn insert_parent_result(
    transaction: &mut Transaction<'_, Postgres>,
    request: &CompleteReusableWorkflowCall,
    context: &CompletionContext,
    aggregate: &CompletionAggregate,
    child_jobs: &[ChildResultEvidence],
    prerequisites: &[PrerequisiteEvidence],
    outputs: &[MappedParentOutput],
) -> Result<(), ReusableWorkflowRuntimeStoreError> {
    let publication = request.publication();
    let expires_at = request
        .completed_at()
        .get()
        .checked_add(900_000)
        .ok_or_else(|| corrupt("parent result claim expiration overflow"))?;
    sqlx::query(
        r"
        INSERT INTO workflow_plan_v2_job_result_claims (
            logical_job_id, run_id, invocation_id, descriptor_digest,
            state, owner_id, generation, claimed_at_ms, expires_at_ms,
            created_at_ms, updated_at_ms
        ) VALUES ($1, $2, $3, $4, 'aggregating', $5, 1, $6, $7, $6, $6)
        ",
    )
    .bind(publication.caller_logical_job_id().as_uuid())
    .bind(publication.run_id().as_uuid())
    .bind(publication.parent_invocation_id().as_uuid())
    .bind(
        aggregate
            .parent_result_descriptor_digest
            .as_bytes()
            .as_slice(),
    )
    .bind(request.operation_id().as_uuid())
    .bind(request.completed_at().get())
    .bind(expires_at)
    .execute(&mut **transaction)
    .await
    .map_err(classify_completion_error)?;

    let instance_count = i32::from(context.condition_matched);
    let prerequisite_count = i32::try_from(prerequisites.len())
        .map_err(|_| corrupt("prerequisite count is not representable"))?;
    let output_count = i32::try_from(outputs.len())
        .map_err(|_| corrupt("parent output count is not representable"))?;
    sqlx::query(
        r"
        INSERT INTO workflow_plan_v2_job_results (
            logical_job_id, run_id, invocation_id, descriptor_digest,
            logical_key, source_order, plan_digest, plan_object_key,
            plan_size_bytes, plan_media_type, plan_schema,
            activation_output_digest, condition_matched, instance_count,
            instances_digest, prerequisite_count, prerequisites_digest,
            effective_conclusion, closure_has_failure,
            closure_has_cancelled, closure_has_skipped, output_count,
            outputs_digest, commit_digest, claim_owner_id,
            claim_generation, claim_started_at_ms, claim_expires_at_ms,
            finalized_at_ms
        ) VALUES (
            $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13,
            $14, $15, $16, $17, $18, $19, $20, $21, $22, $23, $24,
            $25, 1, $26, $27, $26
        )
        ",
    )
    .bind(publication.caller_logical_job_id().as_uuid())
    .bind(publication.run_id().as_uuid())
    .bind(publication.parent_invocation_id().as_uuid())
    .bind(
        aggregate
            .parent_result_descriptor_digest
            .as_bytes()
            .as_slice(),
    )
    .bind(&context.logical_key)
    .bind(context.source_order)
    .bind(context.parent_plan_digest.as_bytes().as_slice())
    .bind(&context.parent_plan_object_key)
    .bind(context.parent_plan_size_bytes)
    .bind(&context.parent_plan_media_type)
    .bind(context.parent_plan_schema)
    .bind(publication.publication_digest().as_bytes().as_slice())
    .bind(context.condition_matched)
    .bind(instance_count)
    .bind(aggregate.parent_instances_digest.as_bytes().as_slice())
    .bind(prerequisite_count)
    .bind(aggregate.parent_prerequisites_digest.as_bytes().as_slice())
    .bind(&aggregate.conclusion)
    .bind(aggregate.closure_has_failure)
    .bind(aggregate.closure_has_cancelled)
    .bind(aggregate.closure_has_skipped)
    .bind(output_count)
    .bind(aggregate.parent_outputs_digest.as_bytes().as_slice())
    .bind(aggregate.parent_commit_digest.as_bytes().as_slice())
    .bind(request.operation_id().as_uuid())
    .bind(request.completed_at().get())
    .bind(expires_at)
    .execute(&mut **transaction)
    .await
    .map_err(classify_completion_error)?;

    if context.condition_matched {
        sqlx::query(
            r"
            INSERT INTO workflow_plan_v2_job_result_instances (
                logical_job_id, instance_id, matrix_index, terminal_ordinal,
                instance_descriptor_digest, instance_outputs_digest,
                instance_commit_digest, raw_conclusion, effective_conclusion
            ) VALUES ($1, $2, 0, 1, $3, $4, $5, $6, $6)
            ",
        )
        .bind(publication.caller_logical_job_id().as_uuid())
        .bind(publication.caller_instance_id())
        .bind(aggregate.call_descriptor_digest.as_bytes().as_slice())
        .bind(request.outputs_digest().as_bytes().as_slice())
        .bind(aggregate.call_commit_digest.as_bytes().as_slice())
        .bind(&aggregate.conclusion)
        .execute(&mut **transaction)
        .await
        .map_err(classify_completion_error)?;
    } else if !child_jobs.is_empty() {
        return Err(corrupt("skipped reusable call retained child jobs"));
    }

    for prerequisite in prerequisites {
        sqlx::query(
            r"
            INSERT INTO workflow_plan_v2_job_result_prerequisites (
                logical_job_id, prerequisite_job_id,
                prerequisite_source_order, prerequisite_commit_digest,
                prerequisite_outputs_digest, effective_conclusion,
                closure_has_failure, closure_has_cancelled,
                closure_has_skipped
            ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
            ",
        )
        .bind(publication.caller_logical_job_id().as_uuid())
        .bind(prerequisite.logical_job_id)
        .bind(prerequisite.source_order)
        .bind(prerequisite.commit_digest.as_bytes().as_slice())
        .bind(prerequisite.outputs_digest.as_bytes().as_slice())
        .bind(&prerequisite.conclusion)
        .bind(prerequisite.closure_has_failure)
        .bind(prerequisite.closure_has_cancelled)
        .bind(prerequisite.closure_has_skipped)
        .execute(&mut **transaction)
        .await
        .map_err(classify_completion_error)?;
    }
    for output in outputs {
        sqlx::query(
            r"
            INSERT INTO workflow_plan_v2_job_result_outputs (
                logical_job_id, output_name, sensitivity, public_value
            ) VALUES ($1, $2, $3, $4)
            ",
        )
        .bind(publication.caller_logical_job_id().as_uuid())
        .bind(&output.name)
        .bind(sensitivity_name(output.sensitivity))
        .bind(output.public_value.as_deref())
        .execute(&mut **transaction)
        .await
        .map_err(classify_completion_error)?;
    }

    let terminal_state = match aggregate.conclusion.as_str() {
        "success" => "completed",
        "failure" | "timed_out" => "failed",
        "cancelled" => "cancelled",
        "skipped" => "skipped",
        _ => return Err(corrupt("unknown reusable conclusion")),
    };
    let updated = sqlx::query(
        r"
        UPDATE workflow_plan_v2_jobs
        SET state = $4, updated_at_ms = $5
        WHERE run_id = $1 AND invocation_id = $2 AND id = $3
          AND execution_kind = 'reusable_workflow'
          AND state = CASE WHEN $6 THEN 'activated' ELSE 'skipped' END
        ",
    )
    .bind(publication.run_id().as_uuid())
    .bind(publication.parent_invocation_id().as_uuid())
    .bind(publication.caller_logical_job_id().as_uuid())
    .bind(terminal_state)
    .bind(request.completed_at().get())
    .bind(context.condition_matched)
    .execute(&mut **transaction)
    .await
    .map_err(classify_completion_error)?
    .rows_affected();
    if updated != 1 {
        return Err(ReusableWorkflowRuntimeStoreError::Conflict);
    }
    let finalized = sqlx::query(
        r"
        UPDATE workflow_plan_v2_job_result_claims
        SET state = 'finalized', updated_at_ms = $4
        WHERE logical_job_id = $1 AND owner_id = $2
          AND generation = 1 AND state = 'aggregating'
          AND descriptor_digest = $3
        ",
    )
    .bind(publication.caller_logical_job_id().as_uuid())
    .bind(request.operation_id().as_uuid())
    .bind(
        aggregate
            .parent_result_descriptor_digest
            .as_bytes()
            .as_slice(),
    )
    .bind(request.completed_at().get())
    .execute(&mut **transaction)
    .await
    .map_err(classify_completion_error)?
    .rows_affected();
    if finalized == 1 {
        Ok(())
    } else {
        Err(ReusableWorkflowRuntimeStoreError::Conflict)
    }
}

fn aggregate_conclusion(
    child_jobs: &[ChildResultEvidence],
    condition_matched: bool,
) -> &'static str {
    if !condition_matched {
        return "skipped";
    }
    for (candidate, conclusion) in [
        ("failure", "failure"),
        ("timed_out", "timed_out"),
        ("cancelled", "cancelled"),
        ("success", "success"),
    ] {
        if child_jobs
            .iter()
            .any(|evidence| evidence.conclusion == candidate)
        {
            return conclusion;
        }
    }
    "skipped"
}

fn hash_child_jobs(child_jobs: &[ChildResultEvidence]) -> Sha256Digest {
    let mut hasher = domain_hasher(b"automata.store.reusable-child-results.v1\0");
    hash_len(&mut hasher, child_jobs.len());
    for evidence in child_jobs {
        hash_bytes(&mut hasher, evidence.logical_job_id.as_bytes());
        hasher.update(evidence.source_order.to_be_bytes());
        hash_bytes(&mut hasher, evidence.descriptor_digest.as_bytes());
        hash_bytes(&mut hasher, evidence.outputs_digest.as_bytes());
        hash_bytes(&mut hasher, evidence.commit_digest.as_bytes());
        hash_bytes(&mut hasher, evidence.conclusion.as_bytes());
        hasher.update([
            u8::from(evidence.closure_has_failure),
            u8::from(evidence.closure_has_cancelled),
            u8::from(evidence.closure_has_skipped),
        ]);
        hasher.update(evidence.finalized_at_ms.to_be_bytes());
    }
    finish_hash(hasher)
}

fn hash_prerequisites(prerequisites: &[PrerequisiteEvidence]) -> Sha256Digest {
    let mut hasher = domain_hasher(b"automata.store.reusable-parent-prerequisites.v1\0");
    hash_len(&mut hasher, prerequisites.len());
    for evidence in prerequisites {
        hash_bytes(&mut hasher, evidence.logical_job_id.as_bytes());
        hasher.update(evidence.source_order.to_be_bytes());
        hash_bytes(&mut hasher, evidence.commit_digest.as_bytes());
        hash_bytes(&mut hasher, evidence.outputs_digest.as_bytes());
        hash_bytes(&mut hasher, evidence.conclusion.as_bytes());
        hasher.update([
            u8::from(evidence.closure_has_failure),
            u8::from(evidence.closure_has_cancelled),
            u8::from(evidence.closure_has_skipped),
        ]);
    }
    finish_hash(hasher)
}

fn hash_parent_outputs(outputs: &[MappedParentOutput]) -> Sha256Digest {
    let mut hasher = domain_hasher(b"automata.store.reusable-parent-outputs.v1\0");
    hash_len(&mut hasher, outputs.len());
    for output in outputs {
        hash_bytes(&mut hasher, output.name.as_bytes());
        hash_bytes(&mut hasher, sensitivity_name(output.sensitivity).as_bytes());
        match &output.public_value {
            Some(value) => {
                hasher.update([1]);
                hash_bytes(&mut hasher, value.as_bytes());
            }
            None => hasher.update([0]),
        }
    }
    finish_hash(hasher)
}

fn hash_call_descriptor(
    request: &CompleteReusableWorkflowCall,
    context: &CompletionContext,
    child_jobs_digest: Sha256Digest,
    conclusion: &str,
) -> Sha256Digest {
    let publication = request.publication();
    let mut hasher = domain_hasher(b"automata.store.reusable-call-result-descriptor.v1\0");
    for id in [
        publication.run_id().as_uuid(),
        publication.parent_invocation_id().as_uuid(),
        publication.caller_logical_job_id().as_uuid(),
        publication.caller_instance_id(),
        publication.child_invocation_id().as_uuid(),
    ] {
        hash_bytes(&mut hasher, id.as_bytes());
    }
    hash_bytes(&mut hasher, context.child_plan_digest.as_bytes());
    hash_bytes(&mut hasher, child_jobs_digest.as_bytes());
    hash_bytes(
        &mut hasher,
        request.workflow_output_evaluation_digest().as_bytes(),
    );
    hash_bytes(&mut hasher, request.outputs_digest().as_bytes());
    hash_bytes(&mut hasher, conclusion.as_bytes());
    hasher.update(request.completed_at().get().to_be_bytes());
    finish_hash(hasher)
}

fn hash_call_commit(
    request: &CompleteReusableWorkflowCall,
    descriptor_digest: Sha256Digest,
    outputs_digest: Sha256Digest,
    conclusion: &str,
) -> Sha256Digest {
    let mut hasher = domain_hasher(b"automata.store.reusable-call-result-commit.v1\0");
    hash_bytes(&mut hasher, request.operation_id().as_uuid().as_bytes());
    hash_bytes(&mut hasher, descriptor_digest.as_bytes());
    hash_bytes(&mut hasher, outputs_digest.as_bytes());
    hash_bytes(&mut hasher, conclusion.as_bytes());
    hasher.update(request.completed_at().get().to_be_bytes());
    finish_hash(hasher)
}

fn hash_parent_instances(
    request: &CompleteReusableWorkflowCall,
    condition_matched: bool,
    descriptor_digest: Sha256Digest,
    outputs_digest: Sha256Digest,
    commit_digest: Sha256Digest,
    conclusion: &str,
) -> Sha256Digest {
    let mut hasher = domain_hasher(b"automata.store.reusable-parent-instances.v1\0");
    hasher.update([u8::from(condition_matched)]);
    if condition_matched {
        hash_bytes(
            &mut hasher,
            request.publication().caller_instance_id().as_bytes(),
        );
        hasher.update(0_i32.to_be_bytes());
        hasher.update(1_i64.to_be_bytes());
        hash_bytes(&mut hasher, descriptor_digest.as_bytes());
        hash_bytes(&mut hasher, outputs_digest.as_bytes());
        hash_bytes(&mut hasher, commit_digest.as_bytes());
        hash_bytes(&mut hasher, conclusion.as_bytes());
    }
    finish_hash(hasher)
}

fn hash_parent_result_descriptor(
    request: &CompleteReusableWorkflowCall,
    context: &CompletionContext,
    instances_digest: Sha256Digest,
    prerequisites_digest: Sha256Digest,
) -> Sha256Digest {
    let publication = request.publication();
    let mut hasher = domain_hasher(b"automata.store.reusable-parent-result-descriptor.v1\0");
    for id in [
        publication.run_id().as_uuid(),
        publication.parent_invocation_id().as_uuid(),
        publication.caller_logical_job_id().as_uuid(),
    ] {
        hash_bytes(&mut hasher, id.as_bytes());
    }
    hash_bytes(&mut hasher, context.parent_plan_digest.as_bytes());
    hash_bytes(&mut hasher, publication.publication_digest().as_bytes());
    hash_bytes(&mut hasher, instances_digest.as_bytes());
    hash_bytes(&mut hasher, prerequisites_digest.as_bytes());
    finish_hash(hasher)
}

#[allow(clippy::too_many_arguments)]
fn hash_parent_commit(
    request: &CompleteReusableWorkflowCall,
    descriptor_digest: Sha256Digest,
    outputs_digest: Sha256Digest,
    conclusion: &str,
    closure_has_failure: bool,
    closure_has_cancelled: bool,
    closure_has_skipped: bool,
) -> Sha256Digest {
    let mut hasher = domain_hasher(b"automata.store.reusable-parent-result-commit.v1\0");
    hash_bytes(&mut hasher, request.operation_id().as_uuid().as_bytes());
    hash_bytes(&mut hasher, descriptor_digest.as_bytes());
    hash_bytes(&mut hasher, outputs_digest.as_bytes());
    hash_bytes(&mut hasher, conclusion.as_bytes());
    hasher.update([
        u8::from(closure_has_failure),
        u8::from(closure_has_cancelled),
        u8::from(closure_has_skipped),
    ]);
    hasher.update(request.completed_at().get().to_be_bytes());
    finish_hash(hasher)
}

fn domain_hasher(domain: &[u8]) -> Sha256 {
    let mut hasher = Sha256::new();
    hasher.update(domain);
    hasher
}

fn hash_bytes(hasher: &mut Sha256, value: &[u8]) {
    hasher.update(u64::try_from(value.len()).unwrap_or(u64::MAX).to_be_bytes());
    hasher.update(value);
}

fn hash_len(hasher: &mut Sha256, value: usize) {
    hasher.update(u64::try_from(value).unwrap_or(u64::MAX).to_be_bytes());
}

fn finish_hash(hasher: Sha256) -> Sha256Digest {
    Sha256Digest::from_bytes(hasher.finalize().into())
}

fn validate_conclusion(value: &str) -> Result<(), ReusableWorkflowRuntimeStoreError> {
    if matches!(
        value,
        "success" | "failure" | "cancelled" | "timed_out" | "skipped"
    ) {
        Ok(())
    } else {
        Err(corrupt("durable reusable conclusion is invalid"))
    }
}

fn digest_column(
    row: &PgRow,
    column: &str,
) -> Result<Sha256Digest, ReusableWorkflowRuntimeStoreError> {
    let value: Vec<u8> = row.try_get(column).map_err(operation_error)?;
    decode_digest(&value)
}

fn decode_digest(value: &[u8]) -> Result<Sha256Digest, ReusableWorkflowRuntimeStoreError> {
    let bytes: [u8; 32] = value
        .try_into()
        .map_err(|_| corrupt("durable reusable workflow digest is not SHA-256"))?;
    Ok(Sha256Digest::from_bytes(bytes))
}

const fn sensitivity_name(value: OutputSensitivity) -> &'static str {
    match value {
        OutputSensitivity::Public => "public",
        OutputSensitivity::SecretDerived => "secret_derived",
    }
}

fn classify_publication_error(error: sqlx::Error) -> ReusableWorkflowRuntimeStoreError {
    let constraint = error
        .as_database_error()
        .and_then(sqlx::error::DatabaseError::constraint);
    if matches!(
        constraint,
        Some(
            "workflow_plan_v2_reusable_call_publication_window"
                | "workflow_plan_v2_reusable_call_output_contract_window"
                | "workflow_plan_v2_reusable_child_results_complete"
        )
    ) {
        return ReusableWorkflowRuntimeStoreError::NotReady;
    }
    if error
        .as_database_error()
        .is_some_and(|database| database.code().as_deref() == Some("23505"))
        || constraint.is_some_and(|name| name.contains("reusable_call"))
    {
        return ReusableWorkflowRuntimeStoreError::Conflict;
    }
    operation_error(error)
}

fn classify_completion_error(error: sqlx::Error) -> ReusableWorkflowRuntimeStoreError {
    let constraint = error
        .as_database_error()
        .and_then(sqlx::error::DatabaseError::constraint);
    if constraint == Some("workflow_plan_v2_reusable_child_results_complete") {
        return ReusableWorkflowRuntimeStoreError::ChildResultsPending;
    }
    if matches!(
        constraint,
        Some(
            "workflow_plan_v2_reusable_call_result_window"
                | "workflow_plan_v2_reusable_call_publication_window"
        )
    ) {
        return ReusableWorkflowRuntimeStoreError::NotReady;
    }
    if error
        .as_database_error()
        .is_some_and(|database| database.code().as_deref() == Some("23505"))
        || constraint.is_some_and(|name| name.contains("reusable_call"))
    {
        return ReusableWorkflowRuntimeStoreError::Conflict;
    }
    operation_error(error)
}

fn corrupt(message: &'static str) -> ReusableWorkflowRuntimeStoreError {
    StoreError::corrupt_data(message).into()
}

fn operation_error(error: sqlx::Error) -> ReusableWorkflowRuntimeStoreError {
    StoreError::operation(error).into()
}
