use automata_ci_core::RunId;
use automata_ci_store::{LogicalWorkflowInvocationId, StoreError, TenantScope};
use sqlx::{Postgres, Transaction};

use super::durable_schema::current_durable_schemas;

pub(super) async fn lock_active_logical_graph(
    transaction: &mut Transaction<'_, Postgres>,
    tenant: &TenantScope,
    run_id: RunId,
    invocation_id: LogicalWorkflowInvocationId,
) -> Result<bool, StoreError> {
    let schemas = current_durable_schemas();
    let run_active: Option<bool> = sqlx::query_scalar(
        r"
        SELECT run.status IN ('queued', 'in_progress')
               AND run.admission_epoch = $4 AND run.plan_schema = $3
        FROM workflow_runs AS run
        JOIN repositories AS repository ON repository.id = run.repository_id
        WHERE repository.tenant_id = $1 AND run.id = $2
        FOR SHARE OF run
        ",
    )
    .bind(tenant.as_str())
    .bind(run_id.as_uuid())
    .bind(schemas.workflow_plan_i32)
    .bind(schemas.admission_epoch_i32)
    .fetch_optional(&mut **transaction)
    .await
    .map_err(StoreError::operation)?;
    if run_active != Some(true) {
        return Ok(false);
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
    .bind(run_id.as_uuid())
    .bind(invocation_id.as_uuid())
    .bind(schemas.logical_orchestration_i16)
    .fetch_optional(&mut **transaction)
    .await
    .map_err(StoreError::operation)?;
    if marker_active != Some(true) {
        return Ok(false);
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
    .bind(run_id.as_uuid())
    .bind(invocation_id.as_uuid())
    .bind(schemas.workflow_plan_i16)
    .fetch_optional(&mut **transaction)
    .await
    .map_err(StoreError::operation)?;
    Ok(invocation_active == Some(true))
}
