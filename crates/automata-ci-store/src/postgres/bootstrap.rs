use std::collections::BTreeSet;

use async_trait::async_trait;
use serde_json::{Value, json};
use sqlx::{PgConnection, Row as _};
use uuid::Uuid;

use automata_ci_core::{RunnerCapabilities, RunnerFeature, RunnerId};

use crate::{
    EnsureTenant, MAX_STATIC_RUNNERS, ProductBootstrapRepository, ProductBootstrapStoreError,
    RunnerCapabilityReadiness, StaticRunnerFleet, StaticRunnerRegistration,
};

use super::PostgresStore;

const RUNNER_CAPABILITY_ADMISSION_BATCH_SIZE: usize = 16;
const RUNNER_CAPABILITY_ADMISSION_TOTAL_LIMIT: usize = MAX_STATIC_RUNNERS;

#[async_trait]
impl ProductBootstrapRepository for PostgresStore {
    async fn verify_runner_capability_readiness(
        &self,
        readiness: RunnerCapabilityReadiness,
    ) -> Result<(), ProductBootstrapStoreError> {
        let mut transaction = self.pool.begin().await.map_err(operation_error)?;
        sqlx::query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY")
            .execute(&mut *transaction)
            .await
            .map_err(operation_error)?;
        let mut after_id: Option<Uuid> = None;
        let mut inspected = 0_usize;
        loop {
            let remaining_with_overflow_probe = RUNNER_CAPABILITY_ADMISSION_TOTAL_LIMIT
                .checked_sub(inspected)
                .and_then(|remaining| remaining.checked_add(1))
                .ok_or(ProductBootstrapStoreError::CorruptData)?;
            let batch_size =
                RUNNER_CAPABILITY_ADMISSION_BATCH_SIZE.min(remaining_with_overflow_probe);
            let batch_limit =
                i64::try_from(batch_size).map_err(|_| ProductBootstrapStoreError::CorruptData)?;
            let rows = if let Some(after_id) = after_id {
                sqlx::query(
                    r"
                    SELECT id, capabilities
                    FROM runners
                    WHERE id > $1
                    ORDER BY id
                    LIMIT $2
                    ",
                )
                .bind(after_id)
                .bind(batch_limit)
                .fetch_all(&mut *transaction)
                .await
            } else {
                sqlx::query(
                    r"
                    SELECT id, capabilities
                    FROM runners
                    ORDER BY id
                    LIMIT $1
                    ",
                )
                .bind(batch_limit)
                .fetch_all(&mut *transaction)
                .await
            }
            .map_err(operation_error)?;
            if rows.is_empty() {
                break;
            }
            inspected = inspected
                .checked_add(rows.len())
                .ok_or(ProductBootstrapStoreError::CorruptData)?;
            if inspected > RUNNER_CAPABILITY_ADMISSION_TOTAL_LIMIT {
                return Err(ProductBootstrapStoreError::drift(
                    "runner capability admission",
                ));
            }
            let fetched = rows.len();
            for row in rows {
                let runner_id: Uuid = row.try_get("id").map_err(operation_error)?;
                let document: Value = row.try_get("capabilities").map_err(operation_error)?;
                let capabilities: RunnerCapabilities = serde_json::from_value(document.clone())
                    .map_err(|_| ProductBootstrapStoreError::CorruptData)?;
                capabilities
                    .validate()
                    .map_err(|_| ProductBootstrapStoreError::CorruptData)?;
                let canonical = serde_json::to_value(&capabilities)
                    .map_err(|_| ProductBootstrapStoreError::CorruptData)?;
                if runner_id.is_nil()
                    || capabilities.runner_id().as_uuid() != runner_id
                    || canonical != document
                {
                    return Err(ProductBootstrapStoreError::CorruptData);
                }
                if capabilities
                    .features()
                    .contains(&RunnerFeature::OIDC_TOKENS)
                    && !readiness.github_oidc()
                {
                    return Err(ProductBootstrapStoreError::drift(
                        "runner capability admission",
                    ));
                }
                after_id = Some(runner_id);
            }
            if fetched < batch_size {
                break;
            }
        }
        transaction.commit().await.map_err(operation_error)?;
        Ok(())
    }

    async fn ensure_tenant(&self, request: EnsureTenant) -> Result<(), ProductBootstrapStoreError> {
        sqlx::query(
            r"
            INSERT INTO tenants (id, display_name, created_at_ms, updated_at_ms)
            VALUES ($1, $1, $2, $2)
            ON CONFLICT (id) DO NOTHING
            ",
        )
        .bind(request.tenant().as_str())
        .bind(request.created_at().get())
        .execute(&self.pool)
        .await
        .map_err(operation_error)?;
        Ok(())
    }

    async fn apply_static_runner_fleet(
        &self,
        fleet: StaticRunnerFleet,
    ) -> Result<(), ProductBootstrapStoreError> {
        let mut transaction = self.pool.begin().await.map_err(operation_error)?;
        ensure_tenant_in_transaction(
            &mut transaction,
            fleet.tenant().as_str(),
            fleet.applied_at().get(),
        )
        .await?;
        let (group_id, group_created) = lock_or_create_group(&mut transaction, &fleet).await?;
        for runner in fleet.runners() {
            apply_runner(&mut transaction, &fleet, group_id, group_created, runner).await?;
        }
        verify_exact_group_membership(&mut transaction, group_id, fleet.runners()).await?;
        transaction.commit().await.map_err(operation_error)?;
        Ok(())
    }
}

async fn ensure_tenant_in_transaction(
    connection: &mut PgConnection,
    tenant: &str,
    applied_at_ms: i64,
) -> Result<(), ProductBootstrapStoreError> {
    sqlx::query(
        r"
        INSERT INTO tenants (id, display_name, created_at_ms, updated_at_ms)
        VALUES ($1, $1, $2, $2)
        ON CONFLICT (id) DO NOTHING
        ",
    )
    .bind(tenant)
    .bind(applied_at_ms)
    .execute(connection)
    .await
    .map_err(operation_error)?;
    Ok(())
}

async fn lock_or_create_group(
    connection: &mut PgConnection,
    fleet: &StaticRunnerFleet,
) -> Result<(Uuid, bool), ProductBootstrapStoreError> {
    let tenant = fleet.tenant().as_str();
    let normalized_name = fleet.group().as_str();
    let mut row = group_row(connection, tenant, normalized_name).await?;
    let mut group_created = false;
    if row.is_none() {
        let inserted = sqlx::query(
            r"
            INSERT INTO runner_groups (
                id, tenant_id, name, normalized_name, routing_policy,
                created_at_ms, updated_at_ms
            )
            VALUES ($1, $2, $3, $3, '{}'::jsonb, $4, $4)
            ON CONFLICT (tenant_id, normalized_name) DO NOTHING
            ",
        )
        .bind(Uuid::new_v4())
        .bind(tenant)
        .bind(normalized_name)
        .bind(fleet.applied_at().get())
        .execute(&mut *connection)
        .await
        .map_err(operation_error)?;
        group_created = inserted.rows_affected() == 1;
        row = group_row(connection, tenant, normalized_name).await?;
    }
    let row = row.ok_or(ProductBootstrapStoreError::CorruptData)?;
    let group_id: Uuid = row.try_get("id").map_err(operation_error)?;
    let name: String = row.try_get("name").map_err(operation_error)?;
    let routing_policy: Value = row.try_get("routing_policy").map_err(operation_error)?;
    if name != normalized_name || routing_policy != json!({}) {
        return Err(ProductBootstrapStoreError::drift("runner group"));
    }
    Ok((group_id, group_created))
}

async fn group_row(
    connection: &mut PgConnection,
    tenant: &str,
    normalized_name: &str,
) -> Result<Option<sqlx::postgres::PgRow>, ProductBootstrapStoreError> {
    sqlx::query(
        r"
        SELECT id, name, routing_policy
        FROM runner_groups
        WHERE tenant_id = $1 AND normalized_name = $2
        FOR UPDATE
        ",
    )
    .bind(tenant)
    .bind(normalized_name)
    .fetch_optional(connection)
    .await
    .map_err(operation_error)
}

async fn apply_runner(
    connection: &mut PgConnection,
    fleet: &StaticRunnerFleet,
    group_id: Uuid,
    group_created: bool,
    runner: &StaticRunnerRegistration,
) -> Result<(), ProductBootstrapStoreError> {
    let row = sqlx::query(
        r"
        SELECT tenant_id, group_id, name, normalized_name, labels, capabilities,
               slots, status, generation, external_identity, desired_state
        FROM runners
        WHERE id = $1
        FOR UPDATE
        ",
    )
    .bind(runner.runner_id().as_uuid())
    .fetch_optional(&mut *connection)
    .await
    .map_err(operation_error)?;

    let labels = runner
        .labels()
        .iter()
        .map(|label| label.as_str().to_owned())
        .collect::<Vec<_>>();
    let capabilities = serde_json::to_value(runner.capabilities())
        .map_err(|_| ProductBootstrapStoreError::CorruptData)?;
    let normalized_name = runner.name().to_lowercase();
    if let Some(row) = row {
        verify_runner_row(
            &row,
            fleet.tenant().as_str(),
            group_id,
            runner,
            &normalized_name,
            &labels,
            &capabilities,
        )?;
    } else {
        if !group_created {
            return Err(ProductBootstrapStoreError::drift("runner group membership"));
        }
        let result = sqlx::query(
            r"
            INSERT INTO runners (
                id, tenant_id, group_id, name, normalized_name, labels,
                capabilities, slots, status, generation, external_identity,
                desired_state, created_at_ms, updated_at_ms
            )
            VALUES (
                $1, $2, $3, $4, $5, $6, $7, $8,
                'offline', 1, $9, 'active', $10, $10
            )
            ",
        )
        .bind(runner.runner_id().as_uuid())
        .bind(fleet.tenant().as_str())
        .bind(group_id)
        .bind(runner.name())
        .bind(&normalized_name)
        .bind(&labels)
        .bind(&capabilities)
        .bind(i32::from(runner.slots().get()))
        .bind(runner.external_identity())
        .bind(fleet.applied_at().get())
        .execute(&mut *connection)
        .await;
        if let Err(error) = result {
            return Err(insert_error(error, "runner identity"));
        }
    }
    apply_certificates(connection, fleet, runner).await
}

#[allow(clippy::too_many_arguments)]
fn verify_runner_row(
    row: &sqlx::postgres::PgRow,
    tenant: &str,
    group_id: Uuid,
    runner: &StaticRunnerRegistration,
    normalized_name: &str,
    labels: &[String],
    capabilities: &Value,
) -> Result<(), ProductBootstrapStoreError> {
    let actual_tenant: String = row.try_get("tenant_id").map_err(operation_error)?;
    let actual_group: Option<Uuid> = row.try_get("group_id").map_err(operation_error)?;
    let actual_name: String = row.try_get("name").map_err(operation_error)?;
    let actual_normalized: String = row.try_get("normalized_name").map_err(operation_error)?;
    let actual_labels: Vec<String> = row.try_get("labels").map_err(operation_error)?;
    let actual_capabilities: Value = row.try_get("capabilities").map_err(operation_error)?;
    let actual_slots: i32 = row.try_get("slots").map_err(operation_error)?;
    let actual_status: String = row.try_get("status").map_err(operation_error)?;
    let actual_generation: i64 = row.try_get("generation").map_err(operation_error)?;
    let actual_external: Option<String> =
        row.try_get("external_identity").map_err(operation_error)?;
    let actual_desired: String = row.try_get("desired_state").map_err(operation_error)?;
    let coherent = actual_tenant == tenant
        && actual_group == Some(group_id)
        && actual_name == runner.name()
        && actual_normalized == normalized_name
        && actual_labels == labels
        && actual_capabilities == *capabilities
        && actual_slots == i32::from(runner.slots().get())
        && matches!(actual_status.as_str(), "offline" | "online")
        && actual_generation > 0
        && actual_external.as_deref() == Some(runner.external_identity())
        && actual_desired == "active";
    if !coherent {
        return Err(ProductBootstrapStoreError::drift("runner registration"));
    }
    Ok(())
}

async fn apply_certificates(
    connection: &mut PgConnection,
    fleet: &StaticRunnerFleet,
    runner: &StaticRunnerRegistration,
) -> Result<(), ProductBootstrapStoreError> {
    let desired = runner
        .active_certificates()
        .iter()
        .map(|(digest, expiry)| (digest.as_bytes().to_vec(), *expiry))
        .collect::<Vec<_>>();
    ensure_desired_certificates(connection, runner, &desired).await?;
    let desired_digests = desired
        .iter()
        .map(|(digest, _)| digest.clone())
        .collect::<BTreeSet<_>>();
    revoke_omitted_certificates(connection, fleet, runner, &desired_digests).await?;
    verify_exact_active_certificates(connection, runner, &desired_digests).await
}

async fn ensure_desired_certificates(
    connection: &mut PgConnection,
    runner: &StaticRunnerRegistration,
    desired: &[(Vec<u8>, i64)],
) -> Result<(), ProductBootstrapStoreError> {
    for (digest, desired_expiry) in desired {
        let row = sqlx::query(
            r"
            SELECT runner_id, expires_at_seconds, revoked_at_seconds
            FROM runner_machine_certificates
            WHERE leaf_sha256 = $1
            FOR UPDATE
            ",
        )
        .bind(digest)
        .fetch_optional(&mut *connection)
        .await
        .map_err(operation_error)?;
        if let Some(row) = row {
            let owner: Uuid = row.try_get("runner_id").map_err(operation_error)?;
            let expires_at: i64 = row.try_get("expires_at_seconds").map_err(operation_error)?;
            let revoked_at: Option<i64> =
                row.try_get("revoked_at_seconds").map_err(operation_error)?;
            if owner != runner.runner_id().as_uuid()
                || expires_at != *desired_expiry
                || revoked_at.is_some()
            {
                return Err(ProductBootstrapStoreError::drift(
                    "runner certificate authority",
                ));
            }
            continue;
        }
        let result = sqlx::query(
            r"
            INSERT INTO runner_machine_certificates (
                leaf_sha256, runner_id, expires_at_seconds
            )
            VALUES ($1, $2, $3)
            ",
        )
        .bind(digest)
        .bind(runner.runner_id().as_uuid())
        .bind(desired_expiry)
        .execute(&mut *connection)
        .await;
        if let Err(error) = result {
            return Err(insert_error(error, "runner certificate authority"));
        }
    }
    Ok(())
}

async fn revoke_omitted_certificates(
    connection: &mut PgConnection,
    fleet: &StaticRunnerFleet,
    runner: &StaticRunnerRegistration,
    desired_digests: &BTreeSet<Vec<u8>>,
) -> Result<(), ProductBootstrapStoreError> {
    let active_rows = sqlx::query(
        r"
        SELECT leaf_sha256, expires_at_seconds
        FROM runner_machine_certificates
        WHERE runner_id = $1 AND revoked_at_seconds IS NULL
        ORDER BY leaf_sha256
        FOR UPDATE
        ",
    )
    .bind(runner.runner_id().as_uuid())
    .fetch_all(&mut *connection)
    .await
    .map_err(operation_error)?;
    let observed_at_seconds = fleet.applied_at().get().div_euclid(1_000);
    for row in active_rows {
        let digest: Vec<u8> = row.try_get("leaf_sha256").map_err(operation_error)?;
        if desired_digests.contains(&digest) {
            continue;
        }
        let expires_at: i64 = row.try_get("expires_at_seconds").map_err(operation_error)?;
        let revoked_at = observed_at_seconds.min(expires_at);
        if revoked_at <= 0 {
            return Err(ProductBootstrapStoreError::CorruptData);
        }
        let result = sqlx::query(
            r"
            UPDATE runner_machine_certificates
            SET revoked_at_seconds = $2
            WHERE leaf_sha256 = $1 AND revoked_at_seconds IS NULL
            ",
        )
        .bind(&digest)
        .bind(revoked_at)
        .execute(&mut *connection)
        .await
        .map_err(operation_error)?;
        if result.rows_affected() != 1 {
            return Err(ProductBootstrapStoreError::drift(
                "runner certificate authority",
            ));
        }
    }
    Ok(())
}

async fn verify_exact_active_certificates(
    connection: &mut PgConnection,
    runner: &StaticRunnerRegistration,
    desired_digests: &BTreeSet<Vec<u8>>,
) -> Result<(), ProductBootstrapStoreError> {
    let durable_active = sqlx::query_scalar::<_, Vec<u8>>(
        r"
        SELECT leaf_sha256
        FROM runner_machine_certificates
        WHERE runner_id = $1 AND revoked_at_seconds IS NULL
        ORDER BY leaf_sha256
        FOR UPDATE
        ",
    )
    .bind(runner.runner_id().as_uuid())
    .fetch_all(connection)
    .await
    .map_err(operation_error)?
    .into_iter()
    .collect::<BTreeSet<_>>();
    if &durable_active != desired_digests {
        return Err(ProductBootstrapStoreError::drift(
            "runner certificate authority",
        ));
    }
    Ok(())
}

async fn verify_exact_group_membership(
    connection: &mut PgConnection,
    group_id: Uuid,
    runners: &[StaticRunnerRegistration],
) -> Result<(), ProductBootstrapStoreError> {
    let durable = sqlx::query_scalar::<_, Uuid>(
        r"
        SELECT id
        FROM runners
        WHERE group_id = $1
        ORDER BY id
        FOR UPDATE
        ",
    )
    .bind(group_id)
    .fetch_all(connection)
    .await
    .map_err(operation_error)?
    .into_iter()
    .map(RunnerId::from_uuid)
    .collect::<BTreeSet<_>>();
    let configured = runners
        .iter()
        .map(StaticRunnerRegistration::runner_id)
        .collect::<BTreeSet<_>>();
    if durable != configured {
        return Err(ProductBootstrapStoreError::drift("runner group membership"));
    }
    Ok(())
}

fn insert_error(error: sqlx::Error, resource: &'static str) -> ProductBootstrapStoreError {
    if error
        .as_database_error()
        .is_some_and(sqlx::error::DatabaseError::is_unique_violation)
    {
        ProductBootstrapStoreError::drift(resource)
    } else {
        operation_error(error)
    }
}

fn operation_error(error: sqlx::Error) -> ProductBootstrapStoreError {
    ProductBootstrapStoreError::operation(error)
}
