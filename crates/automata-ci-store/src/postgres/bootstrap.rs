use async_trait::async_trait;
use serde_json::Value;
use sqlx::Row as _;
use uuid::Uuid;

use automata_ci_core::{RunnerCapabilities, RunnerFeature};

use crate::{
    EnsureTenant, ProductBootstrapRepository, ProductBootstrapStoreError, RunnerCapabilityReadiness,
};

use super::PostgresStore;

const RUNNER_CAPABILITY_ADMISSION_BATCH_SIZE: usize = 16;
const RUNNER_CAPABILITY_ADMISSION_TOTAL_LIMIT: usize = 64;

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
                sqlx::query("SELECT id,capabilities FROM runners WHERE id>$1 ORDER BY id LIMIT $2")
                    .bind(after_id)
                    .bind(batch_limit)
                    .fetch_all(&mut *transaction)
                    .await
            } else {
                sqlx::query("SELECT id,capabilities FROM runners ORDER BY id LIMIT $1")
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
            "INSERT INTO tenants (id,display_name,created_at_ms,updated_at_ms) VALUES ($1,$1,$2,$2) ON CONFLICT (id) DO NOTHING",
        )
        .bind(request.tenant().as_str())
        .bind(request.created_at().get())
        .execute(&self.pool)
        .await
        .map_err(operation_error)?;
        Ok(())
    }
}

fn operation_error(error: sqlx::Error) -> ProductBootstrapStoreError {
    ProductBootstrapStoreError::operation(error)
}
