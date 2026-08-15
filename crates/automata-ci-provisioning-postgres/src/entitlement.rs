use std::fmt;

use automata_ci_provisioning::{
    ApplyWorkspaceEntitlementResult, AuthorizedApplyWorkspaceEntitlement, EntitlementFailure,
    EntitlementFailureKind, EntitlementTimestamp, WorkspaceEntitlementApplier,
    WorkspaceExecutionEntitlement,
};
use sqlx::{FromRow, PgPool, Postgres, Transaction};
use uuid::Uuid;

const WORKSPACE_ENTITLEMENT_APPLIED_AUDIT_ACTION: &str = "workspace.entitlement.applied";

/// Replica-safe `PostgreSQL` implementation of workspace entitlement application.
///
/// The adapter serializes mutations through the immutable workspace management
/// binding, verifies its exact authority and shard, and atomically stores both
/// the current snapshot and stable operation receipt. It deliberately performs
/// no per-job budget allocation.
#[derive(Clone)]
pub struct PostgresWorkspaceEntitlementApplier {
    pool: PgPool,
}

impl PostgresWorkspaceEntitlementApplier {
    /// Binds entitlement application to `pool`.
    #[must_use]
    pub const fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    #[allow(clippy::too_many_lines)] // One ordered transaction owns every entitlement effect.
    async fn apply_inner(
        &self,
        request: AuthorizedApplyWorkspaceEntitlement,
    ) -> Result<ApplyWorkspaceEntitlementResult, EntitlementFailure> {
        let (authority, command) = request.into_parts();
        let authority_id = authority.id().as_str();
        let operation_id = command.operation_id();
        let shard_id = command.shard_id();
        let workspace_id = command.workspace_id();
        let workspace_text = workspace_id.to_string();
        let revision = i64::try_from(command.revision().get())
            .map_err(|_| failure(EntitlementFailureKind::Internal))?;
        let policy = PolicyFields::from(command.execution())?;

        let mut transaction = self.pool.begin().await.map_err(database_failure)?;
        let binding = lock_management_binding(&mut transaction, &workspace_text).await?;
        if binding.as_ref().is_none_or(|binding| {
            binding.authority_id != authority_id || binding.shard_id != shard_id.as_str()
        }) {
            return Err(failure(EntitlementFailureKind::WorkspaceUnavailable));
        }

        if let Some(stored) =
            load_operation(&mut transaction, authority_id, operation_id.as_uuid()).await?
        {
            if !stored.matches(shard_id.as_str(), &workspace_text, revision, policy) {
                return Err(failure(EntitlementFailureKind::OperationConflict));
            }
            return stored.result(operation_id, shard_id.clone(), workspace_id);
        }

        let current_revision: Option<i64> = sqlx::query_scalar(
            r"
            SELECT revision FROM workspace_execution_entitlements
            WHERE workspace_id=$1
            FOR UPDATE
            ",
        )
        .bind(&workspace_text)
        .fetch_optional(&mut *transaction)
        .await
        .map_err(database_failure)?;
        if current_revision.is_some_and(|current| revision <= current) {
            return Err(failure(EntitlementFailureKind::StaleRevision));
        }

        let applied_at_ms = database_time_milliseconds(&mut transaction).await?;
        let expires_at_ms = policy
            .valid_for_ms
            .map(|duration| {
                applied_at_ms
                    .checked_add(duration)
                    .ok_or_else(|| failure(EntitlementFailureKind::Internal))
            })
            .transpose()?;
        let inserted = sqlx::query(
            r"
            INSERT INTO workspace_entitlement_operations (
                authority_id, operation_id, shard_id, workspace_id, revision,
                policy_kind, compute_limit_ms, valid_for_ms, applied_at_ms,
                expires_at_ms
            ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)
            ON CONFLICT (authority_id, operation_id) DO NOTHING
            ",
        )
        .bind(authority_id)
        .bind(operation_id.as_uuid())
        .bind(shard_id.as_str())
        .bind(&workspace_text)
        .bind(revision)
        .bind(policy.kind)
        .bind(policy.compute_limit_ms)
        .bind(policy.valid_for_ms)
        .bind(applied_at_ms)
        .bind(expires_at_ms)
        .execute(&mut *transaction)
        .await
        .map_err(database_failure)?;

        if inserted.rows_affected() == 0 {
            let stored = load_operation(&mut transaction, authority_id, operation_id.as_uuid())
                .await?
                .ok_or_else(|| failure(EntitlementFailureKind::Internal))?;
            if !stored.matches(shard_id.as_str(), &workspace_text, revision, policy) {
                return Err(failure(EntitlementFailureKind::OperationConflict));
            }
            return stored.result(operation_id, shard_id.clone(), workspace_id);
        }

        let state = if policy.kind == "paused" {
            "paused"
        } else {
            "active"
        };
        let updated = sqlx::query(
            r"
            INSERT INTO workspace_execution_entitlements (
                workspace_id, authority_id, shard_id, revision, operation_id,
                policy_kind, compute_limit_ms, valid_for_ms,
                consumed_compute_ms, state, applied_at_ms, expires_at_ms,
                exhausted_at_ms
            ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,0,$9,$10,$11,NULL)
            ON CONFLICT (workspace_id) DO UPDATE SET
                authority_id=EXCLUDED.authority_id,
                shard_id=EXCLUDED.shard_id,
                revision=EXCLUDED.revision,
                operation_id=EXCLUDED.operation_id,
                policy_kind=EXCLUDED.policy_kind,
                compute_limit_ms=EXCLUDED.compute_limit_ms,
                valid_for_ms=EXCLUDED.valid_for_ms,
                consumed_compute_ms=0,
                state=EXCLUDED.state,
                applied_at_ms=EXCLUDED.applied_at_ms,
                expires_at_ms=EXCLUDED.expires_at_ms,
                exhausted_at_ms=NULL
            WHERE workspace_execution_entitlements.revision < EXCLUDED.revision
            ",
        )
        .bind(&workspace_text)
        .bind(authority_id)
        .bind(shard_id.as_str())
        .bind(revision)
        .bind(operation_id.as_uuid())
        .bind(policy.kind)
        .bind(policy.compute_limit_ms)
        .bind(policy.valid_for_ms)
        .bind(state)
        .bind(applied_at_ms)
        .bind(expires_at_ms)
        .execute(&mut *transaction)
        .await
        .map_err(database_failure)?;
        if updated.rows_affected() != 1 {
            return Err(failure(EntitlementFailureKind::StaleRevision));
        }

        sqlx::query(
            r"
            INSERT INTO security_audit_events (
                event_id, tenant_id, occurred_at_ms, actor_kind, action,
                outcome, resource_kind, resource_id
            ) VALUES ($1,$2,$3,'system',$4,'succeeded','workspace',$2)
            ",
        )
        .bind(Uuid::new_v4())
        .bind(&workspace_text)
        .bind(applied_at_ms)
        .bind(WORKSPACE_ENTITLEMENT_APPLIED_AUDIT_ACTION)
        .execute(&mut *transaction)
        .await
        .map_err(database_failure)?;
        transaction.commit().await.map_err(database_failure)?;

        result(
            operation_id,
            shard_id.clone(),
            workspace_id,
            command.revision(),
            applied_at_ms,
            expires_at_ms,
        )
    }
}

impl fmt::Debug for PostgresWorkspaceEntitlementApplier {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PostgresWorkspaceEntitlementApplier")
            .finish_non_exhaustive()
    }
}

impl WorkspaceEntitlementApplier for PostgresWorkspaceEntitlementApplier {
    fn apply(
        &self,
        request: AuthorizedApplyWorkspaceEntitlement,
    ) -> automata_ci_provisioning::EntitlementApplicationFuture<'_> {
        Box::pin(self.apply_inner(request))
    }
}

#[derive(Clone, Copy)]
struct PolicyFields {
    kind: &'static str,
    compute_limit_ms: Option<i64>,
    valid_for_ms: Option<i64>,
}

impl PolicyFields {
    fn from(value: WorkspaceExecutionEntitlement) -> Result<Self, EntitlementFailure> {
        match value {
            WorkspaceExecutionEntitlement::Capped {
                compute_seconds,
                valid_for,
            } => Ok(Self {
                kind: "capped",
                compute_limit_ms: Some(seconds_to_milliseconds(compute_seconds.get())?),
                valid_for_ms: valid_for
                    .map(|duration| seconds_to_milliseconds(duration.get()))
                    .transpose()?,
            }),
            WorkspaceExecutionEntitlement::Uncapped => Ok(Self {
                kind: "uncapped",
                compute_limit_ms: None,
                valid_for_ms: None,
            }),
            WorkspaceExecutionEntitlement::Paused => Ok(Self {
                kind: "paused",
                compute_limit_ms: None,
                valid_for_ms: None,
            }),
        }
    }
}

#[derive(FromRow)]
struct ManagementBinding {
    authority_id: String,
    shard_id: String,
}

async fn lock_management_binding(
    transaction: &mut Transaction<'_, Postgres>,
    workspace_id: &str,
) -> Result<Option<ManagementBinding>, EntitlementFailure> {
    sqlx::query_as::<_, ManagementBinding>(
        r"
        SELECT authority_id, shard_id FROM workspace_management_bindings
        WHERE workspace_id=$1
        FOR UPDATE
        ",
    )
    .bind(workspace_id)
    .fetch_optional(&mut **transaction)
    .await
    .map_err(database_failure)
}

#[derive(FromRow)]
struct StoredOperation {
    shard_id: String,
    workspace_id: String,
    revision: i64,
    policy_kind: String,
    compute_limit_ms: Option<i64>,
    valid_for_ms: Option<i64>,
    applied_at_ms: i64,
    expires_at_ms: Option<i64>,
}

impl StoredOperation {
    fn matches(
        &self,
        shard_id: &str,
        workspace_id: &str,
        revision: i64,
        policy: PolicyFields,
    ) -> bool {
        self.shard_id == shard_id
            && self.workspace_id == workspace_id
            && self.revision == revision
            && self.policy_kind == policy.kind
            && self.compute_limit_ms == policy.compute_limit_ms
            && self.valid_for_ms == policy.valid_for_ms
    }

    fn result(
        self,
        operation_id: automata_ci_provisioning::OperationId,
        shard_id: automata_ci_provisioning::ShardId,
        workspace_id: automata_ci_provisioning::WorkspaceId,
    ) -> Result<ApplyWorkspaceEntitlementResult, EntitlementFailure> {
        result(
            operation_id,
            shard_id,
            workspace_id,
            automata_ci_provisioning::EntitlementRevision::new(
                u64::try_from(self.revision)
                    .map_err(|_| failure(EntitlementFailureKind::Internal))?,
            )
            .map_err(|_| failure(EntitlementFailureKind::Internal))?,
            self.applied_at_ms,
            self.expires_at_ms,
        )
    }
}

async fn load_operation(
    transaction: &mut Transaction<'_, Postgres>,
    authority_id: &str,
    operation_id: Uuid,
) -> Result<Option<StoredOperation>, EntitlementFailure> {
    sqlx::query_as::<_, StoredOperation>(
        r"
        SELECT shard_id, workspace_id, revision, policy_kind,
               compute_limit_ms, valid_for_ms, applied_at_ms, expires_at_ms
        FROM workspace_entitlement_operations
        WHERE authority_id=$1 AND operation_id=$2
        FOR UPDATE
        ",
    )
    .bind(authority_id)
    .bind(operation_id)
    .fetch_optional(&mut **transaction)
    .await
    .map_err(database_failure)
}

fn result(
    operation_id: automata_ci_provisioning::OperationId,
    shard_id: automata_ci_provisioning::ShardId,
    workspace_id: automata_ci_provisioning::WorkspaceId,
    revision: automata_ci_provisioning::EntitlementRevision,
    applied_at_ms: i64,
    expires_at_ms: Option<i64>,
) -> Result<ApplyWorkspaceEntitlementResult, EntitlementFailure> {
    Ok(ApplyWorkspaceEntitlementResult::new(
        operation_id,
        shard_id,
        workspace_id,
        revision,
        timestamp(applied_at_ms)?,
        expires_at_ms.map(timestamp).transpose()?,
    ))
}

fn seconds_to_milliseconds(seconds: u64) -> Result<i64, EntitlementFailure> {
    seconds
        .checked_mul(1_000)
        .and_then(|value| i64::try_from(value).ok())
        .ok_or_else(|| failure(EntitlementFailureKind::Internal))
}

async fn database_time_milliseconds(
    transaction: &mut Transaction<'_, Postgres>,
) -> Result<i64, EntitlementFailure> {
    let now: i64 =
        sqlx::query_scalar("SELECT floor(extract(epoch FROM clock_timestamp()) * 1000)::BIGINT")
            .fetch_one(&mut **transaction)
            .await
            .map_err(database_failure)?;
    if now < 0 {
        return Err(failure(EntitlementFailureKind::Internal));
    }
    Ok(now)
}

fn timestamp(milliseconds: i64) -> Result<EntitlementTimestamp, EntitlementFailure> {
    let seconds = milliseconds.div_euclid(1_000);
    let remainder = milliseconds.rem_euclid(1_000);
    let nanoseconds = u32::try_from(remainder)
        .ok()
        .and_then(|value| value.checked_mul(1_000_000))
        .ok_or_else(|| failure(EntitlementFailureKind::Internal))?;
    EntitlementTimestamp::new(seconds, nanoseconds)
        .map_err(|_| failure(EntitlementFailureKind::Internal))
}

fn database_failure(error: sqlx::Error) -> EntitlementFailure {
    let kind = match &error {
        sqlx::Error::Io(_)
        | sqlx::Error::Tls(_)
        | sqlx::Error::PoolTimedOut
        | sqlx::Error::PoolClosed
        | sqlx::Error::WorkerCrashed
        | sqlx::Error::BeginFailed => EntitlementFailureKind::TemporarilyUnavailable,
        sqlx::Error::Database(database)
            if super::retryable_sqlstate(database.code().as_deref()) =>
        {
            EntitlementFailureKind::TemporarilyUnavailable
        }
        _ => EntitlementFailureKind::Internal,
    };
    drop(error);
    failure(kind)
}

const fn failure(kind: EntitlementFailureKind) -> EntitlementFailure {
    EntitlementFailure::new(kind)
}
