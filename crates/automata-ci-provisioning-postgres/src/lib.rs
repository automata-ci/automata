#![forbid(unsafe_code)]
#![deny(missing_docs)]
//! `PostgreSQL` persistence for atomic Core workspace provisioning.

use std::fmt;

use automata_ci_provisioning::{
    AuthorizedProvisionWorkspace, InitialOwnerPrincipalId, ProvisionWorkspaceResult, ProvisionedAt,
    ProvisioningFailure, ProvisioningFailureKind, WorkspaceProvisioner,
    WorkspaceProvisioningFuture,
};
use sqlx::{FromRow, PgPool, Postgres, Transaction};
use uuid::Uuid;

mod entitlement;
mod usage;

pub use entitlement::PostgresWorkspaceEntitlementApplier;
pub use usage::PostgresWorkspaceUsageExporter;

const WORKSPACE_OWNER_ROLE_NAME: &str = "workspace-owner";
const WORKSPACE_OWNER_ROLE_DISPLAY_NAME: &str = "Workspace owner";
const WORKSPACE_PROVISIONED_AUDIT_ACTION: &str = "workspace.provisioned";

/// Replica-safe `PostgreSQL` implementation of the workspace provisioning port.
///
/// The adapter stores the idempotency receipt and every workspace, identity,
/// membership, authorization, and audit effect in one transaction. An exact
/// retry returns the original stable result; a reused operation or workspace
/// identity fails without changing durable state.
#[derive(Clone)]
pub struct PostgresWorkspaceProvisioner {
    pool: PgPool,
}

impl PostgresWorkspaceProvisioner {
    /// Binds workspace provisioning to `pool`.
    #[must_use]
    pub const fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    #[allow(clippy::too_many_lines)] // The ordered statements intentionally form one transaction.
    async fn provision_inner(
        &self,
        request: AuthorizedProvisionWorkspace,
    ) -> Result<ProvisionWorkspaceResult, ProvisioningFailure> {
        let (authority, command) = request.into_parts();
        let authority_id = authority.id().as_str();
        let operation_id = command.operation_id();
        let shard_id = command.shard_id();
        let workspace_id = command.workspace_id();
        let workspace_text = workspace_id.to_string();
        let workspace_display_name = command.workspace_display_name().as_str();
        let owner_issuer = command.initial_owner_issuer().as_str();
        let owner_subject = command.initial_owner_subject();
        let owner_display_name = command.initial_owner_display_name().as_str();

        let mut transaction = self.pool.begin().await.map_err(database_failure)?;
        let created_at_ms = database_time_milliseconds(&mut transaction).await?;
        let inserted = sqlx::query(
            r"
            INSERT INTO workspace_provisioning_operations (
                authority_id, operation_id, shard_id, workspace_id,
                workspace_display_name, initial_owner_issuer,
                initial_owner_subject, initial_owner_display_name, state,
                created_at_ms
            ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,'pending',$9)
            ON CONFLICT (authority_id, operation_id) DO NOTHING
            ",
        )
        .bind(authority_id)
        .bind(operation_id.as_uuid())
        .bind(shard_id.as_str())
        .bind(&workspace_text)
        .bind(workspace_display_name)
        .bind(owner_issuer)
        .bind(owner_subject.as_uuid())
        .bind(owner_display_name)
        .bind(created_at_ms)
        .execute(&mut *transaction)
        .await
        .map_err(database_failure)?;

        if inserted.rows_affected() == 0 {
            let stored =
                load_operation(&mut transaction, authority_id, operation_id.as_uuid()).await?;
            if !stored.matches(
                shard_id.as_str(),
                &workspace_text,
                workspace_display_name,
                owner_issuer,
                owner_subject.as_uuid(),
                owner_display_name,
            ) {
                return Err(failure(ProvisioningFailureKind::OperationConflict));
            }
            return stored.result(operation_id, shard_id.clone(), workspace_id);
        }

        let tenant_inserted = sqlx::query(
            r"
            INSERT INTO tenants (id, display_name, created_at_ms, updated_at_ms)
            VALUES ($1,$2,$3,$3) ON CONFLICT (id) DO NOTHING
            ",
        )
        .bind(&workspace_text)
        .bind(workspace_display_name)
        .bind(created_at_ms)
        .execute(&mut *transaction)
        .await
        .map_err(database_failure)?;
        if tenant_inserted.rows_affected() != 1 {
            return Err(failure(ProvisioningFailureKind::WorkspaceConflict));
        }
        sqlx::query(
            r"
            INSERT INTO workspace_management_bindings (
                workspace_id, authority_id, shard_id, created_at_ms
            ) VALUES ($1,$2,$3,$4)
            ",
        )
        .bind(&workspace_text)
        .bind(authority_id)
        .bind(shard_id.as_str())
        .bind(created_at_ms)
        .execute(&mut *transaction)
        .await
        .map_err(database_failure)?;

        let principal_id = resolve_or_create_principal(
            &mut transaction,
            owner_issuer,
            owner_subject.as_uuid(),
            owner_display_name,
            created_at_ms,
        )
        .await?;
        let role_id = Uuid::new_v4();
        let binding_id = Uuid::new_v4();

        sqlx::query(
            r"
            INSERT INTO tenant_human_memberships (
                tenant_id, principal_id, status, authorization_revision,
                revision, created_at_ms, updated_at_ms
            ) VALUES ($1,$2,'active',1,1,$3,$3)
            ",
        )
        .bind(&workspace_text)
        .bind(principal_id)
        .bind(created_at_ms)
        .execute(&mut *transaction)
        .await
        .map_err(database_failure)?;
        sqlx::query(
            r"
            INSERT INTO rbac_roles (
                tenant_id, id, name, display_name, role_kind, immutable,
                revision, created_by_principal_id, created_at_ms, updated_at_ms
            ) VALUES ($1,$2,$3,$4,'built_in',TRUE,1,$5,$6,$6)
            ",
        )
        .bind(&workspace_text)
        .bind(role_id)
        .bind(WORKSPACE_OWNER_ROLE_NAME)
        .bind(WORKSPACE_OWNER_ROLE_DISPLAY_NAME)
        .bind(principal_id)
        .bind(created_at_ms)
        .execute(&mut *transaction)
        .await
        .map_err(database_failure)?;
        let granted_permissions: i64 = sqlx::query_scalar(
            r"
            WITH granted AS (
                INSERT INTO rbac_role_permissions (
                    tenant_id, role_id, permission_name,
                    granted_by_principal_id, granted_at_ms
                )
                SELECT $1,$2,name,$3,$4 FROM rbac_permissions
                RETURNING 1
            )
            SELECT count(*) FROM granted
            ",
        )
        .bind(&workspace_text)
        .bind(role_id)
        .bind(principal_id)
        .bind(created_at_ms)
        .fetch_one(&mut *transaction)
        .await
        .map_err(database_failure)?;
        if granted_permissions <= 0 {
            return Err(failure(ProvisioningFailureKind::Internal));
        }
        sqlx::query(
            r"
            INSERT INTO rbac_role_bindings (
                tenant_id, id, principal_id, role_id, scope_kind,
                assignment_source, status, created_by_principal_id,
                created_at_ms, revision
            ) VALUES ($1,$2,$3,$4,'tenant','bootstrap','active',$3,$5,1)
            ",
        )
        .bind(&workspace_text)
        .bind(binding_id)
        .bind(principal_id)
        .bind(role_id)
        .bind(created_at_ms)
        .execute(&mut *transaction)
        .await
        .map_err(database_failure)?;

        let provisioned_at_ms = database_time_milliseconds(&mut transaction).await?;
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
        .bind(provisioned_at_ms)
        .bind(WORKSPACE_PROVISIONED_AUDIT_ACTION)
        .execute(&mut *transaction)
        .await
        .map_err(database_failure)?;
        let completed = sqlx::query(
            r"
            UPDATE workspace_provisioning_operations
            SET state='completed', initial_owner_principal_id=$3,
                provisioned_at_ms=$4
            WHERE authority_id=$1 AND operation_id=$2 AND state='pending'
            ",
        )
        .bind(authority_id)
        .bind(operation_id.as_uuid())
        .bind(principal_id)
        .bind(provisioned_at_ms)
        .execute(&mut *transaction)
        .await
        .map_err(database_failure)?;
        if completed.rows_affected() != 1 {
            return Err(failure(ProvisioningFailureKind::Internal));
        }
        transaction.commit().await.map_err(database_failure)?;

        let initial_owner_principal_id = InitialOwnerPrincipalId::from_uuid(principal_id)
            .map_err(|_| failure(ProvisioningFailureKind::Internal))?;
        Ok(ProvisionWorkspaceResult::new(
            operation_id,
            shard_id.clone(),
            workspace_id,
            initial_owner_principal_id,
            provisioned_at(provisioned_at_ms)?,
        ))
    }
}

impl fmt::Debug for PostgresWorkspaceProvisioner {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PostgresWorkspaceProvisioner")
            .finish_non_exhaustive()
    }
}

impl WorkspaceProvisioner for PostgresWorkspaceProvisioner {
    fn provision(&self, request: AuthorizedProvisionWorkspace) -> WorkspaceProvisioningFuture<'_> {
        Box::pin(self.provision_inner(request))
    }
}

#[derive(FromRow)]
struct StoredOperation {
    shard_id: String,
    workspace_id: String,
    workspace_display_name: String,
    initial_owner_issuer: String,
    initial_owner_subject: Uuid,
    initial_owner_display_name: String,
    state: String,
    initial_owner_principal_id: Option<Uuid>,
    provisioned_at_ms: Option<i64>,
}

impl StoredOperation {
    #[allow(clippy::too_many_arguments)]
    fn matches(
        &self,
        shard_id: &str,
        workspace_id: &str,
        workspace_display_name: &str,
        owner_issuer: &str,
        owner_subject: Uuid,
        owner_display_name: &str,
    ) -> bool {
        self.shard_id == shard_id
            && self.workspace_id == workspace_id
            && self.workspace_display_name == workspace_display_name
            && self.initial_owner_issuer == owner_issuer
            && self.initial_owner_subject == owner_subject
            && self.initial_owner_display_name == owner_display_name
    }

    fn result(
        self,
        operation_id: automata_ci_provisioning::OperationId,
        shard_id: automata_ci_provisioning::ShardId,
        workspace_id: automata_ci_provisioning::WorkspaceId,
    ) -> Result<ProvisionWorkspaceResult, ProvisioningFailure> {
        if self.state != "completed" {
            return Err(failure(ProvisioningFailureKind::Internal));
        }
        let principal_id = self
            .initial_owner_principal_id
            .ok_or_else(|| failure(ProvisioningFailureKind::Internal))?;
        let provisioned_at_ms = self
            .provisioned_at_ms
            .ok_or_else(|| failure(ProvisioningFailureKind::Internal))?;
        Ok(ProvisionWorkspaceResult::new(
            operation_id,
            shard_id,
            workspace_id,
            InitialOwnerPrincipalId::from_uuid(principal_id)
                .map_err(|_| failure(ProvisioningFailureKind::Internal))?,
            provisioned_at(provisioned_at_ms)?,
        ))
    }
}

#[derive(FromRow)]
struct StoredPrincipal {
    principal_id: Uuid,
    status: String,
}

async fn load_operation(
    transaction: &mut Transaction<'_, Postgres>,
    authority_id: &str,
    operation_id: Uuid,
) -> Result<StoredOperation, ProvisioningFailure> {
    sqlx::query_as::<_, StoredOperation>(
        r"
        SELECT shard_id, workspace_id, workspace_display_name,
               initial_owner_issuer, initial_owner_subject,
               initial_owner_display_name, state,
               initial_owner_principal_id, provisioned_at_ms
        FROM workspace_provisioning_operations
        WHERE authority_id=$1 AND operation_id=$2
        FOR UPDATE
        ",
    )
    .bind(authority_id)
    .bind(operation_id)
    .fetch_one(&mut **transaction)
    .await
    .map_err(database_failure)
}

async fn resolve_or_create_principal(
    transaction: &mut Transaction<'_, Postgres>,
    issuer: &str,
    subject: Uuid,
    display_name: &str,
    now_ms: i64,
) -> Result<Uuid, ProvisioningFailure> {
    if let Some(stored) = load_principal(transaction, issuer, subject).await? {
        return active_principal(&stored);
    }

    let candidate = Uuid::new_v4();
    sqlx::query(
        r"
        INSERT INTO human_principals (
            id, status, display_name, revision, created_at_ms, updated_at_ms
        ) VALUES ($1,'active',$2,1,$3,$3)
        ",
    )
    .bind(candidate)
    .bind(display_name)
    .bind(now_ms)
    .execute(&mut **transaction)
    .await
    .map_err(database_failure)?;
    let mapping = sqlx::query(
        r"
        INSERT INTO delegated_actor_identities (
            issuer, subject, principal_id, display_name,
            created_at_ms, updated_at_ms
        ) VALUES ($1,$2,$3,$4,$5,$5)
        ON CONFLICT (issuer, subject) DO NOTHING
        ",
    )
    .bind(issuer)
    .bind(subject)
    .bind(candidate)
    .bind(display_name)
    .bind(now_ms)
    .execute(&mut **transaction)
    .await
    .map_err(database_failure)?;
    if mapping.rows_affected() == 1 {
        return Ok(candidate);
    }

    let deleted = sqlx::query("DELETE FROM human_principals WHERE id=$1")
        .bind(candidate)
        .execute(&mut **transaction)
        .await
        .map_err(database_failure)?;
    if deleted.rows_affected() != 1 {
        return Err(failure(ProvisioningFailureKind::Internal));
    }
    let stored = load_principal(transaction, issuer, subject)
        .await?
        .ok_or_else(|| failure(ProvisioningFailureKind::Internal))?;
    active_principal(&stored)
}

async fn load_principal(
    transaction: &mut Transaction<'_, Postgres>,
    issuer: &str,
    subject: Uuid,
) -> Result<Option<StoredPrincipal>, ProvisioningFailure> {
    sqlx::query_as::<_, StoredPrincipal>(
        r"
        SELECT identity.principal_id, principal.status
        FROM delegated_actor_identities AS identity
        JOIN human_principals AS principal ON principal.id=identity.principal_id
        WHERE identity.issuer=$1 AND identity.subject=$2
        FOR UPDATE OF identity, principal
        ",
    )
    .bind(issuer)
    .bind(subject)
    .fetch_optional(&mut **transaction)
    .await
    .map_err(database_failure)
}

fn active_principal(stored: &StoredPrincipal) -> Result<Uuid, ProvisioningFailure> {
    match stored.status.as_str() {
        "active" => Ok(stored.principal_id),
        "disabled" => Err(failure(ProvisioningFailureKind::PrincipalUnavailable)),
        _ => Err(failure(ProvisioningFailureKind::Internal)),
    }
}

async fn database_time_milliseconds(
    transaction: &mut Transaction<'_, Postgres>,
) -> Result<i64, ProvisioningFailure> {
    let now: i64 =
        sqlx::query_scalar("SELECT floor(extract(epoch FROM clock_timestamp()) * 1000)::BIGINT")
            .fetch_one(&mut **transaction)
            .await
            .map_err(database_failure)?;
    if now < 0 {
        return Err(failure(ProvisioningFailureKind::Internal));
    }
    Ok(now)
}

fn provisioned_at(milliseconds: i64) -> Result<ProvisionedAt, ProvisioningFailure> {
    let seconds = milliseconds.div_euclid(1_000);
    let remainder = milliseconds.rem_euclid(1_000);
    let nanoseconds = u32::try_from(remainder)
        .ok()
        .and_then(|value| value.checked_mul(1_000_000))
        .ok_or_else(|| failure(ProvisioningFailureKind::Internal))?;
    ProvisionedAt::new(seconds, nanoseconds).map_err(|_| failure(ProvisioningFailureKind::Internal))
}

fn database_failure(error: sqlx::Error) -> ProvisioningFailure {
    let kind = match &error {
        sqlx::Error::Io(_)
        | sqlx::Error::Tls(_)
        | sqlx::Error::PoolTimedOut
        | sqlx::Error::PoolClosed
        | sqlx::Error::WorkerCrashed
        | sqlx::Error::BeginFailed => ProvisioningFailureKind::TemporarilyUnavailable,
        sqlx::Error::Database(database) if retryable_sqlstate(database.code().as_deref()) => {
            ProvisioningFailureKind::TemporarilyUnavailable
        }
        _ => ProvisioningFailureKind::Internal,
    };
    drop(error);
    failure(kind)
}

fn retryable_sqlstate(code: Option<&str>) -> bool {
    code.is_some_and(|code| {
        code.starts_with("08")
            || matches!(
                code,
                "40001" | "40P01" | "53000" | "53300" | "53400" | "57P01" | "57P02" | "57P03"
            )
    })
}

const fn failure(kind: ProvisioningFailureKind) -> ProvisioningFailure {
    ProvisioningFailure::new(kind, None)
}
