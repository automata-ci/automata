use std::fmt;

use automata_ci_provisioning::{
    AuthorizedListWorkspaceUsage, ConsumedComputeMilliseconds, EntitlementRevision, ShardId,
    UsageAttemptId, UsageEventId, UsageExportCursor, UsageExportFailure, UsageExportFailureKind,
    UsageExportFuture, UsageTimestamp, WorkspaceId, WorkspaceUsageEvent, WorkspaceUsageExporter,
    WorkspaceUsagePage,
};
use sqlx::{FromRow, PgPool, Postgres, Transaction};
use uuid::Uuid;

const CURSOR_BYTES: usize = 16;

/// Replica-safe `PostgreSQL` reader for an authority-scoped workspace usage feed.
///
/// The cursor is the raw UUID of the last event in a returned page. Resolving it
/// through the authority and shard columns makes a cursor from another export
/// namespace invalid without exposing the internal append sequence.
#[derive(Clone)]
pub struct PostgresWorkspaceUsageExporter {
    pool: PgPool,
}

impl PostgresWorkspaceUsageExporter {
    /// Binds usage export to `pool`.
    #[must_use]
    pub const fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    async fn list_inner(
        &self,
        request: AuthorizedListWorkspaceUsage,
    ) -> Result<WorkspaceUsagePage, UsageExportFailure> {
        let (authority, command) = request.into_parts();
        let authority_id = authority.id().as_str();
        let shard_id = command.shard_id();
        let cursor = command.cursor().clone();
        let page_size = i64::from(command.page_size().get());
        let mut transaction = self.pool.begin().await.map_err(database_failure)?;
        let after_sequence =
            resolve_cursor(&mut transaction, authority_id, shard_id.as_str(), &cursor).await?;
        let rows = sqlx::query_as::<_, StoredUsageEvent>(
            r"
            SELECT event_id, shard_id, workspace_id, attempt_id,
                   entitlement_revision, interval_start_ms, interval_end_ms,
                   consumed_compute_ms
            FROM workspace_usage_events
            WHERE authority_id=$1 AND shard_id=$2 AND sequence > $3
            ORDER BY sequence
            LIMIT $4
            ",
        )
        .bind(authority_id)
        .bind(shard_id.as_str())
        .bind(after_sequence)
        .bind(page_size)
        .fetch_all(&mut *transaction)
        .await
        .map_err(database_failure)?;

        let next_cursor = rows
            .last()
            .map(|row| UsageExportCursor::new(row.event_id.as_bytes().to_vec()))
            .transpose()
            .map_err(|_| failure(UsageExportFailureKind::Internal))?
            .unwrap_or(cursor);
        let events = rows
            .into_iter()
            .map(StoredUsageEvent::decode)
            .collect::<Result<Vec<_>, _>>()?;
        transaction.commit().await.map_err(database_failure)?;
        WorkspaceUsagePage::new(events, next_cursor)
            .map_err(|_| failure(UsageExportFailureKind::Internal))
    }
}

impl fmt::Debug for PostgresWorkspaceUsageExporter {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PostgresWorkspaceUsageExporter")
            .finish_non_exhaustive()
    }
}

impl WorkspaceUsageExporter for PostgresWorkspaceUsageExporter {
    fn list(&self, request: AuthorizedListWorkspaceUsage) -> UsageExportFuture<'_> {
        Box::pin(self.list_inner(request))
    }
}

#[derive(FromRow)]
struct StoredUsageEvent {
    event_id: Uuid,
    shard_id: String,
    workspace_id: String,
    attempt_id: Uuid,
    entitlement_revision: i64,
    interval_start_ms: i64,
    interval_end_ms: i64,
    consumed_compute_ms: i64,
}

impl StoredUsageEvent {
    fn decode(self) -> Result<WorkspaceUsageEvent, UsageExportFailure> {
        WorkspaceUsageEvent::new(
            UsageEventId::from_uuid(self.event_id).map_err(corrupt)?,
            ShardId::new(self.shard_id).map_err(corrupt)?,
            WorkspaceId::parse(&self.workspace_id).map_err(corrupt)?,
            UsageAttemptId::from_uuid(self.attempt_id).map_err(corrupt)?,
            EntitlementRevision::new(u64::try_from(self.entitlement_revision).map_err(corrupt)?)
                .map_err(corrupt)?,
            timestamp(self.interval_start_ms)?,
            timestamp(self.interval_end_ms)?,
            ConsumedComputeMilliseconds::new(
                u64::try_from(self.consumed_compute_ms).map_err(corrupt)?,
            )
            .map_err(corrupt)?,
        )
        .map_err(corrupt)
    }
}

async fn resolve_cursor(
    transaction: &mut Transaction<'_, Postgres>,
    authority_id: &str,
    shard_id: &str,
    cursor: &UsageExportCursor,
) -> Result<i64, UsageExportFailure> {
    if cursor.as_bytes().is_empty() {
        return Ok(0);
    }
    if cursor.as_bytes().len() != CURSOR_BYTES {
        return Err(failure(UsageExportFailureKind::InvalidCursor));
    }
    let event_id = Uuid::from_slice(cursor.as_bytes())
        .map_err(|_| failure(UsageExportFailureKind::InvalidCursor))?;
    sqlx::query_scalar(
        r"
        SELECT sequence FROM workspace_usage_events
        WHERE event_id=$1 AND authority_id=$2 AND shard_id=$3
        ",
    )
    .bind(event_id)
    .bind(authority_id)
    .bind(shard_id)
    .fetch_optional(&mut **transaction)
    .await
    .map_err(database_failure)?
    .ok_or_else(|| failure(UsageExportFailureKind::InvalidCursor))
}

fn timestamp(milliseconds: i64) -> Result<UsageTimestamp, UsageExportFailure> {
    let seconds = milliseconds.div_euclid(1_000);
    let remainder = milliseconds.rem_euclid(1_000);
    let nanoseconds = u32::try_from(remainder)
        .ok()
        .and_then(|value| value.checked_mul(1_000_000))
        .ok_or_else(|| failure(UsageExportFailureKind::Internal))?;
    UsageTimestamp::new(seconds, nanoseconds).map_err(|_| failure(UsageExportFailureKind::Internal))
}

fn database_failure(error: sqlx::Error) -> UsageExportFailure {
    let kind = match &error {
        sqlx::Error::Io(_)
        | sqlx::Error::Tls(_)
        | sqlx::Error::PoolTimedOut
        | sqlx::Error::PoolClosed
        | sqlx::Error::WorkerCrashed
        | sqlx::Error::BeginFailed => UsageExportFailureKind::TemporarilyUnavailable,
        sqlx::Error::Database(database)
            if super::retryable_sqlstate(database.code().as_deref()) =>
        {
            UsageExportFailureKind::TemporarilyUnavailable
        }
        _ => UsageExportFailureKind::Internal,
    };
    drop(error);
    failure(kind)
}

fn corrupt<T>(_error: T) -> UsageExportFailure {
    failure(UsageExportFailureKind::Internal)
}

const fn failure(kind: UsageExportFailureKind) -> UsageExportFailure {
    UsageExportFailure::new(kind)
}
