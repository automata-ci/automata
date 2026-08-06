use async_trait::async_trait;
use automata_core::{
    AttemptId, AttemptNumber, FencingToken, IdentifierError, JobId, JobLifecycle, Lease,
    LeaseGuard, LeaseId, RunnerId, UnixMillis,
};
use sqlx::{PgConnection, PgPool, Row as _, postgres::PgPoolOptions};
use thiserror::Error;
use uuid::Uuid;

use crate::migration::MIGRATOR;
use crate::{
    AcquireLease, AttemptSnapshot, AttemptSnapshotError, AttemptStoreError, ConcludeQueuedAttempt,
    InternalAttemptRepository, QueuedAttempt, RenewLease, TenantAttemptQuery, TenantScope,
    TransitionAttempt,
};

/// Failures specific to configuring or migrating the `PostgreSQL` adapter.
///
/// Repository operations use the backend-neutral [`AttemptStoreError`]
/// instead. This type is intentionally limited to concrete adapter lifecycle
/// APIs where exposing the `PostgreSQL` driver as an error source is useful.
#[derive(Debug, Error)]
pub enum PostgresStoreError {
    #[error("failed to connect to PostgreSQL")]
    Connection(#[source] sqlx::Error),
    #[error("failed to migrate PostgreSQL")]
    Migration(#[source] sqlx::migrate::MigrateError),
}

#[derive(Clone, Debug)]
pub struct PostgresStore {
    pool: PgPool,
}

impl PostgresStore {
    /// Connects to `PostgreSQL` with a bounded connection pool.
    ///
    /// # Errors
    ///
    /// Returns an error if the URL is invalid or `PostgreSQL` cannot be reached.
    pub async fn connect(
        database_url: &str,
        maximum_connections: u32,
    ) -> Result<Self, PostgresStoreError> {
        let pool = PgPoolOptions::new()
            .max_connections(maximum_connections)
            .connect(database_url)
            .await
            .map_err(PostgresStoreError::Connection)?;
        Ok(Self { pool })
    }

    /// Creates the concrete adapter from an existing `sqlx` `PostgreSQL`
    /// pool. This is an adapter-specific integration hook, not a portable
    /// storage port.
    #[must_use]
    pub fn from_postgres_pool(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Returns the adapter's raw `sqlx` `PostgreSQL` pool for concrete
    /// integration and migration tests. Portable callers should depend on
    /// [`InternalAttemptRepository`] or [`TenantAttemptQuery`] instead.
    #[must_use]
    pub const fn postgres_pool(&self) -> &PgPool {
        &self.pool
    }

    /// Applies all embedded migrations under `PostgreSQL`'s migration lock.
    ///
    /// # Errors
    ///
    /// Returns an error if a migration cannot acquire its lock or commit.
    pub async fn migrate(&self) -> Result<(), PostgresStoreError> {
        MIGRATOR
            .run(&self.pool)
            .await
            .map_err(PostgresStoreError::Migration)?;
        Ok(())
    }

    async fn snapshot(&self, attempt_id: AttemptId) -> Result<AttemptSnapshot, AttemptStoreError> {
        let row = sqlx::query(
            r"
            SELECT id, job_id, attempt_number, lifecycle, fencing_token,
                   lease_id, runner_id, lease_issued_at_ms, lease_expires_at_ms,
                   lease_failures, queued_at_ms, changed_at_ms
            FROM job_attempts
            WHERE id = $1
            ",
        )
        .bind(attempt_id.as_uuid())
        .fetch_optional(&self.pool)
        .await
        .map_err(operation_error)?
        .ok_or(AttemptStoreError::NotFound(attempt_id))?;

        decode_snapshot(&row)
    }
}

#[async_trait]
impl InternalAttemptRepository for PostgresStore {
    async fn insert_queued(&self, attempt: QueuedAttempt) -> Result<(), AttemptStoreError> {
        sqlx::query(
            r"
            INSERT INTO job_attempts (
                id, job_id, attempt_number, lifecycle, fencing_token,
                lease_failures, queued_at_ms, changed_at_ms
            )
            VALUES ($1, $2, $3, 'queued', 0, 0, $4, $4)
            ",
        )
        .bind(attempt.attempt_id.as_uuid())
        .bind(attempt.job_id.as_uuid())
        .bind(i32::try_from(attempt.attempt_number.get()).map_err(|_| {
            AttemptStoreError::corrupt_data("attempt number does not fit PostgreSQL INTEGER")
        })?)
        .bind(attempt.queued_at.get())
        .execute(&self.pool)
        .await
        .map_err(operation_error)?;
        Ok(())
    }

    async fn get_attempt(
        &self,
        attempt_id: AttemptId,
    ) -> Result<AttemptSnapshot, AttemptStoreError> {
        self.snapshot(attempt_id).await
    }

    async fn acquire_lease(&self, request: AcquireLease) -> Result<Lease, AttemptStoreError> {
        let mut transaction = self.pool.begin().await.map_err(operation_error)?;
        let snapshot = locked_snapshot(&mut transaction, request.attempt_id).await?;
        if snapshot.lifecycle != JobLifecycle::Queued {
            return Err(AttemptStoreError::NotQueued {
                attempt_id: request.attempt_id,
                lifecycle: snapshot.lifecycle,
            });
        }
        verify_state_time(request.attempt_id, request.observed_at, &snapshot)?;
        verify_runner_tenant(
            &mut transaction,
            request.attempt_id,
            snapshot.job_id,
            request.runner_id,
        )
        .await?;
        let fencing_token = match snapshot.fencing_token {
            Some(current) => current
                .checked_next()
                .map_err(|_| AttemptStoreError::FencingTokenExhausted(request.attempt_id))?,
            None => FencingToken::new(1).map_err(identifier_error)?,
        };

        let result = sqlx::query(
            r"
            UPDATE job_attempts
            SET lifecycle = 'leased',
                fencing_token = $2,
                lease_id = $3,
                runner_id = $4,
                lease_issued_at_ms = $5,
                lease_expires_at_ms = $6,
                changed_at_ms = $5
            WHERE id = $1
              AND lifecycle = 'queued'
              AND changed_at_ms <= $5
            ",
        )
        .bind(request.attempt_id.as_uuid())
        .bind(fencing_to_i64(fencing_token)?)
        .bind(request.lease_id.as_uuid())
        .bind(request.runner_id.as_uuid())
        .bind(request.observed_at.get())
        .bind(request.expires_at.get())
        .execute(&mut *transaction)
        .await
        .map_err(operation_error)?;
        require_single_update(result.rows_affected())?;
        let lease = Lease::new(
            request.lease_id,
            request.attempt_id,
            request.runner_id,
            fencing_token,
            request.observed_at,
            request.expires_at,
        )
        .map_err(|error| {
            AttemptStoreError::corrupt_data(format!(
                "validated lease acquisition produced an invalid lease: {error}"
            ))
        })?;
        transaction.commit().await.map_err(operation_error)?;
        Ok(lease)
    }

    async fn conclude_queued(
        &self,
        request: ConcludeQueuedAttempt,
    ) -> Result<(), AttemptStoreError> {
        let mut transaction = self.pool.begin().await.map_err(operation_error)?;
        let snapshot = locked_snapshot(&mut transaction, request.attempt_id).await?;
        if snapshot.lifecycle != JobLifecycle::Queued {
            return Err(AttemptStoreError::NotQueued {
                attempt_id: request.attempt_id,
                lifecycle: snapshot.lifecycle,
            });
        }
        verify_state_time(request.attempt_id, request.observed_at, &snapshot)?;

        let result = sqlx::query(
            r"
            UPDATE job_attempts
            SET lifecycle = $2,
                changed_at_ms = $3
            WHERE id = $1
              AND lifecycle = 'queued'
              AND changed_at_ms <= $3
            ",
        )
        .bind(request.attempt_id.as_uuid())
        .bind(lifecycle_name(request.conclusion))
        .bind(request.observed_at.get())
        .execute(&mut *transaction)
        .await
        .map_err(operation_error)?;
        require_single_update(result.rows_affected())?;
        transaction.commit().await.map_err(operation_error)?;
        Ok(())
    }

    async fn renew_lease(&self, request: RenewLease) -> Result<Lease, AttemptStoreError> {
        let mut transaction = self.pool.begin().await.map_err(operation_error)?;
        let snapshot = locked_snapshot(&mut transaction, request.attempt_id).await?;
        verify_guard(request.attempt_id, request.guard, &snapshot)?;
        verify_runner(request.attempt_id, request.runner_id, &snapshot)?;
        verify_mutation_time(request.attempt_id, request.observed_at, &snapshot)?;
        let current_expiration = snapshot
            .lease_expires_at
            .ok_or_else(|| corrupt("active lease is missing its expiration"))?;
        if request.expires_at <= current_expiration {
            return Err(AttemptStoreError::RenewalDoesNotExtend(request.attempt_id));
        }

        let result = sqlx::query(
            r"
            UPDATE job_attempts
            SET lease_expires_at_ms = $5,
                changed_at_ms = $6
            WHERE id = $1
              AND lease_id = $2
              AND fencing_token = $3
              AND runner_id = $4
              AND changed_at_ms <= $6
            ",
        )
        .bind(request.attempt_id.as_uuid())
        .bind(request.guard.lease_id().as_uuid())
        .bind(fencing_to_i64(request.guard.fencing_token())?)
        .bind(request.runner_id.as_uuid())
        .bind(request.expires_at.get())
        .bind(request.observed_at.get())
        .execute(&mut *transaction)
        .await
        .map_err(operation_error)?;
        require_single_update(result.rows_affected())?;
        let runner_id = snapshot
            .runner_id
            .ok_or_else(|| corrupt("active lease is missing its runner"))?;
        let issued_at = snapshot
            .lease_issued_at
            .ok_or_else(|| corrupt("active lease is missing its issuance"))?;
        let lease = Lease::new(
            request.guard.lease_id(),
            request.attempt_id,
            runner_id,
            request.guard.fencing_token(),
            issued_at,
            request.expires_at,
        )
        .map_err(|error| {
            AttemptStoreError::corrupt_data(format!(
                "durable renewal produced an invalid lease: {error}"
            ))
        })?;
        transaction.commit().await.map_err(operation_error)?;
        Ok(lease)
    }

    async fn transition(&self, request: TransitionAttempt) -> Result<(), AttemptStoreError> {
        let mut transaction = self.pool.begin().await.map_err(operation_error)?;
        let snapshot = locked_snapshot(&mut transaction, request.attempt_id).await?;
        verify_guard(request.attempt_id, request.guard, &snapshot)?;
        verify_runner(request.attempt_id, request.runner_id, &snapshot)?;
        verify_mutation_time(request.attempt_id, request.observed_at, &snapshot)?;
        snapshot
            .lifecycle
            .validate_transition(request.next)
            .map_err(|_| AttemptStoreError::InvalidTransition {
                attempt_id: request.attempt_id,
                from: snapshot.lifecycle,
                to: request.next,
            })?;
        let next = lifecycle_name(request.next);
        let result = sqlx::query(
            r"
            UPDATE job_attempts
            SET lifecycle = $4,
                lease_id = CASE
                    WHEN $4 IN ('leased', 'preparing', 'running', 'cancelling', 'finalizing')
                    THEN lease_id ELSE NULL END,
                runner_id = CASE
                    WHEN $4 IN ('leased', 'preparing', 'running', 'cancelling', 'finalizing')
                    THEN runner_id ELSE NULL END,
                lease_issued_at_ms = CASE
                    WHEN $4 IN ('leased', 'preparing', 'running', 'cancelling', 'finalizing')
                    THEN lease_issued_at_ms ELSE NULL END,
                lease_expires_at_ms = CASE
                    WHEN $4 IN ('leased', 'preparing', 'running', 'cancelling', 'finalizing')
                    THEN lease_expires_at_ms ELSE NULL END,
                queued_at_ms = CASE WHEN $4 = 'queued' THEN $5 ELSE queued_at_ms END,
                changed_at_ms = $5
            WHERE id = $1
              AND lease_id = $2
              AND fencing_token = $3
              AND runner_id = $6
              AND changed_at_ms <= $5
            ",
        )
        .bind(request.attempt_id.as_uuid())
        .bind(request.guard.lease_id().as_uuid())
        .bind(fencing_to_i64(request.guard.fencing_token())?)
        .bind(next)
        .bind(request.observed_at.get())
        .bind(request.runner_id.as_uuid())
        .execute(&mut *transaction)
        .await
        .map_err(operation_error)?;
        require_single_update(result.rows_affected())?;
        transaction.commit().await.map_err(operation_error)?;
        Ok(())
    }

    async fn requeue_expired(
        &self,
        now: UnixMillis,
        maximum_failures: u32,
        limit: u32,
    ) -> Result<Vec<AttemptId>, AttemptStoreError> {
        if maximum_failures == 0 {
            return Err(AttemptStoreError::InvalidRetryPolicy);
        }
        let maximum_failures =
            i32::try_from(maximum_failures).map_err(|_| AttemptStoreError::InvalidRetryPolicy)?;
        let limit = i64::from(limit);
        let rows = sqlx::query(
            r"
            WITH expired AS (
                SELECT id
                FROM job_attempts
                WHERE lifecycle IN ('leased', 'preparing', 'running', 'cancelling', 'finalizing')
                  AND lease_expires_at_ms <= $1
                  AND changed_at_ms <= $1
                ORDER BY lease_expires_at_ms, id
                FOR UPDATE SKIP LOCKED
                LIMIT $3
            )
            UPDATE job_attempts AS attempt
            SET lifecycle = CASE
                    WHEN attempt.lease_failures + 1 >= $2 THEN 'lost'
                    ELSE 'queued' END,
                lease_id = NULL,
                runner_id = NULL,
                lease_issued_at_ms = NULL,
                lease_expires_at_ms = NULL,
                lease_failures = attempt.lease_failures + 1,
                queued_at_ms = CASE
                    WHEN attempt.lease_failures + 1 >= $2 THEN attempt.queued_at_ms
                    ELSE $1 END,
                changed_at_ms = $1
            FROM expired
            WHERE attempt.id = expired.id
            RETURNING attempt.id
            ",
        )
        .bind(now.get())
        .bind(maximum_failures)
        .bind(limit)
        .fetch_all(&self.pool)
        .await
        .map_err(operation_error)?;

        rows.into_iter()
            .map(|row| {
                row.try_get::<Uuid, _>("id")
                    .map(AttemptId::from_uuid)
                    .map_err(operation_error)
            })
            .collect()
    }
}

#[async_trait]
impl TenantAttemptQuery for PostgresStore {
    async fn get_attempt_for_tenant(
        &self,
        tenant: &TenantScope,
        attempt_id: AttemptId,
    ) -> Result<AttemptSnapshot, AttemptStoreError> {
        let row = sqlx::query(
            r"
            SELECT attempt.id, attempt.job_id, attempt.attempt_number,
                   attempt.lifecycle, attempt.fencing_token, attempt.lease_id,
                   attempt.runner_id, attempt.lease_issued_at_ms,
                   attempt.lease_expires_at_ms, attempt.lease_failures,
                   attempt.queued_at_ms, attempt.changed_at_ms
            FROM job_attempts AS attempt
            JOIN jobs AS job ON job.id = attempt.job_id
            JOIN workflow_runs AS run ON run.id = job.run_id
            JOIN workflow_definitions AS workflow
              ON workflow.id = run.workflow_id
             AND workflow.repository_id = run.repository_id
            JOIN repositories AS repository
              ON repository.id = workflow.repository_id
            WHERE attempt.id = $1
              AND repository.tenant_id = $2
            ",
        )
        .bind(attempt_id.as_uuid())
        .bind(tenant.as_str())
        .fetch_optional(&self.pool)
        .await
        .map_err(operation_error)?
        .ok_or(AttemptStoreError::NotFound(attempt_id))?;

        decode_snapshot(&row)
    }
}

fn decode_snapshot(row: &sqlx::postgres::PgRow) -> Result<AttemptSnapshot, AttemptStoreError> {
    let attempt_id = AttemptId::from_uuid(row.try_get("id").map_err(operation_error)?);
    let job_id = JobId::from_uuid(row.try_get("job_id").map_err(operation_error)?);
    let attempt_number = u32::try_from(
        row.try_get::<i32, _>("attempt_number")
            .map_err(operation_error)?,
    )
    .ok()
    .and_then(|value| AttemptNumber::new(value).ok())
    .ok_or_else(|| AttemptStoreError::corrupt_data("invalid attempt number"))?;
    let lifecycle_name: &str = row.try_get("lifecycle").map_err(operation_error)?;
    let lifecycle = parse_lifecycle(lifecycle_name)?;
    let raw_fence: i64 = row.try_get("fencing_token").map_err(operation_error)?;
    let fencing_token = if raw_fence == 0 {
        None
    } else {
        Some(decode_fencing_token(raw_fence)?)
    };
    let lease_id = row
        .try_get::<Option<Uuid>, _>("lease_id")
        .map_err(operation_error)?
        .map(LeaseId::from_uuid);
    let runner_id = row
        .try_get::<Option<Uuid>, _>("runner_id")
        .map_err(operation_error)?
        .map(RunnerId::from_uuid);
    let lease_issued_at = row
        .try_get::<Option<i64>, _>("lease_issued_at_ms")
        .map_err(operation_error)?
        .map(UnixMillis::new);
    let lease_expires_at = row
        .try_get::<Option<i64>, _>("lease_expires_at_ms")
        .map_err(operation_error)?
        .map(UnixMillis::new);
    let lease_failures = u32::try_from(
        row.try_get::<i32, _>("lease_failures")
            .map_err(operation_error)?,
    )
    .map_err(|_| AttemptStoreError::corrupt_data("negative lease failure count"))?;
    let queued_at = UnixMillis::new(row.try_get("queued_at_ms").map_err(operation_error)?);
    let changed_at = UnixMillis::new(row.try_get("changed_at_ms").map_err(operation_error)?);

    let active_lease = match (lease_id, runner_id, lease_issued_at, lease_expires_at) {
        (None, None, None, None) => None,
        (Some(lease_id), Some(runner_id), Some(issued_at), Some(expires_at)) => {
            let fencing_token = fencing_token.ok_or_else(|| {
                AttemptStoreError::corrupt_data("active lease is missing its fencing token")
            })?;
            Some(
                Lease::new(
                    lease_id,
                    attempt_id,
                    runner_id,
                    fencing_token,
                    issued_at,
                    expires_at,
                )
                .map_err(AttemptSnapshotError::InvalidLease)?,
            )
        }
        _ => {
            return Err(AttemptStoreError::corrupt_data(
                "active lease columns are incomplete",
            ));
        }
    };

    let mut builder = AttemptSnapshot::builder(
        attempt_id,
        job_id,
        attempt_number,
        lifecycle,
        queued_at,
        changed_at,
    )
    .with_lease_failures(lease_failures);
    if let Some(active_lease) = active_lease {
        builder = builder.with_active_lease(active_lease);
    } else if let Some(fencing_token) = fencing_token {
        builder = builder.with_retained_fencing_token(fencing_token);
    }
    builder.build().map_err(AttemptStoreError::from)
}

async fn locked_snapshot(
    connection: &mut PgConnection,
    attempt_id: AttemptId,
) -> Result<AttemptSnapshot, AttemptStoreError> {
    let row = sqlx::query(
        r"
        SELECT id, job_id, attempt_number, lifecycle, fencing_token,
               lease_id, runner_id, lease_issued_at_ms, lease_expires_at_ms,
               lease_failures, queued_at_ms, changed_at_ms
        FROM job_attempts
        WHERE id = $1
        FOR UPDATE
        ",
    )
    .bind(attempt_id.as_uuid())
    .fetch_optional(connection)
    .await
    .map_err(operation_error)?
    .ok_or(AttemptStoreError::NotFound(attempt_id))?;
    decode_snapshot(&row)
}

fn verify_mutation_time(
    attempt_id: AttemptId,
    observed_at: UnixMillis,
    snapshot: &AttemptSnapshot,
) -> Result<(), AttemptStoreError> {
    verify_state_time(attempt_id, observed_at, snapshot)?;
    snapshot
        .lease_issued_at
        .ok_or_else(|| corrupt("active lease is missing its issuance"))?;
    let expires_at = snapshot
        .lease_expires_at
        .ok_or_else(|| corrupt("active lease is missing its expiration"))?;
    if observed_at >= expires_at {
        return Err(AttemptStoreError::LeaseExpired(attempt_id));
    }
    Ok(())
}

fn verify_state_time(
    attempt_id: AttemptId,
    observed_at: UnixMillis,
    snapshot: &AttemptSnapshot,
) -> Result<(), AttemptStoreError> {
    if observed_at < snapshot.changed_at {
        return Err(AttemptStoreError::MutationPredatesState {
            attempt_id,
            observed_at,
            changed_at: snapshot.changed_at,
        });
    }
    Ok(())
}

fn require_single_update(rows_affected: u64) -> Result<(), AttemptStoreError> {
    if rows_affected == 1 {
        return Ok(());
    }
    Err(corrupt(
        "locked attempt update did not affect exactly one row",
    ))
}

fn corrupt(message: &str) -> AttemptStoreError {
    AttemptStoreError::corrupt_data(message)
}

fn verify_guard(
    attempt_id: AttemptId,
    guard: LeaseGuard,
    snapshot: &AttemptSnapshot,
) -> Result<(), AttemptStoreError> {
    if snapshot.lease_id != Some(guard.lease_id())
        || snapshot.fencing_token != Some(guard.fencing_token())
    {
        return Err(AttemptStoreError::FenceRejected(attempt_id));
    }
    Ok(())
}

fn verify_runner(
    attempt_id: AttemptId,
    runner_id: RunnerId,
    snapshot: &AttemptSnapshot,
) -> Result<(), AttemptStoreError> {
    if snapshot.runner_id != Some(runner_id) {
        return Err(AttemptStoreError::RunnerRejected(attempt_id));
    }
    Ok(())
}

async fn verify_runner_tenant(
    connection: &mut PgConnection,
    attempt_id: AttemptId,
    job_id: JobId,
    runner_id: RunnerId,
) -> Result<(), AttemptStoreError> {
    let matches_tenant: bool = sqlx::query_scalar(
        r"
        SELECT EXISTS (
            SELECT 1
            FROM jobs AS job
            JOIN workflow_runs AS run ON run.id = job.run_id
            JOIN repositories AS repository ON repository.id = run.repository_id
            JOIN runners AS runner
              ON runner.id = $2
             AND runner.tenant_id = repository.tenant_id
            WHERE job.id = $1
        )
        ",
    )
    .bind(job_id.as_uuid())
    .bind(runner_id.as_uuid())
    .fetch_one(connection)
    .await
    .map_err(operation_error)?;
    if !matches_tenant {
        return Err(AttemptStoreError::RunnerRejected(attempt_id));
    }
    Ok(())
}

fn operation_error(error: sqlx::Error) -> AttemptStoreError {
    AttemptStoreError::operation(error)
}

fn decode_fencing_token(value: i64) -> Result<FencingToken, AttemptStoreError> {
    let value = u64::try_from(value)
        .map_err(|_| AttemptStoreError::corrupt_data("negative fencing token"))?;
    FencingToken::new(value).map_err(identifier_error)
}

fn fencing_to_i64(value: FencingToken) -> Result<i64, AttemptStoreError> {
    i64::try_from(value.get())
        .map_err(|_| AttemptStoreError::corrupt_data("fencing token exceeds PostgreSQL BIGINT"))
}

fn identifier_error(error: IdentifierError) -> AttemptStoreError {
    AttemptStoreError::corrupt_data(error.to_string())
}

const fn lifecycle_name(lifecycle: JobLifecycle) -> &'static str {
    match lifecycle {
        JobLifecycle::Queued => "queued",
        JobLifecycle::Leased => "leased",
        JobLifecycle::Preparing => "preparing",
        JobLifecycle::Running => "running",
        JobLifecycle::Cancelling => "cancelling",
        JobLifecycle::Finalizing => "finalizing",
        JobLifecycle::Succeeded => "succeeded",
        JobLifecycle::Failed => "failed",
        JobLifecycle::Cancelled => "cancelled",
        JobLifecycle::TimedOut => "timed_out",
        JobLifecycle::Skipped => "skipped",
        JobLifecycle::Lost => "lost",
    }
}

fn parse_lifecycle(value: &str) -> Result<JobLifecycle, AttemptStoreError> {
    match value {
        "queued" => Ok(JobLifecycle::Queued),
        "leased" => Ok(JobLifecycle::Leased),
        "preparing" => Ok(JobLifecycle::Preparing),
        "running" => Ok(JobLifecycle::Running),
        "cancelling" => Ok(JobLifecycle::Cancelling),
        "finalizing" => Ok(JobLifecycle::Finalizing),
        "succeeded" => Ok(JobLifecycle::Succeeded),
        "failed" => Ok(JobLifecycle::Failed),
        "cancelled" => Ok(JobLifecycle::Cancelled),
        "timed_out" => Ok(JobLifecycle::TimedOut),
        "skipped" => Ok(JobLifecycle::Skipped),
        "lost" => Ok(JobLifecycle::Lost),
        other => Err(AttemptStoreError::corrupt_data(format!(
            "unknown job lifecycle {other:?}"
        ))),
    }
}
