use async_trait::async_trait;
use automata_ci_core::{AttemptId, JobLifecycle, RunId};
use sqlx::{Postgres, Row as _, Transaction};
use uuid::Uuid;

use super::{PostgresStore, parse_lifecycle};
use automata_ci_store::{
    BlockedAttemptRepository, BlockedConclusion, ConcludeBlockedAttempt,
    ControlPlaneMaintenanceReport, ControlPlaneMaintenanceRepository,
    ControlPlaneMaintenanceRequest, ExpiredAttemptDisposition, ExpiredAttemptMaintenance,
    RunnableScanLimit, RunnerPayloadTombstoneReason, StoreError,
};

#[async_trait]
impl ControlPlaneMaintenanceRepository for PostgresStore {
    async fn maintain_control_plane(
        &self,
        request: ControlPlaneMaintenanceRequest,
    ) -> Result<ControlPlaneMaintenanceReport, StoreError> {
        let candidates = expired_attempt_candidates(self, request).await?;
        let mut expired_attempts = Vec::with_capacity(candidates.len());
        for attempt_id in candidates {
            if let Some(result) = reap_expired_attempt(self, request, attempt_id).await? {
                expired_attempts.push(result);
            }
        }

        let skipped_blocked_attempts = propagate_blocked_attempts(self, request).await?;

        let candidates = stale_session_candidates(self, request).await?;
        let mut closed_stale_sessions = 0_u16;
        for candidate in candidates {
            if close_stale_session(self, request, candidate).await? {
                closed_stale_sessions = closed_stale_sessions.checked_add(1).ok_or_else(|| {
                    StoreError::corrupt_data("maintenance session count exceeded its batch bound")
                })?;
            }
        }

        Ok(
            automata_ci_store::adapter_spi::control_plane_maintenance_report(
                expired_attempts,
                skipped_blocked_attempts,
                closed_stale_sessions,
            ),
        )
    }
}

async fn propagate_blocked_attempts(
    store: &PostgresStore,
    request: ControlPlaneMaintenanceRequest,
) -> Result<u16, StoreError> {
    let mut skipped = 0_u16;
    let mut inspected = 0_u16;
    loop {
        let remaining = request.batch_size().get().saturating_sub(inspected);
        if remaining == 0 {
            return Ok(skipped);
        }
        let limit = RunnableScanLimit::new(remaining).map_err(|_| {
            StoreError::corrupt_data("maintenance batch exceeded runnable scan limit")
        })?;
        let candidates = store.scan_blocked(limit, request.observed_at()).await?;
        if candidates.is_empty() {
            return Ok(skipped);
        }

        let mut made_progress = false;
        for candidate in candidates {
            inspected = inspected.checked_add(1).ok_or_else(|| {
                StoreError::corrupt_data("maintenance blocked scan exceeded its batch bound")
            })?;
            if store
                .conclude_blocked(ConcludeBlockedAttempt::new(
                    candidate.attempt_id(),
                    request.observed_at(),
                ))
                .await?
                == BlockedConclusion::Skipped
            {
                skipped = skipped.checked_add(1).ok_or_else(|| {
                    StoreError::corrupt_data("maintenance blocked count exceeded its batch bound")
                })?;
                made_progress = true;
            }
        }
        if !made_progress {
            return Ok(skipped);
        }
    }
}

async fn expired_attempt_candidates(
    store: &PostgresStore,
    request: ControlPlaneMaintenanceRequest,
) -> Result<Vec<AttemptId>, StoreError> {
    let mut transaction = store.pool.begin().await.map_err(StoreError::operation)?;
    super::pin_runner_attempt_read_committed(&mut transaction).await?;
    let database_now = super::runner_attempt_database_now(&mut transaction).await?;
    super::validate_runner_attempt_caller_clock(request.observed_at(), database_now)?;
    let rows = sqlx::query_scalar::<_, Uuid>(
        r"
        SELECT id
        FROM job_attempts
        WHERE lifecycle IN ('leased', 'preparing', 'running', 'cancelling', 'finalizing')
          AND lease_expires_at_ms <= $1
          AND changed_at_ms <= $1
        ORDER BY lease_expires_at_ms, id
        LIMIT $2
        ",
    )
    .bind(database_now.get())
    .bind(i64::from(request.batch_size().get()))
    .fetch_all(&mut *transaction)
    .await
    .map_err(StoreError::operation)?;
    transaction.commit().await.map_err(StoreError::operation)?;
    Ok(rows.into_iter().map(AttemptId::from_uuid).collect())
}

async fn reap_expired_attempt(
    store: &PostgresStore,
    request: ControlPlaneMaintenanceRequest,
    attempt_id: AttemptId,
) -> Result<Option<ExpiredAttemptMaintenance>, StoreError> {
    let mut transaction = store.pool.begin().await.map_err(StoreError::operation)?;
    super::pin_runner_attempt_read_committed(&mut transaction).await?;

    // Admission and terminal-result paths acquire this repository/concurrency
    // serialization lock before locking an attempt. Reapers preserve exactly
    // that order, then recheck the unlocked discovery result under row lock.
    super::admission::lock_attempt_concurrency(&mut transaction, attempt_id).await?;
    let Some(mutation) = lock_expired_attempt(&mut transaction, request, attempt_id).await? else {
        transaction.commit().await.map_err(StoreError::operation)?;
        return Ok(None);
    };
    apply_expired_attempt(&mut transaction, attempt_id, mutation).await?;
    let reconciliation = super::admission::reconcile_run_in_transaction(
        &mut transaction,
        mutation.run_id,
        mutation.decided_at,
    )
    .await?;
    transaction.commit().await.map_err(StoreError::operation)?;
    Ok(Some(
        automata_ci_store::adapter_spi::expired_attempt_maintenance(
            attempt_id,
            mutation.disposition,
            reconciliation,
        ),
    ))
}

#[derive(Clone, Copy, Debug)]
struct ExpiredAttemptMutation {
    run_id: RunId,
    next_failures: i32,
    disposition: ExpiredAttemptDisposition,
    decided_at: automata_ci_core::UnixMillis,
}

async fn lock_expired_attempt(
    transaction: &mut Transaction<'_, Postgres>,
    request: ControlPlaneMaintenanceRequest,
    attempt_id: AttemptId,
) -> Result<Option<ExpiredAttemptMutation>, StoreError> {
    let row = sqlx::query(
        r"
        SELECT attempt.lifecycle, attempt.lease_expires_at_ms,
               attempt.lease_failures, attempt.changed_at_ms, job.run_id
        FROM job_attempts AS attempt
        JOIN jobs AS job ON job.id = attempt.job_id
        WHERE attempt.id = $1
        FOR UPDATE OF attempt
        ",
    )
    .bind(attempt_id.as_uuid())
    .fetch_optional(&mut **transaction)
    .await
    .map_err(StoreError::operation)?;
    let Some(row) = row else {
        return Ok(None);
    };
    let lifecycle = parse_lifecycle(
        row.try_get::<&str, _>("lifecycle")
            .map_err(StoreError::operation)?,
    )?;
    let lease_expires_at: Option<i64> = row
        .try_get("lease_expires_at_ms")
        .map_err(StoreError::operation)?;
    let changed_at: i64 = row
        .try_get("changed_at_ms")
        .map_err(StoreError::operation)?;
    let database_now = super::runner_attempt_database_now(transaction).await?;
    super::validate_runner_attempt_caller_clock(request.observed_at(), database_now)?;
    if !is_expired_active(lifecycle, lease_expires_at, changed_at, database_now.get()) {
        return Ok(None);
    }

    let failures: i32 = row
        .try_get("lease_failures")
        .map_err(StoreError::operation)?;
    let next_failures = failures
        .checked_add(1)
        .ok_or_else(|| StoreError::corrupt_data("attempt lease failure counter is exhausted"))?;
    let maximum_failures = i32::try_from(request.maximum_lease_failures().get())
        .map_err(|_| StoreError::corrupt_data("validated lease failure limit is out of range"))?;
    let disposition = if matches!(
        lifecycle,
        JobLifecycle::Running | JobLifecycle::Cancelling | JobLifecycle::Finalizing
    ) || next_failures >= maximum_failures
    {
        ExpiredAttemptDisposition::Lost
    } else {
        ExpiredAttemptDisposition::Requeued
    };
    Ok(Some(ExpiredAttemptMutation {
        run_id: RunId::from_uuid(row.try_get("run_id").map_err(StoreError::operation)?),
        next_failures,
        disposition,
        decided_at: database_now,
    }))
}

async fn apply_expired_attempt(
    transaction: &mut Transaction<'_, Postgres>,
    attempt_id: AttemptId,
    mutation: ExpiredAttemptMutation,
) -> Result<(), StoreError> {
    let next_lifecycle = match mutation.disposition {
        ExpiredAttemptDisposition::Requeued => "queued",
        ExpiredAttemptDisposition::Lost => "lost",
    };
    let rows = sqlx::query(
        r"
        UPDATE job_attempts
        SET lifecycle = $2,
            lease_id = NULL,
            runner_id = NULL,
            lease_issued_at_ms = NULL,
            lease_expires_at_ms = NULL,
            runner_session_id = NULL,
            runner_session_epoch = NULL,
            runner_generation = NULL,
            runner_slot = NULL,
            lease_failures = $3,
            queued_at_ms = CASE WHEN $2 = 'queued' THEN $4 ELSE queued_at_ms END,
            changed_at_ms = $4
        WHERE id = $1
        ",
    )
    .bind(attempt_id.as_uuid())
    .bind(next_lifecycle)
    .bind(mutation.next_failures)
    .bind(mutation.decided_at.get())
    .execute(&mut **transaction)
    .await
    .map_err(StoreError::operation)?
    .rows_affected();
    if rows != 1 {
        return Err(StoreError::corrupt_data(
            "locked expired attempt update did not affect exactly one row",
        ));
    }

    Ok(())
}

const fn is_expired_active(
    lifecycle: JobLifecycle,
    lease_expires_at: Option<i64>,
    changed_at: i64,
    observed_at: i64,
) -> bool {
    matches!(
        lifecycle,
        JobLifecycle::Leased
            | JobLifecycle::Preparing
            | JobLifecycle::Running
            | JobLifecycle::Cancelling
            | JobLifecycle::Finalizing
    ) && matches!(lease_expires_at, Some(expires_at) if expires_at <= observed_at)
        && changed_at <= observed_at
}

#[derive(Clone, Copy, Debug)]
struct StaleSessionCandidate {
    session_id: Uuid,
    runner_id: Uuid,
}

fn maintenance_stale_timeout_millis(
    request: ControlPlaneMaintenanceRequest,
) -> Result<i64, StoreError> {
    request
        .observed_at()
        .get()
        .checked_sub(request.stale_session_cutoff().get())
        .filter(|timeout| timeout.is_positive())
        .ok_or_else(|| StoreError::corrupt_data("invalid maintenance stale-session timeout"))
}

async fn stale_session_candidates(
    store: &PostgresStore,
    request: ControlPlaneMaintenanceRequest,
) -> Result<Vec<StaleSessionCandidate>, StoreError> {
    let stale_timeout_millis = maintenance_stale_timeout_millis(request)?;
    let mut transaction = store.pool.begin().await.map_err(StoreError::operation)?;
    super::pin_runner_attempt_read_committed(&mut transaction).await?;
    let database_now = super::runner_attempt_database_now(&mut transaction).await?;
    super::validate_runner_attempt_caller_clock(request.observed_at(), database_now)?;
    let database_cutoff = database_now
        .get()
        .checked_sub(stale_timeout_millis)
        .ok_or_else(|| StoreError::corrupt_data("database stale-session cutoff overflowed"))?;
    let rows = sqlx::query(
        r"
        SELECT id, runner_id
        FROM runner_sessions
        WHERE disconnected_at_ms IS NULL
          AND heartbeat_at_ms <= $1
        ORDER BY heartbeat_at_ms, id
        LIMIT $2
        ",
    )
    .bind(database_cutoff)
    .bind(i64::from(request.batch_size().get()))
    .fetch_all(&mut *transaction)
    .await
    .map_err(StoreError::operation)?;
    transaction.commit().await.map_err(StoreError::operation)?;
    rows.into_iter()
        .map(|row| {
            Ok(StaleSessionCandidate {
                session_id: row.try_get("id").map_err(StoreError::operation)?,
                runner_id: row.try_get("runner_id").map_err(StoreError::operation)?,
            })
        })
        .collect()
}

async fn close_stale_session(
    store: &PostgresStore,
    request: ControlPlaneMaintenanceRequest,
    candidate: StaleSessionCandidate,
) -> Result<bool, StoreError> {
    let mut transaction = store.pool.begin().await.map_err(StoreError::operation)?;
    super::pin_runner_attempt_read_committed(&mut transaction).await?;
    let Some(authority) = lock_stale_session(&mut transaction, request, candidate).await? else {
        transaction.commit().await.map_err(StoreError::operation)?;
        return Ok(false);
    };
    apply_stale_session_close(&mut transaction, candidate, authority).await?;
    transaction.commit().await.map_err(StoreError::operation)?;
    Ok(true)
}

#[derive(Clone, Copy, Debug)]
struct StaleSessionAuthority {
    generation: i64,
    epoch: i64,
    decided_at: automata_ci_core::UnixMillis,
    stale_cutoff: automata_ci_core::UnixMillis,
}

async fn lock_stale_session(
    transaction: &mut Transaction<'_, Postgres>,
    request: ControlPlaneMaintenanceRequest,
    candidate: StaleSessionCandidate,
) -> Result<Option<StaleSessionAuthority>, StoreError> {
    let runner =
        sqlx::query("SELECT generation, session_epoch FROM runners WHERE id = $1 FOR UPDATE")
            .bind(candidate.runner_id)
            .fetch_optional(&mut **transaction)
            .await
            .map_err(StoreError::operation)?
            .ok_or_else(|| {
                StoreError::corrupt_data("live runner session references a missing runner")
            })?;
    let current_generation: i64 = runner
        .try_get("generation")
        .map_err(StoreError::operation)?;
    let current_epoch: i64 = runner
        .try_get("session_epoch")
        .map_err(StoreError::operation)?;

    let session = sqlx::query(
        r"
        SELECT runner_generation, session_epoch, heartbeat_at_ms, disconnected_at_ms
        FROM runner_sessions
        WHERE id = $1 AND runner_id = $2
        FOR UPDATE
        ",
    )
    .bind(candidate.session_id)
    .bind(candidate.runner_id)
    .fetch_optional(&mut **transaction)
    .await
    .map_err(StoreError::operation)?;
    let Some(session) = session else {
        return Ok(None);
    };
    let disconnected_at: Option<i64> = session
        .try_get("disconnected_at_ms")
        .map_err(StoreError::operation)?;
    let heartbeat_at: i64 = session
        .try_get("heartbeat_at_ms")
        .map_err(StoreError::operation)?;
    let database_now = super::runner_attempt_database_now(transaction).await?;
    super::validate_runner_attempt_caller_clock(request.observed_at(), database_now)?;
    let stale_timeout_millis = maintenance_stale_timeout_millis(request)?;
    let stale_cutoff = database_now
        .get()
        .checked_sub(stale_timeout_millis)
        .map(automata_ci_core::UnixMillis::new)
        .ok_or_else(|| StoreError::corrupt_data("database stale-session cutoff overflowed"))?;
    if disconnected_at.is_some() || heartbeat_at > stale_cutoff.get() {
        return Ok(None);
    }
    let session_generation: i64 = session
        .try_get("runner_generation")
        .map_err(StoreError::operation)?;
    let session_epoch: i64 = session
        .try_get("session_epoch")
        .map_err(StoreError::operation)?;
    if session_generation != current_generation || session_epoch != current_epoch {
        return Err(StoreError::corrupt_data(
            "live runner session does not match current runner authority",
        ));
    }
    Ok(Some(StaleSessionAuthority {
        generation: session_generation,
        epoch: session_epoch,
        decided_at: database_now,
        stale_cutoff,
    }))
}

async fn apply_stale_session_close(
    transaction: &mut Transaction<'_, Postgres>,
    candidate: StaleSessionCandidate,
    authority: StaleSessionAuthority,
) -> Result<(), StoreError> {
    let rows = sqlx::query(
        r"
        UPDATE runner_sessions
        SET disconnected_at_ms = $3
        WHERE id = $1 AND runner_id = $2
          AND runner_generation = $4 AND session_epoch = $5
          AND disconnected_at_ms IS NULL AND heartbeat_at_ms <= $6
        ",
    )
    .bind(candidate.session_id)
    .bind(candidate.runner_id)
    .bind(authority.decided_at.get())
    .bind(authority.generation)
    .bind(authority.epoch)
    .bind(authority.stale_cutoff.get())
    .execute(&mut **transaction)
    .await
    .map_err(StoreError::operation)?
    .rows_affected();
    if rows != 1 {
        return Err(StoreError::corrupt_data(
            "locked stale session update did not affect exactly one row",
        ));
    }
    super::g1::cleanup_session_lease_request_state_uuid(transaction, candidate.session_id).await?;
    super::g1::tombstone_session_runner_payloads_uuid(
        transaction,
        candidate.session_id,
        RunnerPayloadTombstoneReason::SessionClosed,
        authority.decided_at,
    )
    .await?;
    let rows = sqlx::query(
        r"
        UPDATE runners
        SET status = 'offline',
            last_seen_at_ms = greatest(coalesce(last_seen_at_ms, $4), $4),
            updated_at_ms = greatest(updated_at_ms, $4)
        WHERE id = $1 AND generation = $2 AND session_epoch = $3
        ",
    )
    .bind(candidate.runner_id)
    .bind(authority.generation)
    .bind(authority.epoch)
    .bind(authority.decided_at.get())
    .execute(&mut **transaction)
    .await
    .map_err(StoreError::operation)?
    .rows_affected();
    if rows != 1 {
        return Err(StoreError::corrupt_data(
            "stale session lost current runner authority while locked",
        ));
    }
    Ok(())
}
