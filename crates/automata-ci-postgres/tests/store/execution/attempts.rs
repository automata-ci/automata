use std::{
    collections::HashSet,
    sync::atomic::{AtomicU16, Ordering},
    time::Duration,
};

use crate::support::{TestDatabase, TestResult, run_with_database, seed_control_plane};
use automata_ci_core::{
    AttemptId, AttemptNumber, FencingToken, JobId, JobLifecycle, LeaseGuard, LeaseId, UnixMillis,
};
use automata_ci_store::{
    AcquireLease, AttemptCommandError, AttemptStoreError, ConcludeQueuedAttempt,
    InternalAttemptRepository as _, QueuedAttempt, RenewLease, RunnerSessionFence,
    StableRunnerSlot, TenantAttemptQuery as _, TenantScope, TransitionAttempt,
};

const LIVE_LEASE_MILLIS: i64 = 60_000;
const EXTENDED_LEASE_MILLIS: i64 = 120_000;

#[derive(Debug, Eq, PartialEq)]
struct AttemptOutputSafety {
    secret_exposure: String,
    raw_log_disposition: String,
    requested_visibility: String,
    effective_visibility: String,
    reason: String,
    schema: i32,
    classified_at: i64,
}

#[tokio::test]
#[ignore = "requires AUTOMATA_TEST_DATABASE_URL and creates a temporary schema"]
async fn acquisition_is_atomic_and_reacquisition_advances_the_fence() -> TestResult {
    run_with_database(|database| async move { exercise_atomic_acquisition(&database).await }).await
}

#[tokio::test]
#[ignore = "requires AUTOMATA_TEST_DATABASE_URL and creates a temporary schema"]
async fn queued_creation_persists_current_safety_and_retries_reuse_the_job_ceiling() -> TestResult {
    run_with_database(|database| async move {
        let current = seed_control_plane(database.pool(), 1).await?;
        let current_attempt = insert_attempt(&database, current.job_id, 1, 70).await?;
        assert_eq!(
            load_attempt_output_safety(&database, current_attempt).await?,
            AttemptOutputSafety {
                secret_exposure: "readable_secret".to_owned(),
                raw_log_disposition: "persist".to_owned(),
                requested_visibility: "private".to_owned(),
                effective_visibility: "private".to_owned(),
                reason: "repository_policy".to_owned(),
                schema: 1,
                classified_at: 70,
            }
        );

        let lower = seed_control_plane(database.pool(), 1).await?;
        let admitted_attempt = AttemptId::new();
        sqlx::query(
            r"
            INSERT INTO job_attempts (
                id, job_id, attempt_number, lifecycle, fencing_token,
                lease_failures, queued_at_ms, changed_at_ms,
                secret_exposure_class, raw_log_disposition,
                requested_log_visibility, effective_log_visibility,
                output_safety_reason, output_safety_schema, classified_at_ms
            ) VALUES (
                $1,$2,1,'queued',0,0,71,71,
                'secretless','persist','private','private',
                'repository_policy',1,71
            )
            ",
        )
        .bind(admitted_attempt.as_uuid())
        .bind(lower.job_id.as_uuid())
        .execute(database.pool())
        .await?;
        database
            .store()
            .conclude_queued(conclusion_request(
                admitted_attempt,
                JobLifecycle::Cancelled,
                72,
            ))
            .await?;
        let retry = insert_attempt(&database, lower.job_id, 2, 73).await?;
        assert_eq!(
            load_attempt_output_safety(&database, retry).await?,
            AttemptOutputSafety {
                secret_exposure: "secretless".to_owned(),
                raw_log_disposition: "persist".to_owned(),
                requested_visibility: "private".to_owned(),
                effective_visibility: "private".to_owned(),
                reason: "repository_policy".to_owned(),
                schema: 1,
                classified_at: 71,
            }
        );
        Ok(())
    })
    .await
}

#[tokio::test]
#[ignore = "requires AUTOMATA_TEST_DATABASE_URL and creates a temporary schema"]
async fn queued_creation_rejects_a_missing_job_without_writes() -> TestResult {
    run_with_database(|database| async move {
        let attempt_id = AttemptId::new();
        let missing_job_id = JobId::new();
        let result = database
            .store()
            .insert_queued(QueuedAttempt::new(
                attempt_id,
                missing_job_id,
                AttemptNumber::new(1)?,
                UnixMillis::new(70),
            ))
            .await;
        assert!(matches!(
            result,
            Err(AttemptStoreError::CorruptData(message))
                if message == "queued attempt references a missing workflow job"
        ));

        let persisted: i64 = sqlx::query_scalar(
            "SELECT count(*)::BIGINT FROM job_attempts WHERE id = $1 OR job_id = $2",
        )
        .bind(attempt_id.as_uuid())
        .bind(missing_job_id.as_uuid())
        .fetch_one(database.pool())
        .await?;
        assert_eq!(persisted, 0);
        Ok(())
    })
    .await
}

#[tokio::test]
#[ignore = "requires AUTOMATA_TEST_DATABASE_URL and creates a temporary schema"]
async fn guarded_phases_and_renewals_are_strict() -> TestResult {
    run_with_database(|database| async move { exercise_guarded_phases(&database).await }).await
}

#[tokio::test]
#[ignore = "requires AUTOMATA_TEST_DATABASE_URL and creates a temporary schema"]
async fn expiry_reaper_skips_locked_rows_honors_limits_and_marks_lost() -> TestResult {
    run_with_database(|database| async move { exercise_expiry_reaper(&database).await }).await
}

#[tokio::test]
#[ignore = "requires AUTOMATA_TEST_DATABASE_URL and creates a temporary schema"]
async fn queued_conclusion_races_acquisition_and_enforces_monotonic_time() -> TestResult {
    run_with_database(|database| async move { exercise_queued_conclusion(&database).await }).await
}

#[tokio::test]
#[ignore = "requires AUTOMATA_TEST_DATABASE_URL and creates a temporary schema"]
async fn tenant_queries_hide_cross_tenant_attempts() -> TestResult {
    run_with_database(|database| async move { exercise_tenant_queries(&database).await }).await
}

#[tokio::test]
#[ignore = "requires AUTOMATA_TEST_DATABASE_URL and creates a temporary schema"]
async fn direct_attempt_ports_enforce_new_work_and_existing_work_authority() -> TestResult {
    run_with_database(|database| async move {
        let seed = seed_control_plane(database.pool(), 1).await?;
        let fence = seed.session_fences[0];
        let attempt_id = insert_attempt(&database, seed.job_id, 1, 10).await?;
        sqlx::query("UPDATE runners SET desired_state = 'draining' WHERE id = $1")
            .bind(fence.runner_id().as_uuid())
            .execute(database.pool())
            .await?;
        assert!(matches!(
            database
                .store()
                .acquire_lease(
                    fresh_acquire_request(&database, attempt_id, fence, LIVE_LEASE_MILLIS)
                        .await?,
                )
                .await,
            Err(AttemptStoreError::RunnerRejected(id)) if id == attempt_id
        ));

        sqlx::query("UPDATE runners SET desired_state = 'active' WHERE id = $1")
            .bind(fence.runner_id().as_uuid())
            .execute(database.pool())
            .await?;
        let lease = database
            .store()
            .acquire_lease(
                fresh_acquire_request(&database, attempt_id, fence, LIVE_LEASE_MILLIS).await?,
            )
            .await?;
        sqlx::query("UPDATE runners SET desired_state = 'draining' WHERE id = $1")
            .bind(fence.runner_id().as_uuid())
            .execute(database.pool())
            .await?;
        database
            .store()
            .renew_lease(
                fresh_renew_request(
                    &database,
                    attempt_id,
                    fence,
                    lease.guard(),
                    EXTENDED_LEASE_MILLIS,
                )
                .await?,
            )
            .await?;
        let transition_at = database_now(&database).await?;
        database
            .store()
            .transition(transition_request(
                attempt_id,
                fence,
                lease.guard(),
                JobLifecycle::Preparing,
                transition_at.get(),
            ))
            .await?;

        sqlx::query("UPDATE runners SET desired_state = 'disabled' WHERE id = $1")
            .bind(fence.runner_id().as_uuid())
            .execute(database.pool())
            .await?;
        assert!(matches!(
            database
                .store()
                .renew_lease(
                    fresh_renew_request(
                        &database,
                        attempt_id,
                        fence,
                        lease.guard(),
                        EXTENDED_LEASE_MILLIS,
                    )
                    .await?,
                )
                .await,
            Err(AttemptStoreError::RunnerRejected(id)) if id == attempt_id
        ));
        assert_eq!(
            database.store().get_attempt(attempt_id).await?.lifecycle(),
            JobLifecycle::Preparing
        );
        Ok(())
    })
    .await
}

#[allow(clippy::too_many_lines)] // One scenario proves acquisition, expiry, and reacquisition.
async fn exercise_atomic_acquisition(database: &TestDatabase) -> TestResult {
    let seed = seed_control_plane(database.pool(), 2).await?;
    let attempt_id = insert_attempt(database, seed.job_id, 1, 10).await?;
    let observed_at = database_now(database).await?;
    let expires_at = checked_add_millis(observed_at, LIVE_LEASE_MILLIS)?;
    let first = acquire_request(
        attempt_id,
        seed.session_fences[0],
        observed_at.get(),
        expires_at.get(),
    );
    let second = acquire_request(
        attempt_id,
        seed.session_fences[1],
        observed_at.get(),
        expires_at.get(),
    );

    let (left, right) = tokio::join!(
        database.store().acquire_lease(first),
        database.store().acquire_lease(second)
    );
    let acquisition_upper = database_now(database).await?;
    let winner = match (left, right) {
        (Ok(lease), Err(AttemptStoreError::NotQueued { .. }))
        | (Err(AttemptStoreError::NotQueued { .. }), Ok(lease)) => lease,
        outcomes => panic!("exactly one concurrent acquisition must win: {outcomes:?}"),
    };
    assert_eq!(winner.fencing_token().get(), 1);
    assert_database_time_bound(winner.issued_at(), observed_at, acquisition_upper);
    assert_database_time_bound(
        winner.expires_at(),
        expires_at,
        checked_add_millis(acquisition_upper, LIVE_LEASE_MILLIS)?,
    );
    let winner_session = if winner.runner_id() == seed.runner_ids[0] {
        seed.session_fences[0]
    } else {
        seed.session_fences[1]
    };

    expire_active_attempt(database, attempt_id).await?;
    let requeue_at = database_now(database).await?;
    let requeued = database.store().requeue_expired(requeue_at, 3, 10).await?;
    assert_eq!(requeued, vec![attempt_id]);
    let reacquired = database
        .store()
        .acquire_lease(
            fresh_acquire_request(
                database,
                attempt_id,
                seed.session_fences[0],
                LIVE_LEASE_MILLIS,
            )
            .await?,
        )
        .await?;
    assert_eq!(reacquired.fencing_token().get(), 2);

    let stale_at = database_now(database).await?;
    let stale = database
        .store()
        .transition(transition_request(
            attempt_id,
            winner_session,
            winner.guard(),
            JobLifecycle::Preparing,
            stale_at.get(),
        ))
        .await;
    assert!(matches!(stale, Err(AttemptStoreError::FenceRejected(id)) if id == attempt_id));

    let predating_seed = seed_control_plane(database.pool(), 1).await?;
    let current = database_now(database).await?;
    let future_state = checked_add_millis(current, 30_000)?;
    let predating_id =
        insert_attempt(database, predating_seed.job_id, 1, future_state.get()).await?;
    let predating = database
        .store()
        .acquire_lease(acquire_request(
            predating_id,
            predating_seed.session_fences[0],
            current.get(),
            checked_add_millis(current, LIVE_LEASE_MILLIS)?.get(),
        ))
        .await;
    assert!(matches!(
        predating,
        Err(AttemptStoreError::MutationPredatesState { attempt_id: id, .. })
            if id == predating_id
    ));

    let exhausted_seed = seed_control_plane(database.pool(), 1).await?;
    let exhausted_id = insert_attempt(database, exhausted_seed.job_id, 1, 40).await?;
    sqlx::query("UPDATE job_attempts SET fencing_token = $2 WHERE id = $1")
        .bind(exhausted_id.as_uuid())
        .bind(i64::MAX)
        .execute(database.pool())
        .await?;
    let exhausted = database
        .store()
        .acquire_lease(
            fresh_acquire_request(
                database,
                exhausted_id,
                exhausted_seed.session_fences[0],
                LIVE_LEASE_MILLIS,
            )
            .await?,
        )
        .await;
    assert!(matches!(
        exhausted,
        Err(AttemptStoreError::FencingTokenExhausted(id)) if id == exhausted_id
    ));
    Ok(())
}

async fn exercise_guarded_phases(database: &TestDatabase) -> TestResult {
    let seed = seed_control_plane(database.pool(), 2).await?;
    let attempt_id = insert_attempt(database, seed.job_id, 1, 100).await?;
    let lease = database
        .store()
        .acquire_lease(
            fresh_acquire_request(
                database,
                attempt_id,
                seed.session_fences[0],
                LIVE_LEASE_MILLIS,
            )
            .await?,
        )
        .await?;

    exercise_initial_rejections(database, attempt_id, seed.session_fences[0], lease.guard())
        .await?;
    exercise_renewal_guards(
        database,
        attempt_id,
        &lease,
        seed.session_fences[0],
        seed.session_fences[1],
    )
    .await?;

    let phases = [
        JobLifecycle::Preparing,
        JobLifecycle::Running,
        JobLifecycle::Finalizing,
        JobLifecycle::Succeeded,
    ];
    let mut final_changed_at = None;
    for next in phases {
        let changed_at = database_now(database).await?;
        database
            .store()
            .transition(transition_request(
                attempt_id,
                seed.session_fences[0],
                lease.guard(),
                next,
                changed_at.get(),
            ))
            .await?;
        final_changed_at = Some(changed_at);
    }
    let snapshot = database.store().get_attempt(attempt_id).await?;
    assert_eq!(snapshot.lifecycle(), JobLifecycle::Succeeded);
    assert_eq!(snapshot.fencing_token(), Some(lease.fencing_token()));
    assert_eq!(snapshot.lease_id(), None);
    assert_eq!(snapshot.runner_id(), None);
    assert_eq!(snapshot.lease_issued_at(), None);
    assert_eq!(snapshot.lease_expires_at(), None);
    assert_eq!(snapshot.queued_at(), UnixMillis::new(100));
    assert_eq!(
        snapshot.changed_at(),
        final_changed_at.expect("terminal transition")
    );

    exercise_expired_mutations(database, seed.job_id, seed.session_fences[0]).await
}

#[allow(clippy::too_many_lines)] // One scenario keeps every renewal and transition guard adjacent.
async fn exercise_renewal_guards(
    database: &TestDatabase,
    attempt_id: AttemptId,
    lease: &automata_ci_core::Lease,
    session: RunnerSessionFence,
    wrong_session: RunnerSessionFence,
) -> TestResult {
    for duration in [10_000, 20_000] {
        let rejected = database
            .store()
            .renew_lease(
                fresh_renew_request(database, attempt_id, session, lease.guard(), duration).await?,
            )
            .await;
        assert!(matches!(
            rejected,
            Err(AttemptStoreError::RenewalDoesNotExtend(id)) if id == attempt_id
        ));
    }
    let renewal_lower = database_now(database).await?;
    let renewed = database
        .store()
        .renew_lease(
            fresh_renew_request(
                database,
                attempt_id,
                session,
                lease.guard(),
                EXTENDED_LEASE_MILLIS,
            )
            .await?,
        )
        .await?;
    let renewal_upper = database_now(database).await?;
    assert!(renewed.expires_at() > lease.expires_at());
    let renewed_snapshot = database.store().get_attempt(attempt_id).await?;
    assert_database_time_bound(renewed_snapshot.changed_at(), renewal_lower, renewal_upper);
    assert_database_time_bound(
        renewed.expires_at(),
        checked_add_millis(renewal_lower, EXTENDED_LEASE_MILLIS)?,
        checked_add_millis(renewal_upper, EXTENDED_LEASE_MILLIS)?,
    );

    let wrong_guard = LeaseGuard::new(LeaseId::new(), lease.fencing_token());
    let rejected = database
        .store()
        .renew_lease(
            fresh_renew_request(
                database,
                attempt_id,
                session,
                wrong_guard,
                EXTENDED_LEASE_MILLIS,
            )
            .await?,
        )
        .await;
    assert!(matches!(rejected, Err(AttemptStoreError::FenceRejected(id)) if id == attempt_id));

    let wrong_runner = database
        .store()
        .renew_lease(
            fresh_renew_request(
                database,
                attempt_id,
                wrong_session,
                lease.guard(),
                EXTENDED_LEASE_MILLIS,
            )
            .await?,
        )
        .await;
    assert!(matches!(
        wrong_runner,
        Err(AttemptStoreError::RunnerRejected(id)) if id == attempt_id
    ));
    let wrong_runner_transition_at = database_now(database).await?;
    let wrong_runner_transition = database
        .store()
        .transition(transition_request(
            attempt_id,
            wrong_session,
            lease.guard(),
            JobLifecycle::Preparing,
            wrong_runner_transition_at.get(),
        ))
        .await;
    assert!(matches!(
        wrong_runner_transition,
        Err(AttemptStoreError::RunnerRejected(id)) if id == attempt_id
    ));

    let regression_at = UnixMillis::new(
        renewed_snapshot
            .changed_at()
            .get()
            .checked_sub(1)
            .ok_or("renewal timestamp underflow")?,
    );
    let regression = database
        .store()
        .transition(transition_request(
            attempt_id,
            session,
            lease.guard(),
            JobLifecycle::Preparing,
            regression_at.get(),
        ))
        .await;
    assert!(matches!(
        regression,
        Err(AttemptStoreError::MutationPredatesState { attempt_id: id, .. })
            if id == attempt_id
    ));
    Ok(())
}

async fn exercise_initial_rejections(
    database: &TestDatabase,
    attempt_id: AttemptId,
    session: RunnerSessionFence,
    guard: LeaseGuard,
) -> TestResult {
    let invalid_phase_at = database_now(database).await?;
    let invalid_phase = database
        .store()
        .transition(transition_request(
            attempt_id,
            session,
            guard,
            JobLifecycle::Running,
            invalid_phase_at.get(),
        ))
        .await;
    assert!(matches!(
        invalid_phase,
        Err(AttemptStoreError::InvalidTransition {
            attempt_id: id,
            from: JobLifecycle::Leased,
            to: JobLifecycle::Running,
        }) if id == attempt_id
    ));

    Ok(())
}

async fn exercise_expired_mutations(
    database: &TestDatabase,
    job_id: automata_ci_core::JobId,
    session: RunnerSessionFence,
) -> TestResult {
    let expired_attempt = insert_attempt(database, job_id, 2, 300).await?;
    let expired_lease = database
        .store()
        .acquire_lease(
            fresh_acquire_request(database, expired_attempt, session, LIVE_LEASE_MILLIS).await?,
        )
        .await?;
    expire_active_attempt(database, expired_attempt).await?;
    let expired_renewal = database
        .store()
        .renew_lease(
            fresh_renew_request(
                database,
                expired_attempt,
                session,
                expired_lease.guard(),
                LIVE_LEASE_MILLIS,
            )
            .await?,
        )
        .await;
    assert!(matches!(
        expired_renewal,
        Err(AttemptStoreError::LeaseExpired(id)) if id == expired_attempt
    ));
    let expired_transition_at = database_now(database).await?;
    let expired_transition = database
        .store()
        .transition(transition_request(
            expired_attempt,
            session,
            expired_lease.guard(),
            JobLifecycle::Preparing,
            expired_transition_at.get(),
        ))
        .await;
    assert!(matches!(
        expired_transition,
        Err(AttemptStoreError::LeaseExpired(id)) if id == expired_attempt
    ));
    Ok(())
}

async fn exercise_expiry_reaper(database: &TestDatabase) -> TestResult {
    let locked_seed = seed_control_plane(database.pool(), 1).await?;
    let available_seed = seed_control_plane(database.pool(), 1).await?;
    let locked_id = insert_attempt(database, locked_seed.job_id, 1, 1).await?;
    let available_id = insert_attempt(database, available_seed.job_id, 1, 2).await?;
    let attempts = [
        (locked_id, locked_seed.session_fences[0]),
        (available_id, available_seed.session_fences[0]),
    ];
    for (attempt_id, session) in attempts {
        database
            .store()
            .acquire_lease(
                fresh_acquire_request(database, attempt_id, session, LIVE_LEASE_MILLIS).await?,
            )
            .await?;
        expire_active_attempt(database, attempt_id).await?;
    }

    let mut transaction = database.pool().begin().await?;
    sqlx::query("SELECT id FROM job_attempts WHERE id = $1 FOR UPDATE")
        .bind(locked_id.as_uuid())
        .fetch_one(&mut *transaction)
        .await?;
    let first_reap_at = database_now(database).await?;
    let processed = database
        .store()
        .requeue_expired(first_reap_at, 2, 1)
        .await?;
    assert_eq!(processed, vec![available_id]);
    transaction.rollback().await?;

    let second_reap_at = database_now(database).await?;
    let processed = database
        .store()
        .requeue_expired(second_reap_at, 2, 1)
        .await?;
    assert_eq!(processed, vec![locked_id]);

    let predating_seed = seed_control_plane(database.pool(), 1).await?;
    let current = database_now(database).await?;
    let future_state = checked_add_millis(current, 30_000)?;
    let predating_id =
        insert_attempt(database, predating_seed.job_id, 1, future_state.get()).await?;
    let predating_reacquisition = database
        .store()
        .acquire_lease(acquire_request(
            predating_id,
            predating_seed.session_fences[0],
            current.get(),
            checked_add_millis(current, LIVE_LEASE_MILLIS)?.get(),
        ))
        .await;
    assert!(matches!(
        predating_reacquisition,
        Err(AttemptStoreError::MutationPredatesState { attempt_id: id, .. }) if id == predating_id
    ));
    let invalid_policy_at = database_now(database).await?;
    assert!(matches!(
        database
            .store()
            .requeue_expired(invalid_policy_at, 0, 1)
            .await,
        Err(AttemptStoreError::InvalidRetryPolicy)
    ));

    for (attempt_id, session) in attempts {
        let lease = database
            .store()
            .acquire_lease(
                fresh_acquire_request(database, attempt_id, session, LIVE_LEASE_MILLIS).await?,
            )
            .await?;
        assert_eq!(lease.fencing_token(), FencingToken::new(2)?);
        expire_active_attempt(database, attempt_id).await?;
    }
    let final_reap_at = database_now(database).await?;
    let lost: HashSet<_> = database
        .store()
        .requeue_expired(final_reap_at, 2, 10)
        .await?
        .into_iter()
        .collect();
    assert_eq!(lost, HashSet::from([locked_id, available_id]));
    for attempt_id in [locked_id, available_id] {
        let snapshot = database.store().get_attempt(attempt_id).await?;
        assert_eq!(snapshot.lifecycle(), JobLifecycle::Lost);
        assert_eq!(snapshot.lease_failures(), 2);
        assert_eq!(snapshot.lease_id(), None);
    }
    Ok(())
}

async fn exercise_queued_conclusion(database: &TestDatabase) -> TestResult {
    let seed = seed_control_plane(database.pool(), 1).await?;
    let queued_at = database_now(database).await?;
    let predating_at = UnixMillis::new(
        queued_at
            .get()
            .checked_sub(1)
            .ok_or("queued timestamp underflow")?,
    );
    let predating_id = insert_attempt(database, seed.job_id, 1, queued_at.get()).await?;
    let predating = database
        .store()
        .conclude_queued(conclusion_request(
            predating_id,
            JobLifecycle::Cancelled,
            predating_at.get(),
        ))
        .await;
    assert!(matches!(
        predating,
        Err(AttemptStoreError::MutationPredatesState { attempt_id: id, .. })
            if id == predating_id
    ));
    let invalid = ConcludeQueuedAttempt::new(predating_id, JobLifecycle::Succeeded, queued_at);
    assert_eq!(
        invalid,
        Err(AttemptCommandError::InvalidQueuedConclusion(
            JobLifecycle::Succeeded
        ))
    );

    database
        .store()
        .conclude_queued(conclusion_request(
            predating_id,
            JobLifecycle::Skipped,
            queued_at.get(),
        ))
        .await?;
    let concluded = database.store().get_attempt(predating_id).await?;
    assert_eq!(concluded.lifecycle(), JobLifecycle::Skipped);
    assert_eq!(concluded.changed_at(), queued_at);

    for offset in 0..16_u32 {
        let attempt_number = offset + 2;
        let queued_at = database_now(database).await?;
        let attempt_id =
            insert_attempt(database, seed.job_id, attempt_number, queued_at.get()).await?;
        let acquisition_at = database_now(database).await?;
        let acquisition = acquire_request(
            attempt_id,
            seed.session_fences[0],
            acquisition_at.get(),
            checked_add_millis(acquisition_at, LIVE_LEASE_MILLIS)?.get(),
        );
        let conclusion_at = database_now(database).await?;
        let conclusion = conclusion_request(
            attempt_id,
            if offset % 2 == 0 {
                JobLifecycle::Cancelled
            } else {
                JobLifecycle::Skipped
            },
            conclusion_at.get(),
        );
        let (leased, concluded) = tokio::join!(
            database.store().acquire_lease(acquisition),
            database.store().conclude_queued(conclusion)
        );
        match (leased, concluded) {
            (Ok(_), Err(AttemptStoreError::NotQueued { lifecycle, .. })) => {
                assert_eq!(lifecycle, JobLifecycle::Leased);
                expire_active_attempt(database, attempt_id).await?;
                let reaped_at = database_now(database).await?;
                assert_eq!(
                    database.store().requeue_expired(reaped_at, 1, 1).await?,
                    [attempt_id]
                );
            }
            (Err(AttemptStoreError::NotQueued { lifecycle, .. }), Ok(())) => {
                assert_eq!(lifecycle, conclusion.conclusion());
            }
            outcomes => panic!("exactly one queued-state operation must win: {outcomes:?}"),
        }
    }
    Ok(())
}

async fn exercise_tenant_queries(database: &TestDatabase) -> TestResult {
    let owner = seed_control_plane(database.pool(), 1).await?;
    let outsider = seed_control_plane(database.pool(), 1).await?;
    let attempt_id = insert_attempt(database, owner.job_id, 1, 100).await?;
    let owner_scope = TenantScope::from_authenticated_tenant_id(owner.tenant_id)?;
    let outsider_scope = TenantScope::from_authenticated_tenant_id(outsider.tenant_id)?;

    let snapshot = database
        .store()
        .get_attempt_for_tenant(&owner_scope, attempt_id)
        .await?;
    assert_eq!(snapshot.attempt_id(), attempt_id);
    let hidden = database
        .store()
        .get_attempt_for_tenant(&outsider_scope, attempt_id)
        .await;
    assert!(matches!(hidden, Err(AttemptStoreError::NotFound(id)) if id == attempt_id));

    let cross_tenant_runner = database
        .store()
        .acquire_lease(
            fresh_acquire_request(
                database,
                attempt_id,
                outsider.session_fences[0],
                LIVE_LEASE_MILLIS,
            )
            .await?,
        )
        .await;
    assert!(matches!(
        cross_tenant_runner,
        Err(AttemptStoreError::RunnerRejected(id)) if id == attempt_id
    ));
    Ok(())
}

async fn insert_attempt(
    database: &TestDatabase,
    job_id: automata_ci_core::JobId,
    attempt_number: u32,
    queued_at: i64,
) -> TestResult<AttemptId> {
    let attempt_id = AttemptId::new();
    database
        .store()
        .insert_queued(QueuedAttempt::new(
            attempt_id,
            job_id,
            AttemptNumber::new(attempt_number)?,
            UnixMillis::new(queued_at),
        ))
        .await?;
    Ok(attempt_id)
}

async fn load_attempt_output_safety(
    database: &TestDatabase,
    attempt_id: AttemptId,
) -> TestResult<AttemptOutputSafety> {
    let row: (String, String, String, String, String, i32, i64) = sqlx::query_as(
        r"
        SELECT secret_exposure_class, raw_log_disposition,
               requested_log_visibility, effective_log_visibility,
               output_safety_reason, output_safety_schema, classified_at_ms
        FROM job_attempts
        WHERE id = $1
        ",
    )
    .bind(attempt_id.as_uuid())
    .fetch_one(database.pool())
    .await?;
    Ok(AttemptOutputSafety {
        secret_exposure: row.0,
        raw_log_disposition: row.1,
        requested_visibility: row.2,
        effective_visibility: row.3,
        reason: row.4,
        schema: row.5,
        classified_at: row.6,
    })
}

async fn database_now(database: &TestDatabase) -> TestResult<UnixMillis> {
    Ok(UnixMillis::new(
        sqlx::query_scalar("SELECT floor(extract(epoch FROM clock_timestamp()) * 1000)::bigint")
            .fetch_one(database.pool())
            .await?,
    ))
}

fn checked_add_millis(base: UnixMillis, duration_millis: i64) -> TestResult<UnixMillis> {
    Ok(UnixMillis::new(
        base.get()
            .checked_add(duration_millis)
            .ok_or("test timestamp overflow")?,
    ))
}

fn assert_database_time_bound(value: UnixMillis, lower: UnixMillis, upper: UnixMillis) {
    assert!(
        value >= lower && value <= upper,
        "database-issued timestamp {value:?} fell outside {lower:?}..={upper:?}"
    );
}

async fn fresh_acquire_request(
    database: &TestDatabase,
    attempt_id: AttemptId,
    session: RunnerSessionFence,
    duration_millis: i64,
) -> TestResult<AcquireLease> {
    let observed_at = database_now(database).await?;
    Ok(acquire_request(
        attempt_id,
        session,
        observed_at.get(),
        checked_add_millis(observed_at, duration_millis)?.get(),
    ))
}

async fn fresh_renew_request(
    database: &TestDatabase,
    attempt_id: AttemptId,
    session: RunnerSessionFence,
    guard: LeaseGuard,
    duration_millis: i64,
) -> TestResult<RenewLease> {
    let observed_at = database_now(database).await?;
    Ok(renew_request(
        attempt_id,
        session,
        guard,
        observed_at.get(),
        checked_add_millis(observed_at, duration_millis)?.get(),
    ))
}

async fn expire_active_attempt(
    database: &TestDatabase,
    attempt_id: AttemptId,
) -> TestResult<UnixMillis> {
    let expires_at: i64 = sqlx::query_scalar(
        r"
        UPDATE job_attempts
        SET lease_expires_at_ms = GREATEST(lease_issued_at_ms, changed_at_ms) + 1
        WHERE id = $1 AND lease_id IS NOT NULL
        RETURNING lease_expires_at_ms
        ",
    )
    .bind(attempt_id.as_uuid())
    .fetch_one(database.pool())
    .await?;
    let expires_at = UnixMillis::new(expires_at);
    wait_until_database_time(database, expires_at).await?;
    Ok(expires_at)
}

async fn wait_until_database_time(database: &TestDatabase, deadline: UnixMillis) -> TestResult {
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let observed_at: i64 = sqlx::query_scalar(
                "SELECT floor(extract(epoch FROM clock_timestamp()) * 1000)::bigint",
            )
            .fetch_one(database.pool())
            .await?;
            if observed_at >= deadline.get() {
                return Ok::<(), sqlx::Error>(());
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .map_err(|_| "timed out waiting for an explicitly expired test lease")??;
    Ok(())
}

fn acquire_request(
    attempt_id: AttemptId,
    session: RunnerSessionFence,
    observed_at: i64,
    expires_at: i64,
) -> AcquireLease {
    static NEXT_SLOT: AtomicU16 = AtomicU16::new(1);
    let slot = StableRunnerSlot::new(NEXT_SLOT.fetch_add(1, Ordering::Relaxed))
        .expect("bounded one-based test slot");
    AcquireLease::new(
        attempt_id,
        LeaseId::new(),
        session,
        slot,
        UnixMillis::new(observed_at),
        UnixMillis::new(expires_at),
    )
    .expect("valid test lease interval")
}

fn renew_request(
    attempt_id: AttemptId,
    session: RunnerSessionFence,
    guard: LeaseGuard,
    observed_at: i64,
    expires_at: i64,
) -> RenewLease {
    RenewLease::new(
        attempt_id,
        session,
        guard,
        UnixMillis::new(observed_at),
        UnixMillis::new(expires_at),
    )
    .expect("valid test renewal interval")
}

fn transition_request(
    attempt_id: AttemptId,
    session: RunnerSessionFence,
    guard: LeaseGuard,
    next: JobLifecycle,
    observed_at: i64,
) -> TransitionAttempt {
    TransitionAttempt::new(
        attempt_id,
        session,
        guard,
        next,
        UnixMillis::new(observed_at),
    )
}

fn conclusion_request(
    attempt_id: AttemptId,
    conclusion: JobLifecycle,
    observed_at: i64,
) -> ConcludeQueuedAttempt {
    ConcludeQueuedAttempt::new(attempt_id, conclusion, UnixMillis::new(observed_at))
        .expect("valid test queued conclusion")
}
