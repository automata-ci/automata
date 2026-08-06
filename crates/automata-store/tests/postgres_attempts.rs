mod common;

use std::collections::HashSet;

use automata_core::{
    AttemptId, AttemptNumber, FencingToken, JobLifecycle, LeaseGuard, LeaseId, UnixMillis,
};
use automata_store::{
    AcquireLease, AttemptCommandError, AttemptStoreError, ConcludeQueuedAttempt,
    InternalAttemptRepository as _, QueuedAttempt, RenewLease, TenantAttemptQuery as _,
    TenantScope, TransitionAttempt,
};
use common::{TestDatabase, TestResult, run_with_database, seed_control_plane};

#[tokio::test]
#[ignore = "requires AUTOMATA_TEST_DATABASE_URL and creates a temporary schema"]
async fn acquisition_is_atomic_and_reacquisition_advances_the_fence() -> TestResult {
    run_with_database(|database| async move { exercise_atomic_acquisition(&database).await }).await
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

async fn exercise_atomic_acquisition(database: &TestDatabase) -> TestResult {
    let seed = seed_control_plane(database.pool(), 2).await?;
    let attempt_id = insert_attempt(database, seed.job_id, 1, 10).await?;
    let first = acquire_request(attempt_id, seed.runner_ids[0], 20, 30);
    let second = acquire_request(attempt_id, seed.runner_ids[1], 20, 30);

    let (left, right) = tokio::join!(
        database.store().acquire_lease(first),
        database.store().acquire_lease(second)
    );
    let winner = match (left, right) {
        (Ok(lease), Err(AttemptStoreError::NotQueued { .. }))
        | (Err(AttemptStoreError::NotQueued { .. }), Ok(lease)) => lease,
        outcomes => panic!("exactly one concurrent acquisition must win: {outcomes:?}"),
    };
    assert_eq!(winner.fencing_token().get(), 1);

    let requeued = database
        .store()
        .requeue_expired(UnixMillis::new(30), 3, 10)
        .await?;
    assert_eq!(requeued, vec![attempt_id]);
    let reacquired = database
        .store()
        .acquire_lease(acquire_request(attempt_id, seed.runner_ids[0], 31, 41))
        .await?;
    assert_eq!(reacquired.fencing_token().get(), 2);

    let stale = database
        .store()
        .transition(transition_request(
            attempt_id,
            winner.runner_id(),
            winner.guard(),
            JobLifecycle::Preparing,
            32,
        ))
        .await;
    assert!(matches!(stale, Err(AttemptStoreError::FenceRejected(id)) if id == attempt_id));

    let predating_id = insert_attempt(database, seed.job_id, 2, 40).await?;
    let predating = database
        .store()
        .acquire_lease(acquire_request(predating_id, seed.runner_ids[0], 39, 50))
        .await;
    assert!(matches!(
        predating,
        Err(AttemptStoreError::MutationPredatesState { attempt_id: id, .. })
            if id == predating_id
    ));

    let exhausted_id = insert_attempt(database, seed.job_id, 3, 40).await?;
    sqlx::query("UPDATE job_attempts SET fencing_token = $2 WHERE id = $1")
        .bind(exhausted_id.as_uuid())
        .bind(i64::MAX)
        .execute(database.pool())
        .await?;
    let exhausted = database
        .store()
        .acquire_lease(acquire_request(exhausted_id, seed.runner_ids[0], 41, 50))
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
        .acquire_lease(acquire_request(attempt_id, seed.runner_ids[0], 110, 200))
        .await?;

    exercise_initial_rejections(database, attempt_id, lease.runner_id(), lease.guard()).await;
    exercise_renewal_guards(database, attempt_id, &lease, seed.runner_ids[1]).await?;

    let phases = [
        (JobLifecycle::Preparing, 130),
        (JobLifecycle::Running, 140),
        (JobLifecycle::Finalizing, 150),
        (JobLifecycle::Succeeded, 160),
    ];
    for (next, changed_at) in phases {
        database
            .store()
            .transition(transition_request(
                attempt_id,
                lease.runner_id(),
                lease.guard(),
                next,
                changed_at,
            ))
            .await?;
    }
    let snapshot = database.store().get_attempt(attempt_id).await?;
    assert_eq!(snapshot.lifecycle(), JobLifecycle::Succeeded);
    assert_eq!(snapshot.fencing_token(), Some(lease.fencing_token()));
    assert_eq!(snapshot.lease_id(), None);
    assert_eq!(snapshot.runner_id(), None);
    assert_eq!(snapshot.lease_issued_at(), None);
    assert_eq!(snapshot.lease_expires_at(), None);
    assert_eq!(snapshot.queued_at(), UnixMillis::new(100));
    assert_eq!(snapshot.changed_at(), UnixMillis::new(160));

    exercise_expired_mutations(database, seed.job_id, seed.runner_ids[0]).await
}

async fn exercise_renewal_guards(
    database: &TestDatabase,
    attempt_id: AttemptId,
    lease: &automata_core::Lease,
    wrong_runner_id: automata_core::RunnerId,
) -> TestResult {
    for expiration in [200, 199] {
        let rejected = database
            .store()
            .renew_lease(renew_request(
                attempt_id,
                lease.runner_id(),
                lease.guard(),
                120,
                expiration,
            ))
            .await;
        assert!(matches!(
            rejected,
            Err(AttemptStoreError::RenewalDoesNotExtend(id)) if id == attempt_id
        ));
    }
    let renewed = database
        .store()
        .renew_lease(renew_request(
            attempt_id,
            lease.runner_id(),
            lease.guard(),
            120,
            250,
        ))
        .await?;
    assert_eq!(renewed.expires_at(), UnixMillis::new(250));

    let wrong_guard = LeaseGuard::new(LeaseId::new(), lease.fencing_token());
    let rejected = database
        .store()
        .renew_lease(renew_request(
            attempt_id,
            lease.runner_id(),
            wrong_guard,
            130,
            260,
        ))
        .await;
    assert!(matches!(rejected, Err(AttemptStoreError::FenceRejected(id)) if id == attempt_id));

    let wrong_runner = database
        .store()
        .renew_lease(renew_request(
            attempt_id,
            wrong_runner_id,
            lease.guard(),
            130,
            260,
        ))
        .await;
    assert!(matches!(
        wrong_runner,
        Err(AttemptStoreError::RunnerRejected(id)) if id == attempt_id
    ));
    let wrong_runner_transition = database
        .store()
        .transition(transition_request(
            attempt_id,
            wrong_runner_id,
            lease.guard(),
            JobLifecycle::Preparing,
            130,
        ))
        .await;
    assert!(matches!(
        wrong_runner_transition,
        Err(AttemptStoreError::RunnerRejected(id)) if id == attempt_id
    ));

    for regression in [
        database
            .store()
            .renew_lease(renew_request(
                attempt_id,
                lease.runner_id(),
                lease.guard(),
                119,
                260,
            ))
            .await
            .map(|_| ()),
        database
            .store()
            .transition(transition_request(
                attempt_id,
                lease.runner_id(),
                lease.guard(),
                JobLifecycle::Preparing,
                119,
            ))
            .await,
    ] {
        assert!(matches!(
            regression,
            Err(AttemptStoreError::MutationPredatesState { attempt_id: id, .. })
                if id == attempt_id
        ));
    }
    Ok(())
}

async fn exercise_initial_rejections(
    database: &TestDatabase,
    attempt_id: AttemptId,
    runner_id: automata_core::RunnerId,
    guard: LeaseGuard,
) {
    let invalid_phase = database
        .store()
        .transition(transition_request(
            attempt_id,
            runner_id,
            guard,
            JobLifecycle::Running,
            115,
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

    let predating_renewal = database
        .store()
        .renew_lease(renew_request(attempt_id, runner_id, guard, 109, 210))
        .await;
    assert!(matches!(
        predating_renewal,
        Err(AttemptStoreError::MutationPredatesState { attempt_id: id, .. }) if id == attempt_id
    ));
}

async fn exercise_expired_mutations(
    database: &TestDatabase,
    job_id: automata_core::JobId,
    runner_id: automata_core::RunnerId,
) -> TestResult {
    let expired_attempt = insert_attempt(database, job_id, 2, 300).await?;
    let expired_lease = database
        .store()
        .acquire_lease(acquire_request(expired_attempt, runner_id, 310, 320))
        .await?;
    let expired_renewal = database
        .store()
        .renew_lease(renew_request(
            expired_attempt,
            runner_id,
            expired_lease.guard(),
            320,
            400,
        ))
        .await;
    assert!(matches!(
        expired_renewal,
        Err(AttemptStoreError::LeaseExpired(id)) if id == expired_attempt
    ));
    let expired_transition = database
        .store()
        .transition(transition_request(
            expired_attempt,
            runner_id,
            expired_lease.guard(),
            JobLifecycle::Preparing,
            320,
        ))
        .await;
    assert!(matches!(
        expired_transition,
        Err(AttemptStoreError::LeaseExpired(id)) if id == expired_attempt
    ));
    Ok(())
}

async fn exercise_expiry_reaper(database: &TestDatabase) -> TestResult {
    let seed = seed_control_plane(database.pool(), 1).await?;
    let locked_id = insert_attempt(database, seed.job_id, 1, 1).await?;
    let available_id = insert_attempt(database, seed.job_id, 2, 2).await?;
    for (attempt_id, issued_at) in [(locked_id, 10), (available_id, 11)] {
        database
            .store()
            .acquire_lease(acquire_request(
                attempt_id,
                seed.runner_ids[0],
                issued_at,
                20,
            ))
            .await?;
    }

    let mut transaction = database.pool().begin().await?;
    sqlx::query("SELECT id FROM job_attempts WHERE id = $1 FOR UPDATE")
        .bind(locked_id.as_uuid())
        .fetch_one(&mut *transaction)
        .await?;
    let processed = database
        .store()
        .requeue_expired(UnixMillis::new(20), 2, 1)
        .await?;
    assert_eq!(processed, vec![available_id]);
    transaction.rollback().await?;

    let processed = database
        .store()
        .requeue_expired(UnixMillis::new(20), 2, 1)
        .await?;
    assert_eq!(processed, vec![locked_id]);

    let predating_reacquisition = database
        .store()
        .acquire_lease(acquire_request(locked_id, seed.runner_ids[0], 19, 30))
        .await;
    assert!(matches!(
        predating_reacquisition,
        Err(AttemptStoreError::MutationPredatesState { attempt_id: id, .. }) if id == locked_id
    ));
    assert!(matches!(
        database
            .store()
            .requeue_expired(UnixMillis::new(20), 0, 1)
            .await,
        Err(AttemptStoreError::InvalidRetryPolicy)
    ));

    for attempt_id in [locked_id, available_id] {
        let lease = database
            .store()
            .acquire_lease(acquire_request(attempt_id, seed.runner_ids[0], 21, 30))
            .await?;
        assert_eq!(lease.fencing_token(), FencingToken::new(2)?);
    }
    let lost: HashSet<_> = database
        .store()
        .requeue_expired(UnixMillis::new(30), 2, 10)
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
    let predating_id = insert_attempt(database, seed.job_id, 1, 100).await?;
    let predating = database
        .store()
        .conclude_queued(conclusion_request(
            predating_id,
            JobLifecycle::Cancelled,
            99,
        ))
        .await;
    assert!(matches!(
        predating,
        Err(AttemptStoreError::MutationPredatesState { attempt_id: id, .. })
            if id == predating_id
    ));
    let invalid =
        ConcludeQueuedAttempt::new(predating_id, JobLifecycle::Succeeded, UnixMillis::new(100));
    assert_eq!(
        invalid,
        Err(AttemptCommandError::InvalidQueuedConclusion(
            JobLifecycle::Succeeded
        ))
    );

    let predating_acquisition = database
        .store()
        .acquire_lease(acquire_request(predating_id, seed.runner_ids[0], 99, 200))
        .await;
    assert!(matches!(
        predating_acquisition,
        Err(AttemptStoreError::MutationPredatesState { attempt_id: id, .. })
            if id == predating_id
    ));
    database
        .store()
        .conclude_queued(conclusion_request(predating_id, JobLifecycle::Skipped, 100))
        .await?;
    let concluded = database.store().get_attempt(predating_id).await?;
    assert_eq!(concluded.lifecycle(), JobLifecycle::Skipped);
    assert_eq!(concluded.changed_at(), UnixMillis::new(100));

    for offset in 0..16_u32 {
        let attempt_number = offset + 2;
        let queued_at = 200 + i64::from(offset);
        let attempt_id = insert_attempt(database, seed.job_id, attempt_number, queued_at).await?;
        let acquisition = acquire_request(
            attempt_id,
            seed.runner_ids[0],
            queued_at + 1,
            queued_at + 100,
        );
        let conclusion = conclusion_request(
            attempt_id,
            if offset % 2 == 0 {
                JobLifecycle::Cancelled
            } else {
                JobLifecycle::Skipped
            },
            queued_at + 1,
        );
        let (leased, concluded) = tokio::join!(
            database.store().acquire_lease(acquisition),
            database.store().conclude_queued(conclusion)
        );
        match (leased, concluded) {
            (Ok(_), Err(AttemptStoreError::NotQueued { lifecycle, .. })) => {
                assert_eq!(lifecycle, JobLifecycle::Leased);
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
        .acquire_lease(acquire_request(
            attempt_id,
            outsider.runner_ids[0],
            110,
            200,
        ))
        .await;
    assert!(matches!(
        cross_tenant_runner,
        Err(AttemptStoreError::RunnerRejected(id)) if id == attempt_id
    ));
    Ok(())
}

async fn insert_attempt(
    database: &TestDatabase,
    job_id: automata_core::JobId,
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

fn acquire_request(
    attempt_id: AttemptId,
    runner_id: automata_core::RunnerId,
    observed_at: i64,
    expires_at: i64,
) -> AcquireLease {
    AcquireLease::new(
        attempt_id,
        LeaseId::new(),
        runner_id,
        UnixMillis::new(observed_at),
        UnixMillis::new(expires_at),
    )
    .expect("valid test lease interval")
}

fn renew_request(
    attempt_id: AttemptId,
    runner_id: automata_core::RunnerId,
    guard: LeaseGuard,
    observed_at: i64,
    expires_at: i64,
) -> RenewLease {
    RenewLease::new(
        attempt_id,
        runner_id,
        guard,
        UnixMillis::new(observed_at),
        UnixMillis::new(expires_at),
    )
    .expect("valid test renewal interval")
}

fn transition_request(
    attempt_id: AttemptId,
    runner_id: automata_core::RunnerId,
    guard: LeaseGuard,
    next: JobLifecycle,
    observed_at: i64,
) -> TransitionAttempt {
    TransitionAttempt::new(
        attempt_id,
        runner_id,
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
