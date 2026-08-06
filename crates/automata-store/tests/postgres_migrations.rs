mod common;

use uuid::Uuid;

use common::{SeedData, TestDatabase, TestResult, run_with_database, seed_control_plane};

#[tokio::test]
#[ignore = "requires AUTOMATA_TEST_DATABASE_URL and creates a temporary schema"]
async fn migrations_are_repeatable_and_enforce_attempt_invariants() -> TestResult {
    run_with_database(|database| async move { exercise_constraints(&database).await }).await
}

fn assert_constraint(error: &sqlx::Error, expected: &str) {
    let actual = error
        .as_database_error()
        .and_then(sqlx::error::DatabaseError::constraint);
    assert_eq!(actual, Some(expected), "unexpected database error: {error}");
}

async fn exercise_constraints(database: &TestDatabase) -> TestResult {
    database.store().migrate().await?;
    let seed = seed_control_plane(database.pool(), 1).await?;

    let zero_number = sqlx::query(
        r"
        INSERT INTO job_attempts (
            id, job_id, attempt_number, lifecycle, queued_at_ms, changed_at_ms
        )
        VALUES ($1, $2, 0, 'queued', 1, 1)
        ",
    )
    .bind(Uuid::new_v4())
    .bind(seed.job_id.as_uuid())
    .execute(database.pool())
    .await
    .expect_err("a zero attempt number must violate the migration constraint");
    assert_constraint(&zero_number, "job_attempts_number_positive");

    let missing_lease = sqlx::query(
        r"
        INSERT INTO job_attempts (
            id, job_id, attempt_number, lifecycle, fencing_token,
            queued_at_ms, changed_at_ms
        )
        VALUES ($1, $2, 2, 'leased', 1, 1, 1)
        ",
    )
    .bind(Uuid::new_v4())
    .bind(seed.job_id.as_uuid())
    .execute(database.pool())
    .await
    .expect_err("an active lifecycle without lease fields must be rejected");
    assert_constraint(&missing_lease, "job_attempts_active_lease_consistent");

    let unfenced_lease = sqlx::query(
        r"
        INSERT INTO job_attempts (
            id, job_id, attempt_number, lifecycle, fencing_token, lease_id,
            runner_id, lease_issued_at_ms, lease_expires_at_ms,
            queued_at_ms, changed_at_ms
        )
        VALUES ($1, $2, 3, 'leased', 0, $3, $4, 1, 2, 1, 1)
        ",
    )
    .bind(Uuid::new_v4())
    .bind(seed.job_id.as_uuid())
    .bind(Uuid::new_v4())
    .bind(seed.runner_ids[0].as_uuid())
    .execute(database.pool())
    .await
    .expect_err("an active lease without a fencing token must be rejected");
    assert_constraint(&unfenced_lease, "job_attempts_active_lease_fenced");

    let invalid_interval = sqlx::query(
        r"
        INSERT INTO job_attempts (
            id, job_id, attempt_number, lifecycle, fencing_token, lease_id,
            runner_id, lease_issued_at_ms, lease_expires_at_ms,
            queued_at_ms, changed_at_ms
        )
        VALUES ($1, $2, 4, 'leased', 1, $3, $4, 2, 2, 1, 1)
        ",
    )
    .bind(Uuid::new_v4())
    .bind(seed.job_id.as_uuid())
    .bind(Uuid::new_v4())
    .bind(seed.runner_ids[0].as_uuid())
    .execute(database.pool())
    .await
    .expect_err("a non-increasing lease interval must be rejected");
    assert_constraint(&invalid_interval, "job_attempts_lease_interval");

    exercise_attempt_time_constraints(database, &seed).await?;

    let table_count: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM information_schema.tables WHERE table_schema = current_schema()",
    )
    .fetch_one(database.pool())
    .await?;
    assert!(table_count >= 12, "all control-plane tables must exist");
    exercise_workflow_and_concurrency_scope(database, &seed).await?;
    Ok(())
}

async fn exercise_attempt_time_constraints(database: &TestDatabase, seed: &SeedData) -> TestResult {
    let regressed_state = sqlx::query(
        r"
        INSERT INTO job_attempts (
            id, job_id, attempt_number, lifecycle, queued_at_ms, changed_at_ms
        )
        VALUES ($1, $2, 5, 'queued', 10, 9)
        ",
    )
    .bind(Uuid::new_v4())
    .bind(seed.job_id.as_uuid())
    .execute(database.pool())
    .await
    .expect_err("a durable state timestamp must not precede queue entry");
    assert_constraint(&regressed_state, "job_attempts_state_time_monotonic");

    let observation_outside_lease = sqlx::query(
        r"
        INSERT INTO job_attempts (
            id, job_id, attempt_number, lifecycle, fencing_token, lease_id,
            runner_id, lease_issued_at_ms, lease_expires_at_ms,
            queued_at_ms, changed_at_ms
        )
        VALUES ($1, $2, 6, 'leased', 1, $3, $4, 10, 20, 1, 20)
        ",
    )
    .bind(Uuid::new_v4())
    .bind(seed.job_id.as_uuid())
    .bind(Uuid::new_v4())
    .bind(seed.runner_ids[0].as_uuid())
    .execute(database.pool())
    .await
    .expect_err("an active state's observation must remain inside its lease");
    assert_constraint(
        &observation_outside_lease,
        "job_attempts_active_observation_within_lease",
    );
    Ok(())
}

async fn exercise_workflow_and_concurrency_scope(
    database: &TestDatabase,
    seed: &SeedData,
) -> TestResult {
    let snapshot_id: Uuid = sqlx::query_scalar(
        r"
        SELECT snapshot.id
        FROM workflow_snapshots AS snapshot
        JOIN workflow_definitions AS definition ON definition.id = snapshot.workflow_id
        WHERE definition.id = $1
        LIMIT 1
        ",
    )
    .bind(seed.workflow_id)
    .fetch_one(database.pool())
    .await?;
    assert_snapshot_matches_workflow(database, seed, snapshot_id).await?;
    let second_repository = insert_second_repository(database, seed).await?;
    let other_run =
        exercise_repository_bound_runs(database, seed, snapshot_id, second_repository).await?;
    exercise_concurrency_scope(database, seed.repository_id, second_repository, other_run).await?;
    exercise_tenant_scope_constraints(database, seed).await?;
    Ok(())
}

async fn assert_snapshot_matches_workflow(
    database: &TestDatabase,
    seed: &SeedData,
    snapshot_id: Uuid,
) -> TestResult {
    let second_workflow = Uuid::new_v4();
    sqlx::query(
        r"
        INSERT INTO workflow_definitions (
            id, repository_id, path, created_at_ms, updated_at_ms
        )
        VALUES ($1, $2, '.github/workflows/other.yml', 1, 1)
        ",
    )
    .bind(second_workflow)
    .bind(seed.repository_id)
    .execute(database.pool())
    .await?;
    let mismatched_snapshot = sqlx::query(
        r"
        INSERT INTO workflow_runs (
            id, repository_id, workflow_id, snapshot_id, run_number, event_name,
            event_object_key, head_sha, status, created_at_ms, updated_at_ms
        )
        VALUES ($1, $2, $3, $4, 2, 'push', 'test/event', $5, 'queued', 1, 1)
        ",
    )
    .bind(Uuid::new_v4())
    .bind(seed.repository_id)
    .bind(second_workflow)
    .bind(snapshot_id)
    .bind(vec![13_u8; 20])
    .execute(database.pool())
    .await
    .expect_err("a run must not use another workflow's source snapshot");
    assert_constraint(
        &mismatched_snapshot,
        "workflow_runs_snapshot_matches_workflow",
    );
    Ok(())
}

async fn insert_second_repository(database: &TestDatabase, seed: &SeedData) -> TestResult<Uuid> {
    let second_repository = Uuid::new_v4();
    sqlx::query(
        r"
        INSERT INTO repositories (
            id, tenant_id, scm_provider, provider_repository_id, owner, name,
            created_at_ms, updated_at_ms
        )
        VALUES ($1, $2, 'test', $3, 'automata', 'other-store-test', 1, 1)
        ",
    )
    .bind(second_repository)
    .bind(&seed.tenant_id)
    .bind(second_repository.to_string())
    .execute(database.pool())
    .await?;
    Ok(second_repository)
}

async fn exercise_repository_bound_runs(
    database: &TestDatabase,
    seed: &SeedData,
    snapshot_id: Uuid,
    second_repository: Uuid,
) -> TestResult<Uuid> {
    let cross_repository_workflow = sqlx::query(
        r"
        INSERT INTO workflow_runs (
            id, repository_id, workflow_id, snapshot_id, run_number, event_name,
            event_object_key, head_sha, status, created_at_ms, updated_at_ms
        )
        VALUES ($1, $2, $3, $4, 3, 'push', 'test/event', $5, 'queued', 1, 1)
        ",
    )
    .bind(Uuid::new_v4())
    .bind(second_repository)
    .bind(seed.workflow_id)
    .bind(snapshot_id)
    .bind(vec![14_u8; 20])
    .execute(database.pool())
    .await
    .expect_err("a run's explicit repository must own its workflow");
    assert_constraint(
        &cross_repository_workflow,
        "workflow_runs_workflow_matches_repository",
    );

    let other_workflow = Uuid::new_v4();
    let other_snapshot = Uuid::new_v4();
    let other_run = Uuid::new_v4();
    sqlx::query(
        r"
        INSERT INTO workflow_definitions (
            id, repository_id, path, created_at_ms, updated_at_ms
        )
        VALUES ($1, $2, '.github/workflows/test.yml', 1, 1)
        ",
    )
    .bind(other_workflow)
    .bind(second_repository)
    .execute(database.pool())
    .await?;
    sqlx::query(
        r"
        INSERT INTO workflow_snapshots (
            id, workflow_id, source_digest, source_object_key,
            frontend_schema, created_at_ms
        )
        VALUES ($1, $2, $3, 'test/other-workflow', 1, 1)
        ",
    )
    .bind(other_snapshot)
    .bind(other_workflow)
    .bind(vec![15_u8; 32])
    .execute(database.pool())
    .await?;
    sqlx::query(
        r"
        INSERT INTO workflow_runs (
            id, repository_id, workflow_id, snapshot_id, run_number, event_name,
            event_object_key, head_sha, status, created_at_ms, updated_at_ms
        )
        VALUES ($1, $2, $3, $4, 1, 'push', 'test/event', $5, 'queued', 1, 1)
        ",
    )
    .bind(other_run)
    .bind(second_repository)
    .bind(other_workflow)
    .bind(other_snapshot)
    .bind(vec![16_u8; 20])
    .execute(database.pool())
    .await?;
    Ok(other_run)
}

async fn exercise_concurrency_scope(
    database: &TestDatabase,
    first_repository: Uuid,
    second_repository: Uuid,
    other_run: Uuid,
) -> TestResult {
    for scoped_repository in [first_repository, second_repository] {
        sqlx::query(
            r"
            INSERT INTO concurrency_groups (
                repository_id, normalized_key, display_key, updated_at_ms
            )
            VALUES ($1, 'deploy', 'Deploy', 1)
            ",
        )
        .bind(scoped_repository)
        .execute(database.pool())
        .await?;
    }
    let duplicate_in_repository = sqlx::query(
        r"
        INSERT INTO concurrency_groups (
            repository_id, normalized_key, display_key, updated_at_ms
        )
        VALUES ($1, 'deploy', 'Deploy', 2)
        ",
    )
    .bind(first_repository)
    .execute(database.pool())
    .await
    .expect_err("a concurrency key must be unique inside its repository");
    assert_constraint(&duplicate_in_repository, "concurrency_groups_primary_key");

    let cross_repository_slot = sqlx::query(
        r"
        UPDATE concurrency_groups
        SET running_run_id = $2
        WHERE repository_id = $1 AND normalized_key = 'deploy'
        ",
    )
    .bind(first_repository)
    .bind(other_run)
    .execute(database.pool())
    .await
    .expect_err("a concurrency slot must not point at another repository's run");
    assert_constraint(
        &cross_repository_slot,
        "concurrency_groups_running_run_matches_repository",
    );

    let cross_repository_pending_slot = sqlx::query(
        r"
        UPDATE concurrency_groups
        SET pending_run_id = $2
        WHERE repository_id = $1 AND normalized_key = 'deploy'
        ",
    )
    .bind(first_repository)
    .bind(other_run)
    .execute(database.pool())
    .await
    .expect_err("a pending concurrency slot must remain repository-scoped");
    assert_constraint(
        &cross_repository_pending_slot,
        "concurrency_groups_pending_run_matches_repository",
    );

    sqlx::query(
        r"
        UPDATE concurrency_groups
        SET running_run_id = $2
        WHERE repository_id = $1 AND normalized_key = 'deploy'
        ",
    )
    .bind(second_repository)
    .bind(other_run)
    .execute(database.pool())
    .await?;

    Ok(())
}

async fn exercise_tenant_scope_constraints(database: &TestDatabase, seed: &SeedData) -> TestResult {
    let invalid_tenant = sqlx::query(
        r"
        INSERT INTO tenants (id, display_name, created_at_ms, updated_at_ms)
        VALUES ($1, 'Invalid tenant', 1, 1)
        ",
    )
    .bind("invalid\ntenant")
    .execute(database.pool())
    .await
    .expect_err("durable tenant IDs must reject control characters");
    assert_constraint(&invalid_tenant, "tenants_id_shape");

    let other_tenant = format!("tenant-{}", Uuid::new_v4().simple());
    sqlx::query(
        r"
        INSERT INTO tenants (id, display_name, created_at_ms, updated_at_ms)
        VALUES ($1, 'Other tenant', 1, 1)
        ",
    )
    .bind(&other_tenant)
    .execute(database.pool())
    .await?;

    let (provider, provider_repository_id, owner, name): (String, String, String, String) =
        sqlx::query_as(
            r"
            SELECT scm_provider, provider_repository_id, owner, name
            FROM repositories
            WHERE id = $1
            ",
        )
        .bind(seed.repository_id)
        .fetch_one(database.pool())
        .await?;
    sqlx::query(
        r"
        INSERT INTO repositories (
            id, tenant_id, scm_provider, provider_repository_id, owner, name,
            created_at_ms, updated_at_ms
        )
        VALUES ($1, $2, $3, $4, $5, $6, 1, 1)
        ",
    )
    .bind(Uuid::new_v4())
    .bind(&other_tenant)
    .bind(&provider)
    .bind(&provider_repository_id)
    .bind(&owner)
    .bind(&name)
    .execute(database.pool())
    .await?;

    let duplicate_in_tenant = sqlx::query(
        r"
        INSERT INTO repositories (
            id, tenant_id, scm_provider, provider_repository_id, owner, name,
            created_at_ms, updated_at_ms
        )
        VALUES ($1, $2, $3, $4, 'different-owner', 'different-name', 1, 1)
        ",
    )
    .bind(Uuid::new_v4())
    .bind(&seed.tenant_id)
    .bind(&provider)
    .bind(&provider_repository_id)
    .execute(database.pool())
    .await
    .expect_err("provider repository identity must be unique inside a tenant");
    assert_constraint(
        &duplicate_in_tenant,
        "repositories_provider_identity_unique",
    );

    exercise_runner_tenant_constraints(database, seed, &other_tenant).await?;
    Ok(())
}

async fn exercise_runner_tenant_constraints(
    database: &TestDatabase,
    seed: &SeedData,
    other_tenant: &str,
) -> TestResult {
    let group_id = Uuid::new_v4();
    sqlx::query(
        r"
        INSERT INTO runner_groups (
            id, tenant_id, name, normalized_name, created_at_ms, updated_at_ms
        )
        VALUES ($1, $2, 'Default', 'default', 1, 1)
        ",
    )
    .bind(group_id)
    .bind(&seed.tenant_id)
    .execute(database.pool())
    .await?;
    sqlx::query(
        r"
        INSERT INTO runner_groups (
            id, tenant_id, name, normalized_name, created_at_ms, updated_at_ms
        )
        VALUES ($1, $2, 'Default', 'default', 1, 1)
        ",
    )
    .bind(Uuid::new_v4())
    .bind(other_tenant)
    .execute(database.pool())
    .await?;
    sqlx::query(
        r"
        INSERT INTO runners (
            id, tenant_id, name, normalized_name, capabilities,
            slots, status, created_at_ms, updated_at_ms
        )
        VALUES ($1, $2, 'test-runner-0', 'test-runner-0', '{}',
                1, 'online', 1, 1)
        ",
    )
    .bind(Uuid::new_v4())
    .bind(other_tenant)
    .execute(database.pool())
    .await?;
    let cross_tenant_group = sqlx::query(
        r"
        INSERT INTO runners (
            id, tenant_id, group_id, name, normalized_name, capabilities,
            slots, status, created_at_ms, updated_at_ms
        )
        VALUES ($1, $2, $3, 'cross-tenant', 'cross-tenant', '{}',
                1, 'online', 1, 1)
        ",
    )
    .bind(Uuid::new_v4())
    .bind(other_tenant)
    .bind(group_id)
    .execute(database.pool())
    .await
    .expect_err("a runner group must belong to the runner's tenant");
    assert_constraint(&cross_tenant_group, "runners_group_matches_tenant");
    Ok(())
}
