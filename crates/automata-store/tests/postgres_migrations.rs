mod common;

use uuid::Uuid;

use sqlx::migrate::Migrate as _;

use common::{
    SeedData, TestDatabase, TestResult, run_with_database, run_with_unmigrated_database,
    seed_control_plane,
};

static TEST_MIGRATOR: sqlx::migrate::Migrator = sqlx::migrate!("./migrations");

#[tokio::test]
#[ignore = "requires AUTOMATA_TEST_DATABASE_URL and creates a temporary schema"]
async fn migrations_are_repeatable_and_enforce_attempt_invariants() -> TestResult {
    run_with_database(|database| async move { exercise_constraints(&database).await }).await
}

#[tokio::test]
#[ignore = "requires AUTOMATA_TEST_DATABASE_URL and creates a temporary schema"]
#[allow(clippy::too_many_lines)]
async fn g1_upgrade_fences_populated_legacy_execution_state_without_fake_metadata() -> TestResult {
    run_with_unmigrated_database(|database| async move {
        let mut connection = database.pool().acquire().await?;
        let table_name = TEST_MIGRATOR.table_name.as_ref();
        connection.ensure_migrations_table(table_name).await?;
        let initial = TEST_MIGRATOR.iter().next().expect("initial migration");
        connection.apply(table_name, initial).await?;
        drop(connection);

        let tenant = format!("legacy-{}", Uuid::new_v4().simple());
        let repository = Uuid::new_v4();
        let workflow = Uuid::new_v4();
        let snapshot = Uuid::new_v4();
        let run = Uuid::new_v4();
        let job = Uuid::new_v4();
        let runner = Uuid::new_v4();
        let session = Uuid::new_v4();
        let queued_attempt = Uuid::new_v4();
        let active_attempt = Uuid::new_v4();
        sqlx::query("INSERT INTO tenants VALUES ($1, 'Legacy', 1, 1)")
            .bind(&tenant)
            .execute(database.pool())
            .await?;
        sqlx::query(
            r"
            INSERT INTO repositories (
                id, tenant_id, scm_provider, provider_repository_id, owner, name,
                created_at_ms, updated_at_ms
            ) VALUES ($1, $2, 'test', $3, 'automata', 'legacy', 1, 1)
            ",
        )
        .bind(repository)
        .bind(&tenant)
        .bind(repository.to_string())
        .execute(database.pool())
        .await?;
        sqlx::query(
            "INSERT INTO workflow_definitions (id, repository_id, path, created_at_ms, updated_at_ms) VALUES ($1, $2, '.github/workflows/legacy.yml', 1, 1)",
        )
        .bind(workflow)
        .bind(repository)
        .execute(database.pool())
        .await?;
        sqlx::query(
            "INSERT INTO workflow_snapshots (id, workflow_id, source_digest, source_object_key, frontend_schema, created_at_ms) VALUES ($1, $2, $3, 'legacy/workflow', 1, 1)",
        )
        .bind(snapshot)
        .bind(workflow)
        .bind(vec![1_u8; 32])
        .execute(database.pool())
        .await?;
        sqlx::query(
            r"
            INSERT INTO workflow_runs (
                id, repository_id, workflow_id, snapshot_id, run_number,
                event_name, event_object_key, head_sha, status,
                created_at_ms, updated_at_ms
            ) VALUES ($1, $2, $3, $4, 1, 'push', 'legacy/event', $5, 'in_progress', 1, 1)
            ",
        )
        .bind(run)
        .bind(repository)
        .bind(workflow)
        .bind(snapshot)
        .bind(vec![2_u8; 20])
        .execute(database.pool())
        .await?;
        sqlx::query(
            r"
            INSERT INTO jobs (
                id, run_id, job_key, display_name, job_ir_digest,
                job_ir_object_key, requirements, runner_group, labels, created_at_ms
            ) VALUES ($1, $2, 'legacy', 'Legacy', $3, 'legacy/job-ir', '{}', 'legacy-group', ARRAY['legacy-label'], 1)
            ",
        )
        .bind(job)
        .bind(run)
        .bind(vec![3_u8; 32])
        .execute(database.pool())
        .await?;
        sqlx::query(
            r"
            INSERT INTO runners (
                id, tenant_id, name, normalized_name, capabilities,
                slots, status, created_at_ms, updated_at_ms
            ) VALUES ($1, $2, 'Legacy runner', 'legacy-runner', '{}', 2, 'online', 1, 1)
            ",
        )
        .bind(runner)
        .bind(&tenant)
        .execute(database.pool())
        .await?;
        sqlx::query(
            r"
            INSERT INTO runner_sessions (
                id, runner_id, protocol_version, job_ir_schema,
                capability_snapshot, connected_at_ms, heartbeat_at_ms
            ) VALUES ($1, $2, 1, 1, '{}', 2, 3)
            ",
        )
        .bind(session)
        .bind(runner)
        .execute(database.pool())
        .await?;
        sqlx::query(
            "INSERT INTO job_attempts (id, job_id, attempt_number, lifecycle, queued_at_ms, changed_at_ms) VALUES ($1, $2, 1, 'queued', 4, 4)",
        )
        .bind(queued_attempt)
        .bind(job)
        .execute(database.pool())
        .await?;
        sqlx::query(
            r"
            INSERT INTO job_attempts (
                id, job_id, attempt_number, lifecycle, fencing_token,
                lease_id, runner_id, lease_issued_at_ms, lease_expires_at_ms,
                queued_at_ms, changed_at_ms
            ) VALUES ($1, $2, 2, 'running', 1, $3, $4, 5, 50, 4, 6)
            ",
        )
        .bind(active_attempt)
        .bind(job)
        .bind(Uuid::new_v4())
        .bind(runner)
        .execute(database.pool())
        .await?;

        database.store().migrate().await?;

        let compatibility: (i32, i32, i32) = sqlx::query_as(
            "SELECT minimum_admission_epoch, job_ir_schema, runner_requirements_schema FROM automata_cluster_compatibility WHERE singleton",
        )
        .fetch_one(database.pool())
        .await?;
        assert_eq!(compatibility, (3, 4, 2));
        let job_metadata: (i32, Option<i32>, Option<i64>) = sqlx::query_as(
            "SELECT admission_epoch, job_ir_schema, job_ir_size_bytes FROM jobs WHERE id = $1",
        )
        .bind(job)
        .fetch_one(database.pool())
        .await?;
        assert_eq!(job_metadata, (1, None, None));
        let lifecycles: Vec<String> = sqlx::query_scalar(
            "SELECT lifecycle FROM job_attempts WHERE job_id = $1 ORDER BY attempt_number",
        )
        .bind(job)
        .fetch_all(database.pool())
        .await?;
        assert_eq!(lifecycles, ["skipped", "lost"]);
        let session_closed: bool = sqlx::query_scalar(
            "SELECT disconnected_at_ms IS NOT NULL FROM runner_sessions WHERE id = $1",
        )
        .bind(session)
        .fetch_one(database.pool())
        .await?;
        let runner_authority: (String, String, Option<String>) = sqlx::query_as(
            "SELECT status, desired_state, external_identity FROM runners WHERE id = $1",
        )
        .bind(runner)
        .fetch_one(database.pool())
        .await?;
        let machine_certificate_count: i64 =
            sqlx::query_scalar("SELECT count(*) FROM runner_machine_certificates")
                .fetch_one(database.pool())
                .await?;
        assert!(session_closed);
        assert_eq!(runner_authority, ("offline".into(), "active".into(), None));
        assert_eq!(machine_certificate_count, 0);
        Ok(())
    })
    .await
}

#[tokio::test]
#[ignore = "requires AUTOMATA_TEST_DATABASE_URL and creates a temporary schema"]
#[allow(clippy::too_many_lines)]
async fn job_ir_v4_upgrade_preserves_v3_history_and_fences_live_v3_writers() -> TestResult {
    run_with_unmigrated_database(|database| async move {
        let mut connection = database.pool().acquire().await?;
        let table_name = TEST_MIGRATOR.table_name.as_ref();
        connection.ensure_migrations_table(table_name).await?;
        for migration in TEST_MIGRATOR.iter().take(6) {
            connection.apply(table_name, migration).await?;
        }
        drop(connection);

        let tenant = format!("job-ir-v4-upgrade-{}", Uuid::new_v4().simple());
        let repository = Uuid::new_v4();
        let workflow = Uuid::new_v4();
        let snapshot = Uuid::new_v4();
        let run = Uuid::new_v4();
        let job = Uuid::new_v4();
        let runner = Uuid::new_v4();
        let session = Uuid::new_v4();

        sqlx::query("INSERT INTO tenants VALUES ($1, 'JobIR v4 upgrade', 1, 1)")
            .bind(&tenant)
            .execute(database.pool())
            .await?;
        sqlx::query(
            r"
            INSERT INTO repositories (
                id, tenant_id, scm_provider, provider_repository_id, owner, name,
                created_at_ms, updated_at_ms
            ) VALUES ($1, $2, 'test', $3, 'automata', 'job-ir-v4-upgrade', 1, 1)
            ",
        )
        .bind(repository)
        .bind(&tenant)
        .bind(repository.to_string())
        .execute(database.pool())
        .await?;
        sqlx::query(
            "INSERT INTO workflow_definitions (id, repository_id, path, created_at_ms, updated_at_ms) VALUES ($1, $2, '.github/workflows/upgrade.yml', 1, 1)",
        )
        .bind(workflow)
        .bind(repository)
        .execute(database.pool())
        .await?;
        sqlx::query(
            r"
            INSERT INTO workflow_snapshots (
                id, workflow_id, source_digest, source_object_key, frontend_schema,
                created_at_ms, admission_epoch, source_size_bytes, source_media_type
            ) VALUES ($1, $2, $3, 'upgrade/workflow', 1, 1, 2, 128, 'text/yaml')
            ",
        )
        .bind(snapshot)
        .bind(workflow)
        .bind(vec![1_u8; 32])
        .execute(database.pool())
        .await?;
        sqlx::query(
            r"
            INSERT INTO workflow_runs (
                id, repository_id, workflow_id, snapshot_id, run_number, event_name,
                event_object_key, head_sha, status, created_at_ms, updated_at_ms,
                admission_epoch, event_digest, event_size_bytes, event_media_type,
                plan_digest, plan_object_key, plan_size_bytes, plan_media_type, plan_schema
            ) VALUES (
                $1, $2, $3, $4, 1, 'push', 'upgrade/event', $5, 'queued', 1, 1,
                2, $6, 128, 'application/json', $7, 'upgrade/plan', 128,
                'application/json', 1
            )
            ",
        )
        .bind(run)
        .bind(repository)
        .bind(workflow)
        .bind(snapshot)
        .bind(vec![2_u8; 20])
        .bind(vec![3_u8; 32])
        .bind(vec![4_u8; 32])
        .execute(database.pool())
        .await?;
        sqlx::query(
            r#"
            INSERT INTO jobs (
                id, run_id, job_key, display_name, job_ir_digest,
                job_ir_object_key, requirements, admission_epoch,
                job_ir_schema, job_ir_size_bytes, created_at_ms
            ) VALUES (
                $1, $2, 'historical-v3', 'Historical v3', $3, 'upgrade/job-ir-v3',
                '{"schema_version":2,"labels":[],"eligible_groups":[],"platform":null,"minimum_cpu_cores":null,"minimum_memory_bytes":null,"required_features":[]}',
                2, 3, 128, 1
            )
            "#,
        )
        .bind(job)
        .bind(run)
        .bind(vec![5_u8; 32])
        .execute(database.pool())
        .await?;
        sqlx::query(
            r"
            INSERT INTO runners (
                id, tenant_id, name, normalized_name, capabilities, slots, status,
                desired_state, session_epoch, created_at_ms, updated_at_ms
            ) VALUES ($1, $2, 'v3 runner', 'v3-runner', '{}', 1, 'online', 'active', 1, 1, 1)
            ",
        )
        .bind(runner)
        .bind(&tenant)
        .execute(database.pool())
        .await?;
        sqlx::query(
            r"
            INSERT INTO runner_sessions (
                id, runner_id, protocol_version, job_ir_schema, capability_snapshot,
                connected_at_ms, heartbeat_at_ms, runner_generation, session_epoch
            ) VALUES ($1, $2, 1, 3, '{}', 2, 3, 1, 1)
            ",
        )
        .bind(session)
        .bind(runner)
        .execute(database.pool())
        .await?;

        database.store().migrate().await?;

        let compatibility: (i32, i32, i32) = sqlx::query_as(
            "SELECT minimum_admission_epoch, job_ir_schema, runner_requirements_schema FROM automata_cluster_compatibility WHERE singleton",
        )
        .fetch_one(database.pool())
        .await?;
        assert_eq!(compatibility, (3, 4, 2));
        let historical: (i32, i32) =
            sqlx::query_as("SELECT admission_epoch, job_ir_schema FROM jobs WHERE id = $1")
                .bind(job)
                .fetch_one(database.pool())
                .await?;
        assert_eq!(historical, (2, 3));
        let fenced: (bool, String) = sqlx::query_as(
            r"
            SELECT session.disconnected_at_ms IS NOT NULL, runner.status
            FROM runner_sessions AS session
            JOIN runners AS runner ON runner.id = session.runner_id
            WHERE session.id = $1
            ",
        )
        .bind(session)
        .fetch_one(database.pool())
        .await?;
        assert_eq!(fenced, (true, "offline".into()));

        sqlx::query(
            r"
            INSERT INTO jobs (
                id, run_id, job_key, display_name, job_ir_digest,
                job_ir_object_key, requirements, admission_epoch,
                job_ir_schema, job_ir_size_bytes, created_at_ms
            ) SELECT $1, run_id, 'current-v4', 'Current v4', $2,
                     'upgrade/job-ir-v4', requirements, 3, 4, 128, 2
              FROM jobs WHERE id = $3
            ",
        )
        .bind(Uuid::new_v4())
        .bind(vec![6_u8; 32])
        .bind(job)
        .execute(database.pool())
        .await?;
        let current_v3 = sqlx::query(
            r"
            INSERT INTO jobs (
                id, run_id, job_key, display_name, job_ir_digest,
                job_ir_object_key, requirements, admission_epoch,
                job_ir_schema, job_ir_size_bytes, created_at_ms
            ) SELECT $1, run_id, 'current-v3', 'Current v3', $2,
                     'upgrade/current-v3', requirements, 3, 3, 128, 2
              FROM jobs WHERE id = $3
            ",
        )
        .bind(Uuid::new_v4())
        .bind(vec![7_u8; 32])
        .bind(job)
        .execute(database.pool())
        .await
        .expect_err("admission epoch 3 must fail closed on JobIR v3");
        assert_constraint(&current_v3, "jobs_current_admission_metadata");

        let live_v3 = sqlx::query(
            r"
            INSERT INTO runner_sessions (
                id, runner_id, protocol_version, job_ir_schema, capability_snapshot,
                connected_at_ms, heartbeat_at_ms, runner_generation, session_epoch
            ) VALUES ($1, $2, 1, 3, '{}', 4, 4, 1, 2)
            ",
        )
        .bind(Uuid::new_v4())
        .bind(runner)
        .execute(database.pool())
        .await
        .expect_err("a v3 session cannot remain live after the v4 fence");
        assert_constraint(&live_v3, "runner_sessions_live_job_ir_v4");
        Ok(())
    })
    .await
}

#[tokio::test]
#[ignore = "requires AUTOMATA_TEST_DATABASE_URL and creates a temporary schema"]
#[allow(clippy::too_many_lines)]
async fn protocol_v4_lease_head_upgrade_fences_old_live_sessions_and_cleans_closed_retry_state()
-> TestResult {
    run_with_unmigrated_database(|database| async move {
        let mut connection = database.pool().acquire().await?;
        let table_name = TEST_MIGRATOR.table_name.as_ref();
        connection.ensure_migrations_table(table_name).await?;
        for migration in TEST_MIGRATOR.iter().take(7) {
            connection.apply(table_name, migration).await?;
        }
        drop(connection);

        let tenant = format!("protocol-v4-upgrade-{}", Uuid::new_v4().simple());
        let runner = Uuid::new_v4();
        let closed_session = Uuid::new_v4();
        let live_session = Uuid::new_v4();
        sqlx::query("INSERT INTO tenants VALUES ($1, 'Protocol v4 upgrade', 1, 1)")
            .bind(&tenant)
            .execute(database.pool())
            .await?;
        sqlx::query(
            r"
            INSERT INTO runners (
                id, tenant_id, name, normalized_name, capabilities, slots, status,
                desired_state, session_epoch, created_at_ms, updated_at_ms
            ) VALUES ($1, $2, 'v3 runner', 'protocol-v3-runner', '{}', 2,
                      'online', 'active', 2, 1, 1)
            ",
        )
        .bind(runner)
        .bind(&tenant)
        .execute(database.pool())
        .await?;
        sqlx::query(
            r"
            INSERT INTO runner_sessions (
                id, runner_id, protocol_version, job_ir_schema, capability_snapshot,
                connected_at_ms, heartbeat_at_ms, disconnected_at_ms,
                runner_generation, session_epoch
            ) VALUES
                ($1, $3, 3, 4, '{}', 2, 3, 4, 1, 1),
                ($2, $3, 3, 4, '{}', 5, 6, NULL, 1, 2)
            ",
        )
        .bind(closed_session)
        .bind(live_session)
        .bind(runner)
        .execute(database.pool())
        .await?;
        let semantic_operation = Uuid::new_v4();
        sqlx::query(
            r"
            INSERT INTO runner_operation_receipts (
                runner_session_id, operation_id, runner_id,
                runner_session_epoch, runner_generation, operation_kind,
                request_digest, selection_kind, runner_slot, scan_cursor_version,
                committed_cursor_version, observed_at_ms, outcome, completed_at_ms
            ) VALUES ($1, $2, $3, 1, 1, 'automata.lease-request.v1', $4,
                      'no_work', 1, 0, 1, 3, 'no_work', 3)
            ",
        )
        .bind(closed_session)
        .bind(semantic_operation)
        .bind(runner)
        .bind(vec![1_u8; 32])
        .execute(database.pool())
        .await?;
        for (kind, operation) in [
            ("automata.runner.lease-request.v1", Uuid::new_v4()),
            ("automata.runner.lease-heartbeat.v1", Uuid::new_v4()),
        ] {
            sqlx::query(
                r"
                INSERT INTO runner_rpc_receipts (
                    runner_session_id, operation_id, runner_id,
                    runner_session_epoch, runner_generation, operation_kind,
                    request_digest, response_schema, response_digest,
                    response_payload, committed_at_ms
                ) VALUES ($1, $2, $3, 1, 1, $4, $5, 1, $6, $7, 3)
                ",
            )
            .bind(closed_session)
            .bind(operation)
            .bind(runner)
            .bind(kind)
            .bind(vec![2_u8; 32])
            .bind(vec![3_u8; 32])
            .bind(vec![4_u8])
            .execute(database.pool())
            .await?;
        }

        database.store().migrate().await?;

        let fenced: (bool, String) = sqlx::query_as(
            r"
            SELECT session.disconnected_at_ms IS NOT NULL, runner.status
            FROM runner_sessions AS session
            JOIN runners AS runner ON runner.id = session.runner_id
            WHERE session.id = $1
            ",
        )
        .bind(live_session)
        .fetch_one(database.pool())
        .await?;
        assert_eq!(fenced, (true, "offline".into()));
        let retry_counts: (i64, i64, i64) = sqlx::query_as(
            r"
            SELECT
                (SELECT count(*) FROM runner_operation_receipts WHERE runner_session_id = $1),
                (SELECT count(*) FROM runner_rpc_receipts WHERE runner_session_id = $1 AND operation_kind = 'automata.runner.lease-request.v1'),
                (SELECT count(*) FROM runner_rpc_receipts WHERE runner_session_id = $1 AND operation_kind = 'automata.runner.lease-heartbeat.v1')
            ",
        )
        .bind(closed_session)
        .fetch_one(database.pool())
        .await?;
        assert_eq!(retry_counts, (0, 0, 1));
        let head_table: Option<String> = sqlx::query_scalar(
            "SELECT to_regclass('runner_lease_request_heads')::text",
        )
        .fetch_one(database.pool())
        .await?;
        assert_eq!(head_table.as_deref(), Some("runner_lease_request_heads"));

        let rejected = sqlx::query(
            r"
            INSERT INTO runner_sessions (
                id, runner_id, protocol_version, job_ir_schema, capability_snapshot,
                connected_at_ms, heartbeat_at_ms, runner_generation, session_epoch
            ) VALUES ($1, $2, 3, 4, '{}', 7, 7, 1, 3)
            ",
        )
        .bind(Uuid::new_v4())
        .bind(runner)
        .execute(database.pool())
        .await
        .expect_err("a protocol-v3 session cannot remain live after migration 0008");
        assert_constraint(&rejected, "runner_sessions_live_protocol_v4");
        sqlx::query(
            r"
            INSERT INTO runner_sessions (
                id, runner_id, protocol_version, job_ir_schema, capability_snapshot,
                connected_at_ms, heartbeat_at_ms, runner_generation, session_epoch
            ) VALUES ($1, $2, 4, 4, '{}', 7, 7, 1, 3)
            ",
        )
        .bind(Uuid::new_v4())
        .bind(runner)
        .execute(database.pool())
        .await?;
        Ok(())
    })
    .await
}

#[tokio::test]
#[ignore = "requires AUTOMATA_TEST_DATABASE_URL and creates a temporary schema"]
#[allow(clippy::too_many_lines)]
async fn runner_authority_upgrade_preserves_live_draining_without_inventing_trust() -> TestResult {
    run_with_unmigrated_database(|database| async move {
        let mut connection = database.pool().acquire().await?;
        let table_name = TEST_MIGRATOR.table_name.as_ref();
        connection.ensure_migrations_table(table_name).await?;
        for migration in TEST_MIGRATOR.iter().take(3) {
            connection.apply(table_name, migration).await?;
        }
        drop(connection);

        let tenant = format!("authority-upgrade-{}", Uuid::new_v4().simple());
        sqlx::query("INSERT INTO tenants VALUES ($1, 'Authority upgrade', 1, 1)")
            .bind(&tenant)
            .execute(database.pool())
            .await?;
        let online = Uuid::new_v4();
        let offline = Uuid::new_v4();
        let draining_live = Uuid::new_v4();
        let draining_closed = Uuid::new_v4();
        let disabled = Uuid::new_v4();
        for (id, name, status, epoch, fingerprint) in [
            (online, "online", "online", 0_i64, None),
            (offline, "offline", "offline", 0, None),
            (
                draining_live,
                "draining-live",
                "draining",
                1,
                Some(vec![7_u8; 32]),
            ),
            (draining_closed, "draining-closed", "draining", 1, None),
            (disabled, "disabled", "disabled", 0, None),
        ] {
            sqlx::query(
                r"
                INSERT INTO runners (
                    id, tenant_id, name, normalized_name, capabilities, slots,
                    status, session_epoch, certificate_fingerprint,
                    created_at_ms, updated_at_ms
                ) VALUES ($1, $2, $3, $3, '{}', 1, $4, $5, $6, 1, 1)
                ",
            )
            .bind(id)
            .bind(&tenant)
            .bind(name)
            .bind(status)
            .bind(epoch)
            .bind(fingerprint)
            .execute(database.pool())
            .await?;
        }
        let live_session = Uuid::new_v4();
        let closed_session = Uuid::new_v4();
        for (id, runner, disconnected_at_ms) in [
            (live_session, draining_live, None),
            (closed_session, draining_closed, Some(3_i64)),
        ] {
            sqlx::query(
                r"
                INSERT INTO runner_sessions (
                    id, runner_id, protocol_version, job_ir_schema,
                    capability_snapshot, connected_at_ms, heartbeat_at_ms,
                    disconnected_at_ms, runner_generation, session_epoch
                ) VALUES ($1, $2, 1, 3, '{}', 1, 2, $3, 1, 1)
                ",
            )
            .bind(id)
            .bind(runner)
            .bind(disconnected_at_ms)
            .execute(database.pool())
            .await?;
        }

        database.store().migrate().await?;

        let states: Vec<(String, String, String, Option<String>)> = sqlx::query_as(
            r"
            SELECT name, desired_state, status, external_identity
            FROM runners
            WHERE tenant_id = $1
            ORDER BY name
            ",
        )
        .bind(&tenant)
        .fetch_all(database.pool())
        .await?;
        assert_eq!(
            states,
            [
                ("disabled".into(), "disabled".into(), "offline".into(), None),
                (
                    "draining-closed".into(),
                    "draining".into(),
                    "offline".into(),
                    None,
                ),
                (
                    "draining-live".into(),
                    "draining".into(),
                    "offline".into(),
                    None,
                ),
                ("offline".into(), "active".into(), "offline".into(), None),
                ("online".into(), "active".into(), "online".into(), None),
            ]
        );
        let v3_session_fenced: (i64, i64, bool) = sqlx::query_as(
            "SELECT runner_generation, session_epoch, disconnected_at_ms IS NULL FROM runner_sessions WHERE id = $1",
        )
        .bind(live_session)
        .fetch_one(database.pool())
        .await?;
        assert_eq!(v3_session_fenced, (1, 1, false));
        let certificate_count: i64 =
            sqlx::query_scalar("SELECT count(*) FROM runner_machine_certificates")
                .fetch_one(database.pool())
                .await?;
        assert_eq!(certificate_count, 0, "legacy fingerprints are not authority");
        let desired_default: Option<String> = sqlx::query_scalar(
            "SELECT column_default FROM information_schema.columns WHERE table_schema = current_schema() AND table_name = 'runners' AND column_name = 'desired_state'",
        )
        .fetch_one(database.pool())
        .await?;
        assert!(desired_default.is_none(), "stale writers cannot inherit active authority");
        Ok(())
    })
    .await
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
            runner_session_id, runner_session_epoch, runner_generation, runner_slot,
            queued_at_ms, changed_at_ms
        )
        VALUES (
            $1, $2, 3, 'leased', 0, $3, $4, 1, 2,
            $5, $6, $7, 1, 1, 1
        )
        ",
    )
    .bind(Uuid::new_v4())
    .bind(seed.job_id.as_uuid())
    .bind(Uuid::new_v4())
    .bind(seed.runner_ids[0].as_uuid())
    .bind(seed.session_fences[0].session_id().as_uuid())
    .bind(i64::try_from(seed.session_fences[0].session_epoch().get())?)
    .bind(i64::try_from(
        seed.session_fences[0].runner_generation().get(),
    )?)
    .execute(database.pool())
    .await
    .expect_err("an active lease without a fencing token must be rejected");
    assert_constraint(&unfenced_lease, "job_attempts_active_lease_fenced");

    let invalid_interval = sqlx::query(
        r"
        INSERT INTO job_attempts (
            id, job_id, attempt_number, lifecycle, fencing_token, lease_id,
            runner_id, lease_issued_at_ms, lease_expires_at_ms,
            runner_session_id, runner_session_epoch, runner_generation, runner_slot,
            queued_at_ms, changed_at_ms
        )
        VALUES (
            $1, $2, 4, 'leased', 1, $3, $4, 2, 2,
            $5, $6, $7, 1, 1, 1
        )
        ",
    )
    .bind(Uuid::new_v4())
    .bind(seed.job_id.as_uuid())
    .bind(Uuid::new_v4())
    .bind(seed.runner_ids[0].as_uuid())
    .bind(seed.session_fences[0].session_id().as_uuid())
    .bind(i64::try_from(seed.session_fences[0].session_epoch().get())?)
    .bind(i64::try_from(
        seed.session_fences[0].runner_generation().get(),
    )?)
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
    exercise_g1_constraints(database, &seed).await?;
    exercise_workflow_and_concurrency_scope(database, &seed).await?;
    exercise_runner_machine_authority_constraints(database, &seed).await?;
    Ok(())
}

#[allow(clippy::too_many_lines)]
async fn exercise_runner_machine_authority_constraints(
    database: &TestDatabase,
    seed: &SeedData,
) -> TestResult {
    let runner = seed.runner_ids[0];
    sqlx::query("UPDATE runners SET external_identity = 'machine:primary' WHERE id = $1")
        .bind(runner.as_uuid())
        .execute(database.pool())
        .await?;
    for digest in [vec![31_u8; 32], vec![32_u8; 32]] {
        sqlx::query(
            "INSERT INTO runner_machine_certificates (leaf_sha256, runner_id, expires_at_seconds) VALUES ($1, $2, 1000)",
        )
        .bind(digest)
        .bind(runner.as_uuid())
        .execute(database.pool())
        .await?;
    }

    let short_digest = sqlx::query(
        "INSERT INTO runner_machine_certificates (leaf_sha256, runner_id, expires_at_seconds) VALUES ($1, $2, 1000)",
    )
    .bind(vec![1_u8; 31])
    .bind(runner.as_uuid())
    .execute(database.pool())
    .await
    .expect_err("certificate digests must contain exactly 32 bytes");
    assert_constraint(&short_digest, "runner_machine_certificates_leaf_sha256");

    let zero_expiry = sqlx::query(
        "INSERT INTO runner_machine_certificates (leaf_sha256, runner_id, expires_at_seconds) VALUES ($1, $2, 0)",
    )
    .bind(vec![33_u8; 32])
    .bind(runner.as_uuid())
    .execute(database.pool())
    .await
    .expect_err("certificate expiration must be positive");
    assert_constraint(
        &zero_expiry,
        "runner_machine_certificates_expiration_positive",
    );

    let invalid_revocation = sqlx::query(
        "INSERT INTO runner_machine_certificates (leaf_sha256, runner_id, expires_at_seconds, revoked_at_seconds) VALUES ($1, $2, 1000, 1001)",
    )
    .bind(vec![34_u8; 32])
    .bind(runner.as_uuid())
    .execute(database.pool())
    .await
    .expect_err("revocation cannot postdate expiration");
    assert_constraint(
        &invalid_revocation,
        "runner_machine_certificates_revocation_monotonic",
    );

    sqlx::query(
        "UPDATE runner_machine_certificates SET revoked_at_seconds = 500 WHERE leaf_sha256 = $1",
    )
    .bind(vec![31_u8; 32])
    .execute(database.pool())
    .await?;
    let unrevoke = sqlx::query(
        "UPDATE runner_machine_certificates SET revoked_at_seconds = NULL WHERE leaf_sha256 = $1",
    )
    .bind(vec![31_u8; 32])
    .execute(database.pool())
    .await
    .expect_err("revocation must be write-once");
    assert_constraint(
        &unrevoke,
        "runner_machine_certificates_revocation_write_once",
    );

    let invalid_desired = sqlx::query("UPDATE runners SET desired_state = 'paused' WHERE id = $1")
        .bind(runner.as_uuid())
        .execute(database.pool())
        .await
        .expect_err("desired state must use the authority vocabulary");
    assert_constraint(&invalid_desired, "runners_desired_state");
    let legacy_status = sqlx::query("UPDATE runners SET status = 'draining' WHERE id = $1")
        .bind(runner.as_uuid())
        .execute(database.pool())
        .await
        .expect_err("observed status must not carry lifecycle intent");
    assert_constraint(&legacy_status, "runners_status");

    let invalid_identity = sqlx::query(
        "UPDATE runners SET external_identity = E'machine:bad\\nidentity' WHERE id = $1",
    )
    .bind(runner.as_uuid())
    .execute(database.pool())
    .await
    .expect_err("external identity must reject control characters");
    assert_constraint(&invalid_identity, "runners_external_identity_shape");

    let other_tenant = format!("machine-authority-{}", Uuid::new_v4().simple());
    sqlx::query("INSERT INTO tenants VALUES ($1, 'Machine authority', 1, 1)")
        .bind(&other_tenant)
        .execute(database.pool())
        .await?;
    let duplicate_identity = sqlx::query(
        r"
        INSERT INTO runners (
            id, tenant_id, name, normalized_name, capabilities, slots, status,
            desired_state, external_identity, created_at_ms, updated_at_ms
        ) VALUES ($1, $2, 'other', 'other', '{}', 1, 'offline', 'active',
                  'machine:primary', 1, 1)
        ",
    )
    .bind(Uuid::new_v4())
    .bind(&other_tenant)
    .execute(database.pool())
    .await
    .expect_err("external identity must be globally unique across tenants");
    assert_constraint(&duplicate_identity, "runners_external_identity_unique");

    let unknown_runner = sqlx::query(
        "INSERT INTO runner_machine_certificates (leaf_sha256, runner_id, expires_at_seconds) VALUES ($1, $2, 1000)",
    )
    .bind(vec![35_u8; 32])
    .bind(Uuid::new_v4())
    .execute(database.pool())
    .await
    .expect_err("certificate authority must reference a durable runner");
    assert_constraint(
        &unknown_runner,
        "runner_machine_certificates_runner_id_fkey",
    );
    Ok(())
}

#[allow(clippy::too_many_lines)]
async fn exercise_g1_constraints(database: &TestDatabase, seed: &SeedData) -> TestResult {
    let fence = seed.session_fences[0];
    let second_live_session = sqlx::query(
        r"
        INSERT INTO runner_sessions (
            id, runner_id, protocol_version, job_ir_schema, capability_snapshot,
            connected_at_ms, heartbeat_at_ms, runner_generation, session_epoch
        )
        VALUES ($1, $2, 4, 4, '{}', 3, 3, 1, 2)
        ",
    )
    .bind(Uuid::new_v4())
    .bind(fence.runner_id().as_uuid())
    .execute(database.pool())
    .await
    .expect_err("a runner may have only one live durable session");
    assert_constraint(&second_live_session, "runner_sessions_one_live_per_runner");

    let downgraded_live_session =
        sqlx::query("UPDATE runner_sessions SET job_ir_schema = 2 WHERE id = $1")
            .bind(fence.session_id().as_uuid())
            .execute(database.pool())
            .await
            .expect_err("a live runner session must retain the exact admitted JobIR version");
    assert_constraint(&downgraded_live_session, "runner_sessions_live_job_ir_v4");

    let oversized_protocol = sqlx::query(
        r"
        INSERT INTO runner_sessions (
            id, runner_id, protocol_version, job_ir_schema, capability_snapshot,
            connected_at_ms, heartbeat_at_ms, disconnected_at_ms,
            runner_generation, session_epoch
        )
        VALUES ($1, $2, 65536, 1, '{}', 3, 3, 3, 1, 2)
        ",
    )
    .bind(Uuid::new_v4())
    .bind(fence.runner_id().as_uuid())
    .execute(database.pool())
    .await
    .expect_err("durable protocol versions must remain u16-compatible");
    assert_constraint(&oversized_protocol, "runner_sessions_protocol_u16");

    let oversized_slots = sqlx::query("UPDATE runners SET slots = 65536 WHERE id = $1")
        .bind(fence.runner_id().as_uuid())
        .execute(database.pool())
        .await
        .expect_err("runner capacity must remain u16-compatible");
    assert_constraint(&oversized_slots, "runners_slots_u16");

    let empty_job_ir = sqlx::query(
        r"
        INSERT INTO jobs (
            id, run_id, job_key, display_name, job_ir_digest,
            job_ir_object_key, requirements, admission_epoch,
            job_ir_schema, job_ir_size_bytes, created_at_ms
        )
        SELECT $1, run_id, 'empty-ir', 'Empty IR', $2,
               'test/empty-ir', requirements, 3, 4, 0, 1
        FROM jobs WHERE id = $3
        ",
    )
    .bind(Uuid::new_v4())
    .bind(vec![21_u8; 32])
    .bind(seed.job_id.as_uuid())
    .execute(database.pool())
    .await
    .expect_err("JobIR metadata must describe a nonempty bounded object");
    assert_constraint(&empty_job_ir, "jobs_current_admission_metadata");

    let downgraded_job_ir = sqlx::query(
        r"
        INSERT INTO jobs (
            id, run_id, job_key, display_name, job_ir_digest,
            job_ir_object_key, requirements, admission_epoch,
            job_ir_schema, job_ir_size_bytes, created_at_ms
        )
        SELECT $1, run_id, 'downgraded-ir', 'Downgraded IR', $2,
               'test/downgraded-ir', requirements, 3, 3, 128, 1
        FROM jobs WHERE id = $3
        ",
    )
    .bind(Uuid::new_v4())
    .bind(vec![22_u8; 32])
    .bind(seed.job_id.as_uuid())
    .execute(database.pool())
    .await
    .expect_err("current admission must require exact JobIR v4");
    assert_constraint(&downgraded_job_ir, "jobs_current_admission_metadata");

    let old_writer = sqlx::query(
        r"
        INSERT INTO jobs (
            id, run_id, job_key, display_name, job_ir_digest,
            job_ir_object_key, requirements, created_at_ms
        )
        SELECT $1, run_id, 'old-writer', 'Old writer', $2,
               'test/old-writer', requirements, 1
        FROM jobs WHERE id = $3
        ",
    )
    .bind(Uuid::new_v4())
    .bind(vec![23_u8; 32])
    .bind(seed.job_id.as_uuid())
    .execute(database.pool())
    .await
    .expect_err("a pre-epoch writer must fail closed instead of receiving fake defaults");
    assert_eq!(
        old_writer
            .as_database_error()
            .and_then(sqlx::error::DatabaseError::code)
            .as_deref(),
        Some("23502")
    );

    let mutable_plan = sqlx::query("UPDATE jobs SET display_name = 'changed' WHERE id = $1")
        .bind(seed.job_id.as_uuid())
        .execute(database.pool())
        .await
        .expect_err("an admitted job plan must be immutable");
    assert_constraint(&mutable_plan, "jobs_plan_immutable");

    let zero_slot = sqlx::query(
        r"
        INSERT INTO job_attempts (
            id, job_id, attempt_number, lifecycle, fencing_token, lease_id,
            runner_id, lease_issued_at_ms, lease_expires_at_ms,
            runner_session_id, runner_session_epoch, runner_generation, runner_slot,
            queued_at_ms, changed_at_ms
        )
        VALUES (
            $1, $2, 90, 'leased', 1, $3, $4, 3, 10,
            $5, $6, $7, 0, 1, 3
        )
        ",
    )
    .bind(Uuid::new_v4())
    .bind(seed.job_id.as_uuid())
    .bind(Uuid::new_v4())
    .bind(fence.runner_id().as_uuid())
    .bind(fence.session_id().as_uuid())
    .bind(i64::try_from(fence.session_epoch().get())?)
    .bind(i64::try_from(fence.runner_generation().get())?)
    .execute(database.pool())
    .await
    .expect_err("stable runner slots are one-based");
    assert_constraint(&zero_slot, "job_attempts_runner_slot_range");

    let zero_command = sqlx::query(
        r"
        INSERT INTO runner_command_outbox (
            runner_session_id, command_sequence, operation_id, runner_id,
            runner_session_epoch, runner_generation, command_kind,
            command_schema, command_digest, command_payload, created_at_ms
        )
        VALUES ($1, 0, $2, $3, $4, $5, 'automata.test.v1', 1, $6, $7, 3)
        ",
    )
    .bind(fence.session_id().as_uuid())
    .bind(Uuid::new_v4())
    .bind(fence.runner_id().as_uuid())
    .bind(i64::try_from(fence.session_epoch().get())?)
    .bind(i64::try_from(fence.runner_generation().get())?)
    .bind(vec![1_u8; 32])
    .bind(vec![1_u8])
    .execute(database.pool())
    .await
    .expect_err("server command sequences are one-based");
    assert_constraint(&zero_command, "runner_command_outbox_sequence_positive");

    let malformed_receipt = sqlx::query(
        r"
        INSERT INTO runner_rpc_receipts (
            runner_session_id, operation_id, runner_id,
            runner_session_epoch, runner_generation, operation_kind,
            request_digest, response_schema, response_digest,
            response_payload, committed_at_ms
        )
        VALUES ($1, $2, $3, $4, $5, 'automata.test.v1', $6, 1, $7, $8, 3)
        ",
    )
    .bind(fence.session_id().as_uuid())
    .bind(Uuid::new_v4())
    .bind(fence.runner_id().as_uuid())
    .bind(i64::try_from(fence.session_epoch().get())?)
    .bind(i64::try_from(fence.runner_generation().get())?)
    .bind(vec![1_u8; 31])
    .bind(vec![2_u8; 32])
    .bind(vec![3_u8])
    .execute(database.pool())
    .await
    .expect_err("operation request digests must be SHA-256");
    assert_constraint(&malformed_receipt, "runner_rpc_receipts_request_sha256");

    exercise_same_run_dependency_constraint(database, seed).await?;
    exercise_result_and_log_constraints(database, seed).await
}

async fn exercise_same_run_dependency_constraint(
    database: &TestDatabase,
    seed: &SeedData,
) -> TestResult {
    let snapshot_id: Uuid =
        sqlx::query_scalar("SELECT snapshot_id FROM workflow_runs WHERE id = $1")
            .bind(seed.run_id.as_uuid())
            .fetch_one(database.pool())
            .await?;
    let other_run = Uuid::new_v4();
    sqlx::query(
        r"
        INSERT INTO workflow_runs (
            id, repository_id, workflow_id, snapshot_id, run_number, event_name,
            event_object_key, head_sha, status, created_at_ms, updated_at_ms
        )
        VALUES ($1, $2, $3, $4, 99, 'push', 'test/event', $5, 'queued', 1, 1)
        ",
    )
    .bind(other_run)
    .bind(seed.repository_id)
    .bind(seed.workflow_id)
    .bind(snapshot_id)
    .bind(vec![19_u8; 20])
    .execute(database.pool())
    .await?;
    let other_job = Uuid::new_v4();
    sqlx::query(
        r"
        INSERT INTO jobs (
            id, run_id, job_key, display_name, job_ir_digest,
            job_ir_object_key, requirements, admission_epoch,
            job_ir_schema, job_ir_size_bytes, created_at_ms
        )
        SELECT $1, $2, 'other', 'Other', $3, 'test/other-ir',
               requirements, 2, 3, 128, 1
        FROM jobs WHERE id = $4
        ",
    )
    .bind(other_job)
    .bind(other_run)
    .bind(vec![4_u8; 32])
    .bind(seed.job_id.as_uuid())
    .execute(database.pool())
    .await?;
    let cross_run = sqlx::query(
        r"
        INSERT INTO job_dependencies (run_id, job_id, prerequisite_job_id)
        VALUES ($1, $2, $3)
        ",
    )
    .bind(seed.run_id.as_uuid())
    .bind(seed.job_id.as_uuid())
    .bind(other_job)
    .execute(database.pool())
    .await
    .expect_err("dependency endpoints must belong to the declared run");
    assert_constraint(&cross_run, "job_dependencies_prerequisite_same_run");
    Ok(())
}

async fn exercise_result_and_log_constraints(
    database: &TestDatabase,
    seed: &SeedData,
) -> TestResult {
    let fence = seed.session_fences[0];
    let attempt_id = Uuid::new_v4();
    sqlx::query(
        r"
        INSERT INTO job_attempts (
            id, job_id, attempt_number, lifecycle, queued_at_ms, changed_at_ms
        )
        VALUES ($1, $2, 91, 'queued', 1, 1)
        ",
    )
    .bind(attempt_id)
    .bind(seed.job_id.as_uuid())
    .execute(database.pool())
    .await?;

    let empty_result = sqlx::query(
        r"
        INSERT INTO attempt_terminal_results (
            attempt_id, runner_session_id, operation_id, runner_id,
            runner_session_epoch, runner_generation, runner_slot,
            lease_id, fencing_token, result_schema, result_size_bytes,
            result_digest, result_object_key, conclusion,
            completed_at_ms, committed_at_ms
        )
        VALUES (
            $1, $2, $3, $4, $5, $6, 1,
            $7, 1, 1, 0, $8, 'results/key', 'success', 3, 3
        )
        ",
    )
    .bind(attempt_id)
    .bind(fence.session_id().as_uuid())
    .bind(Uuid::new_v4())
    .bind(fence.runner_id().as_uuid())
    .bind(i64::try_from(fence.session_epoch().get())?)
    .bind(i64::try_from(fence.runner_generation().get())?)
    .bind(Uuid::new_v4())
    .bind(vec![5_u8; 32])
    .execute(database.pool())
    .await
    .expect_err("terminal result metadata must describe a nonempty object");
    assert_constraint(&empty_result, "attempt_terminal_results_size_range");

    let stream_id = Uuid::new_v4();
    sqlx::query(
        r"
        INSERT INTO attempt_log_streams (
            id, attempt_id, runner_session_id, operation_id, runner_id,
            runner_session_epoch, runner_generation, runner_slot,
            lease_id, fencing_token, log_schema, opened_at_ms
        )
        VALUES ($1, $2, $3, $4, $5, $6, $7, 1, $8, 1, 1, 3)
        ",
    )
    .bind(stream_id)
    .bind(attempt_id)
    .bind(fence.session_id().as_uuid())
    .bind(Uuid::new_v4())
    .bind(fence.runner_id().as_uuid())
    .bind(i64::try_from(fence.session_epoch().get())?)
    .bind(i64::try_from(fence.runner_generation().get())?)
    .bind(Uuid::new_v4())
    .execute(database.pool())
    .await?;
    let inverted_segment = sqlx::query(
        r"
        INSERT INTO attempt_log_segments (
            stream_id, operation_id, first_sequence, last_sequence,
            object_key, object_digest, encoded_size_bytes,
            uncompressed_size_bytes, stored_at_ms
        )
        VALUES ($1, $2, 2, 1, 'logs/key', $3, 1, 1, 4)
        ",
    )
    .bind(stream_id)
    .bind(Uuid::new_v4())
    .bind(vec![6_u8; 32])
    .execute(database.pool())
    .await
    .expect_err("log segment ranges must not be inverted");
    assert_constraint(&inverted_segment, "attempt_log_segments_sequence_range");
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
            runner_session_id, runner_session_epoch, runner_generation, runner_slot,
            queued_at_ms, changed_at_ms
        )
        VALUES (
            $1, $2, 6, 'leased', 1, $3, $4, 10, 20,
            $5, $6, $7, 1, 1, 20
        )
        ",
    )
    .bind(Uuid::new_v4())
    .bind(seed.job_id.as_uuid())
    .bind(Uuid::new_v4())
    .bind(seed.runner_ids[0].as_uuid())
    .bind(seed.session_fences[0].session_id().as_uuid())
    .bind(i64::try_from(seed.session_fences[0].session_epoch().get())?)
    .bind(i64::try_from(
        seed.session_fences[0].runner_generation().get(),
    )?)
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
            slots, status, desired_state, created_at_ms, updated_at_ms
        )
        VALUES ($1, $2, 'test-runner-0', 'test-runner-0', '{}',
                1, 'online', 'active', 1, 1)
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
            slots, status, desired_state, created_at_ms, updated_at_ms
        )
        VALUES ($1, $2, $3, 'cross-tenant', 'cross-tenant', '{}',
                1, 'online', 'active', 1, 1)
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
