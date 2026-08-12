#[allow(dead_code)]
mod common;

use sqlx::migrate::Migrate as _;
use uuid::Uuid;

use common::{TestDatabase, TestResult, run_with_unmigrated_database, seed_control_plane};

const MIGRATION_VERSION: i64 = 66;
const REFUSAL_CONSTRAINT: &str = "job_environment_evidence_active_legacy_instances";

static MIGRATOR: sqlx::migrate::Migrator = sqlx::migrate!("./migrations");

#[tokio::test]
#[ignore = "requires PostgreSQL 18 and AUTOMATA_TEST_DATABASE_URL"]
async fn active_legacy_instance_refuses_atomically_then_terminal_history_migrates() -> TestResult {
    run_with_unmigrated_database(|database| async move {
        apply_before_0066(&database).await?;
        let seed = seed_control_plane(database.pool(), 0).await?;
        insert_activation_instance(&database, seed.run_id.as_uuid(), false, false).await?;

        let mut connection = database.pool().acquire().await?;
        let error = connection
            .apply(MIGRATOR.table_name.as_ref(), migration_0066())
            .await
            .expect_err("active legacy instances have no reconstructible gate evidence");
        assert_migration_refusal(error);
        drop(connection);

        assert_0066_absent(&database).await?;

        sqlx::query("ALTER TABLE workflow_runs DISABLE TRIGGER USER")
            .execute(database.pool())
            .await?;
        let terminal_update = async {
            let mut transaction = database.pool().begin().await?;
            let updated = sqlx::query(
                "UPDATE workflow_runs SET status = 'completed', updated_at_ms = 3 WHERE id = $1",
            )
            .bind(seed.run_id.as_uuid())
            .execute(&mut *transaction)
            .await?;
            transaction.commit().await?;
            Ok::<_, sqlx::Error>(updated.rows_affected())
        }
        .await;
        let trigger_restore = sqlx::query("ALTER TABLE workflow_runs ENABLE TRIGGER USER")
            .execute(database.pool())
            .await;
        let updated = terminal_update?;
        trigger_restore?;
        assert_eq!(updated, 1);

        let mut connection = database.pool().acquire().await?;
        connection
            .apply(MIGRATOR.table_name.as_ref(), migration_0066())
            .await?;
        drop(connection);

        let applied: (
            i64,
            i64,
            i64,
            Option<String>,
            Option<String>,
            Option<String>,
            i64,
            i64,
            i64,
            String,
        ) = sqlx::query_as(
            r"
            SELECT
                (SELECT count(*) FROM _sqlx_migrations
                 WHERE version = 66 AND success),
                (SELECT count(*) FROM workflow_plan_v2_instances
                 WHERE run_id = $1),
                (SELECT count(*)
                 FROM workflow_plan_v2_job_environment_evidence),
                to_regprocedure(
                    'automata_validate_job_environment_activation_evidence()'
                )::TEXT,
                to_regprocedure(
                    'automata_reusable_secret_identity_chain_is_exact(uuid,uuid,text)'
                )::TEXT,
                to_regprocedure(
                    'automata_require_job_environment_activation_evidence()'
                )::TEXT,
                (SELECT count(*) FROM pg_trigger
                 WHERE tgrelid = 'workflow_plan_v2_instances'::regclass
                   AND tgname =
                       'workflow_plan_v2_instances_require_environment_evidence'
                   AND tgdeferrable
                   AND tginitdeferred),
                (SELECT count(*) FROM pg_constraint
                 WHERE conrelid =
                       'workflow_plan_v2_reusable_secret_bindings'::regclass
                   AND conname =
                       'workflow_plan_v2_reusable_secret_targets_canonicalizable'),
                (SELECT count(*) FROM pg_indexes
                 WHERE schemaname = current_schema()
                   AND tablename =
                       'workflow_plan_v2_reusable_secret_bindings'
                   AND indexname =
                       'workflow_plan_v2_reusable_secret_targets_casefold_unique'),
                (SELECT status FROM workflow_runs WHERE id = $1)
            ",
        )
        .bind(seed.run_id.as_uuid())
        .fetch_one(database.pool())
        .await?;
        assert_eq!(applied.0, 1);
        assert_eq!(applied.1, 1, "terminal activation history must be retained");
        assert_eq!(applied.2, 0, "0066 must not guess historical evidence");
        assert!(applied.3.is_some(), "0066 evidence validator must exist");
        assert!(applied.4.is_some(), "0066 identity-chain helper must exist");
        assert!(
            applied.5.is_some(),
            "0066 commit-time evidence validator must exist"
        );
        assert_eq!(applied.6, 1, "evidence trigger must be deferred");
        assert_eq!(
            (applied.7, applied.8),
            (0, 0),
            "0066 must not globally constrain retained reusable bindings"
        );
        assert_eq!(applied.9, "completed");

        let current_seed = seed_control_plane(database.pool(), 1).await?;
        let error =
            insert_activation_instance(&database, current_seed.run_id.as_uuid(), true, false)
                .await
                .expect_err("a post-0066 instance cannot commit without evidence");
        let database_error = error
            .as_database_error()
            .expect("commit-time refusal is a PostgreSQL error");
        assert_eq!(database_error.code().as_deref(), Some("23514"));
        assert_eq!(
            database_error.constraint(),
            Some("workflow_plan_v2_instances_environment_evidence_required")
        );

        insert_activation_instance(&database, current_seed.run_id.as_uuid(), true, true).await?;
        let evidence_count: i64 = sqlx::query_scalar(
            r"
            SELECT count(*)
            FROM workflow_plan_v2_job_environment_evidence AS evidence
            JOIN workflow_plan_v2_instances AS instance
              ON instance.id = evidence.instance_id
            WHERE instance.run_id = $1
            ",
        )
        .bind(current_seed.run_id.as_uuid())
        .fetch_one(database.pool())
        .await?;
        assert_eq!(evidence_count, 1);
        Ok(())
    })
    .await
}

async fn apply_before_0066(database: &TestDatabase) -> TestResult {
    let mut connection = database.pool().acquire().await?;
    connection
        .ensure_migrations_table(MIGRATOR.table_name.as_ref())
        .await?;
    for migration in MIGRATOR
        .iter()
        .filter(|migration| migration.version < MIGRATION_VERSION)
    {
        connection
            .apply(MIGRATOR.table_name.as_ref(), migration)
            .await?;
    }
    Ok(())
}

fn migration_0066() -> &'static sqlx::migrate::Migration {
    MIGRATOR
        .iter()
        .find(|migration| migration.version == MIGRATION_VERSION)
        .expect("migration 0066 is embedded")
}

fn assert_migration_refusal(error: sqlx::migrate::MigrateError) {
    match error {
        sqlx::migrate::MigrateError::ExecuteMigration(error, MIGRATION_VERSION) => {
            let database_error = error
                .as_database_error()
                .expect("migration refusal is a PostgreSQL error");
            assert_eq!(database_error.code().as_deref(), Some("23514"));
            assert_eq!(database_error.constraint(), Some(REFUSAL_CONSTRAINT));
        }
        other => panic!("unexpected migration error: {other}"),
    }
}

async fn assert_0066_absent(database: &TestDatabase) -> TestResult {
    let absent: (
        i64,
        Option<String>,
        Option<String>,
        Option<String>,
        Option<String>,
        Option<String>,
        Option<String>,
        i64,
    ) = sqlx::query_as(
        r"
        SELECT
            (SELECT count(*) FROM _sqlx_migrations
             WHERE version = 66 AND success),
            to_regclass('workflow_plan_v2_job_environment_evidence')::TEXT,
            to_regprocedure(
                'automata_validate_job_environment_activation_evidence()'
            )::TEXT,
            to_regprocedure(
                'automata_reusable_secret_identity_chain_is_exact(uuid,uuid,text)'
            )::TEXT,
            to_regprocedure(
                'automata_require_job_environment_activation_evidence()'
            )::TEXT,
            to_regprocedure(
                'automata_reject_job_variable_lease_without_custody()'
            )::TEXT,
            to_regprocedure(
                'automata_reject_job_environment_evidence_mutation()'
            )::TEXT,
            (SELECT count(*) FROM pg_trigger
             WHERE tgname IN (
                 'job_attempts_00_require_variable_custody_before_lease',
                 'workflow_plan_v2_instances_require_environment_evidence'
             ))
        ",
    )
    .fetch_one(database.pool())
    .await?;
    assert_eq!(absent, (0, None, None, None, None, None, None, 0));
    Ok(())
}

async fn insert_activation_instance(
    database: &TestDatabase,
    run_id: Uuid,
    preserve_evidence_trigger: bool,
    insert_evidence: bool,
) -> Result<(), sqlx::Error> {
    let invocation_id = Uuid::new_v4();
    let logical_job_id = Uuid::new_v4();
    let instance_id = Uuid::new_v4();
    let owner_id = Uuid::new_v4();
    let runtime_policy_digest = [0x71_u8; 32];
    let activation_input_digest = [0x61_u8; 32];

    let instance_triggers = if preserve_evidence_trigger {
        let triggers: Vec<String> = sqlx::query_scalar(
            r"
            SELECT tgname
            FROM pg_trigger
            WHERE tgrelid = 'workflow_plan_v2_instances'::regclass
              AND NOT tgisinternal
              AND tgname <>
                  'workflow_plan_v2_instances_require_environment_evidence'
            ORDER BY tgname
            ",
        )
        .fetch_all(database.pool())
        .await?;
        triggers
    } else {
        Vec::new()
    };

    if let Err(error) = set_fixture_table_triggers(database, false).await {
        let _ = set_fixture_table_triggers(database, true).await;
        return Err(error);
    }
    if let Err(error) = set_fixture_instance_triggers(
        database,
        preserve_evidence_trigger,
        &instance_triggers,
        false,
    )
    .await
    {
        let _ = set_fixture_instance_triggers(
            database,
            preserve_evidence_trigger,
            &instance_triggers,
            true,
        )
        .await;
        let _ = set_fixture_table_triggers(database, true).await;
        return Err(error);
    }

    let insertion = async {
        let mut transaction = database.pool().begin().await?;
        sqlx::query("SET CONSTRAINTS ALL DEFERRED")
            .execute(&mut *transaction)
            .await?;

        sqlx::query(
            r"
        INSERT INTO workflow_plan_v2_runs (
            run_id, root_invocation_id, admission_digest, state,
            admitted_at_ms, updated_at_ms
        ) VALUES ($1,$2,$3,'active',1,1)
        ",
        )
        .bind(run_id)
        .bind(invocation_id)
        .bind([0x51_u8; 32].as_slice())
        .execute(&mut *transaction)
        .await?;
        sqlx::query(
            r"
        INSERT INTO workflow_plan_v2_invocations (
            id, run_id, plan_digest, plan_object_key, plan_size_bytes,
            plan_media_type, plan_schema, state, created_at_ms, updated_at_ms
        ) VALUES (
            $1,$2,$3,'migration-0066/plan.json',128,
            'application/vnd.automata.workflow-plan+json',2,'active',1,1
        )
        ",
        )
        .bind(invocation_id)
        .bind(run_id)
        .bind([0x41_u8; 32].as_slice())
        .execute(&mut *transaction)
        .await?;
        sqlx::query(
            r"
        INSERT INTO workflow_plan_v2_jobs (
            id, run_id, invocation_id, logical_key, source_order,
            execution_kind, state, activation_fence,
            activation_input_digest, authority_profile,
            runtime_policy_revision, runtime_policy_digest,
            environment_requirement_kind, created_at_ms, updated_at_ms
        ) VALUES (
            $1,$2,$3,'legacy-instance',0,'steps','activated',1,$4,
            'standard',1,$5,'none',1,2
        )
        ",
        )
        .bind(logical_job_id)
        .bind(run_id)
        .bind(invocation_id)
        .bind(activation_input_digest.as_slice())
        .bind(runtime_policy_digest.as_slice())
        .execute(&mut *transaction)
        .await?;
        sqlx::query(
            r"
        INSERT INTO workflow_plan_v2_activation_publications (
            run_id, invocation_id, logical_job_id, activation_input_digest,
            activation_output_digest, activation_owner_id,
            activation_generation, activation_claimed_at_ms,
            activation_expires_at_ms, condition_matched, instance_count,
            job_ir_version, runtime_context_schema, published_at_ms,
            authority_profile, runtime_policy_revision, runtime_policy_digest
        ) VALUES (
            $1,$2,$3,$4,$5,$6,1,1,1000,TRUE,1,5,2,2,'standard',1,$7
        )
        ",
        )
        .bind(run_id)
        .bind(invocation_id)
        .bind(logical_job_id)
        .bind(activation_input_digest.as_slice())
        .bind([0x81_u8; 32].as_slice())
        .bind(owner_id)
        .bind(runtime_policy_digest.as_slice())
        .execute(&mut *transaction)
        .await?;
        sqlx::query(
            r"
        INSERT INTO workflow_plan_v2_instances (
            id, run_id, invocation_id, logical_job_id, matrix_index,
            matrix_total, matrix_digest, workspace, job_ir_digest,
            job_ir_object_key, job_ir_size_bytes, job_ir_media_type,
            job_ir_version, runtime_context_digest,
            runtime_context_object_key, runtime_context_size_bytes,
            runtime_context_media_type, runtime_context_schema, created_at_ms,
            runtime_policy_revision, runtime_policy_digest
        ) VALUES (
            $1,$2,$3,$4,0,1,$5,'/__w/migration-0066',$6,
            'migration-0066/job-ir.pb',128,
            'application/vnd.automata.job-ir.protobuf',5,$7,
            'migration-0066/runtime-context.pb',128,
            'application/vnd.automata.job-runtime-context.protobuf',2,2,1,$8
        )
        ",
        )
        .bind(instance_id)
        .bind(run_id)
        .bind(invocation_id)
        .bind(logical_job_id)
        .bind([0x91_u8; 32].as_slice())
        .bind([0xa1_u8; 32].as_slice())
        .bind([0xb1_u8; 32].as_slice())
        .bind(runtime_policy_digest.as_slice())
        .execute(&mut *transaction)
        .await?;

        if insert_evidence {
            sqlx::query(
                r"
            INSERT INTO workflow_plan_v2_job_environment_evidence (
                instance_id, environment_normalized_name, event_trust,
                source_kind, reusable_secret_permission, created_at_ms
            ) VALUES ($1,NULL,'trusted','same_repository','none',2)
            ",
            )
            .bind(instance_id)
            .execute(&mut *transaction)
            .await?;
        }

        transaction.commit().await
    }
    .await;

    // Restore table-wide trigger state only after the deferred DML transaction
    // has committed or rolled back. PostgreSQL refuses ALTER TABLE while that
    // transaction still has pending constraint-trigger events.
    let instance_restore = set_fixture_instance_triggers(
        database,
        preserve_evidence_trigger,
        &instance_triggers,
        true,
    )
    .await;
    let table_restore = set_fixture_table_triggers(database, true).await;
    if let Err(error) = insertion {
        return Err(error);
    }
    instance_restore?;
    table_restore
}

async fn set_fixture_table_triggers(
    database: &TestDatabase,
    enabled: bool,
) -> Result<(), sqlx::Error> {
    let action = if enabled { "ENABLE" } else { "DISABLE" };
    for table in [
        "workflow_plan_v2_runs",
        "workflow_plan_v2_invocations",
        "workflow_plan_v2_jobs",
        "workflow_plan_v2_activation_publications",
    ] {
        let statement = format!("ALTER TABLE {table} {action} TRIGGER USER");
        sqlx::query(sqlx::AssertSqlSafe(statement))
            .execute(database.pool())
            .await?;
    }
    Ok(())
}

async fn set_fixture_instance_triggers(
    database: &TestDatabase,
    preserve_evidence_trigger: bool,
    trigger_names: &[String],
    enabled: bool,
) -> Result<(), sqlx::Error> {
    let action = if enabled { "ENABLE" } else { "DISABLE" };
    if preserve_evidence_trigger {
        for trigger in trigger_names {
            let statement = format!(
                "ALTER TABLE workflow_plan_v2_instances {action} TRIGGER {}",
                quote_identifier(trigger)
            );
            sqlx::query(sqlx::AssertSqlSafe(statement))
                .execute(database.pool())
                .await?;
        }
    } else {
        let statement = format!("ALTER TABLE workflow_plan_v2_instances {action} TRIGGER USER");
        sqlx::query(sqlx::AssertSqlSafe(statement))
            .execute(database.pool())
            .await?;
    }
    Ok(())
}

fn quote_identifier(value: &str) -> String {
    format!("\"{}\"", value.replace('"', "\"\""))
}
