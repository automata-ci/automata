#[allow(dead_code)]
mod common;

use automata_ci_store::WorkflowRuntimePolicy;
use sha2::{Digest as _, Sha256};
use sqlx::migrate::Migrate as _;
use uuid::Uuid;

use common::{TestDatabase, TestResult, run_with_database, run_with_unmigrated_database};

const ORIGINAL_VERSION: i64 = 43;
const FORWARD_VERSION: i64 = 65;
const ORIGINAL_MIGRATION: &str =
    include_str!("../migrations/0043_workflow_runtime_policy_and_selection.sql");
const FORWARD_MIGRATION: &str =
    include_str!("../migrations/0065_workflow_runtime_resource_policy.sql");
const POLICY: &[u8] = br#"{
  "workspace":{"derivation":1,"root":"/__w","schema":1},
  "mappings":[{
    "container_features":["automata.core/job-containers@v1"],
    "architecture":"x86_64","operating_system":"linux",
    "environment_profile":{"manifest_sha256":"1111111111111111111111111111111111111111111111111111111111111111","id":"automata.example/ubuntu-24-04"},
    "selector":"Ubuntu-24.04"
  }],"resources":{"defaults":{"requests":{"cpu_millis":100,"memory_bytes":268435456,"ephemeral_disk_bytes":0,"gpu_count":0},"limits":{"cpu_millis":1000,"memory_bytes":1073741824,"ephemeral_disk_bytes":0,"gpu_count":0}},"minimum_requests":{"cpu_millis":100,"memory_bytes":268435456,"ephemeral_disk_bytes":0,"gpu_count":0},"maximum_limits":{"cpu_millis":4000,"memory_bytes":8589934592,"ephemeral_disk_bytes":0,"gpu_count":0}},"schema":1
}"#;
static MIGRATOR: sqlx::migrate::Migrator = sqlx::migrate!("./migrations");

#[test]
fn committed_0043_is_byte_exact_and_resources_are_forward_only() {
    let digest: [u8; 32] = Sha256::digest(ORIGINAL_MIGRATION.as_bytes()).into();
    assert_eq!(
        digest,
        [
            0xd9, 0x88, 0xd2, 0x13, 0x67, 0x22, 0xe8, 0x8b, 0xe1, 0xc9, 0xf6, 0xa8, 0xea, 0x2c,
            0x79, 0x20, 0x9a, 0x19, 0x10, 0x5a, 0xf7, 0x8f, 0xa2, 0xa6, 0x7f, 0xec, 0x4b, 0x1c,
            0x74, 0x23, 0x5b, 0x70,
        ],
        "released migration 0043 changed bytes"
    );
    for forward_only in [
        "resource_policy_canonical",
        "automata_workflow_runtime_resource_policy_digest",
        "minimum_requests",
        "maximum_limits",
    ] {
        assert!(
            !ORIGINAL_MIGRATION.contains(forward_only),
            "0043 contains forward-only resource policy surface: {forward_only}"
        );
    }

    let migrations = MIGRATOR.iter().collect::<Vec<_>>();
    let forward = migrations
        .iter()
        .position(|migration| migration.version == FORWARD_VERSION)
        .expect("migration 0065 is embedded");
    assert_eq!(migrations[forward - 1].version, 64);
    assert_eq!(
        migrations[forward].description.as_ref(),
        "workflow runtime resource policy"
    );
    assert_eq!(
        migrations
            .iter()
            .find(|migration| migration.version == ORIGINAL_VERSION)
            .expect("migration 0043 is embedded")
            .description
            .as_ref(),
        "workflow runtime policy and selection"
    );
}

#[test]
fn forward_migration_carries_every_resource_policy_invariant() {
    for required in [
        "workflow_runtime_resource_policy_current_only",
        "LOCK TABLE workflow_runtime_policy_revisions IN ACCESS EXCLUSIVE MODE",
        "resource_policy_canonical BYTEA NOT NULL",
        "policy_schema = 1",
        "automata_workflow_runtime_resource_policy_digest",
        "automata.store.workflow-runtime-policy.v1",
        "resources",
        "4294967295",
        "18446744073709551615",
        "{defaults,requests,cpu_millis}",
        "{defaults,limits,gpu_count}",
        "{minimum_requests,cpu_millis}",
        "{maximum_limits,cpu_millis}",
        "convert_to(canonical, 'UTF8') IS DISTINCT FROM $1",
        "NEW.resource_policy_canonical IS DISTINCT FROM OLD.resource_policy_canonical",
        "workflow_runtime_policy_digest_exact",
        "workflow_runtime_policy_canonical_exact",
    ] {
        assert!(
            FORWARD_MIGRATION.contains(required),
            "missing forward runtime-policy invariant: {required}"
        );
    }
    for prohibited in [
        "policy_schema IN (1, 2)",
        "workflow-runtime-policy.v2",
        "UPDATE workflow_runtime_policy_revisions SET resource_policy_canonical",
    ] {
        assert!(
            !FORWARD_MIGRATION.contains(prohibited),
            "unsafe resource-policy compatibility path remains: {prohibited}"
        );
    }
}

#[test]
fn resource_policy_validator_requires_canonical_integer_json_values() {
    for field in [
        "cpu_millis",
        "memory_bytes",
        "ephemeral_disk_bytes",
        "gpu_count",
    ] {
        assert!(
            FORWARD_MIGRATION.contains(&format!("jsonb_typeof(capacity->'{field}') <> 'number'")),
            "missing numeric type check for {field}"
        );
        assert!(
            FORWARD_MIGRATION.contains(&format!("capacity->>'{field}' !~ '^(0|[1-9][0-9]*)$'")),
            "missing canonical integer check for {field}"
        );
    }
}

#[tokio::test]
#[ignore = "requires PostgreSQL 18 and AUTOMATA_TEST_DATABASE_URL"]
async fn pre_resource_schema_upgrades_cleanly_and_matches_a_fresh_install() -> TestResult {
    run_with_unmigrated_database(|database| async move {
        apply_before(&database, FORWARD_VERSION).await?;
        assert!(!resource_column_exists(&database).await?);
        apply_version(&database, FORWARD_VERSION).await?;
        assert_resource_schema(&database).await?;
        exercise_resource_policy(&database).await
    })
    .await?;

    run_with_database(|database| async move {
        assert_resource_schema(&database).await?;
        exercise_resource_policy(&database).await
    })
    .await
}

#[tokio::test]
#[ignore = "requires PostgreSQL 18 and AUTOMATA_TEST_DATABASE_URL"]
async fn pre_resource_rows_refuse_ambiguous_backfill_atomically() -> TestResult {
    run_with_unmigrated_database(|database| async move {
        apply_before(&database, FORWARD_VERSION).await?;
        insert_pre_resource_staging_revision(&database).await?;

        let mut connection = database.pool().acquire().await?;
        let migration = migration(FORWARD_VERSION);
        let error = connection
            .apply(MIGRATOR.table_name.as_ref(), migration)
            .await
            .expect_err("a historical policy has no authoritative resource-policy backfill");
        match error {
            sqlx::migrate::MigrateError::ExecuteMigration(error, FORWARD_VERSION) => {
                let database_error = error
                    .as_database_error()
                    .expect("migration refusal is a PostgreSQL error");
                assert_eq!(database_error.code().as_deref(), Some("23514"));
                assert_eq!(
                    database_error.constraint(),
                    Some("workflow_runtime_resource_policy_current_only")
                );
            }
            other => panic!("unexpected migration error: {other}"),
        }
        drop(connection);

        let state: (i64, i64, bool) = sqlx::query_as(
            r"
            SELECT
                (SELECT count(*) FROM workflow_runtime_policy_revisions),
                (SELECT count(*) FROM _sqlx_migrations
                 WHERE version = 65 AND success),
                EXISTS (
                    SELECT 1 FROM information_schema.columns
                    WHERE table_schema = current_schema()
                      AND table_name = 'workflow_runtime_policy_revisions'
                      AND column_name = 'resource_policy_canonical'
                )
            ",
        )
        .fetch_one(database.pool())
        .await?;
        assert_eq!(state, (1, 0, false));
        Ok(())
    })
    .await
}

async fn apply_before(database: &TestDatabase, version: i64) -> TestResult {
    let mut connection = database.pool().acquire().await?;
    connection
        .ensure_migrations_table(MIGRATOR.table_name.as_ref())
        .await?;
    for migration in MIGRATOR
        .iter()
        .filter(|migration| migration.version < version)
    {
        connection
            .apply(MIGRATOR.table_name.as_ref(), migration)
            .await?;
    }
    Ok(())
}

async fn apply_version(database: &TestDatabase, version: i64) -> TestResult {
    let mut connection = database.pool().acquire().await?;
    connection
        .apply(MIGRATOR.table_name.as_ref(), migration(version))
        .await?;
    Ok(())
}

fn migration(version: i64) -> &'static sqlx::migrate::Migration {
    MIGRATOR
        .iter()
        .find(|migration| migration.version == version)
        .expect("migration is embedded")
}

async fn resource_column_exists(database: &TestDatabase) -> TestResult<bool> {
    Ok(sqlx::query_scalar(
        r"
        SELECT EXISTS (
            SELECT 1 FROM information_schema.columns
            WHERE table_schema = current_schema()
              AND table_name = 'workflow_runtime_policy_revisions'
              AND column_name = 'resource_policy_canonical'
        )
        ",
    )
    .fetch_one(database.pool())
    .await?)
}

async fn assert_resource_schema(database: &TestDatabase) -> TestResult {
    let state: (bool, i64, Option<String>) = sqlx::query_as(
        r"
        SELECT
            EXISTS (
                SELECT 1 FROM information_schema.columns
                WHERE table_schema = current_schema()
                  AND table_name = 'workflow_runtime_policy_revisions'
                  AND column_name = 'resource_policy_canonical'
                  AND is_nullable = 'NO'
            ),
            (SELECT count(*) FROM _sqlx_migrations
             WHERE version IN (43, 65) AND success),
            to_regprocedure('automata_workflow_runtime_resource_policy_digest(bytea)')::TEXT
        ",
    )
    .fetch_one(database.pool())
    .await?;
    assert!(state.0);
    assert_eq!(state.1, 2);
    assert!(state.2.is_some());
    Ok(())
}

async fn insert_repository(database: &TestDatabase) -> TestResult<(String, Uuid)> {
    let tenant = format!("tenant-{}", Uuid::new_v4().simple());
    let repository = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO tenants (id, display_name, created_at_ms, updated_at_ms) \
         VALUES ($1, 'Runtime resource migration', 1, 1)",
    )
    .bind(&tenant)
    .execute(database.pool())
    .await?;
    sqlx::query(
        r"
        INSERT INTO repositories (
            id, tenant_id, scm_provider, provider_repository_id,
            owner, name, created_at_ms, updated_at_ms
        ) VALUES ($1,$2,'github',$3,'automata-ci','runtime-resource-migration',1,1)
        ",
    )
    .bind(repository)
    .bind(&tenant)
    .bind(repository.to_string())
    .execute(database.pool())
    .await?;
    Ok((tenant, repository))
}

async fn insert_pre_resource_staging_revision(database: &TestDatabase) -> TestResult {
    let (tenant, repository) = insert_repository(database).await?;
    sqlx::query(
        r"
        INSERT INTO workflow_runtime_policy_revisions (
            tenant_id, repository_id, policy_revision, policy_digest,
            canonical_policy, policy_schema, workspace_root,
            workspace_derivation_version, mapping_count, state,
            registered_at_ms, sealed_at_ms
        ) VALUES ($1,$2,1,$3,$4,1,'/__w',1,1,'staging',1,NULL)
        ",
    )
    .bind(tenant)
    .bind(repository)
    .bind([0_u8; 32].as_slice())
    .bind([0_u8].as_slice())
    .execute(database.pool())
    .await?;
    Ok(())
}

#[allow(
    clippy::too_many_lines,
    reason = "one fixture proves the complete relational policy aggregate and its immutable seal"
)]
async fn exercise_resource_policy(database: &TestDatabase) -> TestResult {
    let (tenant, repository) = insert_repository(database).await?;
    let policy = WorkflowRuntimePolicy::decode_configuration(POLICY)?;
    let canonical = policy.canonical_bytes()?;
    let resources = serde_json::to_vec(&policy.resource_policy())?;

    let mut transaction = database.pool().begin().await?;
    sqlx::query(
        r"
        INSERT INTO workflow_runtime_policy_revisions (
            tenant_id, repository_id, policy_revision, policy_digest,
            canonical_policy, resource_policy_canonical, policy_schema,
            workspace_root, workspace_derivation_version, mapping_count,
            state, registered_at_ms, sealed_at_ms
        ) VALUES ($1,$2,1,$3,$4,$5,1,'/__w',1,1,'staging',1,NULL)
        ",
    )
    .bind(&tenant)
    .bind(repository)
    .bind(policy.digest().as_bytes().as_slice())
    .bind(&canonical)
    .bind(&resources)
    .execute(&mut *transaction)
    .await?;
    sqlx::query(
        r"
        INSERT INTO workflow_runtime_policy_mappings (
            tenant_id, repository_id, policy_revision, selector,
            environment_profile_id, environment_profile_digest,
            operating_system, architecture, feature_count
        ) VALUES (
            $1,$2,1,'ubuntu-24.04','automata.example/ubuntu-24-04',$3,
            'linux','x86_64',1
        )
        ",
    )
    .bind(&tenant)
    .bind(repository)
    .bind([0x11_u8; 32].as_slice())
    .execute(&mut *transaction)
    .await?;
    sqlx::query(
        r"
        INSERT INTO workflow_runtime_policy_features (
            tenant_id, repository_id, policy_revision, selector, feature
        ) VALUES ($1,$2,1,'ubuntu-24.04','automata.core/job-containers@v1')
        ",
    )
    .bind(&tenant)
    .bind(repository)
    .execute(&mut *transaction)
    .await?;
    sqlx::query(
        r"
        UPDATE workflow_runtime_policy_revisions
        SET state = 'sealed', sealed_at_ms = registered_at_ms
        WHERE tenant_id = $1 AND repository_id = $2 AND policy_revision = 1
        ",
    )
    .bind(&tenant)
    .bind(repository)
    .execute(&mut *transaction)
    .await?;
    transaction.commit().await?;

    let exact: (Vec<u8>, Vec<u8>, Vec<u8>) = sqlx::query_as(
        r"
        SELECT
            automata_workflow_runtime_policy_digest($1,$2,1),
            automata_workflow_runtime_policy_canonical($1,$2,1),
            resource_policy_canonical
        FROM workflow_runtime_policy_revisions
        WHERE tenant_id = $1 AND repository_id = $2 AND policy_revision = 1
        ",
    )
    .bind(&tenant)
    .bind(repository)
    .fetch_one(database.pool())
    .await?;
    assert_eq!(exact.0.as_slice(), policy.digest().as_bytes().as_slice());
    assert_eq!(exact.1, canonical);
    assert_eq!(exact.2, resources);

    let noncanonical = [b" ".as_slice(), resources.as_slice()].concat();
    let rejected: bool =
        sqlx::query_scalar("SELECT automata_workflow_runtime_resource_policy_digest($1) IS NULL")
            .bind(noncanonical)
            .fetch_one(database.pool())
            .await?;
    assert!(rejected);

    let error = sqlx::query(
        r"
        UPDATE workflow_runtime_policy_revisions
        SET resource_policy_canonical = $3
        WHERE tenant_id = $1 AND repository_id = $2 AND policy_revision = 1
        ",
    )
    .bind(&tenant)
    .bind(repository)
    .bind(b"{}".as_slice())
    .execute(database.pool())
    .await
    .expect_err("sealed resource policy evidence is immutable");
    let database_error = error
        .as_database_error()
        .expect("immutability refusal is a PostgreSQL error");
    assert_eq!(database_error.code().as_deref(), Some("23514"));
    assert_eq!(
        database_error.constraint(),
        Some("workflow_runtime_policy_revision_immutable")
    );
    Ok(())
}
