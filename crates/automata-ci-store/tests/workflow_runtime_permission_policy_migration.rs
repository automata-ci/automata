#[allow(dead_code)]
mod common;

use automata_ci_store::WorkflowRuntimePolicy;
use sqlx::migrate::Migrate as _;
use uuid::Uuid;

use common::{TestDatabase, TestResult, run_with_database, run_with_unmigrated_database};

const FORWARD_VERSION: i64 = 71;
const FORWARD_MIGRATION: &str =
    include_str!("../migrations/0071_workflow_runtime_permission_policy.sql");
const POLICY: &[u8] = br#"{
  "workspace":{"derivation":1,"root":"/__w","schema":1},
  "mappings":[{
    "container_features":["automata.core/job-containers@v1"],
    "architecture":"x86_64","operating_system":"linux",
    "environment_profile":{"manifest_sha256":"1111111111111111111111111111111111111111111111111111111111111111","id":"automata.example/ubuntu-24-04"},
    "selector":"Ubuntu-24.04"
  }],"permissions":{"provider_default":{"contents":"read"},"read_all":{"contents":"read"},"write_all":{"contents":"write","id-token":"write"}},"resources":{"defaults":{"requests":{"cpu_millis":100,"memory_bytes":268435456,"ephemeral_disk_bytes":0,"gpu_count":0},"limits":{"cpu_millis":1000,"memory_bytes":1073741824,"ephemeral_disk_bytes":0,"gpu_count":0}},"minimum_requests":{"cpu_millis":100,"memory_bytes":268435456,"ephemeral_disk_bytes":0,"gpu_count":0},"maximum_limits":{"cpu_millis":4000,"memory_bytes":8589934592,"ephemeral_disk_bytes":0,"gpu_count":0}},"schema":2
}"#;
static MIGRATOR: sqlx::migrate::Migrator = sqlx::migrate!("./migrations");

#[test]
fn permission_policy_migration_carries_the_complete_current_only_contract() {
    let migrations = MIGRATOR.iter().collect::<Vec<_>>();
    let forward = migrations
        .iter()
        .position(|migration| migration.version == FORWARD_VERSION)
        .expect("migration 0071 is embedded");
    assert_eq!(migrations[forward - 1].version, 70);
    assert_eq!(
        migrations[forward].description.as_ref(),
        "workflow runtime permission policy"
    );

    for required in [
        "workflow_runtime_permission_policy_current_only",
        "LOCK TABLE workflow_runtime_policy_revisions IN ACCESS EXCLUSIVE MODE",
        "permission_policy_canonical BYTEA NOT NULL",
        "policy_schema = 2",
        "automata_workflow_runtime_permission_policy_digest",
        "automata.store.workflow-runtime-policy.v2",
        "provider-default",
        "read-all",
        "write-all",
        "NEW.permission_policy_canonical IS DISTINCT FROM OLD.permission_policy_canonical",
        "workflow_runtime_policy_digest_exact",
        "workflow_runtime_policy_canonical_exact",
    ] {
        assert!(
            FORWARD_MIGRATION.contains(required),
            "missing permission-policy invariant: {required}"
        );
    }
    for prohibited in [
        "policy_schema IN (1, 2)",
        "UPDATE workflow_runtime_policy_revisions SET permission_policy_canonical",
    ] {
        assert!(
            !FORWARD_MIGRATION.contains(prohibited),
            "unsafe permission-policy compatibility path remains: {prohibited}"
        );
    }
}

#[test]
fn permission_policy_validator_is_bounded_canonical_and_consistent() {
    for required in [
        "entry_count NOT BETWEEN 1 AND 64",
        "octet_length(permission_entry.key) NOT BETWEEN 1 AND 64",
        "permission_entry.key !~ '^[a-z]([a-z0-9]|-[a-z0-9])*$'",
        "permission_entry.value NOT IN ('read', 'write')",
        "permission_entry.key = 'id-token' AND permission_entry.value = 'read'",
        "section_name = 'read_all' AND permission_entry.value <> 'read'",
        "ORDER BY key COLLATE \"C\"",
        "document->'read_all') ? (default_permission.key",
        "convert_to(canonical, 'UTF8') IS DISTINCT FROM $1",
    ] {
        assert!(
            FORWARD_MIGRATION.contains(required),
            "missing permission validator invariant: {required}"
        );
    }
}

#[tokio::test]
#[ignore = "requires PostgreSQL 18 and AUTOMATA_TEST_DATABASE_URL"]
async fn pre_permission_schema_upgrades_cleanly_and_matches_a_fresh_install() -> TestResult {
    run_with_unmigrated_database(|database| async move {
        apply_before(&database, FORWARD_VERSION).await?;
        assert!(!permission_column_exists(&database).await?);
        apply_version(&database, FORWARD_VERSION).await?;
        assert_permission_schema(&database).await?;
        exercise_permission_policy(&database).await
    })
    .await?;

    run_with_database(|database| async move {
        assert_permission_schema(&database).await?;
        exercise_permission_policy(&database).await
    })
    .await
}

#[tokio::test]
#[ignore = "requires PostgreSQL 18 and AUTOMATA_TEST_DATABASE_URL"]
async fn pre_permission_rows_refuse_ambiguous_backfill_atomically() -> TestResult {
    run_with_unmigrated_database(|database| async move {
        apply_before(&database, FORWARD_VERSION).await?;
        insert_pre_permission_staging_revision(&database).await?;

        let mut connection = database.pool().acquire().await?;
        let error = connection
            .apply(MIGRATOR.table_name.as_ref(), migration(FORWARD_VERSION))
            .await
            .expect_err("a historical policy has no authoritative permission expansion");
        match error {
            sqlx::migrate::MigrateError::ExecuteMigration(error, FORWARD_VERSION) => {
                let database_error = error
                    .as_database_error()
                    .expect("migration refusal is a PostgreSQL error");
                assert_eq!(database_error.code().as_deref(), Some("23514"));
                assert_eq!(
                    database_error.constraint(),
                    Some("workflow_runtime_permission_policy_current_only")
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
                 WHERE version = 71 AND success),
                EXISTS (
                    SELECT 1 FROM information_schema.columns
                    WHERE table_schema = current_schema()
                      AND table_name = 'workflow_runtime_policy_revisions'
                      AND column_name = 'permission_policy_canonical'
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

async fn permission_column_exists(database: &TestDatabase) -> TestResult<bool> {
    Ok(sqlx::query_scalar(
        r"
        SELECT EXISTS (
            SELECT 1 FROM information_schema.columns
            WHERE table_schema = current_schema()
              AND table_name = 'workflow_runtime_policy_revisions'
              AND column_name = 'permission_policy_canonical'
        )
        ",
    )
    .fetch_one(database.pool())
    .await?)
}

async fn assert_permission_schema(database: &TestDatabase) -> TestResult {
    let state: (bool, i64, Option<String>) = sqlx::query_as(
        r"
        SELECT
            EXISTS (
                SELECT 1 FROM information_schema.columns
                WHERE table_schema = current_schema()
                  AND table_name = 'workflow_runtime_policy_revisions'
                  AND column_name = 'permission_policy_canonical'
                  AND is_nullable = 'NO'
            ),
            (SELECT count(*) FROM _sqlx_migrations
             WHERE version IN (43, 66, 71) AND success),
            to_regprocedure(
                'automata_workflow_runtime_permission_policy_digest(bytea)'
            )::TEXT
        ",
    )
    .fetch_one(database.pool())
    .await?;
    assert!(state.0);
    assert_eq!(state.1, 3);
    assert!(state.2.is_some());
    Ok(())
}

async fn insert_repository(database: &TestDatabase) -> TestResult<(String, Uuid)> {
    let tenant = format!("tenant-{}", Uuid::new_v4().simple());
    let repository = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO tenants (id, display_name, created_at_ms, updated_at_ms) \
         VALUES ($1, 'Runtime permission migration', 1, 1)",
    )
    .bind(&tenant)
    .execute(database.pool())
    .await?;
    sqlx::query(
        r"
        INSERT INTO repositories (
            id, tenant_id, scm_provider, provider_repository_id,
            owner, name, created_at_ms, updated_at_ms
        ) VALUES ($1,$2,'github',$3,'automata-ci','runtime-permission-migration',1,1)
        ",
    )
    .bind(repository)
    .bind(&tenant)
    .bind(repository.to_string())
    .execute(database.pool())
    .await?;
    Ok((tenant, repository))
}

async fn insert_pre_permission_staging_revision(database: &TestDatabase) -> TestResult {
    let (tenant, repository) = insert_repository(database).await?;
    let mut transaction = database.pool().begin().await?;
    sqlx::query("SET LOCAL session_replication_role = 'replica'")
        .execute(&mut *transaction)
        .await?;
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
    .bind(tenant)
    .bind(repository)
    .bind([0_u8; 32].as_slice())
    .bind([0_u8].as_slice())
    .bind(b"{}".as_slice())
    .execute(&mut *transaction)
    .await?;
    transaction.commit().await?;
    Ok(())
}

#[allow(
    clippy::too_many_lines,
    reason = "one fixture proves the complete relational policy aggregate and its immutable seal"
)]
async fn exercise_permission_policy(database: &TestDatabase) -> TestResult {
    let (tenant, repository) = insert_repository(database).await?;
    let policy = WorkflowRuntimePolicy::decode_configuration(POLICY)?;
    let canonical = policy.canonical_bytes()?;
    let permissions = policy.permission_policy().canonical_bytes()?;
    let resources = serde_json::to_vec(&policy.resource_policy())?;

    let mut transaction = database.pool().begin().await?;
    sqlx::query(
        r"
        INSERT INTO workflow_runtime_policy_revisions (
            tenant_id, repository_id, policy_revision, policy_digest,
            canonical_policy, permission_policy_canonical,
            resource_policy_canonical, policy_schema, workspace_root,
            workspace_derivation_version, mapping_count, state,
            registered_at_ms, sealed_at_ms
        ) VALUES ($1,$2,1,$3,$4,$5,$6,2,'/__w',1,1,'staging',1,NULL)
        ",
    )
    .bind(&tenant)
    .bind(repository)
    .bind(policy.digest().as_bytes().as_slice())
    .bind(&canonical)
    .bind(&permissions)
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
    let permission_digest_part: Option<Vec<u8>> =
        sqlx::query_scalar("SELECT automata_workflow_runtime_permission_policy_digest($1)")
            .bind(&permissions)
            .fetch_one(&mut *transaction)
            .await?;
    assert!(
        permission_digest_part.is_some(),
        "canonical permission policy must have an exact relational encoding"
    );
    let relational_digest: Option<Vec<u8>> =
        sqlx::query_scalar("SELECT automata_workflow_runtime_policy_digest($1,$2,1)")
            .bind(&tenant)
            .bind(repository)
            .fetch_one(&mut *transaction)
            .await?;
    assert_eq!(
        relational_digest.as_deref(),
        Some(policy.digest().as_bytes().as_slice()),
        "Rust and PostgreSQL policy digests must be byte-exact before sealing"
    );
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
    // This migration owns the runtime-policy representation, not the provider
    // manifest aggregate. Suppress only the current-row trigger event while
    // still allowing the queued revision-seal constraint to validate at commit.
    sqlx::query("SET LOCAL session_replication_role = 'replica'")
        .execute(&mut *transaction)
        .await?;
    sqlx::query(
        r"
        INSERT INTO workflow_runtime_policy_current (
            tenant_id, repository_id, policy_revision,
            policy_digest, activated_at_ms
        ) VALUES ($1,$2,1,$3,1)
        ",
    )
    .bind(&tenant)
    .bind(repository)
    .bind(policy.digest().as_bytes().as_slice())
    .execute(&mut *transaction)
    .await?;
    sqlx::query("SET LOCAL session_replication_role = 'origin'")
        .execute(&mut *transaction)
        .await?;
    transaction.commit().await?;

    let exact: (Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>) = sqlx::query_as(
        r"
        SELECT
            automata_workflow_runtime_policy_digest($1,$2,1),
            automata_workflow_runtime_policy_canonical($1,$2,1),
            permission_policy_canonical,
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
    assert_eq!(exact.2, permissions);
    assert_eq!(exact.3, resources);

    for invalid in [
        [b" ".as_slice(), permissions.as_slice()].concat(),
        br#"{"provider_default":{},"read_all":{"contents":"read"},"write_all":{"contents":"write"}}"#.to_vec(),
        br#"{"provider_default":{"contents":"read"},"read_all":{"id-token":"read"},"write_all":{"id-token":"write"}}"#.to_vec(),
        br#"{"provider_default":{"id-token":"write"},"read_all":{"contents":"read"},"write_all":{"contents":"write","id-token":"write"}}"#.to_vec(),
    ] {
        let rejected: bool = sqlx::query_scalar(
            "SELECT automata_workflow_runtime_permission_policy_digest($1) IS NULL",
        )
        .bind(invalid)
        .fetch_one(database.pool())
        .await?;
        assert!(rejected);
    }

    let error = sqlx::query(
        r"
        UPDATE workflow_runtime_policy_revisions
        SET permission_policy_canonical = $3
        WHERE tenant_id = $1 AND repository_id = $2 AND policy_revision = 1
        ",
    )
    .bind(&tenant)
    .bind(repository)
    .bind(b"{}".as_slice())
    .execute(database.pool())
    .await
    .expect_err("sealed permission policy evidence is immutable");
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
