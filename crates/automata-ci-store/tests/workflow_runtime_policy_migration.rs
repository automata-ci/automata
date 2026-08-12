#[allow(dead_code)]
mod common;

use sha2::{Digest as _, Sha256};
use sqlx::migrate::Migrate as _;
use uuid::Uuid;

use common::{TestDatabase, TestResult, run_with_unmigrated_database};

const ORIGINAL_VERSION: i64 = 43;
const FORWARD_VERSION: i64 = 66;
const ORIGINAL_MIGRATION: &str =
    include_str!("../migrations/0043_workflow_runtime_policy_and_selection.sql");
const FORWARD_MIGRATION: &str =
    include_str!("../migrations/0066_workflow_runtime_resource_policy.sql");
const LEGACY_CANONICAL_POLICY: &[u8] = br#"{"schema":1,"workspace":{"schema":1,"root":"/__w","derivation":1},"mappings":[{"selector":"ubuntu-24.04","environment_profile":{"id":"automata.example/ubuntu-24-04","manifest_sha256":"1111111111111111111111111111111111111111111111111111111111111111"},"operating_system":"linux","architecture":"x86_64","container_features":["automata.core/job-containers@v1"]}]}"#;
const RESOURCE_POLICY_CANONICAL: &[u8] = br#"{"defaults":{"requests":{"cpu_millis":100,"memory_bytes":268435456,"ephemeral_disk_bytes":0,"gpu_count":0},"limits":{"cpu_millis":1000,"memory_bytes":1073741824,"ephemeral_disk_bytes":0,"gpu_count":0}},"minimum_requests":{"cpu_millis":100,"memory_bytes":268435456,"ephemeral_disk_bytes":0,"gpu_count":0},"maximum_limits":{"cpu_millis":4000,"memory_bytes":8589934592,"ephemeral_disk_bytes":0,"gpu_count":0}}"#;
const FORWARD_CANONICAL_POLICY: &[u8] = br#"{"schema":1,"workspace":{"schema":1,"root":"/__w","derivation":1},"mappings":[{"selector":"ubuntu-24.04","environment_profile":{"id":"automata.example/ubuntu-24-04","manifest_sha256":"1111111111111111111111111111111111111111111111111111111111111111"},"operating_system":"linux","architecture":"x86_64","container_features":["automata.core/job-containers@v1"]}],"resources":{"defaults":{"requests":{"cpu_millis":100,"memory_bytes":268435456,"ephemeral_disk_bytes":0,"gpu_count":0},"limits":{"cpu_millis":1000,"memory_bytes":1073741824,"ephemeral_disk_bytes":0,"gpu_count":0}},"minimum_requests":{"cpu_millis":100,"memory_bytes":268435456,"ephemeral_disk_bytes":0,"gpu_count":0},"maximum_limits":{"cpu_millis":4000,"memory_bytes":8589934592,"ephemeral_disk_bytes":0,"gpu_count":0}}}"#;
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
        .expect("migration 0066 is embedded");
    assert_eq!(migrations[forward - 1].version, 65);
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

#[test]
fn schema_one_forward_fixture_has_exact_golden_identities() {
    let canonical_digest: [u8; 32] = Sha256::digest(FORWARD_CANONICAL_POLICY).into();
    assert_eq!(
        canonical_digest,
        [
            0x0c, 0x77, 0x0b, 0xf6, 0x1f, 0xef, 0x18, 0x64, 0x59, 0xc5, 0x5a, 0x27, 0xf2, 0x15,
            0xe6, 0x43, 0xb2, 0x10, 0x64, 0x0b, 0x6f, 0xc3, 0xbc, 0x89, 0xc0, 0x5f, 0x69, 0x92,
            0xf0, 0x71, 0xb8, 0x58,
        ]
    );
    assert_eq!(
        forward_policy_digest(),
        [
            0xf0, 0x56, 0xc8, 0xbf, 0x9c, 0x65, 0xfe, 0xbd, 0x33, 0x49, 0x4c, 0x52, 0xed, 0x0d,
            0x40, 0x2f, 0x9b, 0x5c, 0x01, 0xbf, 0xe0, 0x31, 0x35, 0x4c, 0x49, 0x1f, 0x36, 0x63,
            0x62, 0xf3, 0xa5, 0xc7,
        ]
    );
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

    run_with_unmigrated_database(|database| async move {
        apply_before(&database, FORWARD_VERSION + 1).await?;
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
        insert_pre_resource_policy_revision(&database).await?;

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
                 WHERE version = 66 AND success),
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
             WHERE version IN (43, 66) AND success),
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

async fn insert_pre_resource_policy_revision(database: &TestDatabase) -> TestResult {
    let (tenant, repository) = insert_repository(database).await?;
    let digest = legacy_policy_digest();
    let mut transaction = database.pool().begin().await?;
    // This test needs only the pre-0066 runtime-policy half of the aggregate.
    // Suppress the unrelated provider-manifest pairing event while preserving
    // every runtime-policy lifecycle, catalog, digest, and currentness trigger.
    sqlx::query(
        "ALTER TABLE workflow_runtime_policy_current DISABLE TRIGGER \
         workflow_runtime_policy_current_requires_manifest",
    )
    .execute(&mut *transaction)
    .await?;
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
    .bind(&tenant)
    .bind(repository)
    .bind(digest.as_slice())
    .bind(LEGACY_CANONICAL_POLICY)
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
    .bind(digest.as_slice())
    .execute(&mut *transaction)
    .await?;
    sqlx::query(
        "ALTER TABLE workflow_runtime_policy_current ENABLE TRIGGER \
         workflow_runtime_policy_current_requires_manifest",
    )
    .execute(&mut *transaction)
    .await?;
    transaction.commit().await?;
    Ok(())
}

fn legacy_policy_digest() -> [u8; 32] {
    schema_one_policy_hasher().finalize().into()
}

fn forward_policy_digest() -> [u8; 32] {
    let mut hasher = schema_one_policy_hasher();
    hasher.update(b"resources\0");
    for (cpu_millis, memory_bytes, ephemeral_disk_bytes, gpu_count) in [
        (100_u32, 268_435_456_u64, 0_u64, 0_u16),
        (1_000, 1_073_741_824, 0, 0),
        (100, 268_435_456, 0, 0),
        (4_000, 8_589_934_592, 0, 0),
    ] {
        hasher.update(cpu_millis.to_be_bytes());
        hasher.update(memory_bytes.to_be_bytes());
        hasher.update(ephemeral_disk_bytes.to_be_bytes());
        hasher.update(gpu_count.to_be_bytes());
    }
    hasher.finalize().into()
}

fn schema_one_policy_hasher() -> Sha256 {
    let mut hasher = Sha256::new();
    hasher.update(b"automata.store.workflow-runtime-policy.v1\0");
    hasher.update(1_u16.to_be_bytes());
    hasher.update(1_u16.to_be_bytes());
    hash_legacy_text(&mut hasher, "/__w");
    hasher.update(1_u64.to_be_bytes());
    hash_legacy_text(&mut hasher, "ubuntu-24.04");
    hash_legacy_text(&mut hasher, "automata.example/ubuntu-24-04");
    hasher.update([0x11_u8; 32]);
    hasher.update([1, 1]);
    hasher.update(1_u64.to_be_bytes());
    hash_legacy_text(&mut hasher, "automata.core/job-containers@v1");
    hasher
}

fn hash_legacy_text(hasher: &mut Sha256, value: &str) {
    hasher.update(
        u64::try_from(value.len())
            .expect("fixture text length fits u64")
            .to_be_bytes(),
    );
    hasher.update(value.as_bytes());
}

#[allow(
    clippy::too_many_lines,
    reason = "one fixture proves the complete relational policy aggregate and its immutable seal"
)]
async fn exercise_resource_policy(database: &TestDatabase) -> TestResult {
    let (tenant, repository) = insert_repository(database).await?;
    let digest = forward_policy_digest();

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
    .bind(digest.as_slice())
    .bind(FORWARD_CANONICAL_POLICY)
    .bind(RESOURCE_POLICY_CANONICAL)
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
    .bind(digest.as_slice())
    .execute(&mut *transaction)
    .await?;

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
    .fetch_one(&mut *transaction)
    .await?;
    assert_eq!(exact.0.as_slice(), digest.as_slice());
    assert_eq!(exact.1, FORWARD_CANONICAL_POLICY);
    assert_eq!(exact.2, RESOURCE_POLICY_CANONICAL);

    let noncanonical = [b" ".as_slice(), RESOURCE_POLICY_CANONICAL].concat();
    let rejected: bool =
        sqlx::query_scalar("SELECT automata_workflow_runtime_resource_policy_digest($1) IS NULL")
            .bind(noncanonical)
            .fetch_one(&mut *transaction)
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
    .execute(&mut *transaction)
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
    transaction.rollback().await?;
    Ok(())
}
