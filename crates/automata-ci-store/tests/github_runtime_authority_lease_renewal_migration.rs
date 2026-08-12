#[allow(dead_code)]
mod common;

use sqlx::{PgPool, Postgres, Transaction, migrate::Migrate as _};
use uuid::Uuid;

use common::{
    TestDatabase, TestResult, run_with_database, run_with_unmigrated_database, seed_control_plane,
};

const FORWARD_VERSION: i64 = 72;
const FORWARD_MIGRATION: &str =
    include_str!("../migrations/0072_github_runtime_authority_lease_renewals.sql");
static MIGRATOR: sqlx::migrate::Migrator = sqlx::migrate!("./migrations");

#[test]
fn renewal_migration_is_contiguous_linear_and_reciprocal() {
    let migrations = MIGRATOR.iter().collect::<Vec<_>>();
    let forward = migrations
        .iter()
        .position(|migration| migration.version == FORWARD_VERSION)
        .expect("migration 0072 is embedded");
    assert_eq!(migrations[forward - 1].version, 71);
    assert_eq!(
        migrations[forward].description.as_ref(),
        "github runtime authority lease renewals"
    );

    for required in [
        "github_runtime_authority_lease_renewal_predecessor_unique",
        "previous_lease_expires_at_ms > authorized_at_ms",
        "renewed_lease_expires_at_ms > previous_lease_expires_at_ms",
        "automata_github_runtime_authority_lease_horizon_is_tail",
        "extract(epoch FROM clock_timestamp())",
        "NEW.previous_lease_expires_at_ms <= database_now",
        "FOR SHARE OF runner, session",
        "FOR UPDATE OF attempt",
        "FOR SHARE OF authority",
        "attempt.lifecycle IN ('leased', 'preparing', 'running', 'cancelling')",
        "NEW.lifecycle IN ('leased', 'preparing', 'running', 'cancelling')",
        "github_runtime_authority_lease_renewal_legacy_current",
        "github_runtime_authority_lease_renewal_final_exact",
        "github_runtime_authority_attempt_renewal_final_exact",
        "DEFERRABLE INITIALLY DEFERRED",
        "BEFORE UPDATE OR DELETE ON github_runtime_authority_lease_renewal_receipts",
        "BEFORE TRUNCATE ON github_runtime_authority_lease_renewal_receipts",
        "CREATE OR REPLACE FUNCTION automata_github_runtime_authority_v2_base_is_current",
    ] {
        assert!(
            FORWARD_MIGRATION.contains(required),
            "missing renewal invariant: {required}"
        );
    }
    for prohibited in [
        "ON CONFLICT DO NOTHING",
        "UPDATE github_runtime_authority_issuances SET lease_expires_at_ms",
        "DELETE FROM github_runtime_authority_lease_renewal_receipts",
    ] {
        assert!(
            !FORWARD_MIGRATION.contains(prohibited),
            "unsafe renewal compatibility path remains: {prohibited}"
        );
    }
    let attempt_lock = FORWARD_MIGRATION
        .find("FOR UPDATE OF attempt")
        .expect("attempt lock phase");
    let post_lock_clock = FORWARD_MIGRATION
        .find("database_now := floor(")
        .expect("post-lock database clock sample");
    assert!(post_lock_clock > attempt_lock);
    assert!(FORWARD_MIGRATION.contains("NEW.lease_expires_at_ms IS NOT NULL"));
}

#[tokio::test]
#[ignore = "requires PostgreSQL 18 and AUTOMATA_TEST_DATABASE_URL"]
async fn schema_71_upgrade_and_fresh_install_have_the_exact_renewal_catalog() -> TestResult {
    run_with_unmigrated_database(|database| async move {
        apply_before(&database, FORWARD_VERSION).await?;
        assert!(!renewal_table_exists(&database).await?);
        apply_version(&database, FORWARD_VERSION).await?;
        assert_renewal_catalog(&database).await
    })
    .await?;

    run_with_database(|database| async move { assert_renewal_catalog(&database).await }).await
}

#[tokio::test]
#[ignore = "requires PostgreSQL 18 and AUTOMATA_TEST_DATABASE_URL"]
async fn schema_71_refuses_unevidenced_ready_horizon_atomically() -> TestResult {
    run_with_unmigrated_database(|database| async move {
        apply_before(&database, FORWARD_VERSION).await?;
        let fixture = seed_ready_authority(&database).await?;
        sqlx::query(
            "UPDATE job_attempts SET lease_expires_at_ms = $2, changed_at_ms = $3 \
             WHERE id = $1 AND fencing_token = 7",
        )
        .bind(fixture.attempt_id)
        .bind(fixture.root_horizon + 10_000)
        .bind(fixture.authorized_at)
        .execute(database.pool())
        .await?;

        let error = apply_version(&database, FORWARD_VERSION)
            .await
            .expect_err("0072 must not invent renewal evidence for legacy state");
        let database_error = error
            .downcast_ref::<sqlx::migrate::MigrateError>()
            .and_then(|error| match error {
                sqlx::migrate::MigrateError::ExecuteMigration(error, FORWARD_VERSION) => {
                    error.as_database_error()
                }
                _ => None,
            })
            .expect("migration refusal is a PostgreSQL error");
        assert_eq!(database_error.code().as_deref(), Some("23514"));
        assert_eq!(
            database_error.constraint(),
            Some("github_runtime_authority_lease_renewal_legacy_current")
        );
        assert!(!renewal_table_exists(&database).await?);
        let function_exists: bool = sqlx::query_scalar(
            "SELECT to_regprocedure(\
             'automata_github_runtime_authority_lease_horizon_is_tail(\
             github_runtime_authority_issuances,bigint,bigint)') IS NOT NULL",
        )
        .fetch_one(database.pool())
        .await?;
        assert!(!function_exists);
        let migration_recorded: bool = sqlx::query_scalar(
            "SELECT EXISTS (SELECT 1 FROM _sqlx_migrations \
             WHERE version = 72 AND success)",
        )
        .fetch_one(database.pool())
        .await?;
        assert!(!migration_recorded);
        Ok(())
    })
    .await
}

#[tokio::test]
#[ignore = "requires PostgreSQL 18 and AUTOMATA_TEST_DATABASE_URL"]
async fn renewal_edges_are_linear_current_reciprocal_and_append_only() -> TestResult {
    run_with_database(|database| async move {
        let fixture = seed_ready_authority(&database).await?;
        assert_expired_horizon_rejected(&database, &fixture).await?;
        assert_orphan_and_wrong_target_rejected(&database, &fixture).await?;
        let e1 = fixture.root_horizon + 10_000;
        insert_valid_edge(&database, &fixture, fixture.root_horizon, e1).await?;
        assert_predecessor_and_target_uniqueness(&database, &fixture, e1).await?;
        assert_append_only(&database).await
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

async fn renewal_table_exists(database: &TestDatabase) -> TestResult<bool> {
    Ok(sqlx::query_scalar(
        "SELECT to_regclass('github_runtime_authority_lease_renewal_receipts') IS NOT NULL",
    )
    .fetch_one(database.pool())
    .await?)
}

#[allow(clippy::too_many_lines)] // One catalog assertion pins every 0072 object and binding.
async fn assert_renewal_catalog(database: &TestDatabase) -> TestResult {
    let catalog: (i64, i64, i64, i64, i64) = sqlx::query_as(
        r"
        SELECT
            (SELECT count(*)
             FROM pg_constraint
             WHERE conrelid =
                       'github_runtime_authority_lease_renewal_receipts'::REGCLASS
               AND conname IN (
                   'github_runtime_authority_lease_renewal_receipts_pk',
                   'github_runtime_authority_lease_renewal_predecessor_unique',
                   'github_runtime_authority_lease_renewal_receipts_authority_fk',
                   'github_runtime_authority_lease_renewal_receipts_interval',
                   'github_runtime_authority_lease_renewal_receipts_non_nil'
               )),
            (SELECT count(*)
             FROM pg_trigger
             WHERE tgrelid =
                       'github_runtime_authority_lease_renewal_receipts'::REGCLASS
               AND NOT tgisinternal
               AND tgname IN (
                   'github_runtime_authority_lease_renewal_receipts_validate',
                   'github_runtime_authority_lease_renewal_final_exact',
                   'github_runtime_authority_lease_renewal_receipts_reject_mutation',
                   'github_runtime_authority_lease_renewal_receipts_reject_truncate'
               )),
            (SELECT count(*)
             FROM pg_trigger
             WHERE (
                   (
                       tgname = 'github_runtime_authority_lease_renewal_final_exact'
                       AND tgrelid =
                           'github_runtime_authority_lease_renewal_receipts'::REGCLASS
                   ) OR (
                       tgname = 'job_attempts_github_runtime_authority_renewal_exact'
                       AND tgrelid = 'job_attempts'::REGCLASS
                   )
               )
               AND tgdeferrable
               AND tginitdeferred),
            (SELECT count(*)
             FROM pg_proc
             WHERE pronamespace = current_schema()::REGNAMESPACE
               AND proname IN (
                   'automata_github_runtime_authority_lease_horizon_is_tail',
                   'automata_validate_github_runtime_authority_lease_renewal',
                   'automata_github_runtime_authority_lease_final_exact',
                   'automata_require_github_runtime_authority_lease_final_exact',
                   'automata_require_github_runtime_authority_attempt_renewal',
                   'automata_reject_github_runtime_authority_lease_renewal_mutation'
               )),
            (SELECT count(*) FROM _sqlx_migrations
             WHERE version = 72 AND success)
        ",
    )
    .fetch_one(database.pool())
    .await?;
    assert_eq!(catalog, (5, 4, 2, 6, 1));

    let constraints: Vec<(String, String)> = sqlx::query_as(
        r"
        SELECT conname, contype::TEXT
        FROM pg_constraint
        WHERE conrelid =
                  'github_runtime_authority_lease_renewal_receipts'::REGCLASS
          AND conname IN (
              'github_runtime_authority_lease_renewal_receipts_pk',
              'github_runtime_authority_lease_renewal_predecessor_unique',
              'github_runtime_authority_lease_renewal_receipts_authority_fk',
              'github_runtime_authority_lease_renewal_receipts_interval',
              'github_runtime_authority_lease_renewal_receipts_non_nil'
          )
        ORDER BY conname
        ",
    )
    .fetch_all(database.pool())
    .await?;
    assert_eq!(
        constraints,
        vec![
            (
                "github_runtime_authority_lease_renewal_predecessor_unique".into(),
                "u".into(),
            ),
            (
                "github_runtime_authority_lease_renewal_receipts_authority_fk".into(),
                "f".into(),
            ),
            (
                "github_runtime_authority_lease_renewal_receipts_interval".into(),
                "c".into(),
            ),
            (
                "github_runtime_authority_lease_renewal_receipts_non_nil".into(),
                "c".into(),
            ),
            (
                "github_runtime_authority_lease_renewal_receipts_pk".into(),
                "p".into(),
            ),
        ]
    );
    Ok(())
}

#[derive(Clone, Copy, Debug)]
struct RenewalFixture {
    attempt_id: Uuid,
    lease_id: Uuid,
    runner_id: Uuid,
    runner_session_id: Uuid,
    runner_session_epoch: i64,
    runner_generation: i64,
    root_horizon: i64,
    authorized_at: i64,
}

#[allow(clippy::too_many_lines)] // One exact READY row exercises the released 0071 schema.
async fn seed_ready_authority(database: &TestDatabase) -> TestResult<RenewalFixture> {
    let seed = seed_control_plane(database.pool(), 1).await?;
    let runner_id = seed.runner_ids[0].as_uuid();
    let session = seed.session_fences[0];
    let runner_session_id = session.session_id().as_uuid();
    let runner_session_epoch = i64::try_from(session.session_epoch().get())?;
    let runner_generation = i64::try_from(session.runner_generation().get())?;
    let attempt_id = Uuid::new_v4();
    let lease_id = Uuid::new_v4();
    let authorized_at: i64 =
        sqlx::query_scalar("SELECT floor(extract(epoch FROM clock_timestamp()) * 1000)::BIGINT")
            .fetch_one(database.pool())
            .await?;
    let root_horizon = authorized_at + 120_000;
    let provider_expires_at = authorized_at + 900_000;

    let mut transaction = database.pool().begin().await?;
    sqlx::query("SET LOCAL session_replication_role = replica")
        .execute(&mut *transaction)
        .await?;
    sqlx::query(
        r"
            INSERT INTO job_attempts (
                id, job_id, attempt_number, lifecycle, fencing_token,
                lease_id, runner_id, lease_issued_at_ms, lease_expires_at_ms,
                lease_failures, queued_at_ms, changed_at_ms, started_at_ms,
                runner_session_id, runner_session_epoch, runner_generation,
                runner_slot
            ) VALUES (
                $1, $2, 1, 'running', 7, $3, $4, $5, $6,
                0, $5, $5, $5, $7, $8, $9, 1
            )
            ",
    )
    .bind(attempt_id)
    .bind(seed.job_id.as_uuid())
    .bind(lease_id)
    .bind(runner_id)
    .bind(authorized_at)
    .bind(root_horizon)
    .bind(runner_session_id)
    .bind(runner_session_epoch)
    .bind(runner_generation)
    .execute(&mut *transaction)
    .await?;

    let selection_id = Uuid::new_v4();
    let selection_owner_id = Uuid::new_v4();
    let mint_owner_id = Uuid::new_v4();
    sqlx::query(
        r"
            INSERT INTO github_runtime_authority_issuances (
                tenant_id, attempt_id, fencing_token, lease_id,
                lease_issued_at_ms, lease_expires_at_ms, run_id, job_id,
                runner_id, runner_session_id, runner_session_epoch,
                runner_generation, runner_slot, job_ir_schema,
                job_ir_size_bytes, job_ir_digest, repository_id,
                provider_connection_id, provider_installation_id,
                github_app_id, github_app_client_id,
                github_app_jwt_issuer_kind, github_app_jwt_issuer_value,
                github_repository_id, github_repository_name,
                authority_namespace, policy_digest, issuer_fingerprint,
                configuration_fingerprint,
                preparation_selection_id, preparation_selection_owner_id,
                preparation_selection_generation,
                preparation_selection_descriptor_digest,
                preparation_selection_claimed_at_ms,
                preparation_selection_expires_at_ms,
                activation_selection_id, activation_selection_owner_id,
                activation_selection_generation, activation_selection_input_digest,
                activation_selection_claimed_at_ms, activation_selection_expires_at_ms,
                materialization_selection_id, materialization_selection_owner_id,
                materialization_selection_generation,
                materialization_selection_descriptor_digest,
                materialization_selection_claimed_at_ms,
                materialization_selection_expires_at_ms,
                requested_at_ms, request_deadline_at_ms,
                conservative_expiry_at_ms,
                state, mint_claim_owner_id, mint_claimed_at_ms,
                mint_claim_expires_at_ms, mint_started_at_ms,
                mint_provider_request_millis,
                provider_expires_at_ms, safe_erase_after_ms,
                commit_disposition, plaintext_schema, plaintext_size_bytes,
                plaintext_digest, aad_digest, envelope_schema,
                wrapping_key_id, wrapped_data_key, nonce, ciphertext,
                ready_at_ms, state_updated_at_ms
            ) VALUES (
                $1, $2, 7, $3, $4, $5, $6, $7,
                $8, $9, $10, $11, 1, 5, 128, $12, $13,
                $14, 9001, 9002, 'Iv1.renewal-migration',
                'app_client_id', 'Iv1.renewal-migration',
                4242, 'automata-ci/automata', 'github.repository',
                $12, $15, $16,
                $17, $18, 1, $12, $4, $5,
                $17, $18, 1, $12, $4, $5,
                $17, $18, 1, $12, $4, $5,
                $4, $19, $19 + 3780000,
                'ready', $20, $4, NULL, $4, 1,
                $21, $21 + 120000, 'deliverable', 1, 32,
                $22, $23, 1, 'renewal-migration-test-v1',
                $24, $25, $26, $4, $4
            )
            ",
    )
    .bind(&seed.tenant_id)
    .bind(attempt_id)
    .bind(lease_id)
    .bind(authorized_at)
    .bind(root_horizon)
    .bind(seed.run_id.as_uuid())
    .bind(seed.job_id.as_uuid())
    .bind(runner_id)
    .bind(runner_session_id)
    .bind(runner_session_epoch)
    .bind(runner_generation)
    .bind(vec![0x11_u8; 32])
    .bind(seed.repository_id)
    .bind(Uuid::new_v4())
    .bind(vec![0x12_u8; 32])
    .bind(vec![0x13_u8; 32])
    .bind(selection_id)
    .bind(selection_owner_id)
    .bind(authorized_at + 60_000)
    .bind(mint_owner_id)
    .bind(provider_expires_at)
    .bind(vec![0x21_u8; 32])
    .bind(vec![0x22_u8; 32])
    .bind(vec![0x23_u8; 48])
    .bind(vec![0x24_u8; 12])
    .bind(vec![0x25_u8; 48])
    .execute(&mut *transaction)
    .await?;
    transaction.commit().await?;

    Ok(RenewalFixture {
        attempt_id,
        lease_id,
        runner_id,
        runner_session_id,
        runner_session_epoch,
        runner_generation,
        root_horizon,
        authorized_at,
    })
}

async fn insert_receipt(
    transaction: &mut Transaction<'_, Postgres>,
    fixture: &RenewalFixture,
    previous: i64,
    renewed: i64,
    authorized_at: i64,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        r"
        INSERT INTO github_runtime_authority_lease_renewal_receipts (
            attempt_id, fencing_token, lease_id, runner_id,
            runner_session_id, runner_session_epoch, runner_generation,
            previous_lease_expires_at_ms, renewed_lease_expires_at_ms,
            authorized_at_ms
        ) VALUES ($1, 7, $2, $3, $4, $5, $6, $7, $8, $9)
        ",
    )
    .bind(fixture.attempt_id)
    .bind(fixture.lease_id)
    .bind(fixture.runner_id)
    .bind(fixture.runner_session_id)
    .bind(fixture.runner_session_epoch)
    .bind(fixture.runner_generation)
    .bind(previous)
    .bind(renewed)
    .bind(authorized_at)
    .execute(&mut **transaction)
    .await?;
    Ok(())
}

async fn insert_valid_edge(
    database: &TestDatabase,
    fixture: &RenewalFixture,
    previous: i64,
    renewed: i64,
) -> TestResult {
    let authorized_at: i64 =
        sqlx::query_scalar("SELECT floor(extract(epoch FROM clock_timestamp()) * 1000)::BIGINT")
            .fetch_one(database.pool())
            .await?;
    let mut transaction = database.pool().begin().await?;
    insert_receipt(&mut transaction, fixture, previous, renewed, authorized_at).await?;
    let updated = sqlx::query(
        "UPDATE job_attempts SET lease_expires_at_ms = $2, changed_at_ms = $3 \
         WHERE id = $1 AND fencing_token = 7 AND lease_expires_at_ms = $4",
    )
    .bind(fixture.attempt_id)
    .bind(renewed)
    .bind(authorized_at)
    .bind(previous)
    .execute(&mut *transaction)
    .await?;
    assert_eq!(updated.rows_affected(), 1);
    transaction.commit().await?;
    Ok(())
}

async fn assert_predecessor_and_target_uniqueness(
    database: &TestDatabase,
    fixture: &RenewalFixture,
    e1: i64,
) -> TestResult {
    let authorized_at = database_now(database.pool()).await?;
    let mut predecessor = database.pool().begin().await?;
    sqlx::query("SET LOCAL session_replication_role = replica")
        .execute(&mut *predecessor)
        .await?;
    let error = insert_receipt(
        &mut predecessor,
        fixture,
        fixture.root_horizon,
        e1 + 10_000,
        authorized_at,
    )
    .await
    .expect_err("one predecessor cannot have two successors");
    assert_constraint(
        &error,
        "github_runtime_authority_lease_renewal_predecessor_unique",
    );
    predecessor.rollback().await?;

    let mut target = database.pool().begin().await?;
    sqlx::query("SET LOCAL session_replication_role = replica")
        .execute(&mut *target)
        .await?;
    let error = insert_receipt(&mut target, fixture, e1 - 1, e1, authorized_at)
        .await
        .expect_err("one renewed horizon cannot have two incoming edges");
    assert_constraint(&error, "github_runtime_authority_lease_renewal_receipts_pk");
    target.rollback().await?;
    Ok(())
}

async fn assert_append_only(database: &TestDatabase) -> TestResult {
    for statement in [
        "UPDATE github_runtime_authority_lease_renewal_receipts \
         SET authorized_at_ms = authorized_at_ms",
        "DELETE FROM github_runtime_authority_lease_renewal_receipts",
        "TRUNCATE github_runtime_authority_lease_renewal_receipts",
    ] {
        let error = sqlx::query(statement)
            .execute(database.pool())
            .await
            .expect_err("renewal evidence must remain append-only");
        assert_constraint(
            &error,
            "github_runtime_authority_lease_renewal_receipts_append_only",
        );
    }
    Ok(())
}

fn assert_constraint(error: &sqlx::Error, expected: &str) {
    assert_eq!(
        error
            .as_database_error()
            .and_then(sqlx::error::DatabaseError::constraint),
        Some(expected),
        "unexpected PostgreSQL error: {error}"
    );
}

fn assert_constraint_one_of(error: &sqlx::Error, expected: &[&str]) {
    let actual = error
        .as_database_error()
        .and_then(sqlx::error::DatabaseError::constraint);
    assert!(
        actual.is_some_and(|actual| expected.contains(&actual)),
        "unexpected PostgreSQL error: {error}"
    );
}

async fn database_now(pool: &PgPool) -> TestResult<i64> {
    Ok(
        sqlx::query_scalar("SELECT floor(extract(epoch FROM clock_timestamp()) * 1000)::BIGINT")
            .fetch_one(pool)
            .await?,
    )
}

async fn install_test_clock(pool: &PgPool, now: i64) -> TestResult {
    sqlx::query(
        "CREATE TABLE github_runtime_authority_renewal_test_clock (now_ms BIGINT NOT NULL)",
    )
    .execute(pool)
    .await?;
    sqlx::query("INSERT INTO github_runtime_authority_renewal_test_clock VALUES ($1)")
        .bind(now)
        .execute(pool)
        .await?;
    sqlx::query(
        r"
        CREATE FUNCTION clock_timestamp()
        RETURNS TIMESTAMPTZ
        LANGUAGE SQL
        VOLATILE
        AS $test$
            SELECT TIMESTAMPTZ 'epoch' + now_ms * INTERVAL '1 millisecond'
            FROM github_runtime_authority_renewal_test_clock
        $test$
        ",
    )
    .execute(pool)
    .await?;
    Ok(())
}

async fn remove_test_clock(pool: &PgPool) -> TestResult {
    sqlx::query("DROP FUNCTION clock_timestamp()")
        .execute(pool)
        .await?;
    sqlx::query("DROP TABLE github_runtime_authority_renewal_test_clock")
        .execute(pool)
        .await?;
    Ok(())
}

async fn assert_expired_horizon_rejected(
    database: &TestDatabase,
    fixture: &RenewalFixture,
) -> TestResult {
    install_test_clock(database.pool(), fixture.root_horizon).await?;
    let mut expired = database.pool().begin().await?;
    let error = insert_receipt(
        &mut expired,
        fixture,
        fixture.root_horizon,
        fixture.root_horizon + 2,
        fixture.authorized_at,
    )
    .await
    .expect_err("a predecessor expired at current database time must be rejected");
    expired.rollback().await?;
    assert_constraint(
        &error,
        "github_runtime_authority_lease_renewal_receipts_authority",
    );
    remove_test_clock(database.pool()).await?;

    let mut equal = database.pool().begin().await?;
    sqlx::query("SET LOCAL session_replication_role = replica")
        .execute(&mut *equal)
        .await?;
    let error = insert_receipt(
        &mut equal,
        fixture,
        fixture.root_horizon,
        fixture.root_horizon + 2,
        fixture.root_horizon,
    )
    .await
    .expect_err("a predecessor equal to authorization time must fail its interval");
    equal.rollback().await?;
    assert_constraint(
        &error,
        "github_runtime_authority_lease_renewal_receipts_interval",
    );

    let mut non_extending = database.pool().begin().await?;
    sqlx::query("SET LOCAL session_replication_role = replica")
        .execute(&mut *non_extending)
        .await?;
    let error = insert_receipt(
        &mut non_extending,
        fixture,
        fixture.root_horizon,
        fixture.root_horizon,
        fixture.authorized_at,
    )
    .await
    .expect_err("a renewal target equal to its predecessor must fail its interval");
    non_extending.rollback().await?;
    assert_constraint(
        &error,
        "github_runtime_authority_lease_renewal_receipts_interval",
    );
    Ok(())
}

async fn assert_orphan_and_wrong_target_rejected(
    database: &TestDatabase,
    fixture: &RenewalFixture,
) -> TestResult {
    let authorized_at: i64 =
        sqlx::query_scalar("SELECT floor(extract(epoch FROM clock_timestamp()) * 1000)::BIGINT")
            .fetch_one(database.pool())
            .await?;
    let target = fixture.root_horizon + 10_000;
    let mut orphan = database.pool().begin().await?;
    insert_receipt(
        &mut orphan,
        fixture,
        fixture.root_horizon,
        target,
        authorized_at,
    )
    .await?;
    let error = orphan
        .commit()
        .await
        .expect_err("an orphan receipt must fail at deferred commit");
    assert_constraint(&error, "github_runtime_authority_lease_renewal_final_exact");

    let mut wrong_cas = database.pool().begin().await?;
    insert_receipt(
        &mut wrong_cas,
        fixture,
        fixture.root_horizon,
        target,
        authorized_at,
    )
    .await?;
    let updated = sqlx::query(
        "UPDATE job_attempts SET lease_expires_at_ms = $2, changed_at_ms = $3 \
         WHERE id = $1 AND fencing_token = 7 AND lease_expires_at_ms = $4",
    )
    .bind(fixture.attempt_id)
    .bind(target)
    .bind(authorized_at)
    .bind(fixture.root_horizon - 1)
    .execute(&mut *wrong_cas)
    .await?;
    assert_eq!(updated.rows_affected(), 0);
    let error = wrong_cas
        .commit()
        .await
        .expect_err("a receipt whose exact-old CAS lost must fail at commit");
    assert_constraint(&error, "github_runtime_authority_lease_renewal_final_exact");

    let mut wrong_target = database.pool().begin().await?;
    insert_receipt(
        &mut wrong_target,
        fixture,
        fixture.root_horizon,
        target,
        authorized_at,
    )
    .await?;
    sqlx::query(
        "UPDATE job_attempts SET lease_expires_at_ms = $2, changed_at_ms = $3 \
         WHERE id = $1 AND fencing_token = 7",
    )
    .bind(fixture.attempt_id)
    .bind(target + 1)
    .bind(authorized_at)
    .execute(&mut *wrong_target)
    .await?;
    let error = wrong_target
        .commit()
        .await
        .expect_err("a mismatched attempt target must fail at deferred commit");
    assert_constraint_one_of(
        &error,
        &[
            "github_runtime_authority_lease_renewal_final_exact",
            "github_runtime_authority_attempt_renewal_final_exact",
        ],
    );
    Ok(())
}
