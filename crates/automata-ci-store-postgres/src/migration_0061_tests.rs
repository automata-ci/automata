use std::{env, future::Future, str::FromStr, sync::Arc};

use sqlx::{
    AssertSqlSafe, Connection as _, PgConnection, PgPool,
    postgres::{PgConnectOptions, PgPoolOptions},
};
use uuid::Uuid;

use crate::migration::MIGRATOR;

const DATABASE_URL_ENVIRONMENT: &str = "AUTOMATA_TEST_DATABASE_URL";
const MINIMUM_POSTGRES_VERSION: i32 = 180_000;

type TestError = Box<dyn std::error::Error + Send + Sync + 'static>;
type TestResult<T = ()> = Result<T, TestError>;

#[derive(Debug)]
struct TestDatabase {
    pool: PgPool,
}

async fn run_with_unmigrated_database<Test, TestFuture>(test: Test) -> TestResult
where
    Test: FnOnce(Arc<TestDatabase>) -> TestFuture + Send + 'static,
    TestFuture: Future<Output = TestResult> + Send + 'static,
{
    let database_url = env::var(DATABASE_URL_ENVIRONMENT).map_err(|error| {
        message_error(format!(
            "set {DATABASE_URL_ENVIRONMENT} to an isolated PostgreSQL 18 test server URL: {error}"
        ))
    })?;
    let admin_options = PgConnectOptions::from_str(&database_url)?;
    let database_name = format!("automata_m61_{}", Uuid::new_v4().simple());

    let mut admin = PgConnection::connect_with(&admin_options).await?;
    require_postgres_18(&mut admin).await?;
    sqlx::query(AssertSqlSafe(format!(
        "CREATE DATABASE \"{database_name}\" TEMPLATE template0"
    )))
    .execute(&mut admin)
    .await?;
    admin.close().await?;

    let database_options = admin_options.clone().database(&database_name);
    let pool = match PgPoolOptions::new()
        .max_connections(4)
        .after_connect(|connection, _metadata| {
            Box::pin(async move {
                sqlx::query("SELECT pg_catalog.set_config('search_path', $1, false)")
                    .bind("public, pg_catalog")
                    .execute(connection)
                    .await?;
                Ok(())
            })
        })
        .connect_with(database_options)
        .await
    {
        Ok(pool) => pool,
        Err(error) => {
            cleanup_database(&admin_options, &database_name).await?;
            return Err(error.into());
        }
    };
    let database = Arc::new(TestDatabase { pool });
    let task = tokio::spawn(test(Arc::clone(&database))).await;
    database.pool.close().await;
    let cleanup = cleanup_database(&admin_options, &database_name).await;

    match task {
        Ok(Ok(())) => cleanup,
        Ok(Err(test_error)) => {
            cleanup?;
            Err(test_error)
        }
        Err(join_error) => {
            let _ = cleanup;
            if join_error.is_panic() {
                std::panic::resume_unwind(join_error.into_panic());
            }
            Err(join_error.into())
        }
    }
}

async fn require_postgres_18(connection: &mut PgConnection) -> TestResult {
    let version: i32 =
        sqlx::query_scalar("SELECT pg_catalog.current_setting('server_version_num')::INTEGER")
            .fetch_one(&mut *connection)
            .await?;
    if version < MINIMUM_POSTGRES_VERSION {
        return Err(message_error(format!(
            "migration 0061 live tests require PostgreSQL 18 or newer; server_version_num is {version}"
        )));
    }
    let is_superuser: bool =
        sqlx::query_scalar("SELECT rolsuper FROM pg_catalog.pg_roles WHERE rolname = CURRENT_USER")
            .fetch_one(&mut *connection)
            .await?;
    if !is_superuser {
        return Err(message_error(
            "migration 0061 live tests require a superuser on the isolated PostgreSQL server",
        ));
    }
    Ok(())
}

async fn cleanup_database(options: &PgConnectOptions, database_name: &str) -> TestResult {
    let mut admin = PgConnection::connect_with(options).await?;
    sqlx::query(AssertSqlSafe(format!(
        "DROP DATABASE \"{database_name}\" WITH (FORCE)"
    )))
    .execute(&mut admin)
    .await?;
    admin.close().await?;
    Ok(())
}

fn message_error(message: impl Into<String>) -> TestError {
    std::io::Error::other(message.into()).into()
}

async fn seed_immutable_auxiliary_evidence(pool: &PgPool) -> TestResult {
    let mut transaction = pool.begin().await?;
    sqlx::query("SET LOCAL session_replication_role = 'replica'")
        .execute(&mut *transaction)
        .await?;
    sqlx::query(
        r"
        INSERT INTO github_provider_delivery_evidence (
            provider_delivery_id,tenant_id,repository_id,
            provider_connection_id,provider_installation_id,
            github_repository_id,github_repository_owner_id,
            github_repository_name,repository_visibility,
            provider_manifest_revision,provider_manifest_digest,
            authenticated_webhook_verifier_fingerprint_sha256,
            authenticated_webhook_verifier_revision,
            checks_authority_id,checks_authority_identity_digest,
            checks_authority_app_configuration_revision,
            checks_authority_policy_revision,
            repository_contents_authority_id,
            repository_contents_authority_identity_digest,
            repository_contents_authority_app_configuration_revision,
            repository_contents_authority_policy_revision,
            github_check_subject_id,github_check_head_sha,
            authenticated_event_envelope_version,
            authenticated_event_name,authenticated_event_git_ref,
            aggregate_check_kind
        ) VALUES (
            $1,'migration-upgrade',$2,$3,1,2,3,'automata-ci/automata',
            'private',1,$4,$5,1,$6,$7,1,1,$8,$9,1,1,$10,$11,
            1,'push','refs/heads/main','auxiliary'
        )
        ",
    )
    .bind(Uuid::new_v4())
    .bind(Uuid::new_v4())
    .bind(Uuid::new_v4())
    .bind(vec![0x11_u8; 32])
    .bind(vec![0x12_u8; 32])
    .bind(Uuid::new_v4())
    .bind(vec![0x13_u8; 32])
    .bind(Uuid::new_v4())
    .bind(vec![0x14_u8; 32])
    .bind(Uuid::new_v4())
    .bind(vec![0x15_u8; 20])
    .execute(&mut *transaction)
    .await?;
    transaction.commit().await?;
    Ok(())
}

async fn assert_migrated_contract(pool: &PgPool) -> TestResult {
    let aggregate_check_kind: String =
        sqlx::query_scalar("SELECT aggregate_check_kind FROM github_provider_delivery_evidence")
            .fetch_one(pool)
            .await?;
    assert_eq!(aggregate_check_kind, "jobs_only");

    let endpoint_connection_columns: i64 = sqlx::query_scalar(
        r"
        SELECT count(*)
        FROM information_schema.columns
        WHERE table_schema = 'automata_test'
          AND table_name = 'provider_webhook_endpoint_revisions'
          AND column_name IN ('connection_id', 'connection_revision')
        ",
    )
    .fetch_one(pool)
    .await?;
    assert_eq!(endpoint_connection_columns, 0);

    let connection_foreign_key: bool = sqlx::query_scalar(
        r"
        SELECT EXISTS (
            SELECT 1
            FROM pg_catalog.pg_constraint
            WHERE conrelid = 'provider_deliveries'::regclass
              AND contype = 'f'
              AND pg_catalog.pg_get_constraintdef(oid) =
                  'FOREIGN KEY (connection_id, connection_revision, provider_instance_id, provider_revision) REFERENCES provider_connection_revisions(connection_id, revision, provider_instance_id, provider_revision) ON DELETE RESTRICT'
        )
        ",
    )
    .fetch_one(pool)
    .await?;
    assert!(connection_foreign_key);

    let immutable =
        sqlx::query("UPDATE github_provider_delivery_evidence SET aggregate_check_kind='required'")
            .execute(pool)
            .await
            .expect_err("delivery evidence remains immutable after migration");
    assert_eq!(
        immutable
            .as_database_error()
            .and_then(sqlx::error::DatabaseError::constraint),
        Some("github_provider_delivery_evidence_immutable")
    );
    Ok(())
}

#[tokio::test]
#[ignore = "requires PostgreSQL 18 via AUTOMATA_TEST_DATABASE_URL"]
async fn production_migrations_upgrade_deployed_schema_and_immutable_evidence() -> TestResult {
    run_with_unmigrated_database(|database| async move {
        let deployed = sqlx::migrate::Migrator::with_migrations(
            MIGRATOR
                .iter()
                .filter(|migration| migration.version <= 60)
                .cloned()
                .collect(),
        );
        deployed.run(&database.pool).await?;
        let deployed_version: i64 = sqlx::query_scalar("SELECT max(version) FROM _sqlx_migrations")
            .fetch_one(&database.pool)
            .await?;
        assert_eq!(deployed_version, 60);

        seed_immutable_auxiliary_evidence(&database.pool).await?;

        MIGRATOR.run(&database.pool).await?;
        let applied_version: i64 = sqlx::query_scalar("SELECT max(version) FROM _sqlx_migrations")
            .fetch_one(&database.pool)
            .await?;
        assert_eq!(applied_version, 74);

        assert_migrated_contract(&database.pool).await?;
        Ok(())
    })
    .await
}
