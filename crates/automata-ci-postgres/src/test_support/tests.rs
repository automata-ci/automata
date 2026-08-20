use std::{
    future::Future,
    str::FromStr as _,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

use super::{
    DATABASE_URL_ENVIRONMENT, TestClock, TestResult,
    database::{NamespaceCleanup, PostgresTestHarness, PreparedTemplate, TestNamespace},
};
use sqlx::{AssertSqlSafe, Connection as _, PgConnection, PgPool, postgres::PgConnectOptions};
use tokio::{task::JoinError, time::Instant};
use uuid::Uuid;

type NamespaceCleanupOutcome = Result<TestResult<NamespaceCleanup>, JoinError>;

fn configured_harness() -> TestResult<PostgresTestHarness> {
    PostgresTestHarness::from_environment()
}

async fn run_with_configured_harness<Test, TestFuture>(test: Test) -> TestResult
where
    Test: FnOnce(PostgresTestHarness) -> TestFuture,
    TestFuture: Future<Output = TestResult> + Send + 'static,
{
    let harness = configured_harness()?;
    run_with_harness(harness, test).await
}

async fn run_with_harness<Test, TestFuture>(harness: PostgresTestHarness, test: Test) -> TestResult
where
    Test: FnOnce(PostgresTestHarness) -> TestFuture,
    TestFuture: Future<Output = TestResult> + Send + 'static,
{
    let cleanup_harness = harness.clone();
    let test_outcome = tokio::spawn(test(harness)).await;
    let cleanup_outcome =
        tokio::spawn(async move { cleanup_harness.cleanup_namespace().await }).await;

    match test_outcome {
        Ok(Ok(())) => match cleanup_outcome {
            Ok(Ok(_)) => Ok(()),
            Ok(Err(cleanup_error)) => Err(cleanup_error),
            Err(cleanup_join_error) => {
                if cleanup_join_error.is_panic() {
                    std::panic::resume_unwind(cleanup_join_error.into_panic());
                }
                Err(cleanup_join_error.into())
            }
        },
        Ok(Err(test_error)) => {
            report_secondary_cleanup_failure(&cleanup_outcome);
            Err(test_error)
        }
        Err(test_join_error) => {
            report_secondary_cleanup_failure(&cleanup_outcome);
            if test_join_error.is_panic() {
                std::panic::resume_unwind(test_join_error.into_panic());
            }
            Err(test_join_error.into())
        }
    }
}

fn report_secondary_cleanup_failure(cleanup_outcome: &NamespaceCleanupOutcome) {
    match cleanup_outcome {
        Ok(Ok(_)) => {}
        Ok(Err(cleanup_error)) => {
            eprintln!("PostgreSQL test namespace cleanup also failed: {cleanup_error}");
        }
        Err(cleanup_join_error) => {
            eprintln!("PostgreSQL test namespace cleanup task also failed: {cleanup_join_error}");
        }
    }
}

async fn marker_template(harness: &PostgresTestHarness) -> TestResult<PreparedTemplate> {
    harness
        .prepare_template(|pool| async move {
            sqlx::query(
                r"
                CREATE TABLE automata_test.migration_marker (
                    version INTEGER PRIMARY KEY
                )
                ",
            )
            .execute(&pool)
            .await?;
            sqlx::query("INSERT INTO automata_test.migration_marker (version) VALUES (72)")
                .execute(&pool)
                .await?;
            Ok(())
        })
        .await
}

async fn database_exists(database_name: &str) -> TestResult<bool> {
    let database_url = std::env::var(DATABASE_URL_ENVIRONMENT)?;
    let options = PgConnectOptions::from_str(&database_url)?;
    let mut connection = PgConnection::connect_with(&options).await?;
    Ok(sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM pg_catalog.pg_database WHERE datname = $1)",
    )
    .bind(database_name)
    .fetch_one(&mut connection)
    .await?)
}

async fn create_unmarked_database(database_name: &str) -> TestResult {
    let database_url = std::env::var(DATABASE_URL_ENVIRONMENT)?;
    let options = PgConnectOptions::from_str(&database_url)?;
    let mut connection = PgConnection::connect_with(&options).await?;
    sqlx::query(AssertSqlSafe(format!(
        "CREATE DATABASE \"{database_name}\" TEMPLATE template0"
    )))
    .execute(&mut connection)
    .await?;
    Ok(())
}

async fn observed_clock(pool: &PgPool) -> TestResult<i64> {
    Ok(
        sqlx::query_scalar("SELECT floor(extract(epoch FROM clock_timestamp()) * 1000)::BIGINT")
            .fetch_one(pool)
            .await?,
    )
}

#[tokio::test]
#[ignore = "requires PostgreSQL 18 via AUTOMATA_TEST_DATABASE_URL"]
async fn parallel_template_clones_are_isolated() -> TestResult {
    run_with_configured_harness(|harness| async move {
        let template = harness
            .prepare_template(|pool| async move {
                sqlx::query("CREATE TABLE automata_test.isolation_probe (value TEXT NOT NULL)")
                    .execute(&pool)
                    .await?;
                Ok(())
            })
            .await?;
        let left_template = template.clone();
        let left = left_template.run(|database| async move {
            sqlx::query("INSERT INTO isolation_probe (value) VALUES ('left')")
                .execute(database.pool())
                .await?;
            let values: Vec<String> =
                sqlx::query_scalar("SELECT value FROM isolation_probe ORDER BY value")
                    .fetch_all(database.pool())
                    .await?;
            assert_eq!(values, ["left"]);
            Ok(())
        });
        let right = template.run(|database| async move {
            sqlx::query("INSERT INTO isolation_probe (value) VALUES ('right')")
                .execute(database.pool())
                .await?;
            let values: Vec<String> =
                sqlx::query_scalar("SELECT value FROM isolation_probe ORDER BY value")
                    .fetch_all(database.pool())
                    .await?;
            assert_eq!(values, ["right"]);
            Ok(())
        });
        let (left_result, right_result) = tokio::join!(left, right);
        left_result?;
        right_result
    })
    .await
}

#[tokio::test]
#[ignore = "requires PostgreSQL 18 via AUTOMATA_TEST_DATABASE_URL"]
async fn template_clone_contains_initialized_migration_marker() -> TestResult {
    run_with_configured_harness(|harness| async move {
        let template = marker_template(&harness).await?;
        template
            .run(|database| async move {
                let version: i32 = sqlx::query_scalar("SELECT version FROM migration_marker")
                    .fetch_one(database.pool())
                    .await?;
                assert_eq!(version, 72);
                Ok(())
            })
            .await
    })
    .await
}

#[tokio::test]
#[ignore = "requires PostgreSQL 18 via AUTOMATA_TEST_DATABASE_URL"]
async fn template0_database_is_application_empty() -> TestResult {
    run_with_configured_harness(|harness| async move {
        let _template = marker_template(&harness).await?;
        harness
            .run_with_empty_database(|database| async move {
                let schema_exists: bool = sqlx::query_scalar(
                    "SELECT EXISTS (SELECT 1 FROM pg_catalog.pg_namespace WHERE nspname = 'automata_test')",
                )
                .fetch_one(database.pool())
                .await?;
                let marker_exists: bool = sqlx::query_scalar(
                    "SELECT pg_catalog.to_regclass('automata_test.migration_marker') IS NOT NULL",
                )
                .fetch_one(database.pool())
                .await?;
                let migration_ledger_exists: bool = sqlx::query_scalar(
                    "SELECT pg_catalog.to_regclass('public._sqlx_migrations') IS NOT NULL",
                )
                .fetch_one(database.pool())
                .await?;
                assert!(schema_exists);
                assert!(!marker_exists);
                assert!(!migration_ledger_exists);
                Ok(())
            })
            .await
    })
    .await
}

#[tokio::test]
#[ignore = "requires PostgreSQL 18 via AUTOMATA_TEST_DATABASE_URL"]
async fn replacement_connections_observe_schema_local_test_clock() -> TestResult {
    run_with_configured_harness(|harness| async move {
        let template = marker_template(&harness).await?;
        template
            .run(|database| async move {
                let clock = TestClock::freeze(database.pool(), 12_345).await?;
                let replacement = database.connect_pool(1).await?;
                assert_eq!(observed_clock(&replacement).await?, 12_345);
                replacement.close().await;
                clock.restore().await?;
                let restored_wall_clock = observed_clock(database.pool()).await?;
                let system_wall_clock = i64::try_from(
                    std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)?
                        .as_millis(),
                )?;
                assert!(
                    (restored_wall_clock - system_wall_clock).abs() < 5_000,
                    "restored PostgreSQL wall clock {restored_wall_clock} must track system wall clock {system_wall_clock}"
                );
                Ok(())
            })
            .await
    })
    .await
}

#[tokio::test]
#[ignore = "requires PostgreSQL 18 via AUTOMATA_TEST_DATABASE_URL"]
async fn freeze_at_database_now_samples_the_qualified_builtin_clock() -> TestResult {
    run_with_configured_harness(|harness| async move {
        let template = marker_template(&harness).await?;
        template
            .run(|database| async move {
                // Keep one physical connection so this regression covers the
                // constructor's ordering without relying on pool selection.
                // Do not prepare an unqualified clock call before freezing:
                // PostgreSQL does not re-resolve a prepared function merely
                // because a same-named function later shadows it on search_path.
                let pool = database.connect_pool(1).await?;
                let clock = TestClock::freeze_at_database_now(&pool).await?;
                let frozen_at = clock.now().await?;
                let system_wall_clock = i64::try_from(
                    std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)?
                        .as_millis(),
                )?;
                assert!(
                    (frozen_at - system_wall_clock).abs() < 5_000,
                    "qualified PostgreSQL clock sample {frozen_at} must track system wall clock {system_wall_clock}"
                );

                let advanced = clock.advance(86_400_000).await?;
                assert_eq!(advanced, frozen_at + 86_400_000);
                assert_eq!(observed_clock(&pool).await?, advanced);
                let builtin_now: i64 = sqlx::query_scalar(
                    "SELECT floor(extract(epoch FROM pg_catalog.clock_timestamp()) * 1000)::BIGINT",
                )
                .fetch_one(&pool)
                .await?;
                assert_ne!(builtin_now, advanced);

                clock.restore().await?;
                pool.close().await;
                Ok(())
            })
            .await
    })
    .await
}

#[tokio::test]
#[ignore = "requires PostgreSQL 18 via AUTOMATA_TEST_DATABASE_URL"]
async fn advancing_test_clock_does_not_wait_for_wall_time() -> TestResult {
    run_with_configured_harness(|harness| async move {
        let template = marker_template(&harness).await?;
        template
            .run(|database| async move {
                let clock = TestClock::freeze(database.pool(), 1_000).await?;
                let wall_start = Instant::now();
                let advanced = clock.advance(86_400_000).await?;
                assert_eq!(advanced, 86_401_000);
                assert_eq!(clock.now().await?, advanced);
                assert!(
                    wall_start.elapsed() < Duration::from_secs(2),
                    "advancing a database test clock must not sleep for its logical duration"
                );
                clock.restore().await?;
                Ok(())
            })
            .await
    })
    .await
}

#[tokio::test]
#[ignore = "requires PostgreSQL 18 via AUTOMATA_TEST_DATABASE_URL"]
async fn cleanup_drops_the_exact_test_database() -> TestResult {
    run_with_configured_harness(|harness| async move {
        let template = marker_template(&harness).await?;
        let (database_name_sender, database_name_receiver) = tokio::sync::oneshot::channel();
        let run_result = template
            .run(move |database| async move {
                let database_name = database.database_name().to_owned();
                database_name_sender
                    .send(database_name.clone())
                    .map_err(|_| "exact-cleanup database-name receiver disappeared")?;
                assert!(database_exists(&database_name).await?);
                Ok(())
            })
            .await;
        let database_name = database_name_receiver.await?;
        run_result?;
        assert!(!database_exists(&database_name).await?);
        Ok(())
    })
    .await
}

#[tokio::test]
#[ignore = "requires PostgreSQL 18 via AUTOMATA_TEST_DATABASE_URL"]
async fn panicking_test_still_drops_its_exact_database() -> TestResult {
    run_with_configured_harness(|harness| async move {
        let template = marker_template(&harness).await?;
        let run_template = template.clone();
        let (database_name_sender, database_name_receiver) = tokio::sync::oneshot::channel();
        let outer_task = tokio::spawn(async move {
            run_template
                .run(move |database| async move {
                    database_name_sender
                        .send(database.database_name().to_owned())
                        .map_err(|_| "panic-cleanup database-name receiver disappeared")?;
                    panic!("intentional PostgreSQL fixture cleanup regression panic");
                    #[allow(unreachable_code)]
                    Ok(())
                })
                .await
        });

        let database_name = database_name_receiver.await?;
        let join_error = outer_task
            .await
            .expect_err("PreparedTemplate::run must propagate the test panic");
        assert!(join_error.is_panic());
        assert!(!database_exists(&database_name).await?);
        Ok(())
    })
    .await
}

#[tokio::test]
#[ignore = "requires PostgreSQL 18 via AUTOMATA_TEST_DATABASE_URL"]
async fn incompatible_initializer_fingerprint_cannot_reuse_template() -> TestResult {
    let database_url = std::env::var(DATABASE_URL_ENVIRONMENT)?;
    let namespace = TestNamespace::new(
        std::env::var("AUTOMATA_TEST_DATABASE_NAMESPACE")
            .map_err(|_| "AUTOMATA_TEST_DATABASE_NAMESPACE is required")?,
    )?;
    let template_name = format!("at_{namespace}_template");
    let first_fingerprint = "a".repeat(64);
    let second_fingerprint = "b".repeat(64);
    let first = PostgresTestHarness::new(&database_url, namespace.clone())?
        .with_initializer_fingerprint(first_fingerprint)?;
    let second = PostgresTestHarness::new(&database_url, namespace)?
        .with_initializer_fingerprint(second_fingerprint)?;
    let incompatible_initializer_called = Arc::new(AtomicBool::new(false));
    let incompatible_initializer_probe = Arc::clone(&incompatible_initializer_called);

    run_with_harness(first, move |first| async move {
        let template = first
            .prepare_template(|pool| async move {
                sqlx::query(
                    "CREATE TABLE automata_test.fingerprint_marker (value INTEGER NOT NULL)",
                )
                .execute(&pool)
                .await?;
                sqlx::query("INSERT INTO automata_test.fingerprint_marker (value) VALUES (17)")
                    .execute(&pool)
                    .await?;
                Ok(())
            })
            .await?;

        let error = second
            .prepare_template(move |_pool| async move {
                incompatible_initializer_probe.store(true, Ordering::Release);
                Ok(())
            })
            .await
            .expect_err("an incompatible initializer fingerprint must not reuse the template");
        assert!(
            error.to_string().contains("ownership marker"),
            "fingerprint mismatch must fail as an ownership-marker error: {error}"
        );
        assert!(
            !incompatible_initializer_called.load(Ordering::Acquire),
            "a rejected incompatible initializer must not execute"
        );

        template
            .run(|database| async move {
                let value: i32 = sqlx::query_scalar("SELECT value FROM fingerprint_marker")
                    .fetch_one(database.pool())
                    .await?;
                assert_eq!(value, 17);
                Ok(())
            })
            .await
    })
    .await?;

    assert!(
        !database_exists(&template_name).await?,
        "the exact fingerprinted namespace must be cleaned after rejection"
    );
    Ok(())
}

#[tokio::test]
#[ignore = "requires PostgreSQL 18 via AUTOMATA_TEST_DATABASE_URL"]
async fn unmarked_canonical_crash_leftovers_are_recovered_under_namespace_lock() -> TestResult {
    run_with_configured_harness(|harness| async move {
        let template_name = format!("at_{}_template", harness.namespace());
        create_unmarked_database(&template_name).await?;

        let template = harness
            .prepare_template(|pool| async move {
                sqlx::query("CREATE TABLE automata_test.recovery_marker (singleton BOOLEAN)")
                    .execute(&pool)
                    .await?;
                Ok(())
            })
            .await?;
        template
            .run(|database| async move {
                let recovered_marker_exists: bool = sqlx::query_scalar(
                    "SELECT pg_catalog.to_regclass('automata_test.recovery_marker') IS NOT NULL",
                )
                .fetch_one(database.pool())
                .await?;
                assert!(recovered_marker_exists);
                Ok(())
            })
            .await?;

        let unmarked_clone_name = format!("at_{}_{}", harness.namespace(), Uuid::new_v4().simple());
        create_unmarked_database(&unmarked_clone_name).await?;
        let cleanup = harness.cleanup_namespace().await?;
        assert_eq!(cleanup.dropped_test_databases, 1);
        assert!(cleanup.dropped_template);
        assert!(!database_exists(&template_name).await?);
        assert!(!database_exists(&unmarked_clone_name).await?);
        Ok(())
    })
    .await
}
