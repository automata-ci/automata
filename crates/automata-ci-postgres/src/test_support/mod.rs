//! Process-safe `PostgreSQL` fixtures for Automata's integration tests.
//!
//! Enable the `test-support` feature from development dependencies. The
//! fixture uses the configured namespace's immutable database template, clones
//! an isolated database for each callback, and performs exact cleanup after
//! success, error, or panic.

mod clock;
mod database;
#[cfg(feature = "test-support")]
mod github_workflow_permissions;
mod timing;

#[cfg(test)]
mod tests;

use std::error::Error;

#[cfg(feature = "test-support")]
use std::{future::Future, sync::Arc};

pub use clock::TestClock;
#[cfg(feature = "test-support")]
use database::{PostgresTestHarness, PreparedTemplate, TestDatabase};
#[cfg(feature = "test-support")]
pub use github_workflow_permissions::activate_github_workflow_permission_defaults;
#[cfg(feature = "test-support")]
use sqlx::PgPool;
#[cfg(feature = "test-support")]
use tokio::sync::OnceCell;

#[cfg(feature = "test-support")]
use automata_ci_store_postgres::PostgresStore;

/// Environment variable containing the isolated `PostgreSQL` server URL.
const DATABASE_URL_ENVIRONMENT: &str = "AUTOMATA_TEST_DATABASE_URL";

/// Optional job-scoped namespace shared by cooperating test processes.
const DATABASE_NAMESPACE_ENVIRONMENT: &str = "AUTOMATA_TEST_DATABASE_NAMESPACE";

/// Optional SHA-256 fingerprint of the prepared-template initializer.
const INITIALIZER_FINGERPRINT_ENVIRONMENT: &str = "AUTOMATA_TEST_TEMPLATE_FINGERPRINT";

/// Optional directory for per-process `PostgreSQL` fixture timing records.
const TIMINGS_DIRECTORY_ENVIRONMENT: &str = "AUTOMATA_TEST_TIMINGS_DIR";

/// Constrained, secret-free invocation identity written to every timing record.
const TIMING_INVOCATION_ENVIRONMENT: &str = "AUTOMATA_TEST_TIMING_INVOCATION";

/// Decimal benchmark-run attribution written to every timing record.
const TIMING_RUN_ENVIRONMENT: &str = "AUTOMATA_TEST_TIMING_RUN";

type TestError = Box<dyn Error + Send + Sync + 'static>;

/// Result type used by the test fixture API and its callbacks.
pub type TestResult<T = ()> = Result<T, Box<dyn Error + Send + Sync + 'static>>;

#[cfg(feature = "test-support")]
static PREPARED_TEMPLATE: OnceCell<PreparedTemplate> = OnceCell::const_new();

/// An isolated database paired with its `PostgresStore` adapter.
#[derive(Debug)]
#[cfg(feature = "test-support")]
pub struct PostgresTestDatabase {
    database: Arc<TestDatabase>,
    store: Arc<PostgresStore>,
}

#[cfg(feature = "test-support")]
impl PostgresTestDatabase {
    /// Returns the database's configured Store adapter.
    pub fn store(&self) -> &PostgresStore {
        &self.store
    }

    /// Returns shared ownership of the configured Store adapter.
    pub fn shared_store(&self) -> Arc<PostgresStore> {
        Arc::clone(&self.store)
    }

    /// Returns the database's primary connection pool.
    pub fn pool(&self) -> &PgPool {
        self.store.postgres_pool()
    }

    /// Opens another pool connected to this exact isolated database.
    ///
    /// # Errors
    ///
    /// Returns an error if `max_connections` is zero or `PostgreSQL` cannot
    /// establish the pool.
    pub async fn connect_pool(&self, max_connections: u32) -> TestResult<PgPool> {
        self.database.connect_pool(max_connections).await
    }
}

/// Runs a test with an isolated, migrated database and default Store adapter.
///
/// # Errors
///
/// Returns the template, clone, test, task-join, or cleanup error.
#[cfg(feature = "test-support")]
pub async fn run_with_database<Test, TestFuture>(test: Test) -> TestResult
where
    Test: FnOnce(Arc<PostgresTestDatabase>) -> TestFuture + Send + 'static,
    TestFuture: Future<Output = TestResult> + Send + 'static,
{
    run_with_configured_database(|store| store, test).await
}

/// Runs a test with an isolated, migrated database and configured Store adapter.
///
/// The configurator may install deterministic test-only authorities on the
/// adapter. Template migration itself is independent of that configuration.
///
/// # Errors
///
/// Returns the template, clone, test, task-join, or cleanup error.
#[cfg(feature = "test-support")]
pub async fn run_with_configured_database<Configure, Test, TestFuture>(
    configure: Configure,
    test: Test,
) -> TestResult
where
    Configure: FnOnce(PostgresStore) -> PostgresStore + Send + 'static,
    Test: FnOnce(Arc<PostgresTestDatabase>) -> TestFuture + Send + 'static,
    TestFuture: Future<Output = TestResult> + Send + 'static,
{
    prepared_template()
        .await?
        .run(move |database| async move {
            let store = configure(PostgresStore::from_postgres_pool(database.pool().clone()));
            test(Arc::new(PostgresTestDatabase {
                database,
                store: Arc::new(store),
            }))
            .await
        })
        .await
}

/// Runs a test with an application-empty database and configured Store adapter.
///
/// The database contains the `automata_test` schema but no current application
/// objects or migration ledger.
///
/// # Errors
///
/// Returns the database creation, test, task-join, or cleanup error.
#[cfg(feature = "test-support")]
pub async fn run_with_unmigrated_database<Configure, Test, TestFuture>(
    configure: Configure,
    test: Test,
) -> TestResult
where
    Configure: FnOnce(PostgresStore) -> PostgresStore + Send + 'static,
    Test: FnOnce(Arc<PostgresTestDatabase>) -> TestFuture + Send + 'static,
    TestFuture: Future<Output = TestResult> + Send + 'static,
{
    PostgresTestHarness::from_environment()?
        .run_with_empty_database(move |database| async move {
            let store = configure(PostgresStore::from_postgres_pool(database.pool().clone()));
            test(Arc::new(PostgresTestDatabase {
                database,
                store: Arc::new(store),
            }))
            .await
        })
        .await
}

/// Removes every database owned by the explicitly configured test namespace.
///
/// The returned message contains no database URL or credential and is suitable
/// for direct diagnostic output by the cleanup example.
///
/// # Errors
///
/// Returns an error if the namespace is absent or invalid, an ownership marker
/// differs, or `PostgreSQL` cannot complete exact cleanup.
#[cfg(feature = "test-support")]
pub async fn cleanup_namespace_from_environment() -> TestResult<String> {
    let harness = PostgresTestHarness::from_environment_for_cleanup()?;
    let namespace = harness.namespace().to_string();
    let cleanup = harness.cleanup_namespace().await?;
    Ok(format!(
        "cleaned PostgreSQL test namespace {namespace}: {} test database(s), template removed: {}",
        cleanup.dropped_test_databases, cleanup.dropped_template
    ))
}

#[cfg(feature = "test-support")]
async fn prepared_template() -> TestResult<&'static PreparedTemplate> {
    PREPARED_TEMPLATE
        .get_or_try_init(|| async {
            PostgresTestHarness::from_environment()?
                .prepare_template(|pool| async move {
                    PostgresStore::from_postgres_pool(pool).migrate().await?;
                    Ok(())
                })
                .await
        })
        .await
}

fn message_error(message: impl Into<String>) -> TestError {
    std::io::Error::other(message.into()).into()
}
