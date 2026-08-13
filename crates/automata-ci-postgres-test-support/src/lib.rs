//! Process-safe PostgreSQL fixtures for Automata's integration tests.
//!
//! A [`PostgresTestHarness`] prepares one immutable, disconnected database
//! template per CI job. Tests clone that template into independent databases,
//! so current-schema tests can run concurrently without repeating migrations.
//! Migration tests use [`PostgresTestHarness::create_empty_database`] instead.
//!
//! The harness intentionally retains no global connection pool. A process-local
//! namespace fallback is global only as a string, so separate Tokio runtimes do
//! not inherit connections created by an earlier runtime.
//!
//! Templates have no implicit process-exit cleanup. The CI wrapper owns the
//! externally unique run namespace and must call
//! [`PostgresTestHarness::cleanup_namespace`] after all cooperating processes
//! stop. Single-process callers may instead call [`PreparedTemplate::cleanup`].

mod clock;
mod database;

pub use clock::TestClock;
pub use database::{
    NamespaceCleanup, PostgresTestHarness, PreparedTemplate, TestDatabase, TestNamespace,
};

use std::error::Error;

/// Environment variable containing the isolated PostgreSQL server URL.
pub const DATABASE_URL_ENVIRONMENT: &str = "AUTOMATA_TEST_DATABASE_URL";

/// Optional job-scoped namespace shared by cooperating test processes.
pub const DATABASE_NAMESPACE_ENVIRONMENT: &str = "AUTOMATA_TEST_DATABASE_NAMESPACE";

/// Error type used by the test fixture API and initializer callbacks.
pub type TestError = Box<dyn Error + Send + Sync + 'static>;

/// Result type used by the test fixture API and initializer callbacks.
pub type TestResult<T = ()> = Result<T, TestError>;

fn message_error(message: impl Into<String>) -> TestError {
    std::io::Error::other(message.into()).into()
}
