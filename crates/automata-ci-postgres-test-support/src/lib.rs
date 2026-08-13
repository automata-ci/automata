//! Process-safe `PostgreSQL` fixtures for Automata's integration tests.
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
mod timing;

pub use clock::TestClock;
pub use database::{
    NamespaceCleanup, PostgresTestHarness, PreparedTemplate, TestDatabase, TestNamespace,
};

use std::error::Error;

/// Environment variable containing the isolated `PostgreSQL` server URL.
pub const DATABASE_URL_ENVIRONMENT: &str = "AUTOMATA_TEST_DATABASE_URL";

/// Optional job-scoped namespace shared by cooperating test processes.
pub const DATABASE_NAMESPACE_ENVIRONMENT: &str = "AUTOMATA_TEST_DATABASE_NAMESPACE";

/// Optional SHA-256 fingerprint of the prepared-template initializer.
///
/// When set, the value must be exactly 64 lowercase hexadecimal characters.
/// It is included in the template ownership marker, so a caller cannot
/// silently reuse a template prepared by a different initializer. CI and
/// benchmark wrappers should derive it from the complete workspace or the
/// exact migration/fixture inputs rather than from a human-written label.
pub const INITIALIZER_FINGERPRINT_ENVIRONMENT: &str = "AUTOMATA_TEST_TEMPLATE_FINGERPRINT";

/// Optional directory for per-process `PostgreSQL` fixture timing records.
///
/// Each process appends secret-free JSON Lines records to
/// `postgres-test-timings-<pid>.jsonl`. Timing I/O is best-effort and never
/// changes a fixture or test result. When this is set, wrappers must also set
/// [`TIMING_INVOCATION_ENVIRONMENT`] and [`TIMING_RUN_ENVIRONMENT`], validate
/// them through `postgres-test-environment.sh`, and create an isolated output
/// directory before starting test processes.
pub const TIMINGS_DIRECTORY_ENVIRONMENT: &str = "AUTOMATA_TEST_TIMINGS_DIR";

/// Constrained, secret-free invocation identity written to every timing record.
///
/// The value must contain 1-64 lowercase ASCII letters, digits, or underscores.
pub const TIMING_INVOCATION_ENVIRONMENT: &str = "AUTOMATA_TEST_TIMING_INVOCATION";

/// Decimal benchmark-run attribution written to every timing record.
///
/// Zero is reserved for invocation-level operations such as final namespace
/// cleanup. Positive values identify one exact requested benchmark run.
pub const TIMING_RUN_ENVIRONMENT: &str = "AUTOMATA_TEST_TIMING_RUN";

/// Error type used by the test fixture API and initializer callbacks.
pub type TestError = Box<dyn Error + Send + Sync + 'static>;

/// Result type used by the test fixture API and initializer callbacks.
pub type TestResult<T = ()> = Result<T, TestError>;

fn message_error(message: impl Into<String>) -> TestError {
    std::io::Error::other(message.into()).into()
}
