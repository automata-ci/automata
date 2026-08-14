use std::{
    env, fmt,
    future::Future,
    str::FromStr as _,
    sync::{
        Arc, Mutex, OnceLock,
        atomic::{AtomicU8, Ordering},
    },
};

use sqlx::{
    AssertSqlSafe, Connection as _, PgConnection, PgPool,
    postgres::{PgConnectOptions, PgPoolOptions},
};
use uuid::Uuid;

use crate::{
    DATABASE_NAMESPACE_ENVIRONMENT, DATABASE_URL_ENVIRONMENT, INITIALIZER_FINGERPRINT_ENVIRONMENT,
    TestResult, message_error,
    timing::{TimingDetail, TimingOperation, TimingOutcome, TimingSpan},
};

const DATABASE_PREFIX: &str = "at_";
const TEMPLATE_SUFFIX: &str = "_template";
const MAX_NAMESPACE_LENGTH: usize = 27;
const DEFAULT_POOL_CONNECTIONS: u32 = 16;
const MINIMUM_POSTGRES_VERSION: i32 = 180_000;
const TEMPLATE_MARKER_VERSION: &str = "automata-ci-postgres-test-support:v1";
const TEMPLATE_LOCK_SALT: i64 = 6_482_851_405_936_141_723;
const INITIALIZER_FINGERPRINT_LENGTH_LIMIT: usize = 64;

const CLEANUP_LIVE: u8 = 0;
const CLEANUP_RUNNING: u8 = 1;
const CLEANUP_COMPLETE: u8 = 2;
const CLEANUP_FAILED: u8 = 3;

static PROCESS_NAMESPACE: OnceLock<TestNamespace> = OnceLock::new();

#[derive(Clone, Debug, Eq, PartialEq)]
struct InitializerFingerprint(String);

impl InitializerFingerprint {
    fn new(value: impl Into<String>) -> TestResult<Self> {
        let value = value.into();
        if value.len() != INITIALIZER_FINGERPRINT_LENGTH_LIMIT
            || !value
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
        {
            return Err(message_error(format!(
                "PostgreSQL template initializer fingerprint must be exactly {INITIALIZER_FINGERPRINT_LENGTH_LIMIT} lowercase hexadecimal characters"
            )));
        }
        Ok(Self(value))
    }

    fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum TemplatePreparation {
    Prepared,
    Reused,
}

/// Databases removed by one exact namespace-cleanup operation.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct NamespaceCleanup {
    /// Number of isolated clone or empty databases removed.
    pub dropped_test_databases: usize,
    /// Whether the prepared template was present and removed.
    pub dropped_template: bool,
}

/// A validated namespace that scopes a prepared template to one test job.
///
/// Values contain only lowercase ASCII letters, digits, and underscores, and
/// are capped so generated `PostgreSQL` identifiers remain within 63 bytes.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct TestNamespace(String);

impl TestNamespace {
    /// Validates an explicitly supplied job namespace.
    ///
    /// # Errors
    ///
    /// Returns an error if the value is empty, oversized, or contains a byte
    /// outside the canonical lowercase identifier subset.
    pub fn new(value: impl Into<String>) -> TestResult<Self> {
        let value = value.into();
        if value.is_empty() {
            return Err(message_error("PostgreSQL test namespace must not be empty"));
        }
        if value.len() > MAX_NAMESPACE_LENGTH {
            return Err(message_error(format!(
                "PostgreSQL test namespace {value:?} is {} bytes; maximum is {MAX_NAMESPACE_LENGTH}",
                value.len()
            )));
        }
        if !value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
        {
            return Err(message_error(format!(
                "PostgreSQL test namespace {value:?} must contain only lowercase ASCII letters, digits, and underscores"
            )));
        }
        Ok(Self(value))
    }

    /// Returns the validated namespace text.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    fn process_local() -> Self {
        PROCESS_NAMESPACE
            .get_or_init(|| {
                let random = Uuid::new_v4().simple().to_string();
                Self(format!("p{}_{random:.12}", std::process::id()))
            })
            .clone()
    }
}

impl fmt::Display for TestNamespace {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct DatabaseIdentifier(String);

impl DatabaseIdentifier {
    fn template(namespace: &TestNamespace) -> TestResult<Self> {
        Self::new(format!("{DATABASE_PREFIX}{namespace}{TEMPLATE_SUFFIX}"))
    }

    fn test(namespace: &TestNamespace) -> TestResult<Self> {
        Self::new(format!(
            "{DATABASE_PREFIX}{namespace}_{}",
            Uuid::new_v4().simple()
        ))
    }

    fn new(value: String) -> TestResult<Self> {
        if value.is_empty() || value.len() > 63 {
            return Err(message_error(format!(
                "generated PostgreSQL database identifier is not between 1 and 63 bytes: {value:?}"
            )));
        }
        let mut bytes = value.bytes();
        if !bytes.next().is_some_and(|byte| byte.is_ascii_lowercase())
            || !bytes.all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
        {
            return Err(message_error(format!(
                "generated PostgreSQL database identifier is not canonical: {value:?}"
            )));
        }
        Ok(Self(value))
    }

    fn as_str(&self) -> &str {
        &self.0
    }

    fn is_test_database(&self, namespace: &TestNamespace) -> bool {
        let prefix = format!("{DATABASE_PREFIX}{namespace}_");
        self.as_str().strip_prefix(&prefix).is_some_and(|suffix| {
            suffix.len() == 32 && suffix.bytes().all(|byte| byte.is_ascii_hexdigit())
        })
    }

    fn quoted(&self) -> String {
        // DatabaseIdentifier accepts a strict ASCII subset without quote
        // characters. Keeping the quotes makes case-folding behavior explicit.
        format!("\"{}\"", self.as_str())
    }
}

/// Configuration and administrative connection information for one test job.
///
/// This value contains connection options, never an open connection or pool.
#[derive(Clone)]
pub struct PostgresTestHarness {
    admin_options: PgConnectOptions,
    namespace: TestNamespace,
    initializer_fingerprint: Option<InitializerFingerprint>,
}

impl PostgresTestHarness {
    /// Parses [`DATABASE_URL_ENVIRONMENT`](crate::DATABASE_URL_ENVIRONMENT).
    ///
    /// If [`DATABASE_NAMESPACE_ENVIRONMENT`](crate::DATABASE_NAMESPACE_ENVIRONMENT)
    /// is unset, a stable process-local namespace is generated. Set an explicit
    /// job namespace when multiple test processes must share one template. CI
    /// and every reused `PostgreSQL` server must supply a namespace unique to the
    /// complete run; the fallback is only a single-process convenience.
    ///
    /// # Errors
    ///
    /// Returns an error if either environment value is invalid or unavailable.
    pub fn from_environment() -> TestResult<Self> {
        let namespace = match env::var(DATABASE_NAMESPACE_ENVIRONMENT) {
            Ok(value) => TestNamespace::new(value)?,
            Err(env::VarError::NotPresent) => TestNamespace::process_local(),
            Err(error) => {
                return Err(message_error(format!(
                    "could not read {DATABASE_NAMESPACE_ENVIRONMENT}: {error}"
                )));
            }
        };
        Self::from_environment_with_namespace(namespace)
    }

    /// Parses the environment for a destructive namespace-cleanup operation.
    ///
    /// Unlike [`Self::from_environment`], this constructor never generates a
    /// process-local fallback. Cleanup callers must explicitly identify the
    /// externally owned job namespace they intend to remove.
    ///
    /// # Errors
    ///
    /// Returns an error if either environment value is unavailable or invalid.
    pub fn from_environment_for_cleanup() -> TestResult<Self> {
        let namespace = env::var(DATABASE_NAMESPACE_ENVIRONMENT).map_err(|error| {
            message_error(format!(
                "set {DATABASE_NAMESPACE_ENVIRONMENT} explicitly before PostgreSQL test namespace cleanup: {error}"
            ))
        })?;
        Self::from_environment_with_namespace(TestNamespace::new(namespace)?)
    }

    /// Parses the database URL while using an explicit job namespace.
    ///
    /// # Errors
    ///
    /// Returns an error if the database URL environment value is unavailable
    /// or invalid.
    pub fn from_environment_with_namespace(
        namespace: impl Into<TestNamespace>,
    ) -> TestResult<Self> {
        let database_url = env::var(DATABASE_URL_ENVIRONMENT).map_err(|error| {
            message_error(format!(
                "set {DATABASE_URL_ENVIRONMENT} to an isolated PostgreSQL 18 test server URL: {error}"
            ))
        })?;
        let harness = Self::new(&database_url, namespace)?;
        match env::var(INITIALIZER_FINGERPRINT_ENVIRONMENT) {
            Ok(fingerprint) => harness.with_initializer_fingerprint(fingerprint),
            Err(env::VarError::NotPresent) => Ok(harness),
            Err(error) => Err(message_error(format!(
                "could not read {INITIALIZER_FINGERPRINT_ENVIRONMENT}: {error}"
            ))),
        }
    }

    /// Parses an explicit database URL and uses a validated job namespace.
    ///
    /// # Errors
    ///
    /// Returns an error if `database_url` is not a valid `PostgreSQL` URL.
    pub fn new(database_url: &str, namespace: impl Into<TestNamespace>) -> TestResult<Self> {
        let admin_options = PgConnectOptions::from_str(database_url).map_err(|error| {
            message_error(format!(
                "invalid PostgreSQL URL supplied through {DATABASE_URL_ENVIRONMENT}: {error}"
            ))
        })?;
        Ok(Self {
            admin_options,
            namespace: namespace.into(),
            initializer_fingerprint: None,
        })
    }

    /// Adds an exact SHA-256 identity for the template initializer.
    ///
    /// The fingerprint becomes part of the template ownership marker. Reusing
    /// the same namespace with a different fingerprint therefore fails closed
    /// instead of silently cloning stale or incompatible fixture contents.
    /// Prefer a digest of every migration and fixture input; a human-maintained
    /// version label does not provide the same protection.
    ///
    /// # Errors
    ///
    /// Returns an error unless `fingerprint` is exactly 64 lowercase
    /// hexadecimal characters.
    pub fn with_initializer_fingerprint(
        mut self,
        fingerprint: impl Into<String>,
    ) -> TestResult<Self> {
        self.initializer_fingerprint = Some(InitializerFingerprint::new(fingerprint)?);
        Ok(self)
    }

    /// Returns the job namespace used for template and database names.
    pub const fn namespace(&self) -> &TestNamespace {
        &self.namespace
    }

    /// Creates or reuses the fully initialized, disconnected job template.
    ///
    /// The initializer executes at most once for a namespace across cooperating
    /// processes. Its pool searches `automata_test, pg_catalog`. Callers must
    /// supply a namespace unique to the complete CI run. Set
    /// [`INITIALIZER_FINGERPRINT_ENVIRONMENT`](crate::INITIALIZER_FINGERPRINT_ENVIRONMENT)
    /// or call [`Self::with_initializer_fingerprint`] so incompatible
    /// initializers fail closed. Without a fingerprint, callers must change the
    /// namespace whenever initializer contents or migrations change.
    ///
    /// # Errors
    ///
    /// Returns an error when `PostgreSQL` 18 cannot be reached, the namespace is
    /// owned by a different fixture, initialization fails, or exact recovery
    /// and advisory-lock release cannot be completed.
    pub async fn prepare_template<Initializer, InitializerFuture>(
        &self,
        initializer: Initializer,
    ) -> TestResult<PreparedTemplate>
    where
        Initializer: FnOnce(PgPool) -> InitializerFuture,
        InitializerFuture: Future<Output = TestResult>,
    {
        let timing = TimingSpan::start(
            TimingOperation::TemplatePrepare,
            TimingDetail::PreparedTemplate,
        );
        let preparation = async {
            let template_name = DatabaseIdentifier::template(&self.namespace)?;
            let mut admin = self.admin_connection().await?;
            require_postgres_18(&mut admin).await?;
            acquire_template_lock(&mut admin, &template_name).await?;

            let preparation = self
                .prepare_template_while_locked(&mut admin, &template_name, initializer)
                .await;
            let unlock = release_template_lock(&mut admin, &template_name).await;
            let disposition = combine_operation_and_unlock(preparation, unlock)?;

            Ok((
                PreparedTemplate {
                    harness: self.clone(),
                    database_name: template_name,
                },
                disposition,
            ))
        }
        .await;
        match &preparation {
            Ok((_template, TemplatePreparation::Prepared)) => {
                timing.finish(TimingOutcome::Success);
            }
            Ok((_template, TemplatePreparation::Reused)) => {
                timing.finish_as(TimingOperation::TemplateReuse, TimingOutcome::Success);
            }
            Err(_) => timing.finish(TimingOutcome::Error),
        }
        preparation.map(|(template, _disposition)| template)
    }

    /// Creates an application-empty test database from `PostgreSQL` `template0`.
    ///
    /// Only the `automata_test` schema is bootstrapped, so migration tests start
    /// without any current application objects or migration ledger.
    ///
    /// # Errors
    ///
    /// Returns an error when `PostgreSQL` 18 cannot create, bootstrap, connect to,
    /// or clean up the isolated database.
    pub async fn create_empty_database(&self) -> TestResult<TestDatabase> {
        let timing = TimingSpan::start(TimingOperation::Clone, TimingDetail::EmptyTemplateZero);
        let database = self.create_empty_database_inner().await;
        timing.finish(if database.is_ok() {
            TimingOutcome::Success
        } else {
            TimingOutcome::Error
        });
        database
    }

    async fn create_empty_database_inner(&self) -> TestResult<TestDatabase> {
        let mut admin = self.admin_connection().await?;
        require_postgres_18(&mut admin).await?;
        let database_name = DatabaseIdentifier::test(&self.namespace)?;
        create_database_from_template(
            &mut admin,
            &database_name,
            &DatabaseIdentifier::new("template0".to_owned())?,
        )
        .await?;
        let database_marker = self.database_marker();
        if let Err(error) = set_database_comment(&mut admin, &database_name, &database_marker).await
        {
            cleanup_failed_database_creation(&mut admin, &database_name, error).await?;
            unreachable!("failed empty-database marker cleanup always returns an error");
        }

        let pool = match connect_database_pool(
            &self.admin_options,
            &database_name,
            DEFAULT_POOL_CONNECTIONS,
        )
        .await
        {
            Ok(pool) => pool,
            Err(error) => {
                cleanup_failed_database_creation(&mut admin, &database_name, error).await?;
                unreachable!("failed database connection cleanup always returns an error");
            }
        };
        if let Err(error) = sqlx::query("CREATE SCHEMA automata_test")
            .execute(&pool)
            .await
        {
            pool.close().await;
            cleanup_failed_database_creation(&mut admin, &database_name, error.into()).await?;
            unreachable!("failed database bootstrap cleanup always returns an error");
        }
        Ok(TestDatabase::new(
            self.admin_options.clone(),
            database_name,
            database_marker,
            pool,
        ))
    }

    /// Runs a migration-style test and always drops its empty database.
    ///
    /// # Errors
    ///
    /// Returns the database creation, test, task-join, or cleanup error. When
    /// both the test and cleanup fail, the returned error reports both.
    pub async fn run_with_empty_database<Test, TestFuture>(&self, test: Test) -> TestResult
    where
        Test: FnOnce(Arc<TestDatabase>) -> TestFuture,
        TestFuture: Future<Output = TestResult> + Send + 'static,
    {
        run_test_database(self.create_empty_database().await?, test).await
    }

    /// Removes every owned database in this exact job namespace.
    ///
    /// The cleanup first validates the complete candidate set. It refuses to
    /// delete anything if a database shares the reserved canonical prefix but
    /// has a noncanonical name or an unexpected ownership comment. Call this
    /// only after every process using the namespace has stopped.
    ///
    /// # Errors
    ///
    /// Returns an error for an ownership mismatch, a malformed reserved name,
    /// an administrative `PostgreSQL` failure, or an advisory-lock release error.
    pub async fn cleanup_namespace(&self) -> TestResult<NamespaceCleanup> {
        let timing = TimingSpan::start(
            TimingOperation::NamespaceCleanup,
            TimingDetail::CompleteNamespace,
        );
        let cleanup = async {
            let template_name = DatabaseIdentifier::template(&self.namespace)?;
            let mut admin = self.admin_connection().await?;
            require_postgres_18(&mut admin).await?;
            acquire_template_lock(&mut admin, &template_name).await?;
            let cleanup = self.cleanup_namespace_while_locked(&mut admin).await;
            let unlock = release_template_lock(&mut admin, &template_name).await;
            combine_operation_and_unlock(cleanup, unlock)
        }
        .await;
        timing.finish(if cleanup.is_ok() {
            TimingOutcome::Success
        } else {
            TimingOutcome::Error
        });
        cleanup
    }

    async fn prepare_template_while_locked<Initializer, InitializerFuture>(
        &self,
        admin: &mut PgConnection,
        template_name: &DatabaseIdentifier,
        initializer: Initializer,
    ) -> TestResult<TemplatePreparation>
    where
        Initializer: FnOnce(PgPool) -> InitializerFuture,
        InitializerFuture: Future<Output = TestResult>,
    {
        let marker = self.template_marker();
        if let Some((allows_connections, existing_marker)) =
            database_state(admin, template_name).await?
        {
            if let Some(existing_marker) = existing_marker.as_deref()
                && existing_marker != marker.as_str()
            {
                return Err(message_error(format!(
                    "refusing to reuse or replace PostgreSQL database {} because its ownership marker is {existing_marker:?}, expected {marker:?}",
                    template_name.as_str(),
                )));
            }
            if existing_marker.is_none() {
                // CREATE DATABASE and COMMENT cannot be atomic. Under this
                // exact namespace lock, an unmarked canonical template is only
                // the interrupted first half of this fixture's preparation.
                drop_database(admin, template_name).await?;
            } else if !allows_connections {
                disconnect_database(admin, template_name).await?;
                return Ok(TemplatePreparation::Reused);
            } else {
                // A marked database that still permits connections is an
                // incomplete preparation left by an interrupted owner.
                drop_database(admin, template_name).await?;
            }
        }

        create_database_from_template(
            admin,
            template_name,
            &DatabaseIdentifier::new("template0".to_owned())?,
        )
        .await?;
        if let Err(error) = set_database_comment(admin, template_name, &marker).await {
            cleanup_failed_database_creation(admin, template_name, error).await?;
            unreachable!("failed template marker cleanup always returns an error");
        }

        let pool = match connect_database_pool(
            &self.admin_options,
            template_name,
            DEFAULT_POOL_CONNECTIONS,
        )
        .await
        {
            Ok(pool) => pool,
            Err(error) => {
                cleanup_failed_database_creation(admin, template_name, error).await?;
                unreachable!("failed template connection cleanup always returns an error");
            }
        };

        let initialization = async {
            sqlx::query("CREATE SCHEMA automata_test")
                .execute(&pool)
                .await?;
            initializer(pool.clone()).await
        }
        .await;
        pool.close().await;
        if let Err(error) = initialization {
            cleanup_failed_database_creation(admin, template_name, error).await?;
            unreachable!("failed template initialization cleanup always returns an error");
        }

        if let Err(error) = async {
            set_database_allows_connections(admin, template_name, false).await?;
            disconnect_database(admin, template_name).await
        }
        .await
        {
            cleanup_failed_database_creation(admin, template_name, error).await?;
            unreachable!("failed template finalization cleanup always returns an error");
        }
        Ok(TemplatePreparation::Prepared)
    }

    async fn admin_connection(&self) -> TestResult<PgConnection> {
        Ok(PgConnection::connect_with(&self.admin_options).await?)
    }

    fn template_marker(&self) -> String {
        match &self.initializer_fingerprint {
            Some(fingerprint) => format!(
                "{TEMPLATE_MARKER_VERSION}:template:{}:initializer_sha256:{}",
                self.namespace,
                fingerprint.as_str()
            ),
            None => format!("{TEMPLATE_MARKER_VERSION}:template:{}", self.namespace),
        }
    }

    fn database_marker(&self) -> String {
        format!("{TEMPLATE_MARKER_VERSION}:database:{}", self.namespace)
    }

    async fn cleanup_namespace_while_locked(
        &self,
        admin: &mut PgConnection,
    ) -> TestResult<NamespaceCleanup> {
        let prefix = format!("{DATABASE_PREFIX}{}_", self.namespace);
        let candidates: Vec<(String, Option<String>)> = sqlx::query_as(
            r"
            SELECT
                datname,
                pg_catalog.shobj_description(oid, 'pg_database')
            FROM pg_catalog.pg_database
            WHERE pg_catalog.left(datname, pg_catalog.length($1::TEXT)) = $1
            ORDER BY datname
            ",
        )
        .bind(&prefix)
        .fetch_all(&mut *admin)
        .await?;

        let template_name = DatabaseIdentifier::template(&self.namespace)?;
        let template_marker = self.template_marker();
        let database_marker = self.database_marker();
        let mut validated = Vec::with_capacity(candidates.len());
        for (name, marker) in candidates {
            let identifier = DatabaseIdentifier::new(name.clone())?;
            let is_template = identifier == template_name;
            if !is_template && !identifier.is_test_database(&self.namespace) {
                return Err(message_error(format!(
                    "refusing namespace cleanup because PostgreSQL database {name:?} uses reserved prefix {prefix:?} but is not a canonical fixture name"
                )));
            }
            let expected_marker = if is_template {
                &template_marker
            } else {
                &database_marker
            };
            if marker
                .as_deref()
                .is_some_and(|marker| marker != expected_marker)
            {
                return Err(message_error(format!(
                    "refusing namespace cleanup because PostgreSQL database {name:?} has ownership marker {marker:?}, expected {expected_marker:?}"
                )));
            }
            validated.push((identifier, is_template));
        }

        // Drop clones first and their source template last.
        validated.sort_by_key(|(_identifier, is_template)| *is_template);
        let mut cleanup = NamespaceCleanup::default();
        for (identifier, is_template) in validated {
            drop_database(admin, &identifier).await?;
            if is_template {
                cleanup.dropped_template = true;
            } else {
                cleanup.dropped_test_databases += 1;
            }
        }
        Ok(cleanup)
    }
}

impl fmt::Debug for PostgresTestHarness {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PostgresTestHarness")
            .field("namespace", &self.namespace)
            .finish_non_exhaustive()
    }
}

impl TryFrom<&str> for TestNamespace {
    type Error = crate::TestError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

/// A disconnected, fully initialized job template.
///
/// The value contains no connection pool and can safely cross Tokio runtimes.
/// It has no implicit drop hook: the wrapper that owns the namespace must call
/// [`Self::cleanup`] or [`PostgresTestHarness::cleanup_namespace`] explicitly.
#[derive(Clone, Debug)]
pub struct PreparedTemplate {
    harness: PostgresTestHarness,
    database_name: DatabaseIdentifier,
}

impl PreparedTemplate {
    /// Returns the `PostgreSQL` template database identifier.
    pub fn database_name(&self) -> &str {
        self.database_name.as_str()
    }

    /// Clones the prepared template into an isolated per-test database.
    ///
    /// # Errors
    ///
    /// Returns an error when `PostgreSQL` 18 cannot clone, connect to, or recover
    /// from a failed connection to the database.
    pub async fn create_database(&self) -> TestResult<TestDatabase> {
        let timing = TimingSpan::start(TimingOperation::Clone, TimingDetail::PreparedTemplate);
        let database = self.create_database_inner().await;
        timing.finish(if database.is_ok() {
            TimingOutcome::Success
        } else {
            TimingOutcome::Error
        });
        database
    }

    async fn create_database_inner(&self) -> TestResult<TestDatabase> {
        let database_name = DatabaseIdentifier::test(self.harness.namespace())?;
        let mut admin = self.harness.admin_connection().await?;
        // PreparedTemplate is only constructed after prepare_template has
        // validated PostgreSQL 18 and CREATEDB authority. Avoid repeating both
        // catalog queries for every isolated clone on this prepared server.
        // PostgreSQL 18's default WAL_LOG strategy permits fast concurrent
        // template clones without requesting the blocking FILE_COPY strategy.
        create_database_from_template(&mut admin, &database_name, &self.database_name).await?;
        let database_marker = self.harness.database_marker();
        if let Err(error) = set_database_comment(&mut admin, &database_name, &database_marker).await
        {
            cleanup_failed_database_creation(&mut admin, &database_name, error).await?;
            unreachable!("failed clone marker cleanup always returns an error");
        }
        let pool = match connect_database_pool(
            &self.harness.admin_options,
            &database_name,
            DEFAULT_POOL_CONNECTIONS,
        )
        .await
        {
            Ok(pool) => pool,
            Err(error) => {
                cleanup_failed_database_creation(&mut admin, &database_name, error).await?;
                unreachable!("failed clone connection cleanup always returns an error");
            }
        };
        Ok(TestDatabase::new(
            self.harness.admin_options.clone(),
            database_name,
            database_marker,
            pool,
        ))
    }

    /// Runs a current-schema test and always drops its cloned database.
    ///
    /// # Errors
    ///
    /// Returns the clone, test, task-join, or cleanup error. When both the test
    /// and cleanup fail, the returned error reports both.
    pub async fn run<Test, TestFuture>(&self, test: Test) -> TestResult
    where
        Test: FnOnce(Arc<TestDatabase>) -> TestFuture,
        TestFuture: Future<Output = TestResult> + Send + 'static,
    {
        run_test_database(self.create_database().await?, test).await
    }

    /// Drops the job template after all cooperating processes have stopped.
    ///
    /// # Errors
    ///
    /// Returns an error when the template is absent, its ownership marker does
    /// not match, `PostgreSQL` cannot drop it, or the advisory lock cannot release.
    pub async fn cleanup(self) -> TestResult {
        let timing = TimingSpan::start(TimingOperation::Cleanup, TimingDetail::ExactTemplate);
        let cleanup = async {
            let mut admin = self.harness.admin_connection().await?;
            require_postgres_18(&mut admin).await?;
            acquire_template_lock(&mut admin, &self.database_name).await?;
            let cleanup = async {
                let state = database_state(&mut admin, &self.database_name).await?;
                let Some((_allows_connections, marker)) = state else {
                    return Err(message_error(format!(
                        "PostgreSQL template {} was already absent during exact cleanup",
                        self.database_name.as_str()
                    )));
                };
                let expected_marker = self.harness.template_marker();
                if marker.as_deref() != Some(expected_marker.as_str()) {
                    return Err(message_error(format!(
                        "refusing to drop PostgreSQL template {} because its ownership marker is {:?}, expected {expected_marker:?}",
                        self.database_name.as_str(),
                        marker
                    )));
                }
                drop_database(&mut admin, &self.database_name).await
            }
            .await;
            let unlock = release_template_lock(&mut admin, &self.database_name).await;
            combine_operation_and_unlock(cleanup, unlock)
        }
        .await;
        timing.finish(if cleanup.is_ok() {
            TimingOutcome::Success
        } else {
            TimingOutcome::Error
        });
        cleanup
    }
}

/// One isolated `PostgreSQL` database and its primary connection pool.
pub struct TestDatabase {
    admin_options: PgConnectOptions,
    database_name: DatabaseIdentifier,
    expected_marker: String,
    pool: PgPool,
    test_body_timing: Mutex<Option<TimingSpan>>,
    cleanup_state: AtomicU8,
}

impl TestDatabase {
    fn new(
        admin_options: PgConnectOptions,
        database_name: DatabaseIdentifier,
        expected_marker: String,
        pool: PgPool,
    ) -> Self {
        Self {
            admin_options,
            database_name,
            expected_marker,
            pool,
            test_body_timing: Mutex::new(Some(TimingSpan::start(
                TimingOperation::TestBody,
                TimingDetail::TestDatabase,
            ))),
            cleanup_state: AtomicU8::new(CLEANUP_LIVE),
        }
    }

    /// Returns the database's primary pool.
    pub const fn pool(&self) -> &PgPool {
        &self.pool
    }

    /// Returns the exact generated `PostgreSQL` database identifier.
    pub fn database_name(&self) -> &str {
        self.database_name.as_str()
    }

    /// Creates a replacement pool with the canonical fixed search path.
    ///
    /// # Errors
    ///
    /// Returns an error if `max_connections` is zero or `PostgreSQL` cannot open
    /// the pool.
    pub async fn connect_pool(&self, max_connections: u32) -> TestResult<PgPool> {
        connect_database_pool(&self.admin_options, &self.database_name, max_connections).await
    }

    /// Closes the primary pool and drops exactly this database with `FORCE`.
    ///
    /// # Errors
    ///
    /// Returns an error for repeated or concurrent cleanup, an administrative
    /// connection failure, or an inexact database drop.
    pub async fn cleanup(&self) -> TestResult {
        let timing = TimingSpan::start(TimingOperation::Cleanup, TimingDetail::TestDatabase);
        let cleanup = self.cleanup_inner().await;
        timing.finish(if cleanup.is_ok() {
            TimingOutcome::Success
        } else {
            TimingOutcome::Error
        });
        cleanup
    }

    async fn cleanup_inner(&self) -> TestResult {
        self.cleanup_state
            .compare_exchange(
                CLEANUP_LIVE,
                CLEANUP_RUNNING,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .map_err(|state| {
                message_error(format!(
                    "PostgreSQL test database {} cleanup was requested in state {}",
                    self.database_name.as_str(),
                    cleanup_state_name(state)
                ))
            })?;

        // Direct fixture consumers own the test future, so cleanup cannot know
        // whether assertions succeeded. Record the checked-out database
        // lifetime neutrally; run_test_database replaces this with an exact
        // success, error, panic, or cancellation outcome when it owns the task.
        self.finish_test_body_timing(TimingOutcome::Completed);

        self.pool.close().await;
        let cleanup = async {
            let mut admin = PgConnection::connect_with(&self.admin_options).await?;
            drop_owned_database(&mut admin, &self.database_name, &self.expected_marker).await
        }
        .await;
        match cleanup {
            Ok(()) => {
                self.cleanup_state
                    .store(CLEANUP_COMPLETE, Ordering::Release);
                Ok(())
            }
            Err(error) => {
                self.cleanup_state.store(CLEANUP_FAILED, Ordering::Release);
                eprintln!(
                    "FAILED to clean PostgreSQL test database {}: {error}",
                    self.database_name.as_str()
                );
                Err(error)
            }
        }
    }

    fn finish_test_body_timing(&self, outcome: TimingOutcome) {
        let Ok(mut timing) = self.test_body_timing.lock() else {
            return;
        };
        if let Some(timing) = timing.take() {
            timing.finish(outcome);
        }
    }
}

impl fmt::Debug for TestDatabase {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TestDatabase")
            .field("database_name", &self.database_name)
            .field(
                "cleanup_state",
                &cleanup_state_name(self.cleanup_state.load(Ordering::Acquire)),
            )
            .finish_non_exhaustive()
    }
}

impl Drop for TestDatabase {
    fn drop(&mut self) {
        match self.cleanup_state.load(Ordering::Acquire) {
            CLEANUP_COMPLETE => {}
            CLEANUP_FAILED => eprintln!(
                "LEAKED PostgreSQL test database {} after cleanup failed",
                self.database_name.as_str()
            ),
            state => {
                let message = format!(
                    "LEAKED PostgreSQL test database {} without completed cleanup (state {})",
                    self.database_name.as_str(),
                    cleanup_state_name(state)
                );
                if std::thread::panicking() {
                    eprintln!("{message}");
                } else {
                    panic!("{message}");
                }
            }
        }
    }
}

async fn run_test_database<Test, TestFuture>(database: TestDatabase, test: Test) -> TestResult
where
    Test: FnOnce(Arc<TestDatabase>) -> TestFuture,
    TestFuture: Future<Output = TestResult> + Send + 'static,
{
    let database = Arc::new(database);
    let outcome = tokio::spawn(test(Arc::clone(&database))).await;
    database.finish_test_body_timing(match &outcome {
        Ok(Ok(())) => TimingOutcome::Success,
        Ok(Err(_)) => TimingOutcome::Error,
        Err(join_error) if join_error.is_panic() => TimingOutcome::Panic,
        Err(_) => TimingOutcome::Cancelled,
    });
    let cleanup = database.cleanup().await;

    match outcome {
        Ok(test_result) => match (test_result, cleanup) {
            (Ok(()), Ok(())) => Ok(()),
            (Err(test_error), Ok(())) => Err(test_error),
            (Ok(()), Err(cleanup_error)) => Err(cleanup_error),
            (Err(test_error), Err(cleanup_error)) => Err(message_error(format!(
                "PostgreSQL test failed: {test_error}; database cleanup also failed: {cleanup_error}"
            ))),
        },
        Err(join_error) => {
            if let Err(cleanup_error) = cleanup {
                eprintln!(
                    "PostgreSQL test task failed and database cleanup also failed: {cleanup_error}"
                );
            }
            if join_error.is_panic() {
                std::panic::resume_unwind(join_error.into_panic());
            }
            Err(join_error.into())
        }
    }
}

async fn connect_database_pool(
    admin_options: &PgConnectOptions,
    database_name: &DatabaseIdentifier,
    max_connections: u32,
) -> TestResult<PgPool> {
    if max_connections == 0 {
        return Err(message_error(
            "PostgreSQL test pool must allow at least one connection",
        ));
    }
    let options = admin_options.clone().database(database_name.as_str());
    Ok(PgPoolOptions::new()
        .max_connections(max_connections)
        .after_connect(|connection, _metadata| {
            Box::pin(async move {
                sqlx::query("SELECT pg_catalog.set_config('search_path', $1, false)")
                    .bind("automata_test, pg_catalog")
                    .execute(connection)
                    .await?;
                Ok(())
            })
        })
        .connect_with(options)
        .await?)
}

async fn require_postgres_18(admin: &mut PgConnection) -> TestResult {
    let version: i32 =
        sqlx::query_scalar("SELECT pg_catalog.current_setting('server_version_num')::INTEGER")
            .fetch_one(&mut *admin)
            .await?;
    if version < MINIMUM_POSTGRES_VERSION {
        return Err(message_error(format!(
            "PostgreSQL test database cloning requires PostgreSQL 18 or newer; server_version_num is {version}"
        )));
    }
    let can_create_database: bool = sqlx::query_scalar(
        r"
        SELECT COALESCE(
            (
                SELECT rolcreatedb OR rolsuper
                FROM pg_catalog.pg_roles
                WHERE rolname = CURRENT_USER
            ),
            FALSE
        )
        ",
    )
    .fetch_one(&mut *admin)
    .await?;
    if !can_create_database {
        return Err(message_error(
            "PostgreSQL test role must have CREATEDB or SUPERUSER to clone and clean isolated databases",
        ));
    }
    Ok(())
}

async fn acquire_template_lock(
    admin: &mut PgConnection,
    template_name: &DatabaseIdentifier,
) -> TestResult {
    sqlx::query("SELECT pg_catalog.pg_advisory_lock(pg_catalog.hashtextextended($1, $2))")
        .bind(template_name.as_str())
        .bind(TEMPLATE_LOCK_SALT)
        .execute(&mut *admin)
        .await?;
    Ok(())
}

async fn release_template_lock(
    admin: &mut PgConnection,
    template_name: &DatabaseIdentifier,
) -> TestResult {
    let unlocked: bool = sqlx::query_scalar(
        "SELECT pg_catalog.pg_advisory_unlock(pg_catalog.hashtextextended($1, $2))",
    )
    .bind(template_name.as_str())
    .bind(TEMPLATE_LOCK_SALT)
    .fetch_one(&mut *admin)
    .await?;
    if !unlocked {
        return Err(message_error(format!(
            "PostgreSQL template advisory lock for {} was not held during release",
            template_name.as_str()
        )));
    }
    Ok(())
}

fn combine_operation_and_unlock<T>(operation: TestResult<T>, unlock: TestResult) -> TestResult<T> {
    match (operation, unlock) {
        (Ok(value), Ok(())) => Ok(value),
        (Err(error), Ok(())) | (Ok(_), Err(error)) => Err(error),
        (Err(operation_error), Err(unlock_error)) => Err(message_error(format!(
            "PostgreSQL template operation failed: {operation_error}; advisory-lock release also failed: {unlock_error}"
        ))),
    }
}

async fn database_state(
    admin: &mut PgConnection,
    database_name: &DatabaseIdentifier,
) -> TestResult<Option<(bool, Option<String>)>> {
    Ok(sqlx::query_as(
        r"
        SELECT
            datallowconn,
            pg_catalog.shobj_description(oid, 'pg_database')
        FROM pg_catalog.pg_database
        WHERE datname = $1
        ",
    )
    .bind(database_name.as_str())
    .fetch_optional(&mut *admin)
    .await?)
}

async fn create_database_from_template(
    admin: &mut PgConnection,
    database_name: &DatabaseIdentifier,
    template_name: &DatabaseIdentifier,
) -> TestResult {
    sqlx::query(AssertSqlSafe(format!(
        "CREATE DATABASE {} TEMPLATE {}",
        database_name.quoted(),
        template_name.quoted()
    )))
    .execute(&mut *admin)
    .await?;
    Ok(())
}

async fn set_database_comment(
    admin: &mut PgConnection,
    database_name: &DatabaseIdentifier,
    comment: &str,
) -> TestResult {
    let quoted_comment = format!("'{}'", comment.replace('\'', "''"));
    sqlx::query(AssertSqlSafe(format!(
        "COMMENT ON DATABASE {} IS {quoted_comment}",
        database_name.quoted()
    )))
    .execute(&mut *admin)
    .await?;
    Ok(())
}

async fn set_database_allows_connections(
    admin: &mut PgConnection,
    database_name: &DatabaseIdentifier,
    allows_connections: bool,
) -> TestResult {
    sqlx::query(AssertSqlSafe(format!(
        "ALTER DATABASE {} ALLOW_CONNECTIONS {}",
        database_name.quoted(),
        if allows_connections { "TRUE" } else { "FALSE" }
    )))
    .execute(&mut *admin)
    .await?;
    Ok(())
}

async fn disconnect_database(
    admin: &mut PgConnection,
    database_name: &DatabaseIdentifier,
) -> TestResult {
    let disconnected: Vec<bool> = sqlx::query_scalar(
        r"
        SELECT pg_catalog.pg_terminate_backend(pid)
        FROM pg_catalog.pg_stat_activity
        WHERE datname = $1
          AND pid <> pg_catalog.pg_backend_pid()
        ",
    )
    .bind(database_name.as_str())
    .fetch_all(&mut *admin)
    .await?;
    if disconnected.iter().any(|terminated| !terminated) {
        return Err(message_error(format!(
            "PostgreSQL refused to disconnect every session from template {}",
            database_name.as_str()
        )));
    }
    Ok(())
}

async fn drop_owned_database(
    admin: &mut PgConnection,
    database_name: &DatabaseIdentifier,
    expected_marker: &str,
) -> TestResult {
    let Some((_allows_connections, marker)) = database_state(admin, database_name).await? else {
        return Err(message_error(format!(
            "PostgreSQL test database {} was already absent during exact cleanup",
            database_name.as_str()
        )));
    };
    if marker.as_deref() != Some(expected_marker) {
        return Err(message_error(format!(
            "refusing to drop PostgreSQL test database {} because its ownership marker is {:?}, expected {expected_marker:?}",
            database_name.as_str(),
            marker
        )));
    }
    drop_database(admin, database_name).await
}

async fn drop_database(admin: &mut PgConnection, database_name: &DatabaseIdentifier) -> TestResult {
    sqlx::query(AssertSqlSafe(format!(
        "DROP DATABASE {} WITH (FORCE)",
        database_name.quoted()
    )))
    .execute(&mut *admin)
    .await?;
    let still_exists: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM pg_catalog.pg_database WHERE datname = $1)",
    )
    .bind(database_name.as_str())
    .fetch_one(&mut *admin)
    .await?;
    if still_exists {
        return Err(message_error(format!(
            "PostgreSQL reported success but database {} still exists",
            database_name.as_str()
        )));
    }
    Ok(())
}

async fn cleanup_failed_database_creation(
    admin: &mut PgConnection,
    database_name: &DatabaseIdentifier,
    primary_error: crate::TestError,
) -> TestResult {
    match drop_database(admin, database_name).await {
        Ok(()) => Err(primary_error),
        Err(cleanup_error) => Err(message_error(format!(
            "PostgreSQL database {} setup failed: {primary_error}; exact cleanup also failed: {cleanup_error}",
            database_name.as_str()
        ))),
    }
}

const fn cleanup_state_name(state: u8) -> &'static str {
    match state {
        CLEANUP_LIVE => "live",
        CLEANUP_RUNNING => "cleanup-running",
        CLEANUP_COMPLETE => "cleanup-complete",
        CLEANUP_FAILED => "cleanup-failed",
        _ => "invalid",
    }
}

#[cfg(test)]
mod tests {
    use super::{
        DatabaseIdentifier, INITIALIZER_FINGERPRINT_LENGTH_LIMIT, InitializerFingerprint,
        MAX_NAMESPACE_LENGTH, TEMPLATE_MARKER_VERSION, TestNamespace,
    };

    #[test]
    fn namespace_validation_accepts_canonical_job_scope() {
        let namespace = TestNamespace::new("run42_store_1").expect("valid namespace");
        assert_eq!(namespace.as_str(), "run42_store_1");
        assert!(DatabaseIdentifier::template(&namespace).is_ok());
        assert!(DatabaseIdentifier::test(&namespace).is_ok());
    }

    #[test]
    fn namespace_validation_rejects_ambiguous_or_oversized_values() {
        for invalid in ["", "Uppercase", "contains-hyphen", "has space"] {
            assert!(
                TestNamespace::new(invalid).is_err(),
                "namespace {invalid:?} must be rejected"
            );
        }
        assert!(TestNamespace::new("x".repeat(MAX_NAMESPACE_LENGTH + 1)).is_err());
    }

    #[test]
    fn maximum_namespace_still_produces_exact_postgres_identifiers() {
        let namespace =
            TestNamespace::new("n".repeat(MAX_NAMESPACE_LENGTH)).expect("maximum namespace");
        let template = DatabaseIdentifier::template(&namespace).expect("template name");
        let database = DatabaseIdentifier::test(&namespace).expect("database name");
        assert!(template.as_str().len() <= 63);
        assert_eq!(database.as_str().len(), 63);
    }

    #[test]
    fn initializer_fingerprint_accepts_exact_lowercase_sha256() {
        let fingerprint = "9".repeat(INITIALIZER_FINGERPRINT_LENGTH_LIMIT);
        assert_eq!(
            InitializerFingerprint::new(&fingerprint)
                .expect("canonical SHA-256 fingerprint")
                .as_str(),
            fingerprint
        );
    }

    #[test]
    fn initializer_fingerprint_rejects_ambiguous_values() {
        for invalid in [
            "a".repeat(INITIALIZER_FINGERPRINT_LENGTH_LIMIT - 1),
            "a".repeat(INITIALIZER_FINGERPRINT_LENGTH_LIMIT + 1),
            "A".repeat(INITIALIZER_FINGERPRINT_LENGTH_LIMIT),
            "g".repeat(INITIALIZER_FINGERPRINT_LENGTH_LIMIT),
        ] {
            assert!(InitializerFingerprint::new(invalid).is_err());
        }
    }

    #[test]
    fn initializer_fingerprint_is_part_of_template_ownership_marker() {
        let namespace = TestNamespace::new("fingerprint_contract").expect("valid namespace");
        let fingerprint = "b".repeat(INITIALIZER_FINGERPRINT_LENGTH_LIMIT);
        let harness = super::PostgresTestHarness::new(
            "postgres://postgres@localhost/postgres",
            namespace.clone(),
        )
        .expect("syntactically valid PostgreSQL URL")
        .with_initializer_fingerprint(fingerprint.clone())
        .expect("canonical fingerprint");
        assert_eq!(
            harness.template_marker(),
            format!(
                "{TEMPLATE_MARKER_VERSION}:template:{namespace}:initializer_sha256:{fingerprint}"
            )
        );
    }
}
