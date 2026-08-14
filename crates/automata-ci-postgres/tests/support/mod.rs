//! Shared isolated-database fixture for every `PostgreSQL` adapter domain.

use std::{error::Error, future::Future, sync::Arc};

use automata_ci_postgres_test_support::{
    PostgresTestHarness, PreparedTemplate, TestDatabase as IsolatedTestDatabase,
};
use automata_ci_store::PostgresStore;
use sqlx::PgPool;
use tokio::sync::OnceCell;

pub type TestError = Box<dyn Error + Send + Sync>;
pub type TestResult<T = ()> = Result<T, TestError>;

static PREPARED_TEMPLATE: OnceCell<PreparedTemplate> = OnceCell::const_new();

pub async fn run_with_database<Test, TestFuture>(test: Test) -> TestResult
where
    Test: FnOnce(Arc<TestDatabase>) -> TestFuture,
    TestFuture: Future<Output = TestResult> + Send + 'static,
{
    let database = Arc::new(TestDatabase::create().await?);
    let outcome = tokio::spawn(test(Arc::clone(&database))).await;
    let cleanup = database.cleanup().await;
    match outcome {
        Ok(result) => {
            result?;
            cleanup
        }
        Err(join_error) => {
            cleanup?;
            if join_error.is_panic() {
                std::panic::resume_unwind(join_error.into_panic());
            }
            Err(join_error.into())
        }
    }
}

#[derive(Debug)]
pub struct TestDatabase {
    database: IsolatedTestDatabase,
    store: PostgresStore,
}

impl TestDatabase {
    async fn create() -> TestResult<Self> {
        let harness = PostgresTestHarness::from_environment()?;
        let template = PREPARED_TEMPLATE
            .get_or_try_init(|| async {
                harness
                    .prepare_template(|pool| async move {
                        PostgresStore::from_postgres_pool(pool).migrate().await?;
                        Ok(())
                    })
                    .await
            })
            .await?;
        let database = template.create_database().await?;
        let store = PostgresStore::from_postgres_pool(database.pool().clone());
        Ok(Self { database, store })
    }

    pub const fn pool(&self) -> &PgPool {
        self.store.postgres_pool()
    }

    pub const fn store(&self) -> &PostgresStore {
        &self.store
    }

    async fn cleanup(&self) -> TestResult {
        self.store.postgres_pool().close().await;
        self.database.cleanup().await
    }
}
