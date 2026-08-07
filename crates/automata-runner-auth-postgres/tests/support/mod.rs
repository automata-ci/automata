use std::{error::Error, future::Future, str::FromStr as _, sync::Arc};

use automata_store::{PostgresStore, PostgresStoreError};
use sqlx::{
    AssertSqlSafe, PgPool,
    postgres::{PgConnectOptions, PgPoolOptions},
};
use uuid::Uuid;

pub const DATABASE_URL_ENVIRONMENT: &str = "AUTOMATA_TEST_DATABASE_URL";
pub type TestError = Box<dyn Error + Send + Sync>;
pub type TestResult<T = ()> = Result<T, TestError>;

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
    schema: String,
    admin: PgPool,
    store: PostgresStore,
}

impl TestDatabase {
    async fn create() -> TestResult<Self> {
        let database_url = std::env::var(DATABASE_URL_ENVIRONMENT).map_err(|_| {
            format!("set {DATABASE_URL_ENVIRONMENT} to an isolated PostgreSQL test server URL")
        })?;
        let admin = PgPoolOptions::new()
            .max_connections(4)
            .connect(&database_url)
            .await?;
        let schema = format!("automata_runner_auth_{}", Uuid::new_v4().simple());
        let quoted_schema: String = sqlx::query_scalar("SELECT pg_catalog.quote_ident($1)")
            .bind(&schema)
            .fetch_one(&admin)
            .await?;
        sqlx::query(AssertSqlSafe(format!("CREATE SCHEMA {quoted_schema}")))
            .execute(&admin)
            .await?;

        let connection_schema = schema.clone();
        let options = PgConnectOptions::from_str(&database_url)?;
        let pool = match PgPoolOptions::new()
            .max_connections(8)
            .after_connect(move |connection, _metadata| {
                let schema = connection_schema.clone();
                Box::pin(async move {
                    sqlx::query("SELECT pg_catalog.set_config('search_path', $1, false)")
                        .bind(schema)
                        .execute(connection)
                        .await?;
                    Ok(())
                })
            })
            .connect_with(options)
            .await
        {
            Ok(pool) => pool,
            Err(error) => {
                drop_schema(&admin, &schema).await?;
                admin.close().await;
                return Err(error.into());
            }
        };
        let store = PostgresStore::from_postgres_pool(pool);
        if let Err(error) = store.migrate().await {
            store.postgres_pool().close().await;
            drop_schema(&admin, &schema).await?;
            admin.close().await;
            return Err(error.into());
        }
        Ok(Self {
            schema,
            admin,
            store,
        })
    }

    pub const fn pool(&self) -> &PgPool {
        self.store.postgres_pool()
    }

    pub const fn store(&self) -> &PostgresStore {
        &self.store
    }

    async fn cleanup(&self) -> TestResult {
        self.store.postgres_pool().close().await;
        drop_schema(&self.admin, &self.schema).await?;
        self.admin.close().await;
        Ok(())
    }
}

async fn drop_schema(pool: &PgPool, schema: &str) -> Result<(), PostgresStoreError> {
    let quoted_schema: String = sqlx::query_scalar("SELECT pg_catalog.quote_ident($1)")
        .bind(schema)
        .fetch_one(pool)
        .await
        .map_err(PostgresStoreError::Connection)?;
    sqlx::query(AssertSqlSafe(format!(
        "DROP SCHEMA IF EXISTS {quoted_schema} CASCADE"
    )))
    .execute(pool)
    .await
    .map_err(PostgresStoreError::Connection)?;
    Ok(())
}
