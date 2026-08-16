// Integration-test targets compile this shared module independently and use different subsets.
#![allow(dead_code)]

use automata_ci_core::UnixMillis;
use sqlx::PgPool;

use super::postgres::{TestDatabase, TestResult};

pub(crate) async fn database_now_seconds(database: &TestDatabase) -> TestResult<u64> {
    database_now_seconds_from_pool(database.pool()).await
}

pub(crate) async fn database_now_seconds_from_pool(pool: &PgPool) -> TestResult<u64> {
    let database_now: i64 =
        sqlx::query_scalar("SELECT floor(extract(epoch FROM clock_timestamp()))::BIGINT")
            .fetch_one(pool)
            .await?;
    Ok(u64::try_from(database_now)?)
}

pub(crate) async fn database_now_millis(database: &TestDatabase) -> TestResult<UnixMillis> {
    let database_now: i64 =
        sqlx::query_scalar("SELECT floor(extract(epoch FROM clock_timestamp()) * 1000)::BIGINT")
            .fetch_one(database.pool())
            .await?;
    Ok(UnixMillis::new(database_now))
}
