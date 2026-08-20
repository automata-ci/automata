use sqlx::{PgPool, Row as _};

use super::{TestResult, message_error};

/// A schema-local replacement for `PostgreSQL`'s wall clock.
///
/// Application pools created by this crate search `automata_test` before the
/// production `public` schema and `pg_catalog`, so
/// unqualified calls to `clock_timestamp()` resolve this fixture on every
/// current and replacement connection while the clock is frozen.
#[derive(Debug)]
pub struct TestClock {
    pool: PgPool,
}

impl TestClock {
    /// Samples `PostgreSQL`'s built-in wall clock and immediately freezes the
    /// test database at that millisecond.
    ///
    /// The sampling call is schema-qualified deliberately. `PostgreSQL` does not
    /// re-resolve an already prepared unqualified function call when a new
    /// same-named function appears earlier on `search_path`, so callers should
    /// use this constructor before executing application SQL that refers to
    /// `clock_timestamp()`.
    ///
    /// # Errors
    ///
    /// Returns an error if `PostgreSQL` cannot sample its wall clock or install
    /// the schema-local test clock.
    pub async fn freeze_at_database_now(pool: &PgPool) -> TestResult<Self> {
        let now_ms: i64 = sqlx::query_scalar(
            r"
            SELECT floor(
                extract(epoch FROM pg_catalog.clock_timestamp()) * 1000
            )::BIGINT
            ",
        )
        .fetch_one(pool)
        .await?;
        Self::freeze(pool, now_ms).await
    }

    /// Installs the test clock and freezes it at an exact Unix millisecond.
    ///
    /// # Errors
    ///
    /// Returns an error if the fixture objects already exist, `PostgreSQL`
    /// rejects their installation, or the installed clock is not observable.
    pub async fn freeze(pool: &PgPool, now_ms: i64) -> TestResult<Self> {
        let mut transaction = pool.begin().await?;
        sqlx::query(
            r"
            CREATE TABLE automata_test.__automata_test_clock (
                singleton BOOLEAN PRIMARY KEY CHECK (singleton),
                now_ms BIGINT NOT NULL
            )
            ",
        )
        .execute(&mut *transaction)
        .await?;
        sqlx::query(
            r"
            INSERT INTO automata_test.__automata_test_clock (singleton, now_ms)
            VALUES (TRUE, $1)
            ",
        )
        .bind(now_ms)
        .execute(&mut *transaction)
        .await?;
        sqlx::query(
            r"
            CREATE FUNCTION automata_test.clock_timestamp()
            RETURNS TIMESTAMPTZ
            LANGUAGE SQL
            VOLATILE
            AS $automata_test_clock$
                SELECT TIMESTAMPTZ 'epoch' + now_ms * INTERVAL '1 millisecond'
                FROM automata_test.__automata_test_clock
                WHERE singleton
            $automata_test_clock$
            ",
        )
        .execute(&mut *transaction)
        .await?;
        transaction.commit().await?;

        let clock = Self { pool: pool.clone() };
        let installed_now = clock.now().await?;
        if installed_now != now_ms {
            return Err(message_error(format!(
                "installed PostgreSQL test clock returned {installed_now}, expected {now_ms}"
            )));
        }
        Ok(clock)
    }

    /// Moves the frozen clock to an exact Unix millisecond.
    ///
    /// # Errors
    ///
    /// Returns an error if `PostgreSQL` rejects the update or the singleton clock
    /// row is missing.
    #[cfg(feature = "test-support")]
    pub async fn set(&self, now_ms: i64) -> TestResult {
        let result = sqlx::query(
            r"
            UPDATE automata_test.__automata_test_clock
            SET now_ms = $1
            WHERE singleton
            ",
        )
        .bind(now_ms)
        .execute(&self.pool)
        .await?;
        if result.rows_affected() != 1 {
            return Err(message_error(format!(
                "PostgreSQL test clock update affected {} rows, expected exactly one",
                result.rows_affected()
            )));
        }
        Ok(())
    }

    /// Advances the frozen clock without waiting for wall time.
    ///
    /// # Errors
    ///
    /// Returns an error for a negative delta, a missing clock row, arithmetic
    /// overflow, or another `PostgreSQL` failure.
    pub async fn advance(&self, delta_ms: i64) -> TestResult<i64> {
        if delta_ms < 0 {
            return Err(message_error(format!(
                "PostgreSQL test clock advance must be non-negative, got {delta_ms}"
            )));
        }
        let row = sqlx::query(
            r"
            UPDATE automata_test.__automata_test_clock
            SET now_ms = now_ms + $1
            WHERE singleton
            RETURNING now_ms
            ",
        )
        .bind(delta_ms)
        .fetch_optional(&self.pool)
        .await?
        .ok_or_else(|| message_error("PostgreSQL test clock row is missing"))?;
        Ok(row.try_get("now_ms")?)
    }

    /// Reads the time observed by an unqualified `clock_timestamp()` call.
    ///
    /// # Errors
    ///
    /// Returns an error if `PostgreSQL` cannot evaluate or return the clock.
    pub async fn now(&self) -> TestResult<i64> {
        Ok(sqlx::query_scalar(
            r"
            SELECT floor(
                extract(epoch FROM clock_timestamp()) * 1000
            )::BIGINT
            ",
        )
        .fetch_one(&self.pool)
        .await?)
    }

    /// Removes the schema-local clock and restores `PostgreSQL`'s wall clock.
    ///
    /// # Errors
    ///
    /// Returns an error if either fixture object cannot be removed exactly.
    #[cfg(test)]
    pub(super) async fn restore(self) -> TestResult {
        let mut transaction = self.pool.begin().await?;
        sqlx::query("DROP FUNCTION automata_test.clock_timestamp()")
            .execute(&mut *transaction)
            .await?;
        sqlx::query("DROP TABLE automata_test.__automata_test_clock")
            .execute(&mut *transaction)
            .await?;
        transaction.commit().await?;
        Ok(())
    }
}
