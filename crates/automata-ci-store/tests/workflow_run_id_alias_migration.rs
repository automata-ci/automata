#[allow(dead_code)]
mod common;

use sqlx::migrate::Migrate as _;

use common::{TestResult, run_with_unmigrated_database, seed_control_plane};

const MIGRATION: &str = include_str!("../migrations/0047_workflow_run_id_alias.sql");

static MIGRATOR: sqlx::migrate::Migrator = sqlx::migrate!("./migrations");

#[test]
fn migration_allocates_one_exact_positive_immutable_alias() {
    let migration = MIGRATOR
        .iter()
        .find(|migration| migration.version == 47)
        .expect("migration 0047 is embedded");
    assert_eq!(migration.description.as_ref(), "workflow run id alias");
    for required in [
        "run_id_alias BIGINT GENERATED ALWAYS AS IDENTITY",
        "MAXVALUE 9007199254740991",
        "workflow_runs_id_alias_exact_positive",
        "workflow_runs_id_alias_unique",
        "workflow_runs_id_alias_immutable",
        "BEFORE UPDATE OF run_id_alias ON workflow_runs",
        "status IN ('queued', 'in_progress')",
        "requires drained active runs",
    ] {
        assert!(
            MIGRATION.contains(required),
            "missing invariant: {required}"
        );
    }
    for prohibited in ["run_number AS", "::UUID", "hashtextextended"] {
        assert!(
            !MIGRATION.contains(prohibited),
            "migration must not derive an alias from a colliding identity: {prohibited}",
        );
    }
}

#[tokio::test]
#[ignore = "requires PostgreSQL 18 and AUTOMATA_TEST_DATABASE_URL"]
async fn existing_and_new_runs_receive_distinct_stable_aliases() -> TestResult {
    run_with_unmigrated_database(|database| async move {
        let mut connection = database.pool().acquire().await?;
        let table_name = MIGRATOR.table_name.as_ref();
        connection.ensure_migrations_table(table_name).await?;
        for migration in MIGRATOR.iter().filter(|migration| migration.version <= 46) {
            connection.apply(table_name, migration).await?;
        }
        drop(connection);

        let existing = seed_control_plane(database.pool(), 0).await?;
        sqlx::query(
            "UPDATE workflow_runs SET status = 'completed', updated_at_ms = 2 WHERE id = $1",
        )
        .bind(existing.run_id.as_uuid())
        .execute(database.pool())
        .await?;
        let mut connection = database.pool().acquire().await?;
        let migration = MIGRATOR
            .iter()
            .find(|migration| migration.version == 47)
            .expect("migration 0047");
        connection.apply(table_name, migration).await?;
        drop(connection);

        let existing_alias = alias(database.pool(), existing.run_id).await?;
        let new = seed_control_plane(database.pool(), 0).await?;
        let new_alias = alias(database.pool(), new.run_id).await?;
        assert!(existing_alias > 0);
        assert!(new_alias > existing_alias);
        assert!(new_alias <= 9_007_199_254_740_991);
        assert_eq!(
            alias(database.pool(), existing.run_id).await?,
            existing_alias,
        );

        let rewrite = sqlx::query("UPDATE workflow_runs SET run_id_alias = DEFAULT WHERE id = $1")
            .bind(existing.run_id.as_uuid())
            .execute(database.pool())
            .await
            .expect_err("run aliases are immutable");
        assert_eq!(
            rewrite
                .as_database_error()
                .and_then(sqlx::error::DatabaseError::constraint),
            Some("workflow_runs_id_alias_immutable"),
        );
        Ok(())
    })
    .await
}

async fn alias(pool: &sqlx::PgPool, run_id: automata_ci_core::RunId) -> TestResult<i64> {
    Ok(
        sqlx::query_scalar("SELECT run_id_alias FROM workflow_runs WHERE id = $1")
            .bind(run_id.as_uuid())
            .fetch_one(pool)
            .await?,
    )
}
