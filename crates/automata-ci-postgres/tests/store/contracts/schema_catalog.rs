use crate::support::{TestResult, run_with_database};

#[tokio::test]
#[ignore = "requires PostgreSQL 18 and AUTOMATA_TEST_DATABASE_URL"]
async fn schema_has_no_redundant_indexes() -> TestResult {
    run_with_database(|database| async move {
        let exact_duplicates = sqlx::query_as::<_, (String, String)>(
            r"
            WITH application_indexes AS (
                SELECT catalog_index.*,
                       catalog_index_relation.relname::TEXT AS index_name,
                       catalog_table.relname::TEXT AS table_name
                FROM pg_catalog.pg_index AS catalog_index
                JOIN pg_catalog.pg_class AS catalog_index_relation
                  ON catalog_index_relation.oid = catalog_index.indexrelid
                JOIN pg_catalog.pg_class AS catalog_table
                  ON catalog_table.oid = catalog_index.indrelid
                JOIN pg_catalog.pg_namespace AS catalog_namespace
                  ON catalog_namespace.oid = catalog_table.relnamespace
                WHERE catalog_namespace.nspname = current_schema()
            )
            SELECT duplicate.table_name,
                   string_agg(duplicate.index_name, ', ' ORDER BY duplicate.index_name)
            FROM application_indexes AS duplicate
            GROUP BY duplicate.table_name,
                     duplicate.indrelid,
                     duplicate.indkey,
                     duplicate.indclass,
                     duplicate.indcollation,
                     duplicate.indoption,
                     duplicate.indexprs,
                     duplicate.indpred
            HAVING count(*) > 1
            ORDER BY duplicate.table_name
            ",
        )
        .fetch_all(database.pool())
        .await?;
        assert!(
            exact_duplicates.is_empty(),
            "schema contains indexes with identical keys: {exact_duplicates:?}"
        );

        let unique_prefix_duplicates = sqlx::query_as::<_, (String, String, String)>(
            r"
            WITH application_indexes AS (
                SELECT catalog_index.*,
                       catalog_index_relation.relname::TEXT AS index_name,
                       catalog_table.relname::TEXT AS table_name
                FROM pg_catalog.pg_index AS catalog_index
                JOIN pg_catalog.pg_class AS catalog_index_relation
                  ON catalog_index_relation.oid = catalog_index.indexrelid
                JOIN pg_catalog.pg_class AS catalog_table
                  ON catalog_table.oid = catalog_index.indrelid
                JOIN pg_catalog.pg_namespace AS catalog_namespace
                  ON catalog_namespace.oid = catalog_table.relnamespace
                WHERE catalog_namespace.nspname = current_schema()
                  AND catalog_index.indexprs IS NULL
                  AND catalog_index.indpred IS NULL
            )
            SELECT shorter.table_name,
                   shorter.index_name,
                   longer.index_name
            FROM application_indexes AS shorter
            JOIN application_indexes AS longer
              ON longer.indrelid = shorter.indrelid
             AND longer.indexrelid <> shorter.indexrelid
             AND longer.indnkeyatts > shorter.indnkeyatts
             AND (shorter.indkey::SMALLINT[])[0:shorter.indnkeyatts - 1]
                 = (longer.indkey::SMALLINT[])[0:shorter.indnkeyatts - 1]
             AND (shorter.indclass::OID[])[0:shorter.indnkeyatts - 1]
                 = (longer.indclass::OID[])[0:shorter.indnkeyatts - 1]
             AND (shorter.indcollation::OID[])[0:shorter.indnkeyatts - 1]
                 = (longer.indcollation::OID[])[0:shorter.indnkeyatts - 1]
             AND (shorter.indoption::SMALLINT[])[0:shorter.indnkeyatts - 1]
                 = (longer.indoption::SMALLINT[])[0:shorter.indnkeyatts - 1]
            WHERE shorter.indisunique
              AND NOT longer.indisunique
              AND longer.indnatts = longer.indnkeyatts
            ORDER BY shorter.table_name, shorter.index_name, longer.index_name
            ",
        )
        .fetch_all(database.pool())
        .await?;
        assert!(
            unique_prefix_duplicates.is_empty(),
            "schema contains non-covering indexes extended from already-unique keys: \
             {unique_prefix_duplicates:?}"
        );
        Ok(())
    })
    .await
}
