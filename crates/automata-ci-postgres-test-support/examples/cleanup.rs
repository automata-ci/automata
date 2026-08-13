use automata_ci_postgres_test_support::{PostgresTestHarness, TestResult};

#[tokio::main]
async fn main() -> TestResult {
    let harness = PostgresTestHarness::from_environment_for_cleanup()?;
    let namespace = harness.namespace().to_string();
    let cleanup = harness.cleanup_namespace().await?;
    println!(
        "cleaned PostgreSQL test namespace {namespace}: {} test database(s), template removed: {}",
        cleanup.dropped_test_databases, cleanup.dropped_template
    );
    Ok(())
}
