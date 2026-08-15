use automata_ci_postgres::test_support::{TestResult, cleanup_namespace_from_environment};

#[tokio::main]
async fn main() -> TestResult {
    println!("{}", cleanup_namespace_from_environment().await?);
    Ok(())
}
