use std::sync::Arc;

use automata_ci_runner_auth::RunnerMachineDirectory;
use automata_ci_runner_auth_postgres::PostgresRunnerMachineDirectory;
use sqlx::postgres::{PgConnectOptions, PgPoolOptions};
#[tokio::test]
async fn adapter_debug_omits_pool_configuration() {
    let pool = PgPoolOptions::new().connect_lazy_with(PgConnectOptions::new());
    let concrete = PostgresRunnerMachineDirectory::new(pool);
    assert_eq!(
        format!("{concrete:?}"),
        "PostgresRunnerMachineDirectory { .. }"
    );
    let object: Arc<dyn RunnerMachineDirectory> = Arc::new(concrete);
    assert_eq!(
        format!("{object:?}"),
        "PostgresRunnerMachineDirectory { .. }"
    );
}
