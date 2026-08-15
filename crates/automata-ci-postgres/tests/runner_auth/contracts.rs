use std::sync::Arc;

use automata_ci_control::runner_auth::RunnerMachineDirectory;
use automata_ci_postgres::runner_auth::PostgresRunnerMachineDirectory;
use sqlx::postgres::{PgConnectOptions, PgPoolOptions};
use static_assertions::assert_impl_all;

assert_impl_all!(PostgresRunnerMachineDirectory: RunnerMachineDirectory, Clone, Send, Sync);

#[tokio::test]
async fn adapter_is_object_safe_and_debug_omits_pool_configuration() {
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
