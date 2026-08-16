use automata_ci_store::{
    BuiltinSecretCleanupRepository, RepositorySecretManagementReadRepository,
    RepositorySecretManagementRepository, SecretMutationRecoveryRepository,
};
use automata_ci_store_postgres::PostgresSecretManagementRepository;

#[tokio::test]
async fn concrete_adapter_is_redacted_and_ports_are_object_safe() {
    fn accepts_management(_: &dyn RepositorySecretManagementRepository) {}
    fn accepts_management_reads(_: &dyn RepositorySecretManagementReadRepository) {}
    fn accepts_cleanup(_: &dyn BuiltinSecretCleanupRepository) {}
    fn accepts_recovery(_: &dyn SecretMutationRecoveryRepository) {}

    let pool = sqlx::postgres::PgPoolOptions::new()
        .connect_lazy("postgres://sentinel-user:sentinel-password@127.0.0.1:1/sentinel")
        .expect("valid lazy URL");
    let adapter = PostgresSecretManagementRepository::new(pool);
    accepts_management(&adapter);
    accepts_management_reads(&adapter);
    accepts_cleanup(&adapter);
    accepts_recovery(&adapter);
    let debug = format!("{adapter:?}");
    assert!(!debug.contains("sentinel-password"));
    assert_eq!(debug, "PostgresSecretManagementRepository { .. }");
}
