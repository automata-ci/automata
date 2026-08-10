const INSTALLATION_MIGRATION: &str =
    include_str!("../migrations/0015_human_auth_installation_bootstrap.sql");

#[test]
fn installation_bootstrap_schema_is_exact_single_use_and_fail_closed() {
    assert!(INSTALLATION_MIGRATION.contains("installation_rows <> 1"));
    assert!(INSTALLATION_MIGRATION.contains("target_tenant_display_name TEXT"));
    assert!(INSTALLATION_MIGRATION.contains("octet_length(bootstrap_token_hash) = 32"));
    assert!(INSTALLATION_MIGRATION.contains("OLD.challenge_expires_at_ms <= NEW.updated_at_ms"));
    assert!(INSTALLATION_MIGRATION.contains("OLD.setup_transaction_id IS NULL"));
    assert!(INSTALLATION_MIGRATION.contains("login.purpose = 'installation_setup'"));
    assert!(INSTALLATION_MIGRATION.contains("login.status = 'succeeded'"));
    assert!(
        INSTALLATION_MIGRATION
            .contains("login.completed_principal_id = NEW.configured_principal_id")
    );
    assert!(INSTALLATION_MIGRATION.contains("human_auth_installation_state_no_insert_delete"));
    assert!(INSTALLATION_MIGRATION.contains("human_auth_installation_state_no_truncate"));
    assert!(INSTALLATION_MIGRATION.contains("human_login_transactions_identity_immutable"));
    assert!(
        INSTALLATION_MIGRATION.contains("(OLD.status = 'consumed' AND NEW.status = 'succeeded')")
    );
    assert!(!INSTALLATION_MIGRATION.contains("bootstrap_token TEXT"));
    assert!(!INSTALLATION_MIGRATION.contains("provider_access_token"));
    assert!(!INSTALLATION_MIGRATION.contains("provider_refresh_token"));
    assert!(!INSTALLATION_MIGRATION.contains("DELETE FROM human_auth_installation_state"));
}
