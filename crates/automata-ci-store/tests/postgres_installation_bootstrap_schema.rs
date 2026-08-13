const INSTALLATION_MIGRATION: &str = include_str!("../migrations/0001_initial_schema.sql");

#[test]
fn installation_bootstrap_schema_is_exact_single_use_and_fail_closed() {
    let normalized = INSTALLATION_MIGRATION.to_ascii_lowercase();
    assert!(normalized.contains("insert into human_auth_installation_state"));
    assert!(normalized.contains("target_tenant_display_name text"));
    assert!(normalized.contains("octet_length(bootstrap_token_hash) = 32"));
    assert!(normalized.contains("old.challenge_expires_at_ms <= new.updated_at_ms"));
    assert!(normalized.contains("old.setup_transaction_id is null"));
    assert!(normalized.contains("login.purpose = 'installation_setup'"));
    assert!(normalized.contains("login.status = 'succeeded'"));
    assert!(normalized.contains("login.completed_principal_id = new.configured_principal_id"));
    assert!(normalized.contains("human_auth_installation_state_no_insert_delete"));
    assert!(normalized.contains("human_auth_installation_state_no_truncate"));
    assert!(normalized.contains("human_login_transactions_identity_immutable"));
    assert!(normalized.contains("(old.status = 'consumed' and new.status = 'succeeded')"));
    assert!(!normalized.contains("bootstrap_token text"));
    assert!(!normalized.contains("provider_access_token"));
    assert!(!normalized.contains("provider_refresh_token"));
    assert!(!normalized.contains("delete from human_auth_installation_state"));
}
