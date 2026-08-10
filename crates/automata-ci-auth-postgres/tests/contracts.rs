use std::sync::Arc;

use automata_ci_auth::{
    installation::InstallationRepository, login::LoginTransactionRepository,
    request_auth::RequestAuthenticationResolver, session::HumanSessionRepository,
    vault::ProviderTokenVault,
};
use automata_ci_auth_postgres::{
    PostgresHumanSessionRepository, PostgresInstallationRepository,
    PostgresLoginTransactionRepository, PostgresProviderTokenVault,
    PostgresRequestAuthenticationResolver,
};
use automata_ci_key_management::{KeyId, LocalAes256GcmKeyring, LocalKeyMaterial, SecretBytes};
use sqlx::postgres::{PgConnectOptions, PgPoolOptions};
use static_assertions::assert_impl_all;

assert_impl_all!(PostgresLoginTransactionRepository: LoginTransactionRepository, Clone, Send, Sync);
assert_impl_all!(PostgresHumanSessionRepository: HumanSessionRepository, Clone, Send, Sync);
assert_impl_all!(PostgresProviderTokenVault: ProviderTokenVault, Clone, Send, Sync);
assert_impl_all!(PostgresInstallationRepository: InstallationRepository, Clone, Send, Sync);
assert_impl_all!(
    PostgresRequestAuthenticationResolver: RequestAuthenticationResolver,
    Clone,
    Send,
    Sync
);

fn keyring() -> Arc<LocalAes256GcmKeyring> {
    let active = LocalKeyMaterial::new(
        KeyId::new("login-kek-v1").expect("key ID"),
        SecretBytes::new(vec![0x5a; 32]).expect("key bytes"),
    )
    .expect("key material");
    Arc::new(LocalAes256GcmKeyring::new(active, Vec::new(), []).expect("keyring"))
}

#[tokio::test]
async fn adapters_are_object_safe_and_debug_output_omits_pool_and_key_material() {
    let pool = PgPoolOptions::new().connect_lazy_with(PgConnectOptions::new());
    let login = PostgresLoginTransactionRepository::new(pool.clone(), keyring());
    let sessions = PostgresHumanSessionRepository::new(pool.clone());
    let request_auth = PostgresRequestAuthenticationResolver::new(pool.clone());
    let provider_tokens = PostgresProviderTokenVault::new(pool, keyring());
    let installation = PostgresInstallationRepository::new(
        PgPoolOptions::new().connect_lazy_with(PgConnectOptions::new()),
        keyring(),
    );
    let login_debug = format!("{login:?}");
    assert!(login_debug.contains("auth/login-state:v1"));
    assert!(!login_debug.contains("5a"));
    assert!(!login_debug.contains("password"));
    assert_eq!(
        format!("{sessions:?}"),
        "PostgresHumanSessionRepository { .. }"
    );
    assert!(format!("{provider_tokens:?}").contains("auth/provider-token:v1"));
    assert!(!format!("{provider_tokens:?}").contains("5a"));
    assert!(!format!("{installation:?}").contains("5a"));
    assert_eq!(
        format!("{request_auth:?}"),
        "PostgresRequestAuthenticationResolver { .. }"
    );

    let login_object: Arc<dyn LoginTransactionRepository> = Arc::new(login);
    let session_object: Arc<dyn HumanSessionRepository> = Arc::new(sessions);
    let provider_token_object: Arc<dyn ProviderTokenVault> = Arc::new(provider_tokens);
    let installation_object: Arc<dyn InstallationRepository> = Arc::new(installation);
    let request_auth_object: Arc<dyn RequestAuthenticationResolver> = Arc::new(request_auth);
    assert!(!format!("{login_object:?}").contains("5a"));
    assert_eq!(
        format!("{session_object:?}"),
        "PostgresHumanSessionRepository { .. }"
    );
    assert!(!format!("{provider_token_object:?}").contains("5a"));
    assert!(!format!("{installation_object:?}").contains("5a"));
    assert_eq!(
        format!("{request_auth_object:?}"),
        "PostgresRequestAuthenticationResolver { .. }"
    );
}

#[test]
fn adapter_errors_are_sanitized_and_never_carry_database_or_secret_details() {
    let rendered = [
        automata_ci_auth::login::LoginTransactionRepositoryError::Unavailable.to_string(),
        automata_ci_auth::login::LoginTransactionRepositoryError::IntegrityFailure.to_string(),
        automata_ci_auth::session::SessionRepositoryError::Unavailable.to_string(),
        automata_ci_auth::session::SessionRepositoryError::CorruptData.to_string(),
        automata_ci_auth::request_auth::RequestAuthenticationResolverError::Unavailable.to_string(),
        automata_ci_auth::request_auth::RequestAuthenticationResolverError::CorruptData.to_string(),
        automata_ci_auth::vault::ProviderTokenVaultError::Unavailable.to_string(),
        automata_ci_auth::vault::ProviderTokenVaultError::IntegrityFailure.to_string(),
    ]
    .join(" ");
    assert!(!rendered.contains("SELECT"));
    assert!(!rendered.contains("postgres"));
    assert!(!rendered.contains("provider-state"));
}
