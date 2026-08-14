use std::{fmt::Write as _, sync::Arc};

use automata_ci_auth::{
    installation::InstallationRepository, login::LoginTransactionRepository,
    request_auth::RequestAuthenticationResolver, session::HumanSessionRepository,
    vault::ProviderTokenVault,
};
use automata_ci_key_management::{KeyId, LocalAes256GcmKeyring, LocalKeyMaterial, SecretBytes};
use automata_ci_postgres::auth::{
    PostgresHumanSessionRepository, PostgresInstallationRepository,
    PostgresLoginTransactionRepository, PostgresProviderTokenVault,
    PostgresRequestAuthenticationResolver,
};
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

const KEY_MATERIAL: &[u8; 32] = b"auth-postgres-key-material-12345";
const KEY_MATERIAL_BASE64: &str = "YXV0aC1wb3N0Z3Jlcy1rZXktbWF0ZXJpYWwtMTIzNDU";

fn keyring() -> Arc<LocalAes256GcmKeyring> {
    let active = LocalKeyMaterial::new(
        KeyId::new("login-kek-v1").expect("key ID"),
        SecretBytes::new(KEY_MATERIAL.to_vec()).expect("key bytes"),
    )
    .expect("key material");
    Arc::new(LocalAes256GcmKeyring::new(active, Vec::new(), []).expect("keyring"))
}

fn key_material_representations() -> [(&'static str, String); 6] {
    let mut lowercase_hex = String::with_capacity(KEY_MATERIAL.len() * 2);
    let mut uppercase_hex = String::with_capacity(KEY_MATERIAL.len() * 2);
    for byte in KEY_MATERIAL {
        write!(&mut lowercase_hex, "{byte:02x}").expect("write lowercase hex");
        write!(&mut uppercase_hex, "{byte:02X}").expect("write uppercase hex");
    }
    let decimal_values = KEY_MATERIAL.map(|byte| byte.to_string());

    [
        (
            "raw ASCII",
            std::str::from_utf8(KEY_MATERIAL)
                .expect("ASCII sentinel")
                .to_owned(),
        ),
        ("lowercase hex", lowercase_hex),
        ("uppercase hex", uppercase_hex),
        ("decimal array", format!("{KEY_MATERIAL:?}")),
        (
            "compact decimal array",
            format!("[{}]", decimal_values.join(",")),
        ),
        ("base64", KEY_MATERIAL_BASE64.to_owned()),
    ]
}

fn assert_key_material_is_redacted(surface: &str, rendered: &str) {
    for (encoding, representation) in key_material_representations() {
        assert!(
            !rendered.contains(&representation),
            "{surface} debug output exposed {encoding} key material: {rendered}"
        );
    }
}

#[tokio::test]
async fn adapters_construct_as_trait_objects_and_redact_every_key_representation() {
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
    let sessions_debug = format!("{sessions:?}");
    let request_auth_debug = format!("{request_auth:?}");
    let provider_tokens_debug = format!("{provider_tokens:?}");
    let installation_debug = format!("{installation:?}");

    assert!(login_debug.contains("auth/login-state:v1"));
    assert!(!login_debug.contains("password"));
    assert_eq!(sessions_debug, "PostgresHumanSessionRepository { .. }");
    assert!(provider_tokens_debug.contains("auth/provider-token:v1"));
    assert_eq!(
        request_auth_debug,
        "PostgresRequestAuthenticationResolver { .. }"
    );
    for (surface, rendered) in [
        ("login adapter", login_debug.as_str()),
        ("session adapter", sessions_debug.as_str()),
        ("request-auth adapter", request_auth_debug.as_str()),
        ("provider-token adapter", provider_tokens_debug.as_str()),
        ("installation adapter", installation_debug.as_str()),
    ] {
        assert_key_material_is_redacted(surface, rendered);
    }

    let login_object: Arc<dyn LoginTransactionRepository> = Arc::new(login);
    let session_object: Arc<dyn HumanSessionRepository> = Arc::new(sessions);
    let provider_token_object: Arc<dyn ProviderTokenVault> = Arc::new(provider_tokens);
    let installation_object: Arc<dyn InstallationRepository> = Arc::new(installation);
    let request_auth_object: Arc<dyn RequestAuthenticationResolver> = Arc::new(request_auth);
    let login_object_debug = format!("{login_object:?}");
    let session_object_debug = format!("{session_object:?}");
    let provider_token_object_debug = format!("{provider_token_object:?}");
    let installation_object_debug = format!("{installation_object:?}");
    let request_auth_object_debug = format!("{request_auth_object:?}");

    assert_eq!(
        session_object_debug,
        "PostgresHumanSessionRepository { .. }"
    );
    assert_eq!(
        request_auth_object_debug,
        "PostgresRequestAuthenticationResolver { .. }"
    );
    for (surface, rendered) in [
        ("login trait object", login_object_debug.as_str()),
        ("session trait object", session_object_debug.as_str()),
        (
            "provider-token trait object",
            provider_token_object_debug.as_str(),
        ),
        (
            "installation trait object",
            installation_object_debug.as_str(),
        ),
        (
            "request-auth trait object",
            request_auth_object_debug.as_str(),
        ),
    ] {
        assert_key_material_is_redacted(surface, rendered);
    }
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
