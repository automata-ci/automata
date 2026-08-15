mod support;

use std::sync::Arc;

use automata_ci_auth::{
    github::{GithubTokenResponse, GithubWebCallback},
    human::ProviderCredential,
    secret::{CsrfToken, PkceVerifier, SecretBytes, SecretString, SharedSensitiveString},
    vault::{ProviderAccessToken, ProviderRefreshToken, ProviderTokenSet, VersionedProviderTokens},
};
use static_assertions::{assert_impl_all, assert_not_impl_any};
use support::{DeterministicRandom, secret, token_response};

assert_not_impl_any!(SecretString: serde::Serialize, Clone);
assert_not_impl_any!(SecretBytes: serde::Serialize, Clone);
assert_not_impl_any!(ProviderAccessToken: serde::Serialize, Clone);
assert_not_impl_any!(ProviderRefreshToken: serde::Serialize, Clone);
assert_not_impl_any!(ProviderTokenSet: serde::Serialize, Clone);
assert_not_impl_any!(ProviderCredential: serde::Serialize, Clone);
assert_not_impl_any!(VersionedProviderTokens: serde::Serialize, Clone);
assert_not_impl_any!(GithubTokenResponse: serde::Serialize, Clone);
assert_impl_all!(SharedSensitiveString: Clone, Send, Sync);
assert_not_impl_any!(
    SharedSensitiveString: Copy, std::fmt::Display, serde::Serialize, serde::Deserialize<'static>
);

#[test]
fn all_secret_debug_output_is_redacted() {
    let token = secret("do-not-print-this-token");
    assert!(!format!("{token:?}").contains(token.expose_secret()));

    let response = token_response();
    let rendered = format!("{response:?}");
    assert!(!rendered.contains("ghu_access_token_value"));
    assert!(!rendered.contains("ghr_refresh_token_value"));

    let callback = GithubWebCallback::Authorized {
        code: secret("authorization-code"),
        state: secret("oauth-state"),
    };
    let rendered = format!("{callback:?}");
    assert!(!rendered.contains("authorization-code"));
    assert!(!rendered.contains("oauth-state"));
}

#[test]
fn secret_deserialization_does_not_enable_serialization() {
    let parsed: SecretString =
        serde_json::from_str("\"provider-secret\"").expect("deserialize secret");
    assert_eq!(parsed.expose_secret(), "provider-secret");
    assert!(serde_json::from_str::<SecretString>("\"\"").is_err());
}

#[test]
fn pkce_matches_the_rfc_7636_s256_vector() {
    let verifier = PkceVerifier::from_secret(secret("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"))
        .expect("valid verifier");
    assert_eq!(
        verifier.challenge_s256().as_str(),
        "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
    );
}

#[test]
fn csrf_tokens_are_unpredictable_length_and_constant_time_comparable() {
    let random = DeterministicRandom::new(7);
    let token = CsrfToken::generate(&random).expect("CSRF token");
    assert_eq!(token.expose_secret().len(), 43);
    assert!(token.matches(token.expose_secret()));
    assert!(!token.matches("not-the-token"));
    assert!(!format!("{token:?}").contains(token.expose_secret()));
    assert!(CsrfToken::from_generated_secret(secret(token.expose_secret())).is_ok());
    assert!(CsrfToken::from_generated_secret(secret("too-short")).is_err());
}

#[test]
fn shared_sensitive_string_reuses_existing_secret_backing() {
    let source = Arc::new(secret("existing-shared-sentinel"));
    let source_plaintext_pointer = source.expose_secret().as_ptr();
    let sensitive = SharedSensitiveString::from_secret(Arc::clone(&source));

    assert_eq!(Arc::strong_count(&source), 2);
    assert_eq!(sensitive.expose_secret().as_ptr(), source_plaintext_pointer);
    assert_eq!(sensitive.len(), source.expose_secret().len());
    assert!(!sensitive.is_empty());
    assert!(sensitive.constant_time_eq(source.expose_secret()));

    let clone = sensitive.clone();
    assert_eq!(Arc::strong_count(&source), 3);
    assert_eq!(clone.expose_secret().as_ptr(), source_plaintext_pointer);

    drop(source);
    assert_eq!(clone.expose_secret(), "existing-shared-sentinel");
}

#[test]
fn shared_sensitive_string_reuses_owned_zeroizing_backing() {
    let owned = String::from("owned-shared-sentinel");
    let owned_plaintext_pointer = owned.as_ptr();
    let sensitive = SharedSensitiveString::from_string(owned);

    assert_eq!(sensitive.expose_secret().as_ptr(), owned_plaintext_pointer);
    assert_eq!(sensitive.len(), "owned-shared-sentinel".len());
    assert!(sensitive.constant_time_eq("owned-shared-sentinel"));

    let clone = sensitive.clone();
    assert_eq!(clone.expose_secret().as_ptr(), owned_plaintext_pointer);
    assert!(clone.constant_time_eq(sensitive.expose_secret()));
}

#[test]
fn shared_sensitive_string_handles_empty_and_length_mismatched_values() {
    let empty = SharedSensitiveString::from_string(String::new());

    assert!(empty.is_empty());
    assert_eq!(empty.len(), 0);
    assert!(empty.constant_time_eq(""));
    assert!(!empty.constant_time_eq("x"));

    let non_empty = SharedSensitiveString::from_string(String::from("prefix"));
    assert!(!non_empty.constant_time_eq(""));
    assert!(!non_empty.constant_time_eq("prefix-longer"));
    assert!(!non_empty.constant_time_eq("prefiy"));
}

#[test]
fn shared_sensitive_string_debug_output_is_redacted() {
    let sensitive = SharedSensitiveString::from_string(String::from("debug-shared-sentinel"));
    let rendered = format!("{sensitive:?}");

    assert_eq!(rendered, "SharedSensitiveString([REDACTED])");
    assert!(!rendered.contains("debug-shared-sentinel"));
}
