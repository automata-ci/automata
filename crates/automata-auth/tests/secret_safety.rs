mod support;

use automata_auth::{
    github::{GithubTokenResponse, GithubWebCallback},
    human::ProviderCredential,
    secret::{CsrfToken, PkceVerifier, SecretBytes, SecretString, SessionToken},
    session::IssuedSession,
    vault::{
        ProviderAccessToken, ProviderRefreshToken, ProviderTokenSet, VersionedProviderTokens,
        WrappedDataKey,
    },
};
use static_assertions::assert_not_impl_any;

use support::{DeterministicRandom, secret, token_response};

assert_not_impl_any!(SecretString: serde::Serialize, Clone);
assert_not_impl_any!(SecretBytes: serde::Serialize, Clone);
assert_not_impl_any!(ProviderAccessToken: serde::Serialize, Clone);
assert_not_impl_any!(ProviderRefreshToken: serde::Serialize, Clone);
assert_not_impl_any!(ProviderTokenSet: serde::Serialize, Clone);
assert_not_impl_any!(ProviderCredential: serde::Serialize, Clone);
assert_not_impl_any!(IssuedSession: serde::Serialize, Clone);
assert_not_impl_any!(VersionedProviderTokens: serde::Serialize, Clone);
assert_not_impl_any!(WrappedDataKey: serde::Serialize, Clone);
assert_not_impl_any!(GithubTokenResponse: serde::Serialize, Clone);
assert_not_impl_any!(SessionToken: serde::Serialize, Clone);

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
}
