use std::sync::{
    Arc,
    atomic::{AtomicU64, Ordering},
};

use automata_core::{AttemptId, FencingToken, JobId, RunId};
use automata_results_github::{
    ExecutionAuthority, HmacResultsAuthority, HmacResultsAuthorityConfig, ResultsClock,
    ResultsPublicEndpoint, RuntimeTokenIssuer as _, RuntimeTokenVerifier, SignedUploadCapability,
    TokenError, UploadId,
};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use ring::hmac;
use serde_json::{Value, json};
use url::Url;
use uuid::Uuid;

const SECRET: &[u8] = b"automata-results-test-key-material-32-bytes-minimum";
const RUNTIME_LABEL: &[u8] = b"automata/results/runtime-jwt/hs256/v1";

#[derive(Debug)]
struct MutableClock(AtomicU64);

impl MutableClock {
    fn new(now: u64) -> Self {
        Self(AtomicU64::new(now))
    }

    fn set(&self, now: u64) {
        self.0.store(now, Ordering::SeqCst);
    }
}

impl ResultsClock for MutableClock {
    fn now_seconds(&self) -> u64 {
        self.0.load(Ordering::SeqCst)
    }
}

fn authority(clock: Arc<MutableClock>) -> HmacResultsAuthority {
    let config = HmacResultsAuthorityConfig::new(
        "automata-tests",
        "actions-results",
        "test-v1",
        ResultsPublicEndpoint::loopback_development(
            Url::parse("http://results.automata.localhost:8080/").expect("valid test URL"),
            "127.0.0.1:8080".parse().expect("loopback bind"),
        )
        .expect("loopback development endpoint"),
        900,
        300,
        5,
    )
    .expect("valid config");
    HmacResultsAuthority::new(SECRET, config, clock).expect("valid authority")
}

fn execution() -> ExecutionAuthority {
    ExecutionAuthority::new(
        RunId::new(),
        JobId::new(),
        AttemptId::new(),
        FencingToken::new(7).expect("positive fence"),
    )
}

#[test]
fn issued_runtime_token_has_exact_results_scope_and_round_trips() {
    let clock = Arc::new(MutableClock::new(10_000));
    let authority = authority(clock);
    let execution = execution();

    let token = authority.issue(execution, 600).expect("token issued");
    let claims =
        RuntimeTokenVerifier::verify(&authority, token.expose_secret()).expect("token verifies");

    assert_eq!(claims.authority(), execution);
    assert_eq!(claims.issued_at_seconds(), 10_000);
    assert_eq!(claims.expires_at_seconds(), 10_600);
    let payload = token
        .expose_secret()
        .split('.')
        .nth(1)
        .and_then(|part| URL_SAFE_NO_PAD.decode(part).ok())
        .and_then(|bytes| serde_json::from_slice::<Value>(&bytes).ok())
        .expect("JWT payload");
    assert_eq!(
        payload["scp"],
        format!(
            "Actions.Results:{}:{}",
            execution.run_id(),
            execution.job_id()
        )
    );
    assert_eq!(format!("{token:?}"), "RuntimeToken([redacted])");
}

#[test]
fn signature_tampering_and_expiry_are_rejected() {
    let clock = Arc::new(MutableClock::new(20_000));
    let authority = authority(Arc::clone(&clock));
    let token = authority.issue(execution(), 60).expect("token issued");
    let mut parts = token
        .expose_secret()
        .split('.')
        .map(str::to_owned)
        .collect::<Vec<_>>();
    let replacement = if parts[2].starts_with('A') { "B" } else { "A" };
    parts[2].replace_range(..1, replacement);
    assert_eq!(
        RuntimeTokenVerifier::verify(&authority, &parts.join(".")),
        Err(TokenError::Invalid)
    );

    clock.set(20_060);
    assert_eq!(
        RuntimeTokenVerifier::verify(&authority, token.expose_secret()),
        Err(TokenError::Expired)
    );
}

#[test]
fn validly_signed_ambiguous_scope_and_algorithm_confusion_are_rejected() {
    let clock = Arc::new(MutableClock::new(30_000));
    let authority = authority(clock);
    let execution = execution();
    let common = json!({
        "iss": "automata-tests",
        "aud": "actions-results",
        "sub": execution.attempt_id().to_string(),
        "iat": 30000,
        "nbf": 30000,
        "exp": 30600,
        "attempt_id": execution.attempt_id().to_string(),
        "fencing_token": execution.fencing_token().get()
    });

    let mut ambiguous = common.clone();
    ambiguous["scp"] = json!(format!(
        "Actions.Results:{}:{} Actions.Results:{}:{}",
        execution.run_id(),
        execution.job_id(),
        RunId::new(),
        JobId::new()
    ));
    let header = json!({"alg":"HS256", "typ":"JWT", "kid":"test-v1"});
    let token = sign_test_jwt(&header, &ambiguous);
    assert_eq!(
        RuntimeTokenVerifier::verify(&authority, &token),
        Err(TokenError::Scope)
    );

    let mut valid_payload = common;
    valid_payload["scp"] = json!(format!(
        "Actions.Results:{}:{}",
        execution.run_id(),
        execution.job_id()
    ));
    let header = json!({"alg":"none", "typ":"JWT", "kid":"test-v1"});
    let token = sign_test_jwt(&header, &valid_payload);
    assert_eq!(
        RuntimeTokenVerifier::verify(&authority, &token),
        Err(TokenError::Invalid)
    );
}

#[test]
fn signed_upload_is_exactly_bound_tamper_proof_and_lifetime_clamped() {
    let clock = Arc::new(MutableClock::new(40_000));
    let authority = authority(Arc::clone(&clock));
    let upload_id = UploadId::from_uuid(Uuid::new_v4());
    let url = authority
        .issue_url(upload_id, 40_900)
        .expect("signed URL issued");
    let query = url
        .query_pairs()
        .collect::<std::collections::HashMap<_, _>>();
    assert_eq!(query.get("se").map(std::borrow::Cow::as_ref), Some("40300"));
    let signature = query.get("sig").expect("signature");
    SignedUploadCapability::verify(&authority, upload_id, 40_300, signature)
        .expect("capability verifies");
    assert_eq!(
        SignedUploadCapability::verify(
            &authority,
            UploadId::from_uuid(Uuid::new_v4()),
            40_300,
            signature,
        ),
        Err(TokenError::Invalid)
    );
    assert_eq!(
        SignedUploadCapability::verify(&authority, upload_id, 40_301, signature),
        Err(TokenError::Policy)
    );
    clock.set(40_300);
    assert_eq!(
        SignedUploadCapability::verify(&authority, upload_id, 40_300, signature),
        Err(TokenError::Expired)
    );
}

#[test]
fn insecure_non_loopback_results_url_and_short_keys_are_rejected() {
    assert_eq!(
        ResultsPublicEndpoint::https(
            Url::parse("http://results.example.test/").expect("valid URL")
        ),
        Err(TokenError::Policy)
    );

    let config = HmacResultsAuthorityConfig::new(
        "issuer",
        "audience",
        "kid",
        ResultsPublicEndpoint::https(
            Url::parse("https://results.example.test/").expect("valid URL"),
        )
        .expect("HTTPS endpoint"),
        60,
        60,
        0,
    )
    .expect("HTTPS config");
    assert!(matches!(
        HmacResultsAuthority::new(b"too short", config, Arc::new(MutableClock::new(1))),
        Err(TokenError::Policy)
    ));
}

fn sign_test_jwt(header: &Value, payload: &Value) -> String {
    let encoded_header = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header).expect("header JSON"));
    let encoded_payload =
        URL_SAFE_NO_PAD.encode(serde_json::to_vec(&payload).expect("payload JSON"));
    let input = format!("{encoded_header}.{encoded_payload}");
    let root = hmac::Key::new(hmac::HMAC_SHA256, SECRET);
    let derived = hmac::sign(&root, RUNTIME_LABEL);
    let key = hmac::Key::new(hmac::HMAC_SHA256, derived.as_ref());
    let signature = URL_SAFE_NO_PAD.encode(hmac::sign(&key, input.as_bytes()));
    format!("{input}.{signature}")
}
