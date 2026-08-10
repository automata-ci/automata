use std::sync::{
    Arc,
    atomic::{AtomicU64, Ordering},
};

use automata_ci_core::{AttemptId, FencingToken, JobId, RunId};
use automata_ci_results_github::{
    ArtifactId, CacheAccessScope, CacheAuthority, CacheEntryId, CachePermission,
    ExecutionAuthority, HmacResultsAuthority, HmacResultsAuthorityConfig, ResultsClock,
    ResultsPublicEndpoint, RuntimeTokenIssuer as _, RuntimeTokenVerifier, SignedCacheCapability,
    SignedDownloadCapability, SignedUploadCapability, TokenError, UploadId,
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

fn cache_authority() -> CacheAuthority {
    CacheAuthority::new(
        "automata-ci/automata",
        vec![
            CacheAccessScope::new("refs/heads/main", CachePermission::ReadWrite)
                .expect("cache scope"),
        ],
    )
    .expect("cache authority")
}

#[test]
fn issued_runtime_token_has_exact_results_scope_and_round_trips() {
    let clock = Arc::new(MutableClock::new(10_000));
    let authority = authority(clock);
    let execution = execution();

    let cache = cache_authority();
    let token = authority
        .issue(execution, cache.clone(), 600)
        .expect("token issued");
    let claims =
        RuntimeTokenVerifier::verify(&authority, token.expose_secret()).expect("token verifies");

    assert_eq!(claims.authority(), execution);
    assert_eq!(claims.cache(), &cache);
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
    assert_eq!(payload["repository"], "automata-ci/automata");
    assert_eq!(
        payload["ac"],
        r#"[{"Scope":"refs/heads/main","Permission":3}]"#
    );
    assert_eq!(format!("{token:?}"), "RuntimeToken([redacted])");
}

#[test]
fn signature_tampering_and_expiry_are_rejected() {
    let clock = Arc::new(MutableClock::new(20_000));
    let authority = authority(Arc::clone(&clock));
    let token = authority
        .issue(execution(), cache_authority(), 60)
        .expect("token issued");
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
        "fencing_token": execution.fencing_token().get(),
        "repository": "automata-ci/automata",
        "ac": r#"[{"Scope":"refs/heads/main","Permission":3}]"#
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
fn missing_or_invalid_current_cache_access_controls_are_rejected() {
    let authority = authority(Arc::new(MutableClock::new(35_000)));
    let execution = execution();
    let header = json!({"alg":"HS256", "typ":"JWT", "kid":"test-v1"});
    let base = json!({
        "iss": "automata-tests",
        "aud": "actions-results",
        "sub": execution.attempt_id().to_string(),
        "iat": 35000,
        "nbf": 35000,
        "exp": 35600,
        "scp": format!("Actions.Results:{}:{}", execution.run_id(), execution.job_id()),
        "attempt_id": execution.attempt_id().to_string(),
        "fencing_token": execution.fencing_token().get(),
        "repository": "automata-ci/automata",
        "ac": r#"[{"Scope":"refs/heads/main","Permission":3}]"#
    });
    for field in ["repository", "ac"] {
        let mut payload = base.clone();
        payload
            .as_object_mut()
            .expect("payload object")
            .remove(field);
        assert_eq!(
            RuntimeTokenVerifier::verify(&authority, &sign_test_jwt(&header, &payload)),
            Err(TokenError::Malformed)
        );
    }
    let mut invalid_permission = base;
    invalid_permission["ac"] = json!(r#"[{"Scope":"refs/heads/main","Permission":4}]"#);
    assert_eq!(
        RuntimeTokenVerifier::verify(&authority, &sign_test_jwt(&header, &invalid_permission),),
        Err(TokenError::Scope)
    );
}

#[test]
fn cache_capabilities_are_separate_and_bind_identity_digest_and_expiry() {
    let clock = Arc::new(MutableClock::new(37_000));
    let authority = authority(Arc::clone(&clock));
    let entry_id = CacheEntryId::new(Uuid::new_v4()).expect("entry ID");
    let digest = automata_ci_core::Sha256Digest::from_bytes([0x73; 32]);
    let upload = authority
        .issue_cache_upload_url(entry_id, 37_900)
        .expect("upload URL");
    assert_eq!(
        upload.path(),
        format!("/_apis/results/caches/{entry_id}/blob")
    );
    let query = upload
        .query_pairs()
        .collect::<std::collections::HashMap<_, _>>();
    let signature = query.get("sig").expect("upload signature");
    authority
        .verify_cache_upload(entry_id, 37_300, signature)
        .expect("upload verifies");
    assert_eq!(
        authority.verify_cache_upload(
            CacheEntryId::new(Uuid::new_v4()).expect("other entry"),
            37_300,
            signature,
        ),
        Err(TokenError::Invalid)
    );

    let download = authority
        .issue_cache_download_url(entry_id, digest, 37_900)
        .expect("download URL");
    let query = download
        .query_pairs()
        .collect::<std::collections::HashMap<_, _>>();
    let signature = query.get("sig").expect("download signature");
    authority
        .verify_cache_download(entry_id, digest, 37_300, signature)
        .expect("download verifies");
    assert_eq!(
        authority.verify_cache_download(
            entry_id,
            automata_ci_core::Sha256Digest::from_bytes([0x74; 32]),
            37_300,
            signature,
        ),
        Err(TokenError::Invalid)
    );
    clock.set(37_300);
    assert_eq!(
        authority.verify_cache_download(entry_id, digest, 37_300, signature),
        Err(TokenError::Expired)
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
fn signed_download_is_bound_to_artifact_digest_and_a_separate_signature_domain() {
    let clock = Arc::new(MutableClock::new(50_000));
    let authority = authority(Arc::clone(&clock));
    let artifact_id = ArtifactId::new(17).expect("artifact ID");
    let digest = automata_ci_core::Sha256Digest::from_bytes([0x5a; 32]);
    let url = authority
        .issue_download_url(artifact_id, digest, 50_900)
        .expect("signed URL issued");
    assert_eq!(
        url.path(),
        format!("/_apis/results/artifacts/{artifact_id}/{digest}/download.zip")
    );
    let query = url
        .query_pairs()
        .collect::<std::collections::HashMap<_, _>>();
    assert_eq!(query.get("se").map(std::borrow::Cow::as_ref), Some("50300"));
    let signature = query.get("sig").expect("signature");
    authority
        .verify_download(artifact_id, digest, 50_300, signature)
        .expect("capability verifies");
    assert_eq!(
        authority.verify_download(
            ArtifactId::new(18).expect("artifact ID"),
            digest,
            50_300,
            signature,
        ),
        Err(TokenError::Invalid)
    );
    assert_eq!(
        authority.verify_download(
            artifact_id,
            automata_ci_core::Sha256Digest::from_bytes([0x5b; 32]),
            50_300,
            signature,
        ),
        Err(TokenError::Invalid)
    );
    assert_eq!(
        SignedUploadCapability::verify(
            &authority,
            UploadId::from_uuid(Uuid::new_v4()),
            50_300,
            signature,
        ),
        Err(TokenError::Invalid)
    );
    clock.set(50_300);
    assert_eq!(
        authority.verify_download(artifact_id, digest, 50_300, signature),
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
