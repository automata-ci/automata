use std::fmt::Write as _;

use automata_ci_github::{
    GithubPushRefKind, GithubRepositoryVisibility, GithubWebhookError, GithubWebhookEventMetadata,
    GithubWebhookVerifier, MAX_GITHUB_PUSH_COMMITS, MAX_GITHUB_WEBHOOK_BODY_BYTES,
    MAX_GITHUB_WEBHOOK_SECRET_BYTES, X_GITHUB_DELIVERY, X_GITHUB_EVENT, X_HUB_SIGNATURE_256,
};
use automata_ci_scm::ExactRevision;
use bytes::Bytes;
use reqwest::header::{HeaderMap, HeaderValue};
use ring::{digest, hmac};
use serde_json::{Value, json};

const SECRET: &[u8] = b"correct horse battery staple webhook secret";
const BEFORE: &str = "89abcdef0123456789abcdef0123456789abcdef";
const AFTER: &str = "0123456789abcdef0123456789abcdef01234567";
const PUSHED_OTHER: &str = "fedcba9876543210fedcba9876543210fedcba98";
const ZERO_SHA: &str = "0000000000000000000000000000000000000000";
const REPOSITORY_OWNER_ID: u64 = 9_876_543;

#[test]
fn valid_push_preserves_exact_authenticated_and_provider_evidence() {
    let body = encode(&valid_payload());
    let headers = signed_headers(SECRET, &body, "push", "delivery-123");
    let boundary = GithubWebhookVerifier::new(SECRET).expect("verifier");
    let split = [
        &body[..13],
        &body[13..body.len() - 7],
        &body[body.len() - 7..],
    ];

    let push = boundary
        .verify_chunks(&headers, split)
        .expect("verified push");

    assert_eq!(push.delivery_id(), "delivery-123");
    assert_eq!(push.event_name(), "push");
    assert_eq!(push.raw_body().as_ref(), body);
    assert_eq!(
        push.body_sha256().as_bytes(),
        digest::digest(&digest::SHA256, &body).as_ref()
    );
    assert_eq!(push.installation_id().get(), 77);
    assert_eq!(push.repository().id().get(), 42);
    assert_eq!(push.repository().owner_id().get(), REPOSITORY_OWNER_ID);
    assert_eq!(
        push.repository().visibility(),
        GithubRepositoryVisibility::Public
    );
    assert_eq!(push.repository().owner(), "octocat");
    assert_eq!(push.repository().name(), "automata");
    assert_eq!(push.repository().full_name(), "octocat/automata");
    assert_eq!(push.git_ref().full(), "refs/heads/main");
    assert_eq!(push.git_ref().short_name(), "main");
    assert_eq!(push.git_ref().kind(), GithubPushRefKind::Branch);
    assert_eq!(push.before_commit_sha(), BEFORE);
    assert_eq!(push.after_commit_sha(), AFTER);
    assert_eq!(push.commit_count(), 2);
    assert_eq!(
        push.complete_pushed_commit_revisions()
            .expect("two commits are complete")
            .iter()
            .map(ExactRevision::as_str)
            .collect::<Vec<_>>(),
        vec![AFTER, PUSHED_OTHER]
    );
    assert!(!push.path_filter_commit_limit_exceeded());
    assert_eq!(
        push.event_metadata(),
        GithubWebhookEventMetadata::Push {
            created: false,
            deleted: false,
            forced: false,
        }
    );
    assert!(!push.created());
    assert!(!push.deleted());
    assert!(!push.forced());
}

#[test]
fn every_required_header_must_be_present_exactly_once() {
    let body = encode(&valid_payload());
    let base = signed_headers(SECRET, &body, "push", "delivery-123");
    let verifier = GithubWebhookVerifier::new(SECRET).expect("verifier");

    for name in [X_HUB_SIGNATURE_256, X_GITHUB_EVENT, X_GITHUB_DELIVERY] {
        let mut missing = base.clone();
        missing.remove(name);
        assert_eq!(
            verifier
                .verify(&missing, Bytes::copy_from_slice(&body))
                .expect_err("missing header"),
            GithubWebhookError::InvalidHeaders
        );

        let mut duplicate = base.clone();
        let value = duplicate.get(name).expect("original header").clone();
        duplicate.append(name, value);
        assert_eq!(
            verifier
                .verify(&duplicate, Bytes::copy_from_slice(&body))
                .expect_err("duplicate header"),
            GithubWebhookError::InvalidHeaders
        );
    }
}

#[test]
fn signature_encoding_is_exactly_canonical_lowercase_sha256() {
    let body = encode(&valid_payload());
    let base = signed_headers(SECRET, &body, "push", "delivery-123");
    let verifier = GithubWebhookVerifier::new(SECRET).expect("verifier");
    let malformed = [
        format!("SHA256={}", "0".repeat(64)),
        format!("sha256={}", "A".repeat(64)),
        format!("sha256={}", "g".repeat(64)),
        format!("sha256={}", "0".repeat(63)),
        format!("sha256={}", "0".repeat(65)),
        "sha1=0000000000000000000000000000000000000000".to_owned(),
    ];

    for signature in malformed {
        let mut headers = base.clone();
        headers.insert(
            X_HUB_SIGNATURE_256,
            HeaderValue::from_str(&signature).expect("header value"),
        );
        assert_eq!(
            verifier
                .verify(&headers, Bytes::copy_from_slice(&body))
                .expect_err("noncanonical signature"),
            GithubWebhookError::InvalidSignature
        );
    }
}

#[test]
fn body_limit_is_enforced_before_and_while_buffering() {
    assert_eq!(MAX_GITHUB_WEBHOOK_BODY_BYTES, 25 * 1024 * 1024);
    let verifier = GithubWebhookVerifier::new(SECRET).expect("verifier");
    let mut exact = encode(&valid_payload());
    exact.resize(MAX_GITHUB_WEBHOOK_BODY_BYTES, b' ');
    let exact_headers = signed_headers(SECRET, &exact, "push", "delivery-limit");
    verifier
        .verify(&exact_headers, Bytes::copy_from_slice(&exact))
        .expect("exact limit is accepted");

    let mut oversized = exact;
    oversized.push(b' ');
    assert_eq!(
        verifier
            .verify(&exact_headers, Bytes::copy_from_slice(&oversized))
            .expect_err("pre-buffered oversized body"),
        GithubWebhookError::BodyTooLarge
    );
    assert_eq!(
        verifier
            .verify_chunks(
                &exact_headers,
                [
                    &oversized[..MAX_GITHUB_WEBHOOK_BODY_BYTES],
                    &oversized[MAX_GITHUB_WEBHOOK_BODY_BYTES..],
                ],
            )
            .expect_err("streamed oversized body"),
        GithubWebhookError::BodyTooLarge
    );
}

#[test]
fn authentication_covers_exact_raw_bytes_and_precedes_json() {
    let verifier = GithubWebhookVerifier::new(SECRET).expect("verifier");
    let body = encode(&valid_payload());
    let headers = signed_headers(SECRET, &body, "push", "delivery-exact");
    let mut changed = body.clone();
    changed.push(b' ');
    assert_eq!(
        verifier
            .verify(&headers, Bytes::from(changed))
            .expect_err("changed raw bytes"),
        GithubWebhookError::AuthenticationFailed
    );

    let malformed = b"raw-body-private-marker:{";
    let wrong_headers = signed_headers(b"wrong secret", malformed, "push", "delivery-json");
    assert_eq!(
        verifier
            .verify(&wrong_headers, Bytes::from_static(malformed))
            .expect_err("authentication precedes JSON"),
        GithubWebhookError::AuthenticationFailed
    );
    let authenticated_headers = signed_headers(SECRET, malformed, "push", "delivery-json");
    assert_eq!(
        verifier
            .verify(&authenticated_headers, Bytes::from_static(malformed))
            .expect_err("authenticated malformed JSON"),
        GithubWebhookError::MalformedPayload
    );
}

#[test]
fn unsupported_signed_events_are_rejected_without_json_admission() {
    let body = encode(&valid_payload());
    let headers = signed_headers(SECRET, &body, "pull_request", "delivery-event");
    let verifier = GithubWebhookVerifier::new(SECRET).expect("verifier");
    assert_eq!(
        verifier
            .verify(&headers, Bytes::from(body))
            .expect_err("unsupported event"),
        GithubWebhookError::UnsupportedEvent
    );
}

#[test]
fn unauthenticated_headers_remain_distinct_durable_evidence() {
    let body = encode(&valid_payload());
    let verifier = GithubWebhookVerifier::new(SECRET).expect("verifier");
    let first = verifier
        .verify(
            &signed_headers(SECRET, &body, "push", "delivery-one"),
            Bytes::copy_from_slice(&body),
        )
        .expect("first delivery");
    let second = verifier
        .verify(
            &signed_headers(SECRET, &body, "push", "delivery-two"),
            Bytes::copy_from_slice(&body),
        )
        .expect("second delivery");

    assert_eq!(first.body_sha256(), second.body_sha256());
    assert_eq!(first.raw_body(), second.raw_body());
    assert_ne!(first.delivery_id(), second.delivery_id());
    assert_eq!(first.event_name(), second.event_name());
}

#[test]
fn repository_and_installation_identity_must_be_nonzero_and_consistent() {
    for (pointer, value) in [
        ("/installation/id", json!(0)),
        ("/repository/id", json!(0)),
        ("/repository/full_name", json!("someone/else")),
        ("/repository/owner/login", json!("octocat/ambiguous")),
        ("/repository/name", json!("automata.git")),
    ] {
        let mut payload = valid_payload();
        *payload.pointer_mut(pointer).expect("fixture pointer") = value;
        assert_invalid_payload(&payload);
    }

    let mut missing = valid_payload();
    missing
        .get_mut("installation")
        .expect("installation")
        .as_object_mut()
        .expect("installation object")
        .remove("id");
    assert_malformed_payload(&missing);
}

#[test]
fn repository_owner_id_is_required_positive_and_postgres_bigint_representable() {
    let mut missing = valid_payload();
    missing["repository"]["owner"]
        .as_object_mut()
        .expect("owner object")
        .remove("id");
    assert_malformed_payload(&missing);

    for malformed in [json!("9876543"), json!(-1), json!(1.5), Value::Null] {
        let mut payload = valid_payload();
        payload["repository"]["owner"]["id"] = malformed;
        assert_malformed_payload(&payload);
    }

    let mut zero = valid_payload();
    zero["repository"]["owner"]["id"] = json!(0);
    assert_invalid_payload(&zero);

    let mut overflow = valid_payload();
    overflow["repository"]["owner"]["id"] =
        json!(u64::try_from(i64::MAX).expect("i64 fits u64") + 1);
    assert_invalid_payload(&overflow);

    let mut maximum = valid_payload();
    maximum["repository"]["owner"]["id"] = json!(i64::MAX);
    assert_eq!(
        verify_payload(&maximum)
            .expect("positive PostgreSQL BIGINT maximum")
            .repository()
            .owner_id()
            .get(),
        u64::try_from(i64::MAX).expect("i64 fits u64")
    );
}

#[test]
fn repository_owner_id_is_covered_by_the_exact_body_signature() {
    let body = encode(&valid_payload());
    let headers = signed_headers(SECRET, &body, "push", "delivery-owner-id");
    let mut tampered_payload = valid_payload();
    tampered_payload["repository"]["owner"]["id"] = json!(9_876_544);
    let tampered_body = encode(&tampered_payload);
    assert_eq!(
        tampered_body.len(),
        body.len(),
        "fixture changes only digits"
    );

    assert_eq!(
        GithubWebhookVerifier::new(SECRET)
            .expect("verifier")
            .verify(&headers, Bytes::from(tampered_body))
            .expect_err("tampered owner identity"),
        GithubWebhookError::AuthenticationFailed
    );
}

#[test]
fn repository_visibility_is_required_closed_and_internally_consistent() {
    let mut private = valid_payload();
    private["repository"]["private"] = json!(true);
    private["repository"]["visibility"] = json!("private");
    assert_eq!(
        verify_payload(&private)
            .expect("consistent private repository")
            .repository()
            .visibility(),
        GithubRepositoryVisibility::Private
    );

    for (private, visibility) in [
        (false, "private"),
        (true, "public"),
        (false, "internal"),
        (true, "internal"),
        (false, "PUBLIC"),
    ] {
        let mut payload = valid_payload();
        payload["repository"]["private"] = json!(private);
        payload["repository"]["visibility"] = json!(visibility);
        assert_invalid_payload(&payload);
    }

    for field in ["private", "visibility"] {
        let mut payload = valid_payload();
        payload["repository"]
            .as_object_mut()
            .expect("repository object")
            .remove(field);
        assert_malformed_payload(&payload);
    }
}

#[test]
fn only_canonical_full_head_and_tag_refs_are_admitted() {
    for invalid_ref in [
        "main",
        "refs/pull/1/merge",
        "refs/remotes/origin/main",
        "refs/heads/",
        "refs/heads/.hidden",
        "refs/heads/a..b",
        "refs/heads/a@{b",
        "refs/heads/a//b",
        "refs/heads/a.lock",
        "refs/heads/a b",
        "refs/tags/end.",
        "refs/tags/a\\b",
    ] {
        let mut payload = valid_payload();
        payload["ref"] = json!(invalid_ref);
        assert_invalid_payload(&payload);
    }

    let mut tag = valid_payload();
    tag["ref"] = json!("refs/tags/v1.2.3");
    let push = verify_payload(&tag).expect("canonical tag");
    assert_eq!(push.git_ref().kind(), GithubPushRefKind::Tag);
    assert_eq!(push.git_ref().short_name(), "v1.2.3");
}

#[test]
fn commit_range_is_canonical_and_coherent_with_exact_provider_flags() {
    for invalid_before in [
        "89abcdef0123456789abcdef0123456789abcde",
        "89abcdef0123456789abcdef0123456789abcdef0",
        "89ABCDEF0123456789ABCDEF0123456789ABCDEF",
        "g9abcdef0123456789abcdef0123456789abcdef",
    ] {
        let mut payload = valid_payload();
        payload["before"] = json!(invalid_before);
        assert_invalid_payload(&payload);
    }

    for invalid_after in [
        "0123456789abcdef0123456789abcdef0123456",
        "0123456789abcdef0123456789abcdef012345678",
        "0123456789ABCDEF0123456789ABCDEF01234567",
        "g123456789abcdef0123456789abcdef01234567",
    ] {
        let mut payload = valid_payload();
        payload["after"] = json!(invalid_after);
        assert_invalid_payload(&payload);
    }

    let mut zero_without_deletion = valid_payload();
    zero_without_deletion["after"] = json!(ZERO_SHA);
    assert_invalid_payload(&zero_without_deletion);

    let mut deletion_with_nonzero_after = valid_payload();
    deletion_with_nonzero_after["deleted"] = json!(true);
    assert_invalid_payload(&deletion_with_nonzero_after);

    let mut zero_before_without_creation = valid_payload();
    zero_before_without_creation["before"] = json!(ZERO_SHA);
    assert_invalid_payload(&zero_before_without_creation);

    let mut creation_with_nonzero_before = valid_payload();
    creation_with_nonzero_before["created"] = json!(true);
    assert_invalid_payload(&creation_with_nonzero_before);

    let mut missing_deleted = valid_payload();
    missing_deleted
        .as_object_mut()
        .expect("payload object")
        .remove("deleted");
    assert_malformed_payload(&missing_deleted);

    let mut non_boolean_deleted = valid_payload();
    non_boolean_deleted["deleted"] = json!("false");
    assert_malformed_payload(&non_boolean_deleted);

    for missing_flag in ["before", "created", "forced"] {
        let mut missing = valid_payload();
        missing
            .as_object_mut()
            .expect("payload object")
            .remove(missing_flag);
        assert_malformed_payload(&missing);
    }

    let mut non_boolean_forced = valid_payload();
    non_boolean_forced["forced"] = json!("false");
    assert_malformed_payload(&non_boolean_forced);

    let mut deletion = valid_payload();
    deletion["deleted"] = json!(true);
    deletion["after"] = json!(ZERO_SHA);
    let push = verify_payload(&deletion).expect("coherent deletion");
    assert!(push.deleted());
    assert_eq!(push.after_commit_sha(), ZERO_SHA);
    assert_eq!(
        push.event_metadata(),
        GithubWebhookEventMetadata::Push {
            created: false,
            deleted: true,
            forced: false,
        }
    );

    let mut creation = valid_payload();
    creation["before"] = json!(ZERO_SHA);
    creation["created"] = json!(true);
    creation["forced"] = json!(true);
    let push = verify_payload(&creation).expect("coherent creation");
    assert!(push.created());
    assert!(!push.deleted());
    assert!(push.forced());
    assert_eq!(push.before_commit_sha(), ZERO_SHA);
}

#[test]
fn retained_strings_and_provider_commit_collection_are_bounded() {
    let mut owner = valid_payload();
    owner["repository"]["owner"]["login"] = json!("o".repeat(101));
    assert_invalid_payload(&owner);

    let mut reference = valid_payload();
    reference["ref"] = json!(format!("refs/heads/{}", "a".repeat(1_024)));
    assert_invalid_payload(&reference);

    let mut complete = valid_payload();
    complete["commits"] = Value::Array(commit_entries(1_000));
    let complete_push = verify_payload(&complete).expect("path-filter evidence maximum");
    assert_eq!(complete_push.commit_count(), 1_000);
    assert_eq!(
        complete_push
            .complete_pushed_commit_revisions()
            .expect("one thousand commit IDs remain complete")
            .len(),
        1_000
    );
    assert!(!complete_push.path_filter_commit_limit_exceeded());

    let mut bypass = valid_payload();
    bypass["commits"] = Value::Array(commit_entries(1_001));
    let bypass_push = verify_payload(&bypass).expect("documented path-filter bypass");
    assert_eq!(bypass_push.commit_count(), 1_001);
    assert!(bypass_push.complete_pushed_commit_revisions().is_none());
    assert!(bypass_push.path_filter_commit_limit_exceeded());

    let mut maximum = valid_payload();
    maximum["commits"] = Value::Array(commit_entries(MAX_GITHUB_PUSH_COMMITS));
    let bounded_push = verify_payload(&maximum).expect("documented payload maximum");
    assert_eq!(bounded_push.commit_count(), MAX_GITHUB_PUSH_COMMITS);
    assert!(bounded_push.path_filter_commit_limit_exceeded());

    let mut excessive = valid_payload();
    excessive["commits"] = Value::Array(commit_entries(MAX_GITHUB_PUSH_COMMITS + 1));
    assert_malformed_payload(&excessive);

    let body = encode(&valid_payload());
    let headers = signed_headers(SECRET, &body, "push", &"d".repeat(129));
    let boundary = GithubWebhookVerifier::new(SECRET).expect("verifier");
    assert_eq!(
        boundary
            .verify(&headers, Bytes::from(body))
            .expect_err("delivery bound"),
        GithubWebhookError::InvalidHeaders
    );
}

#[test]
fn pushed_commit_ids_are_required_canonical_nonzero_and_unique() {
    for malformed in [json!({}), json!({ "id": 7 })] {
        let mut payload = valid_payload();
        payload["commits"] = json!([malformed]);
        assert_malformed_payload(&payload);
    }

    for invalid in [
        "0123456789abcdef0123456789abcdef0123456",
        "0123456789ABCDEF0123456789ABCDEF01234567",
        "0123456789abcdef0123456789abcdef0123456g",
        ZERO_SHA,
    ] {
        let mut payload = valid_payload();
        payload["commits"] = json!([{ "id": invalid }]);
        assert_invalid_payload(&payload);
    }

    let mut duplicate = valid_payload();
    duplicate["commits"] = json!([{ "id": AFTER }, { "id": AFTER }]);
    assert_invalid_payload(&duplicate);
}

#[test]
fn secrets_raw_payloads_and_signatures_never_appear_in_debug_or_errors() {
    let secret = b"unique-secret-leak-marker-1234567890";
    let mut payload = valid_payload();
    payload["private_marker"] = json!("unique-raw-body-leak-marker");
    payload["repository"]["owner"]["login"] = json!("private-owner-marker");
    payload["repository"]["full_name"] = json!("private-owner-marker/automata");
    let body = encode(&payload);
    let headers = signed_headers(secret, &body, "push", "private-delivery-marker");
    let boundary = GithubWebhookVerifier::new(secret).expect("verifier");
    let push = boundary
        .verify(&headers, Bytes::copy_from_slice(&body))
        .expect("verified");
    let signature = headers
        .get(X_HUB_SIGNATURE_256)
        .expect("signature")
        .to_str()
        .expect("ASCII signature");

    let boundary_debug = format!("{boundary:?}");
    let push_debug = format!("{push:?}");
    assert!(!boundary_debug.contains("unique-secret-leak-marker"));
    for marker in [
        "unique-secret-leak-marker",
        "unique-raw-body-leak-marker",
        "private-owner-marker",
        "private-delivery-marker",
        signature,
    ] {
        assert!(!push_debug.contains(marker), "leaked marker: {marker}");
    }

    let wrong_headers = signed_headers(b"another secret", &body, "push", "delivery-error");
    let error = boundary
        .verify(&wrong_headers, Bytes::from(body))
        .expect_err("wrong HMAC");
    let rendered = format!("{error:?} {error}");
    assert_eq!(error, GithubWebhookError::AuthenticationFailed);
    assert!(!rendered.contains("unique-secret-leak-marker"));
    assert!(!rendered.contains("unique-raw-body-leak-marker"));
    assert!(!rendered.contains(signature));

    assert_eq!(
        GithubWebhookVerifier::new(&[]).expect_err("empty secret"),
        GithubWebhookError::InvalidSecret
    );
    let excessive_secret = vec![b'x'; MAX_GITHUB_WEBHOOK_SECRET_BYTES + 1];
    assert_eq!(
        GithubWebhookVerifier::new(&excessive_secret).expect_err("excessive secret"),
        GithubWebhookError::InvalidSecret
    );
}

#[test]
fn verifier_fingerprint_binds_the_exact_hmac_key_without_exposing_it() {
    let verifier = GithubWebhookVerifier::new(SECRET).expect("verifier");
    let mut expected = digest::Context::new(&digest::SHA256);
    expected.update(b"automata.store.github-webhook-verifier-fingerprint.v1\0");
    expected.update(SECRET);
    assert_eq!(
        verifier.fingerprint().as_bytes(),
        expected.finish().as_ref()
    );

    let changed =
        GithubWebhookVerifier::new(b"different webhook verifier secret").expect("changed verifier");
    assert_ne!(verifier.fingerprint(), changed.fingerprint());
    let rendered = format!("{verifier:?} {:?}", verifier.fingerprint());
    assert!(!rendered.contains("correct horse battery staple"));
    assert!(!rendered.contains("different webhook verifier secret"));
}

fn valid_payload() -> Value {
    json!({
        "ref": "refs/heads/main",
        "before": BEFORE,
        "after": AFTER,
        "created": false,
        "deleted": false,
        "forced": false,
        "repository": {
            "id": 42,
            "private": false,
            "visibility": "public",
            "name": "automata",
            "full_name": "octocat/automata",
            "owner": {
                "id": REPOSITORY_OWNER_ID,
                "login": "octocat"
            },
            "ignored_repository_collection": [1, 2, 3]
        },
        "installation": {
            "id": 77
        },
        "commits": [
            { "id": PUSHED_OTHER, "message": "ignored one" },
            { "id": AFTER, "message": "ignored two" }
        ],
        "private_marker": "ignored exact body evidence"
    })
}

fn commit_entries(count: usize) -> Vec<Value> {
    (1..=count)
        .map(|value| json!({ "id": format!("{value:040x}") }))
        .collect()
}

fn verify_payload(
    payload: &Value,
) -> Result<automata_ci_github::VerifiedGithubPush, GithubWebhookError> {
    let body = encode(payload);
    GithubWebhookVerifier::new(SECRET)
        .expect("verifier")
        .verify(
            &signed_headers(SECRET, &body, "push", "delivery-payload"),
            Bytes::from(body),
        )
}

fn assert_invalid_payload(payload: &Value) {
    assert_eq!(
        verify_payload(payload).expect_err("invalid payload"),
        GithubWebhookError::InvalidPayload
    );
}

fn assert_malformed_payload(payload: &Value) {
    assert_eq!(
        verify_payload(payload).expect_err("malformed payload"),
        GithubWebhookError::MalformedPayload
    );
}

fn encode(payload: &Value) -> Vec<u8> {
    serde_json::to_vec(payload).expect("JSON fixture")
}

fn signed_headers(secret: &[u8], body: &[u8], event: &str, delivery: &str) -> HeaderMap {
    let mut headers = HeaderMap::new();
    headers.insert(
        X_HUB_SIGNATURE_256,
        HeaderValue::from_str(&signature(secret, body)).expect("signature header"),
    );
    headers.insert(
        X_GITHUB_EVENT,
        HeaderValue::from_str(event).expect("event header"),
    );
    headers.insert(
        X_GITHUB_DELIVERY,
        HeaderValue::from_str(delivery).expect("delivery header"),
    );
    headers
}

fn signature(secret: &[u8], body: &[u8]) -> String {
    let key = hmac::Key::new(hmac::HMAC_SHA256, secret);
    let tag = hmac::sign(&key, body);
    let mut encoded = String::from("sha256=");
    for byte in tag.as_ref() {
        write!(encoded, "{byte:02x}").expect("write signature");
    }
    encoded
}
