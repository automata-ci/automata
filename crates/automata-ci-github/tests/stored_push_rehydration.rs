use crate::support::{json_body, signed_webhook_headers, webhook_body_digest};

use automata_ci_github::{
    GITHUB_PUSH_EVENT_MEDIA_TYPE, GithubRepositoryVisibility, GithubStoredPushError,
    GithubWebhookBodyDigest, GithubWebhookVerifier, MAX_GITHUB_WEBHOOK_BODY_BYTES,
    StoredAuthenticatedGithubPush, rehydrate_stored_authenticated_github_push,
};
use bytes::Bytes;
use serde_json::{Value, json};

const SECRET: &[u8] = b"stored-push-equivalence-secret";
const DELIVERY: &str = "delivery-stored-123";
const BEFORE: &str = "89abcdef0123456789abcdef0123456789abcdef";
const AFTER: &str = "0123456789abcdef0123456789abcdef01234567";
const INSTALLATION_ID: u64 = 77;
const REPOSITORY_ID: u64 = 42;
const REPOSITORY_OWNER_ID: u64 = 9_876_543;
const REPOSITORY_OWNER: &str = "octocat";
const REPOSITORY_NAME: &str = "automata";

#[test]
fn durable_rehydration_is_exactly_equivalent_to_the_hmac_path() {
    let body = json_body(&valid_payload());
    let hmac_push = GithubWebhookVerifier::new(SECRET)
        .expect("verifier")
        .verify(
            &signed_webhook_headers(SECRET, &body, "push", DELIVERY),
            Bytes::copy_from_slice(&body),
        )
        .expect("authenticated push");

    let stored_push = rehydrate_stored_authenticated_github_push(evidence(
        Bytes::copy_from_slice(&body),
        webhook_body_digest(&body),
        u64::try_from(body.len()).expect("fixture size fits u64"),
        GITHUB_PUSH_EVENT_MEDIA_TYPE,
        DELIVERY,
        INSTALLATION_ID,
        REPOSITORY_ID,
        REPOSITORY_OWNER,
        REPOSITORY_NAME,
    ))
    .expect("stored authenticated push");

    assert_eq!(stored_push, hmac_push);
    assert_eq!(stored_push.before_commit_sha(), BEFORE);
    assert_eq!(stored_push.after_commit_sha(), AFTER);
    assert_eq!(
        stored_push.repository().owner_id().get(),
        REPOSITORY_OWNER_ID
    );
    assert!(!stored_push.created());
    assert!(!stored_push.deleted());
    assert!(stored_push.forced());
    assert_eq!(
        stored_push
            .complete_pushed_commit_revisions()
            .expect("one pushed commit is complete")[0]
            .as_str(),
        AFTER
    );
    assert!(!stored_push.path_filter_commit_limit_exceeded());
}

#[test]
fn durable_rehydration_accepts_the_exact_webhook_ceiling() {
    let mut payload = valid_payload();
    payload["padding"] = json!("");
    let empty_padding = json_body(&payload);
    let padding_bytes = MAX_GITHUB_WEBHOOK_BODY_BYTES
        .checked_sub(empty_padding.len())
        .expect("base push is smaller than the webhook ceiling");
    payload["padding"] = json!("x".repeat(padding_bytes));
    let body = json_body(&payload);
    assert_eq!(body.len(), MAX_GITHUB_WEBHOOK_BODY_BYTES);

    let stored = rehydrate_stored_authenticated_github_push(evidence(
        Bytes::from(body.clone()),
        webhook_body_digest(&body),
        u64::try_from(body.len()).expect("exact webhook ceiling fits u64"),
        GITHUB_PUSH_EVENT_MEDIA_TYPE,
        DELIVERY,
        INSTALLATION_ID,
        REPOSITORY_ID,
        REPOSITORY_OWNER,
        REPOSITORY_NAME,
    ))
    .expect("exact webhook ceiling rehydrates");
    assert_eq!(stored.raw_body().len(), MAX_GITHUB_WEBHOOK_BODY_BYTES);
}

#[test]
fn durable_coordinates_and_stale_body_bytes_fail_before_normalization() {
    let malformed = Bytes::from_static(b"private-malformed-body-marker:{");
    let size = u64::try_from(malformed.len()).expect("fixture size fits u64");
    let digest = webhook_body_digest(&malformed);

    assert_eq!(
        rehydrate_stored_authenticated_github_push(evidence(
            malformed.clone(),
            digest,
            size,
            "application/json",
            DELIVERY,
            INSTALLATION_ID,
            REPOSITORY_ID,
            REPOSITORY_OWNER,
            REPOSITORY_NAME,
        ))
        .expect_err("noncanonical media"),
        GithubStoredPushError::UnexpectedMediaType
    );
    assert_eq!(
        rehydrate_stored_authenticated_github_push(evidence(
            malformed.clone(),
            digest,
            size + 1,
            GITHUB_PUSH_EVENT_MEDIA_TYPE,
            DELIVERY,
            INSTALLATION_ID,
            REPOSITORY_ID,
            REPOSITORY_OWNER,
            REPOSITORY_NAME,
        ))
        .expect_err("changed encoded size"),
        GithubStoredPushError::SizeMismatch
    );
    assert_eq!(
        rehydrate_stored_authenticated_github_push(evidence(
            malformed.clone(),
            GithubWebhookBodyDigest::from_bytes([0x5a; 32]),
            size,
            GITHUB_PUSH_EVENT_MEDIA_TYPE,
            DELIVERY,
            INSTALLATION_ID,
            REPOSITORY_ID,
            REPOSITORY_OWNER,
            REPOSITORY_NAME,
        ))
        .expect_err("changed digest"),
        GithubStoredPushError::DigestMismatch
    );
    assert_eq!(
        rehydrate_stored_authenticated_github_push(evidence(
            malformed,
            digest,
            size,
            GITHUB_PUSH_EVENT_MEDIA_TYPE,
            "invalid delivery identity",
            INSTALLATION_ID,
            REPOSITORY_ID,
            REPOSITORY_OWNER,
            REPOSITORY_NAME,
        ))
        .expect_err("changed durable identity"),
        GithubStoredPushError::InvalidDurableIdentity
    );

    let original = json_body(&valid_payload());
    let original_digest = webhook_body_digest(&original);
    let mut changed = original;
    changed.push(b' ');
    assert_eq!(
        rehydrate_stored_authenticated_github_push(evidence(
            Bytes::copy_from_slice(&changed),
            original_digest,
            u64::try_from(changed.len()).expect("fixture size fits u64"),
            GITHUB_PUSH_EVENT_MEDIA_TYPE,
            DELIVERY,
            INSTALLATION_ID,
            REPOSITORY_ID,
            REPOSITORY_OWNER,
            REPOSITORY_NAME,
        ))
        .expect_err("stored body changed after authentication"),
        GithubStoredPushError::DigestMismatch
    );
}

#[test]
fn every_durable_identity_mismatch_precedes_push_normalization() {
    let mut invalid_ref_payload = valid_payload();
    invalid_ref_payload["ref"] = json!("not-a-full-ref");
    let body = json_body(&invalid_ref_payload);
    let size = u64::try_from(body.len()).expect("fixture size fits u64");
    let digest = webhook_body_digest(&body);

    for stored in [
        evidence(
            Bytes::copy_from_slice(&body),
            digest,
            size,
            GITHUB_PUSH_EVENT_MEDIA_TYPE,
            DELIVERY,
            INSTALLATION_ID + 1,
            REPOSITORY_ID,
            REPOSITORY_OWNER,
            REPOSITORY_NAME,
        ),
        evidence(
            Bytes::copy_from_slice(&body),
            digest,
            size,
            GITHUB_PUSH_EVENT_MEDIA_TYPE,
            DELIVERY,
            INSTALLATION_ID,
            REPOSITORY_ID + 1,
            REPOSITORY_OWNER,
            REPOSITORY_NAME,
        ),
        evidence(
            Bytes::copy_from_slice(&body),
            digest,
            size,
            GITHUB_PUSH_EVENT_MEDIA_TYPE,
            DELIVERY,
            INSTALLATION_ID,
            REPOSITORY_ID,
            "different-owner",
            REPOSITORY_NAME,
        ),
        evidence(
            Bytes::copy_from_slice(&body),
            digest,
            size,
            GITHUB_PUSH_EVENT_MEDIA_TYPE,
            DELIVERY,
            INSTALLATION_ID,
            REPOSITORY_ID,
            REPOSITORY_OWNER,
            "different-name",
        ),
        evidence_with_owner_id(
            Bytes::copy_from_slice(&body),
            digest,
            size,
            GITHUB_PUSH_EVENT_MEDIA_TYPE,
            DELIVERY,
            INSTALLATION_ID,
            REPOSITORY_ID,
            REPOSITORY_OWNER_ID + 1,
            REPOSITORY_OWNER,
            REPOSITORY_NAME,
        ),
    ] {
        assert_eq!(
            rehydrate_stored_authenticated_github_push(stored)
                .expect_err("identity mismatch precedes invalid ref normalization"),
            GithubStoredPushError::IdentityMismatch
        );
    }
}

#[test]
fn every_invalid_durable_identity_precedes_push_normalization() {
    let mut invalid_ref_payload = valid_payload();
    invalid_ref_payload["ref"] = json!("not-a-full-ref");
    let body = json_body(&invalid_ref_payload);
    let size = u64::try_from(body.len()).expect("fixture size fits u64");
    let digest = webhook_body_digest(&body);

    for stored in [
        evidence(
            Bytes::copy_from_slice(&body),
            digest,
            size,
            GITHUB_PUSH_EVENT_MEDIA_TYPE,
            DELIVERY,
            0,
            REPOSITORY_ID,
            REPOSITORY_OWNER,
            REPOSITORY_NAME,
        ),
        evidence(
            Bytes::copy_from_slice(&body),
            digest,
            size,
            GITHUB_PUSH_EVENT_MEDIA_TYPE,
            DELIVERY,
            INSTALLATION_ID,
            u64::MAX,
            REPOSITORY_OWNER,
            REPOSITORY_NAME,
        ),
        evidence(
            Bytes::copy_from_slice(&body),
            digest,
            size,
            GITHUB_PUSH_EVENT_MEDIA_TYPE,
            DELIVERY,
            INSTALLATION_ID,
            REPOSITORY_ID,
            "owner/ambiguous",
            REPOSITORY_NAME,
        ),
        evidence(
            Bytes::copy_from_slice(&body),
            digest,
            size,
            GITHUB_PUSH_EVENT_MEDIA_TYPE,
            DELIVERY,
            INSTALLATION_ID,
            REPOSITORY_ID,
            REPOSITORY_OWNER,
            "automata.git",
        ),
        evidence_with_owner_id(
            Bytes::copy_from_slice(&body),
            digest,
            size,
            GITHUB_PUSH_EVENT_MEDIA_TYPE,
            DELIVERY,
            INSTALLATION_ID,
            REPOSITORY_ID,
            0,
            REPOSITORY_OWNER,
            REPOSITORY_NAME,
        ),
        evidence_with_owner_id(
            Bytes::copy_from_slice(&body),
            digest,
            size,
            GITHUB_PUSH_EVENT_MEDIA_TYPE,
            DELIVERY,
            INSTALLATION_ID,
            REPOSITORY_ID,
            u64::try_from(i64::MAX).expect("i64 fits u64") + 1,
            REPOSITORY_OWNER,
            REPOSITORY_NAME,
        ),
    ] {
        assert_eq!(
            rehydrate_stored_authenticated_github_push(stored)
                .expect_err("invalid durable identity precedes push normalization"),
            GithubStoredPushError::InvalidDurableIdentity
        );
    }
}

#[test]
fn stored_repository_owner_identity_rejects_missing_malformed_tampered_and_mismatched_evidence() {
    let mut missing = valid_payload();
    missing["repository"]["owner"]
        .as_object_mut()
        .expect("owner object")
        .remove("id");
    assert_stored_error(&missing, GithubStoredPushError::MalformedPayload);

    let mut malformed = valid_payload();
    malformed["repository"]["owner"]["id"] = json!("9876543");
    assert_stored_error(&malformed, GithubStoredPushError::MalformedPayload);

    for invalid in [
        0,
        u64::try_from(i64::MAX).expect("i64 fits u64") + 1,
        REPOSITORY_OWNER_ID + 1,
    ] {
        let mut mismatched = valid_payload();
        mismatched["repository"]["owner"]["id"] = json!(invalid);
        assert_stored_error(&mismatched, GithubStoredPushError::IdentityMismatch);
    }

    let original = json_body(&valid_payload());
    let mut tampered = valid_payload();
    tampered["repository"]["owner"]["id"] = json!(REPOSITORY_OWNER_ID + 1);
    let tampered = json_body(&tampered);
    assert_eq!(
        tampered.len(),
        original.len(),
        "fixture changes only digits"
    );
    assert_eq!(
        rehydrate_stored_authenticated_github_push(evidence(
            Bytes::from(tampered.clone()),
            webhook_body_digest(&original),
            u64::try_from(tampered.len()).expect("fixture size fits u64"),
            GITHUB_PUSH_EVENT_MEDIA_TYPE,
            DELIVERY,
            INSTALLATION_ID,
            REPOSITORY_ID,
            REPOSITORY_OWNER,
            REPOSITORY_NAME,
        ))
        .expect_err("tampered owner identity bytes"),
        GithubStoredPushError::DigestMismatch
    );
}

#[test]
fn stored_body_identity_and_strict_push_constraints_cannot_be_rebound() {
    let mut changed_identity = valid_payload();
    changed_identity["repository"]["owner"]["login"] = json!("private-changed-owner");
    changed_identity["repository"]["full_name"] = json!("private-changed-owner/automata");
    assert_stored_error(&changed_identity, GithubStoredPushError::IdentityMismatch);

    let mut changed_visibility = valid_payload();
    changed_visibility["repository"]["private"] = json!(true);
    changed_visibility["repository"]["visibility"] = json!("private");
    assert_stored_error(&changed_visibility, GithubStoredPushError::IdentityMismatch);

    let mut inconsistent_range = valid_payload();
    inconsistent_range["before"] = json!("0000000000000000000000000000000000000000");
    inconsistent_range["created"] = json!(false);
    assert_stored_error(&inconsistent_range, GithubStoredPushError::InvalidPayload);

    let mut missing_forced = valid_payload();
    missing_forced
        .as_object_mut()
        .expect("payload object")
        .remove("forced");
    assert_stored_error(&missing_forced, GithubStoredPushError::MalformedPayload);

    let mut duplicate_commit = valid_payload();
    duplicate_commit["commits"] = json!([{ "id": AFTER }, { "id": AFTER }]);
    assert_stored_error(&duplicate_commit, GithubStoredPushError::InvalidPayload);

    let mut zero_commit = valid_payload();
    zero_commit["commits"] = json!([{
        "id": "0000000000000000000000000000000000000000"
    }]);
    assert_stored_error(&zero_commit, GithubStoredPushError::InvalidPayload);
}

#[test]
fn stored_evidence_debug_and_errors_redact_body_and_identity_values() {
    let mut payload = valid_payload();
    payload["private_marker"] = json!("private-stored-body-marker");
    payload["repository"]["owner"]["login"] = json!("private-owner-marker");
    payload["repository"]["full_name"] = json!("private-owner-marker/private-name-marker");
    payload["repository"]["name"] = json!("private-name-marker");
    let body = json_body(&payload);
    let stored = evidence(
        Bytes::copy_from_slice(&body),
        webhook_body_digest(&body),
        u64::try_from(body.len()).expect("fixture size fits u64"),
        "private-media-marker",
        "private-delivery-marker",
        INSTALLATION_ID,
        REPOSITORY_ID,
        "private-owner-marker",
        "private-name-marker",
    );

    let debug = format!("{stored:?}");
    for marker in [
        "private-stored-body-marker",
        "private-owner-marker",
        "private-name-marker",
        "private-delivery-marker",
        "private-media-marker",
        &webhook_body_digest(&body).to_string(),
    ] {
        assert!(!debug.contains(marker), "stored Debug leaked {marker}");
    }

    let error = rehydrate_stored_authenticated_github_push(evidence(
        Bytes::copy_from_slice(&body),
        webhook_body_digest(&body),
        u64::try_from(body.len()).expect("fixture size fits u64"),
        GITHUB_PUSH_EVENT_MEDIA_TYPE,
        "private-delivery-marker",
        INSTALLATION_ID,
        REPOSITORY_ID,
        REPOSITORY_OWNER,
        REPOSITORY_NAME,
    ))
    .expect_err("body identity differs from durable identity");
    let rendered = format!("{error:?} {error}");
    assert_eq!(error, GithubStoredPushError::IdentityMismatch);
    for marker in [
        "private-stored-body-marker",
        "private-owner-marker",
        "private-name-marker",
        "private-delivery-marker",
    ] {
        assert!(!rendered.contains(marker), "stored error leaked {marker}");
    }
}

#[allow(clippy::too_many_arguments)]
fn evidence(
    raw_body: Bytes,
    body_sha256: GithubWebhookBodyDigest,
    encoded_size: u64,
    media_type: &str,
    delivery_id: &str,
    installation_id: u64,
    repository_id: u64,
    repository_owner: &str,
    repository_name: &str,
) -> StoredAuthenticatedGithubPush {
    evidence_with_owner_id(
        raw_body,
        body_sha256,
        encoded_size,
        media_type,
        delivery_id,
        installation_id,
        repository_id,
        REPOSITORY_OWNER_ID,
        repository_owner,
        repository_name,
    )
}

#[allow(clippy::too_many_arguments)]
fn evidence_with_owner_id(
    raw_body: Bytes,
    body_sha256: GithubWebhookBodyDigest,
    encoded_size: u64,
    media_type: &str,
    delivery_id: &str,
    installation_id: u64,
    repository_id: u64,
    repository_owner_id: u64,
    repository_owner: &str,
    repository_name: &str,
) -> StoredAuthenticatedGithubPush {
    StoredAuthenticatedGithubPush::from_durable_coordinates(
        raw_body,
        body_sha256,
        encoded_size,
        media_type,
        delivery_id,
        installation_id,
        repository_id,
        repository_owner_id,
        GithubRepositoryVisibility::Public,
        repository_owner,
        repository_name,
    )
}

fn assert_stored_error(payload: &Value, expected: GithubStoredPushError) {
    let body = json_body(payload);
    let error = rehydrate_stored_authenticated_github_push(evidence(
        Bytes::copy_from_slice(&body),
        webhook_body_digest(&body),
        u64::try_from(body.len()).expect("fixture size fits u64"),
        GITHUB_PUSH_EVENT_MEDIA_TYPE,
        DELIVERY,
        INSTALLATION_ID,
        REPOSITORY_ID,
        REPOSITORY_OWNER,
        REPOSITORY_NAME,
    ))
    .expect_err("stored payload is rejected");
    assert_eq!(error, expected);
}

fn valid_payload() -> Value {
    json!({
        "ref": "refs/heads/main",
        "before": BEFORE,
        "after": AFTER,
        "created": false,
        "deleted": false,
        "forced": true,
        "repository": {
            "id": REPOSITORY_ID,
            "private": false,
            "visibility": "public",
            "name": REPOSITORY_NAME,
            "full_name": "octocat/automata",
            "owner": {
                "id": REPOSITORY_OWNER_ID,
                "login": REPOSITORY_OWNER
            }
        },
        "installation": {
            "id": INSTALLATION_ID
        },
        "commits": [
            { "id": AFTER, "message": "not interpreted as a diff" }
        ]
    })
}
