use std::fmt::Write as _;

use automata_ci_github::{
    GITHUB_AUTHENTICATED_EVENT_V1_MEDIA_TYPE, GithubMergeGroupAction, GithubPullRequestAction,
    GithubPushRefKind, GithubRepositoryVisibility, GithubStoredWebhookError,
    GithubWebhookBodyDigest, GithubWebhookError, GithubWebhookVerifier,
    StoredAuthenticatedGithubWebhookV1, VerifiedGithubWebhook, X_GITHUB_DELIVERY, X_GITHUB_EVENT,
    X_HUB_SIGNATURE_256, rehydrate_stored_authenticated_github_webhook_v1,
};
use bytes::Bytes;
use reqwest::header::{HeaderMap, HeaderValue};
use ring::{digest, hmac};
use serde_json::{Value, json};

const SECRET: &[u8] = b"independent synthetic webhook secret";
const BASE_SHA: &str = "0123456789abcdef0123456789abcdef01234567";
const HEAD_SHA: &str = "89abcdef0123456789abcdef0123456789abcdef";
const MERGE_SHA: &str = "76543210fedcba9876543210fedcba9876543210";
const GROUP_SHA: &str = "fedcba9876543210fedcba9876543210fedcba98";

#[test]
fn pull_request_normalization_retains_exact_dispatch_evidence() {
    let body = encode(&pull_request_payload());
    let event = normalize_bytes(&body, "pull_request", "delivery-pr-7").expect("normalized event");

    assert_eq!(event.delivery_id(), "delivery-pr-7");
    assert_eq!(event.event_name(), "pull_request");
    assert_eq!(event.raw_body().as_ref(), body);
    assert_eq!(
        event.body_sha256().as_bytes(),
        digest::digest(&digest::SHA256, &body).as_ref()
    );
    assert_eq!(event.installation_id().get(), 71);
    assert_eq!(event.repository().id().get(), 41);

    let VerifiedGithubWebhook::PullRequest(event) = event else {
        panic!("expected pull-request evidence");
    };
    assert_eq!(event.action(), GithubPullRequestAction::Opened);
    assert_eq!(event.action().as_str(), "opened");
    assert!(!event.merged());
    assert_eq!(event.number().get(), 7);
    assert_eq!(event.repository().owner_id().get(), 11);
    assert_eq!(
        event.repository().visibility(),
        GithubRepositoryVisibility::Public
    );
    assert_eq!(event.repository().full_name(), "example/base-repository");
    assert_eq!(event.head_repository().id().get(), 42);
    assert_eq!(
        event.head_repository().full_name(),
        "contributor/head-repository"
    );
    assert_eq!(event.head_revision().as_str(), HEAD_SHA);
    assert_eq!(event.base_revision().as_str(), BASE_SHA);
    assert_eq!(event.merge_revision().as_str(), MERGE_SHA);
    assert_eq!(event.head_ref(), "feature/topic");
    assert_eq!(event.base_ref(), "main");
    assert_eq!(event.git_ref(), "refs/pull/7/merge");
}

#[test]
fn merged_pull_request_uses_the_target_branch_workflow_ref() {
    let mut payload = pull_request_payload();
    payload["action"] = json!("closed");
    payload["pull_request"]["merged"] = json!(true);

    let event = normalize_payload(&payload, "pull_request").expect("merged pull request");
    let VerifiedGithubWebhook::PullRequest(event) = event else {
        panic!("expected pull-request evidence");
    };
    assert!(event.merged());
    assert_eq!(event.action(), GithubPullRequestAction::Closed);
    assert_eq!(event.git_ref(), "refs/heads/main");

    payload["action"] = json!("opened");
    assert_invalid_pull_request(&payload);
}

#[test]
fn merge_group_normalization_retains_exact_dispatch_evidence() {
    let body = encode(&merge_group_payload());
    let event =
        normalize_bytes(&body, "merge_group", "delivery-group-9").expect("normalized merge group");

    assert_eq!(event.delivery_id(), "delivery-group-9");
    assert_eq!(event.raw_body().as_ref(), body);
    assert_eq!(event.installation_id().get(), 71);
    let VerifiedGithubWebhook::MergeGroup(event) = event else {
        panic!("expected merge-group evidence");
    };
    assert_eq!(event.action(), GithubMergeGroupAction::ChecksRequested);
    assert_eq!(event.action().as_str(), "checks_requested");
    assert_eq!(event.head_revision().as_str(), GROUP_SHA);
    assert_eq!(event.base_revision().as_str(), BASE_SHA);
    assert_eq!(
        event.head_ref().full(),
        "refs/heads/merge-queue/main/group-9"
    );
    assert_eq!(event.head_ref().short_name(), "merge-queue/main/group-9");
    assert_eq!(event.head_ref().kind(), GithubPushRefKind::Branch);
    assert_eq!(event.base_ref().full(), "refs/heads/main");
}

#[test]
fn only_documented_event_actions_are_admitted() {
    let mut pull_request = pull_request_payload();
    pull_request["action"] = json!("future_activity");
    assert_payload_error(
        &pull_request,
        "pull_request",
        GithubWebhookError::InvalidPayload,
    );

    let mut merge_group = merge_group_payload();
    merge_group["action"] = json!("future_activity");
    assert_payload_error(
        &merge_group,
        "merge_group",
        GithubWebhookError::InvalidPayload,
    );

    merge_group["action"] = json!("destroyed");
    let event = normalize_payload(&merge_group, "merge_group").expect("documented activity");
    let VerifiedGithubWebhook::MergeGroup(event) = event else {
        panic!("expected merge-group evidence");
    };
    assert_eq!(event.action(), GithubMergeGroupAction::Destroyed);
}

#[test]
fn duplicate_or_malformed_json_is_rejected_before_typed_decoding() {
    let canonical = String::from_utf8(encode(&pull_request_payload())).expect("UTF-8 JSON");
    let duplicate_action = canonical.replacen(
        "\"action\":\"opened\"",
        "\"action\":\"opened\",\"action\":\"closed\"",
        1,
    );
    assert_bytes_error(
        duplicate_action.as_bytes(),
        "pull_request",
        GithubWebhookError::MalformedPayload,
    );

    let duplicate_untyped_nested = canonical.replacen(
        "\"sender\":{\"id\":301}",
        "\"sender\":{\"opaque\":1,\"opaque\":2}",
        1,
    );
    assert_bytes_error(
        duplicate_untyped_nested.as_bytes(),
        "pull_request",
        GithubWebhookError::MalformedPayload,
    );
    assert_bytes_error(
        b"{\"action\":",
        "pull_request",
        GithubWebhookError::MalformedPayload,
    );
}

#[test]
fn pull_request_identities_revisions_and_refs_must_be_coherent() {
    let mut mismatched_number = pull_request_payload();
    mismatched_number["pull_request"]["number"] = json!(8);
    assert_invalid_pull_request(&mismatched_number);

    let mut mismatched_repository = pull_request_payload();
    mismatched_repository["pull_request"]["base"]["repo"]["id"] = json!(99);
    assert_invalid_pull_request(&mismatched_repository);

    for (pointer, value) in [
        ("/installation/id", json!(0)),
        (
            "/repository/id",
            json!(u64::try_from(i64::MAX).expect("fits") + 1),
        ),
        (
            "/pull_request/head/sha",
            json!(HEAD_SHA.to_ascii_uppercase()),
        ),
        ("/pull_request/merge_commit_sha", json!("0".repeat(40))),
        ("/pull_request/base/sha", json!("0".repeat(40))),
        ("/pull_request/head/ref", json!("feature//topic")),
        ("/pull_request/base/ref", json!("bad..branch")),
    ] {
        let mut payload = pull_request_payload();
        *payload.pointer_mut(pointer).expect("fixture pointer") = value;
        let error = normalize_payload(&payload, "pull_request")
            .err()
            .unwrap_or_else(|| panic!("accepted invalid field {pointer}"));
        assert_eq!(
            error,
            GithubWebhookError::InvalidPayload,
            "wrong error for invalid field {pointer}"
        );
    }

    let mut missing_installation = pull_request_payload();
    missing_installation
        .as_object_mut()
        .expect("object")
        .remove("installation");
    assert_payload_error(
        &missing_installation,
        "pull_request",
        GithubWebhookError::MalformedPayload,
    );

    let mut missing_merge_revision = pull_request_payload();
    missing_merge_revision["pull_request"]
        .as_object_mut()
        .expect("pull request object")
        .remove("merge_commit_sha");
    assert_payload_error(
        &missing_merge_revision,
        "pull_request",
        GithubWebhookError::InvalidPayload,
    );
}

#[test]
fn merge_group_revisions_and_full_branch_refs_are_strict() {
    for (pointer, value) in [
        ("/merge_group/head_sha", json!("0".repeat(40))),
        (
            "/merge_group/base_sha",
            json!(BASE_SHA.to_ascii_uppercase()),
        ),
        ("/merge_group/head_ref", json!("refs/tags/group-9")),
        ("/merge_group/base_ref", json!("main")),
        (
            "/merge_group/head_ref",
            json!(format!("refs/heads/{}", "a".repeat(1_024))),
        ),
    ] {
        let mut payload = merge_group_payload();
        *payload.pointer_mut(pointer).expect("fixture pointer") = value;
        let error = normalize_payload(&payload, "merge_group")
            .err()
            .unwrap_or_else(|| panic!("accepted invalid field {pointer}"));
        assert_eq!(
            error,
            GithubWebhookError::InvalidPayload,
            "wrong error for invalid field {pointer}"
        );
    }
}

#[test]
fn normalized_debug_redacts_authenticated_and_selector_values() {
    let payload = pull_request_payload();
    let body = encode(&payload);
    let event = normalize_bytes(&body, "pull_request", "private-delivery-marker")
        .expect("normalized event");
    let debug = format!("{event:?}");

    for marker in [
        "private-delivery-marker",
        "example/base-repository",
        "contributor/head-repository",
        "feature/topic",
        HEAD_SHA,
        BASE_SHA,
        MERGE_SHA,
    ] {
        assert!(!debug.contains(marker), "leaked marker: {marker}");
    }
}

#[test]
fn unsupported_event_headers_fail_closed_after_authentication() {
    let payload = pull_request_payload();
    assert_payload_error(
        &payload,
        "repository_dispatch",
        GithubWebhookError::UnsupportedEvent,
    );
}

#[test]
fn durable_event_v1_rehydrates_each_supported_kind_without_reserialization() {
    for (payload, event_name, delivery_id) in [
        (push_payload(), "push", "durable-push-5"),
        (pull_request_payload(), "pull_request", "durable-pr-7"),
        (merge_group_payload(), "merge_group", "durable-group-9"),
    ] {
        let body = encode(&payload);
        let stored = stored_event_v1(&body, event_name, delivery_id);
        let event = rehydrate_stored_authenticated_github_webhook_v1(stored)
            .expect("rehydrated authenticated event");
        assert_eq!(event.event_name(), event_name);
        assert_eq!(event.delivery_id(), delivery_id);
        assert_eq!(event.raw_body().as_ref(), body);
        assert_eq!(event.repository().full_name(), "example/base-repository");
    }
}

#[test]
fn durable_event_v1_rejects_envelope_drift_and_duplicate_json() {
    let body = encode(&pull_request_payload());
    let wrong_event = stored_event_v1(&body, "merge_group", "durable-pr-7");
    assert_eq!(
        rehydrate_stored_authenticated_github_webhook_v1(wrong_event)
            .expect_err("event-name drift must fail"),
        GithubStoredWebhookError::MalformedPayload
    );

    let duplicate = String::from_utf8(body)
        .expect("UTF-8 JSON")
        .replacen(
            "\"action\":\"opened\"",
            "\"action\":\"opened\",\"action\":\"closed\"",
            1,
        )
        .into_bytes();
    let stored = stored_event_v1(&duplicate, "pull_request", "durable-pr-7");
    assert_eq!(
        rehydrate_stored_authenticated_github_webhook_v1(stored)
            .expect_err("duplicate JSON must fail"),
        GithubStoredWebhookError::MalformedPayload
    );
}

fn pull_request_payload() -> Value {
    json!({
        "action": "opened",
        "number": 7,
        "pull_request": {
            "number": 7,
            "merged": false,
            "merge_commit_sha": MERGE_SHA,
            "head": {
                "ref": "feature/topic",
                "sha": HEAD_SHA,
                "repo": head_repository()
            },
            "base": {
                "ref": "main",
                "sha": BASE_SHA,
                "repo": base_repository()
            }
        },
        "repository": base_repository(),
        "installation": { "id": 71 },
        "sender": { "id": 301 }
    })
}

fn push_payload() -> Value {
    json!({
        "ref": "refs/heads/main",
        "before": BASE_SHA,
        "after": HEAD_SHA,
        "created": false,
        "deleted": false,
        "forced": false,
        "repository": base_repository(),
        "installation": { "id": 71 },
        "commits": []
    })
}

fn merge_group_payload() -> Value {
    json!({
        "action": "checks_requested",
        "merge_group": {
            "head_sha": GROUP_SHA,
            "head_ref": "refs/heads/merge-queue/main/group-9",
            "base_sha": BASE_SHA,
            "base_ref": "refs/heads/main",
            "head_commit": {}
        },
        "repository": base_repository(),
        "installation": { "id": 71 },
        "sender": { "id": 301 }
    })
}

fn base_repository() -> Value {
    repository(41, 11, "example", "base-repository")
}

fn head_repository() -> Value {
    repository(42, 12, "contributor", "head-repository")
}

fn repository(id: u64, owner_id: u64, owner: &str, name: &str) -> Value {
    json!({
        "id": id,
        "private": false,
        "visibility": "public",
        "name": name,
        "full_name": format!("{owner}/{name}"),
        "owner": { "id": owner_id, "login": owner }
    })
}

fn normalize_payload(
    payload: &Value,
    event_name: &str,
) -> Result<VerifiedGithubWebhook, GithubWebhookError> {
    normalize_bytes(&encode(payload), event_name, "synthetic-delivery")
}

fn normalize_bytes(
    body: &[u8],
    event_name: &str,
    delivery_id: &str,
) -> Result<VerifiedGithubWebhook, GithubWebhookError> {
    let headers = signed_headers(body, event_name, delivery_id);
    GithubWebhookVerifier::new(SECRET)
        .expect("verifier")
        .authenticate(&headers, Bytes::copy_from_slice(body))?
        .normalize()
}

fn assert_invalid_pull_request(payload: &Value) {
    assert_payload_error(payload, "pull_request", GithubWebhookError::InvalidPayload);
}

fn assert_payload_error(payload: &Value, event_name: &str, expected: GithubWebhookError) {
    assert_bytes_error(&encode(payload), event_name, expected);
}

fn assert_bytes_error(body: &[u8], event_name: &str, expected: GithubWebhookError) {
    assert_eq!(
        normalize_bytes(body, event_name, "synthetic-delivery").expect_err("rejected payload"),
        expected
    );
}

fn encode(payload: &Value) -> Vec<u8> {
    serde_json::to_vec(payload).expect("JSON fixture")
}

fn signed_headers(body: &[u8], event_name: &str, delivery_id: &str) -> HeaderMap {
    let key = hmac::Key::new(hmac::HMAC_SHA256, SECRET);
    let tag = hmac::sign(&key, body);
    let mut signature = String::from("sha256=");
    for byte in tag.as_ref() {
        write!(&mut signature, "{byte:02x}").expect("write signature");
    }

    let mut headers = HeaderMap::new();
    headers.insert(
        X_HUB_SIGNATURE_256,
        HeaderValue::from_str(&signature).expect("signature header"),
    );
    headers.insert(
        X_GITHUB_EVENT,
        HeaderValue::from_str(event_name).expect("event header"),
    );
    headers.insert(
        X_GITHUB_DELIVERY,
        HeaderValue::from_str(delivery_id).expect("delivery header"),
    );
    headers
}

fn stored_event_v1(
    body: &[u8],
    event_name: &str,
    delivery_id: &str,
) -> StoredAuthenticatedGithubWebhookV1 {
    let body_digest: [u8; 32] = digest::digest(&digest::SHA256, body)
        .as_ref()
        .try_into()
        .expect("SHA-256 length");
    StoredAuthenticatedGithubWebhookV1::from_durable_coordinates(
        Bytes::copy_from_slice(body),
        GithubWebhookBodyDigest::from_bytes(body_digest),
        u64::try_from(body.len()).expect("fixture size"),
        GITHUB_AUTHENTICATED_EVENT_V1_MEDIA_TYPE,
        event_name,
        delivery_id,
        71,
        41,
        11,
        GithubRepositoryVisibility::Public,
        "example",
        "base-repository",
    )
}
