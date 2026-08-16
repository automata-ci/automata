use crate::support::{
    BASE_SHA, GROUP_SHA, HEAD_SHA, MERGE_SHA, base_repository, head_repository, json_body,
    signed_webhook_headers, webhook_body_digest,
};

use automata_ci_github::{
    GITHUB_AUTHENTICATED_EVENT_MEDIA_TYPE, GithubCheckRunAction, GithubMergeGroupAction,
    GithubPullRequestAction, GithubPushRefKind, GithubRepositoryVisibility,
    GithubStoredWebhookError, GithubWebhookError, GithubWebhookVerifier,
    StoredAuthenticatedGithubWebhook, VerifiedGithubWebhook,
    rehydrate_stored_authenticated_github_webhook,
};
use bytes::Bytes;
use ring::digest;
use serde_json::{Value, json};

const SECRET: &[u8] = b"independent synthetic webhook secret";

#[test]
fn check_run_controls_retain_exact_signed_identity() {
    let event = normalize_payload(&check_run_payload("rerequested", None), "check_run")
        .expect("check run rerun");
    let VerifiedGithubWebhook::CheckRun(event) = event else {
        panic!("expected check-run evidence");
    };
    assert_eq!(event.installation_id().get(), 71);
    assert_eq!(event.repository().id().get(), 41);
    assert_eq!(event.sender_id().get(), 301);
    assert_eq!(event.app_id().get(), 17);
    assert_eq!(event.run_id().get(), 41);
    assert_eq!(event.suite_id().get(), 23);
    assert_eq!(event.head_revision().as_str(), HEAD_SHA);
    assert_eq!(
        event.external_id(),
        "automata-check:00000000-0000-4000-8000-000000000001"
    );
    assert_eq!(event.action(), GithubCheckRunAction::Rerequested);

    let event = normalize_payload(
        &check_run_payload("requested_action", Some("rerun_failed")),
        "check_run",
    )
    .expect("requested action");
    let VerifiedGithubWebhook::CheckRun(event) = event else {
        panic!("expected check-run evidence");
    };
    assert_eq!(event.action(), GithubCheckRunAction::RerunFailed);
    assert!(!format!("{event:?}").contains(event.external_id()));
}

#[test]
fn check_controls_reject_unsupported_or_inconsistent_payloads() {
    for payload in [
        check_run_payload("completed", None),
        check_run_payload("requested_action", None),
        check_run_payload("requested_action", Some("unknown")),
    ] {
        assert_payload_error(&payload, "check_run", GithubWebhookError::InvalidPayload);
    }
    let mut inconsistent = check_run_payload("rerequested", None);
    inconsistent["check_run"]["check_suite"]["head_sha"] = json!(BASE_SHA);
    assert_payload_error(
        &inconsistent,
        "check_run",
        GithubWebhookError::InvalidPayload,
    );

    let mut suite = check_suite_payload();
    suite["action"] = json!("completed");
    assert_payload_error(&suite, "check_suite", GithubWebhookError::InvalidPayload);
}

#[test]
fn check_suite_rerequest_retains_suite_app_sender_and_revision() {
    let event = normalize_payload(&check_suite_payload(), "check_suite").expect("check suite");
    let VerifiedGithubWebhook::CheckSuite(event) = event else {
        panic!("expected check-suite evidence");
    };
    assert_eq!(event.sender_id().get(), 301);
    assert_eq!(event.app_id().get(), 17);
    assert_eq!(event.suite_id().get(), 23);
    assert_eq!(event.head_revision().as_str(), HEAD_SHA);
}

#[test]
fn pull_request_normalization_retains_exact_dispatch_evidence() {
    let body = json_body(&pull_request_payload());
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
fn unmerged_pull_request_without_materialized_merge_revision_uses_head_revision() {
    let mut payload = pull_request_payload();
    payload["pull_request"]["merge_commit_sha"] = Value::Null;

    let event = normalize_payload(&payload, "pull_request")
        .expect("GitHub may not have materialized the merge revision yet");
    let VerifiedGithubWebhook::PullRequest(event) = event else {
        panic!("expected pull-request evidence");
    };
    assert!(!event.merged());
    assert_eq!(event.head_revision().as_str(), HEAD_SHA);
    assert_eq!(event.merge_revision().as_str(), HEAD_SHA);
    assert_eq!(event.git_ref(), "refs/pull/7/merge");

    payload["action"] = json!("closed");
    payload["pull_request"]["merged"] = json!(true);
    assert_invalid_pull_request(&payload);
}

#[test]
fn merge_group_normalization_retains_exact_dispatch_evidence() {
    let body = json_body(&merge_group_payload());
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
fn repository_dispatch_normalization_retains_bounded_custom_evidence() {
    let body = json_body(&repository_dispatch_payload());
    let event = normalize_bytes(&body, "repository_dispatch", "delivery-custom-3")
        .expect("normalized repository dispatch");

    assert_eq!(event.delivery_id(), "delivery-custom-3");
    assert_eq!(event.event_name(), "repository_dispatch");
    assert_eq!(event.raw_body().as_ref(), body);
    assert_eq!(event.installation_id().get(), 71);
    let VerifiedGithubWebhook::RepositoryDispatch(event) = event else {
        panic!("expected repository-dispatch evidence");
    };
    assert_eq!(event.event_type(), "synthetic_signal");
    assert_eq!(event.branch(), "main");
    assert_eq!(event.git_ref(), "refs/heads/main");
    assert_eq!(
        event
            .client_payload()
            .and_then(|payload| payload.get("sequence")),
        Some(&json!(3))
    );
}

#[test]
fn repository_dispatch_contract_is_strict_and_fail_closed() {
    for (pointer, value) in [
        ("/action", json!("")),
        ("/action", json!("x".repeat(101))),
        ("/action", json!("bad\nevent")),
        ("/branch", json!("release")),
        ("/branch", json!("bad..branch")),
        ("/client_payload", json!([])),
    ] {
        let mut payload = repository_dispatch_payload();
        *payload.pointer_mut(pointer).expect("fixture pointer") = value;
        assert_payload_error(
            &payload,
            "repository_dispatch",
            GithubWebhookError::InvalidPayload,
        );
    }

    let mut missing_default_branch = repository_dispatch_payload();
    missing_default_branch["repository"]
        .as_object_mut()
        .expect("repository object")
        .remove("default_branch");
    assert_payload_error(
        &missing_default_branch,
        "repository_dispatch",
        GithubWebhookError::InvalidPayload,
    );

    let mut too_many_properties = repository_dispatch_payload();
    too_many_properties["client_payload"] = Value::Object(
        (0..11)
            .map(|index| (format!("key_{index}"), json!(index)))
            .collect(),
    );
    assert_payload_error(
        &too_many_properties,
        "repository_dispatch",
        GithubWebhookError::InvalidPayload,
    );

    let mut excessive_payload = repository_dispatch_payload();
    excessive_payload["client_payload"] = json!({ "data": "x".repeat(65_536) });
    assert_payload_error(
        &excessive_payload,
        "repository_dispatch",
        GithubWebhookError::InvalidPayload,
    );

    let mut null_payload = repository_dispatch_payload();
    null_payload["client_payload"] = Value::Null;
    let event = normalize_payload(&null_payload, "repository_dispatch").expect("null payload");
    let VerifiedGithubWebhook::RepositoryDispatch(event) = event else {
        panic!("expected repository-dispatch evidence");
    };
    assert!(event.client_payload().is_none());
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
    let canonical = String::from_utf8(json_body(&pull_request_payload())).expect("UTF-8 JSON");
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

    let dispatch =
        String::from_utf8(json_body(&repository_dispatch_payload())).expect("UTF-8 JSON");
    let duplicate_client_value =
        dispatch.replacen("\"sequence\":3", "\"sequence\":3,\"sequence\":4", 1);
    assert_bytes_error(
        duplicate_client_value.as_bytes(),
        "repository_dispatch",
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
    let body = json_body(&payload);
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
fn repository_dispatch_debug_redacts_custom_values() {
    let body = json_body(&repository_dispatch_payload());
    let event = normalize_bytes(&body, "repository_dispatch", "private-custom-delivery")
        .expect("normalized event");
    let debug = format!("{event:?}");

    for marker in [
        "private-custom-delivery",
        "synthetic_signal",
        "private-payload-marker",
        "refs/heads/main",
    ] {
        assert!(!debug.contains(marker), "leaked marker: {marker}");
    }
}

#[test]
fn unsupported_event_headers_fail_closed_after_authentication() {
    let payload = pull_request_payload();
    assert_payload_error(&payload, "issues", GithubWebhookError::UnsupportedEvent);
}

#[test]
fn durable_event_v1_rehydrates_each_supported_kind_without_reserialization() {
    for (payload, event_name, delivery_id) in [
        (push_payload(), "push", "durable-push-5"),
        (pull_request_payload(), "pull_request", "durable-pr-7"),
        (merge_group_payload(), "merge_group", "durable-group-9"),
        (
            repository_dispatch_payload(),
            "repository_dispatch",
            "durable-custom-3",
        ),
    ] {
        let body = json_body(&payload);
        let stored = stored_event_v1(&body, event_name, delivery_id);
        let event = rehydrate_stored_authenticated_github_webhook(stored)
            .expect("rehydrated authenticated event");
        assert_eq!(event.event_name(), event_name);
        assert_eq!(event.delivery_id(), delivery_id);
        assert_eq!(event.raw_body().as_ref(), body);
        assert_eq!(event.repository().full_name(), "example/base-repository");
    }
}

#[test]
fn durable_event_v1_rejects_envelope_drift_and_duplicate_json() {
    assert_eq!(
        GITHUB_AUTHENTICATED_EVENT_MEDIA_TYPE,
        "application/vnd.automata.github-authenticated-event+json"
    );
    let body = json_body(&pull_request_payload());
    let wrong_event = stored_event_v1(&body, "merge_group", "durable-pr-7");
    assert_eq!(
        rehydrate_stored_authenticated_github_webhook(wrong_event)
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
        rehydrate_stored_authenticated_github_webhook(stored)
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

fn repository_dispatch_payload() -> Value {
    let mut repository = base_repository();
    repository["default_branch"] = json!("main");
    json!({
        "action": "synthetic_signal",
        "branch": "main",
        "client_payload": {
            "sequence": 3,
            "marker": "private-payload-marker"
        },
        "repository": repository,
        "installation": { "id": 71 },
        "sender": { "id": 301 }
    })
}

fn check_run_payload(action: &str, requested_action: Option<&str>) -> Value {
    let mut payload = json!({
        "action": action,
        "check_run": {
            "id": 41,
            "head_sha": HEAD_SHA,
            "external_id": "automata-check:00000000-0000-4000-8000-000000000001",
            "status": "completed",
            "conclusion": "failure",
            "app": { "id": 17 },
            "check_suite": { "id": 23, "head_sha": HEAD_SHA }
        },
        "repository": base_repository(),
        "installation": { "id": 71 },
        "sender": { "id": 301 }
    });
    if let Some(identifier) = requested_action {
        payload["requested_action"] = json!({ "identifier": identifier });
    }
    payload
}

fn check_suite_payload() -> Value {
    json!({
        "action": "rerequested",
        "check_suite": {
            "id": 23,
            "head_sha": HEAD_SHA,
            "status": "completed",
            "conclusion": "failure",
            "app": { "id": 17 }
        },
        "repository": base_repository(),
        "installation": { "id": 71 },
        "sender": { "id": 301 }
    })
}

fn normalize_payload(
    payload: &Value,
    event_name: &str,
) -> Result<VerifiedGithubWebhook, GithubWebhookError> {
    normalize_bytes(&json_body(payload), event_name, "synthetic-delivery")
}

fn normalize_bytes(
    body: &[u8],
    event_name: &str,
    delivery_id: &str,
) -> Result<VerifiedGithubWebhook, GithubWebhookError> {
    let headers = signed_webhook_headers(SECRET, body, event_name, delivery_id);
    GithubWebhookVerifier::new(SECRET)
        .expect("verifier")
        .authenticate(&headers, Bytes::copy_from_slice(body))?
        .normalize()
}

fn assert_invalid_pull_request(payload: &Value) {
    assert_payload_error(payload, "pull_request", GithubWebhookError::InvalidPayload);
}

fn assert_payload_error(payload: &Value, event_name: &str, expected: GithubWebhookError) {
    assert_bytes_error(&json_body(payload), event_name, expected);
}

fn assert_bytes_error(body: &[u8], event_name: &str, expected: GithubWebhookError) {
    assert_eq!(
        normalize_bytes(body, event_name, "synthetic-delivery").expect_err("rejected payload"),
        expected
    );
}

fn stored_event_v1(
    body: &[u8],
    event_name: &str,
    delivery_id: &str,
) -> StoredAuthenticatedGithubWebhook {
    StoredAuthenticatedGithubWebhook::from_durable_coordinates(
        Bytes::copy_from_slice(body),
        webhook_body_digest(body),
        u64::try_from(body.len()).expect("fixture size"),
        GITHUB_AUTHENTICATED_EVENT_MEDIA_TYPE,
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
