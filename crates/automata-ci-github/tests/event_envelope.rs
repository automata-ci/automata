use std::fmt::Write as _;

use automata_ci_blob::{BlobDescriptor, BlobKey, MediaType};
use automata_ci_core::Sha256Digest;
use automata_ci_github::{
    GITHUB_AUTHENTICATED_EVENT_MEDIA_TYPE, GITHUB_RAW_EVENT_OBJECT_KEY_PREFIX,
    GithubEventEnvelopeError, GithubEventFacts, GithubEventRegistryV1, GithubEventTrustFact,
    GithubSealedEventEnvelopeV1, GithubWebhookVerifier, GithubWorkflowEventKind,
    MAX_GITHUB_EVENT_ENVELOPE_BYTES, VerifiedGithubWebhook, X_GITHUB_DELIVERY, X_GITHUB_EVENT,
    X_HUB_SIGNATURE_256,
};
use bytes::Bytes;
use reqwest::header::{HeaderMap, HeaderValue};
use ring::hmac;
use serde_json::{Value, json};

const SECRET: &[u8] = b"event-envelope-test-secret";
const BASE_SHA: &str = "0123456789abcdef0123456789abcdef01234567";
const HEAD_SHA: &str = "89abcdef0123456789abcdef0123456789abcdef";
const MERGE_SHA: &str = "76543210fedcba9876543210fedcba9876543210";
const GROUP_SHA: &str = "fedcba9876543210fedcba9876543210fedcba98";

#[test]
fn registry_and_envelopes_cover_every_workflow_event_exactly_once() {
    GithubEventRegistryV1::validate().expect("complete registry");
    assert_eq!(
        GithubEventRegistryV1::entries()
            .iter()
            .map(|entry| entry.kind())
            .collect::<Vec<_>>(),
        GithubWorkflowEventKind::ALL
    );

    for (payload, event_name, expected_kind, expected_activity) in [
        (push_payload(), "push", GithubWorkflowEventKind::Push, None),
        (
            pull_request_payload(),
            "pull_request",
            GithubWorkflowEventKind::PullRequest,
            Some("opened"),
        ),
        (
            merge_group_payload(),
            "merge_group",
            GithubWorkflowEventKind::MergeGroup,
            Some("checks_requested"),
        ),
        (
            repository_dispatch_payload(),
            "repository_dispatch",
            GithubWorkflowEventKind::RepositoryDispatch,
            Some("synthetic_signal"),
        ),
    ] {
        let event = normalize(&payload, event_name);
        let envelope = seal(&event);
        assert_eq!(envelope.event().kind(), expected_kind);
        assert_eq!(envelope.event().activity(), expected_activity);
        assert_eq!(
            envelope.raw_event().descriptor().digest(),
            Sha256Digest::from_bytes(*event.body_sha256().as_bytes())
        );
        assert_eq!(
            envelope.raw_event().descriptor().size(),
            u64::try_from(event.raw_body().len()).expect("fixture size")
        );
        let round_trip = GithubSealedEventEnvelopeV1::from_canonical_bytes(
            envelope.canonical_bytes(),
            envelope.digest(),
        )
        .expect("canonical round trip");
        assert_eq!(round_trip, envelope);
    }
}

#[test]
fn pull_request_envelope_retains_auth02_actor_source_target_and_fork_facts() {
    let event = normalize(&pull_request_payload(), "pull_request");
    let envelope = seal(&event);
    let GithubEventFacts::PullRequest(facts) = envelope.event() else {
        panic!("pull-request facts");
    };
    assert_eq!(facts.actor().expect("sender").id().get(), 301);
    assert_eq!(
        facts.actor().and_then(|actor| actor.login()),
        Some("octocat")
    );
    assert_eq!(facts.source_actor().expect("author").id().get(), 302);
    assert_eq!(facts.source_repository().id().get(), 42);
    assert_eq!(facts.target_repository().id().get(), 41);
    assert!(facts.is_fork());
    assert_eq!(facts.source_ref(), "feature/topic");
    assert_eq!(facts.target_ref(), "main");
    assert_eq!(facts.source_revision().as_str(), HEAD_SHA);
    assert_eq!(facts.target_revision().as_str(), BASE_SHA);
    assert_eq!(facts.execution_revision().as_str(), MERGE_SHA);

    let trust_facts =
        GithubEventRegistryV1::entry(GithubWorkflowEventKind::PullRequest).trust_facts();
    for required in [
        GithubEventTrustFact::TriggeringActor,
        GithubEventTrustFact::SourceActor,
        GithubEventTrustFact::SourceRepository,
        GithubEventTrustFact::TargetRepository,
        GithubEventTrustFact::ForkRelationship,
        GithubEventTrustFact::Activity,
        GithubEventTrustFact::References,
        GithubEventTrustFact::Revisions,
        GithubEventTrustFact::Recursion,
    ] {
        assert!(trust_facts.contains(&required), "missing {required:?}");
    }
}

#[test]
fn future_actor_kind_preserves_event_behavior_but_cannot_claim_complete_trust_facts() {
    let mut payload = push_payload();
    payload["sender"]["type"] = json!("FutureProviderKind");
    let event = normalize(&payload, "push");
    let envelope = seal(&event);
    let actor = envelope
        .event()
        .triggering_actor()
        .expect("stable sender identity");
    assert_eq!(actor.login(), Some("octocat"));
    assert_eq!(actor.kind(), None);
    assert!(!actor.has_complete_classification());
}

#[test]
fn repository_dispatch_keeps_arbitrary_payload_out_of_policy_facts() {
    let event = normalize(&repository_dispatch_payload(), "repository_dispatch");
    let envelope = seal(&event);
    let encoded = std::str::from_utf8(envelope.canonical_bytes()).expect("UTF-8 JSON");
    assert!(!encoded.contains("private-payload-marker"));
    assert!(encoded.contains("synthetic_signal"));
}

#[test]
fn check_controls_cannot_cross_the_workflow_event_envelope_boundary() {
    for (payload, event_name) in [
        (check_run_payload(), "check_run"),
        (check_suite_payload(), "check_suite"),
    ] {
        let event = normalize(&payload, event_name);
        assert!(matches!(
            event,
            VerifiedGithubWebhook::CheckRun(_) | VerifiedGithubWebhook::CheckSuite(_)
        ));
        let descriptor = raw_descriptor(&event);
        assert_eq!(
            GithubSealedEventEnvelopeV1::seal(&event, descriptor),
            Err(GithubEventEnvelopeError::ControlEvent)
        );
    }
}

#[test]
fn seal_rejects_wrong_raw_digest_size_key_and_media_type() {
    let event = normalize(&push_payload(), "push");
    let body_digest = Sha256Digest::from_bytes(*event.body_sha256().as_bytes());
    let wrong_digest = Sha256Digest::from_bytes([7; 32]);

    assert_eq!(
        GithubSealedEventEnvelopeV1::seal(
            &event,
            descriptor_for(
                wrong_digest,
                u64::try_from(event.raw_body().len()).expect("size"),
                GITHUB_AUTHENTICATED_EVENT_MEDIA_TYPE,
                None,
            ),
        ),
        Err(GithubEventEnvelopeError::RawDigestMismatch)
    );
    assert_eq!(
        GithubSealedEventEnvelopeV1::seal(
            &event,
            descriptor_for(
                body_digest,
                u64::try_from(event.raw_body().len()).expect("size") + 1,
                GITHUB_AUTHENTICATED_EVENT_MEDIA_TYPE,
                None,
            ),
        ),
        Err(GithubEventEnvelopeError::RawSizeMismatch)
    );
    assert_eq!(
        GithubSealedEventEnvelopeV1::seal(
            &event,
            descriptor_for(
                body_digest,
                u64::try_from(event.raw_body().len()).expect("size"),
                GITHUB_AUTHENTICATED_EVENT_MEDIA_TYPE,
                Some("provider-deliveries/github/event/sha256/not-the-digest.json"),
            ),
        ),
        Err(GithubEventEnvelopeError::RawObjectKey)
    );
    assert_eq!(
        GithubSealedEventEnvelopeV1::seal(
            &event,
            descriptor_for(
                body_digest,
                u64::try_from(event.raw_body().len()).expect("size"),
                "application/json",
                None,
            ),
        ),
        Err(GithubEventEnvelopeError::RawMediaType)
    );
}

#[test]
fn canonical_decoder_rejects_duplicates_unknowns_size_and_prior_schema() {
    let event = normalize(&push_payload(), "push");
    let envelope = seal(&event);
    let canonical = std::str::from_utf8(envelope.canonical_bytes()).expect("canonical UTF-8");

    let duplicate = canonical.replacen("{\"schema\":1", "{\"schema\":1,\"schema\":1", 1);
    assert_eq!(
        GithubSealedEventEnvelopeV1::from_canonical_bytes(duplicate.as_bytes(), envelope.digest(),),
        Err(GithubEventEnvelopeError::MalformedEncoding)
    );

    let unknown = canonical.replacen("\"kind\":\"push\"", "\"kind\":\"issues\"", 1);
    assert_ne!(unknown, canonical);
    assert_eq!(
        GithubSealedEventEnvelopeV1::from_canonical_bytes(unknown.as_bytes(), envelope.digest(),),
        Err(GithubEventEnvelopeError::MalformedEncoding)
    );

    let prior = canonical.replacen("\"schema\":1", "\"schema\":0", 1);
    assert_eq!(
        GithubSealedEventEnvelopeV1::from_canonical_bytes(prior.as_bytes(), envelope.digest(),),
        Err(GithubEventEnvelopeError::UnsupportedSchema)
    );

    let prior_registry = canonical.replacen("\"registry_schema\":1", "\"registry_schema\":0", 1);
    assert_eq!(
        GithubSealedEventEnvelopeV1::from_canonical_bytes(
            prior_registry.as_bytes(),
            envelope.digest(),
        ),
        Err(GithubEventEnvelopeError::UnsupportedRegistrySchema)
    );

    let oversized = vec![b' '; MAX_GITHUB_EVENT_ENVELOPE_BYTES + 1];
    assert_eq!(
        GithubSealedEventEnvelopeV1::from_canonical_bytes(&oversized, envelope.digest()),
        Err(GithubEventEnvelopeError::EnvelopeSize)
    );

    let noncanonical = format!(" {canonical}");
    assert_eq!(
        GithubSealedEventEnvelopeV1::from_canonical_bytes(
            noncanonical.as_bytes(),
            envelope.digest(),
        ),
        Err(GithubEventEnvelopeError::NoncanonicalEncoding)
    );

    assert_eq!(
        GithubSealedEventEnvelopeV1::from_canonical_bytes(
            envelope.canonical_bytes(),
            Sha256Digest::from_bytes([9; 32]),
        ),
        Err(GithubEventEnvelopeError::EnvelopeDigestMismatch)
    );
}

#[test]
fn envelope_debug_redacts_delivery_actor_repository_refs_revisions_and_bytes() {
    let event = normalize(&pull_request_payload(), "pull_request");
    let envelope = seal(&event);
    let debug = format!("{envelope:?}");
    for marker in [
        "sensitive-delivery",
        "octocat",
        "contributor",
        "example/base-repository",
        "feature/topic",
        HEAD_SHA,
        BASE_SHA,
        MERGE_SHA,
    ] {
        assert!(!debug.contains(marker), "debug leaked {marker}");
    }
}

fn seal(event: &VerifiedGithubWebhook) -> GithubSealedEventEnvelopeV1 {
    GithubSealedEventEnvelopeV1::seal(event, raw_descriptor(event)).expect("sealed event")
}

fn raw_descriptor(event: &VerifiedGithubWebhook) -> BlobDescriptor {
    descriptor_for(
        Sha256Digest::from_bytes(*event.body_sha256().as_bytes()),
        u64::try_from(event.raw_body().len()).expect("fixture size"),
        GITHUB_AUTHENTICATED_EVENT_MEDIA_TYPE,
        None,
    )
}

fn descriptor_for(
    digest: Sha256Digest,
    size: u64,
    media_type: &str,
    key: Option<&str>,
) -> BlobDescriptor {
    let key = key.map_or_else(
        || format!("{GITHUB_RAW_EVENT_OBJECT_KEY_PREFIX}/{digest}.json"),
        str::to_owned,
    );
    BlobDescriptor::new(
        BlobKey::new(key).expect("blob key"),
        digest,
        size,
        MediaType::new(media_type).expect("media type"),
    )
}

fn normalize(payload: &Value, event_name: &str) -> VerifiedGithubWebhook {
    let body = serde_json::to_vec(payload).expect("JSON fixture");
    let headers = signed_headers(&body, event_name, "sensitive-delivery");
    GithubWebhookVerifier::new(SECRET)
        .expect("verifier")
        .authenticate(&headers, Bytes::from(body))
        .expect("authenticated")
        .normalize()
        .expect("normalized")
}

fn signed_headers(body: &[u8], event_name: &str, delivery_id: &str) -> HeaderMap {
    let key = hmac::Key::new(hmac::HMAC_SHA256, SECRET);
    let tag = hmac::sign(&key, body);
    let mut signature = String::from("sha256=");
    for byte in tag.as_ref() {
        write!(&mut signature, "{byte:02x}").expect("signature encoding");
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

fn actor(id: u64, login: &str, kind: &str) -> Value {
    json!({ "id": id, "login": login, "type": kind })
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

fn base_repository() -> Value {
    repository(41, 11, "example", "base-repository")
}

fn head_repository() -> Value {
    repository(42, 12, "contributor", "head-repository")
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
        "sender": actor(301, "octocat", "User"),
        "commits": []
    })
}

fn pull_request_payload() -> Value {
    json!({
        "action": "opened",
        "number": 7,
        "pull_request": {
            "number": 7,
            "merged": false,
            "merge_commit_sha": MERGE_SHA,
            "user": actor(302, "contributor", "User"),
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
        "sender": actor(301, "octocat", "User")
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
        "sender": actor(301, "github-merge-queue[bot]", "Bot")
    })
}

fn repository_dispatch_payload() -> Value {
    let mut repository = base_repository();
    repository["default_branch"] = json!("main");
    json!({
        "action": "synthetic_signal",
        "branch": "main",
        "client_payload": { "marker": "private-payload-marker" },
        "repository": repository,
        "installation": { "id": 71 },
        "sender": actor(301, "octocat", "User")
    })
}

fn check_run_payload() -> Value {
    json!({
        "action": "rerequested",
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
        "sender": actor(301, "octocat", "User")
    })
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
        "sender": actor(301, "octocat", "User")
    })
}
