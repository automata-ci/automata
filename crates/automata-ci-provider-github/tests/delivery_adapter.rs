use crate::support::{
    BASE_SHA, GROUP_SHA, HEAD_SHA, MERGE_SHA, base_repository, head_repository, json_body,
    signed_webhook_headers,
};

use automata_ci_core::{GitObjectId, ManagedTenantId, Sha256Digest, UnixMillis};
use automata_ci_key_management::SecretBytes;
use automata_ci_provider::{
    DeliveryAdapter as _, ExternalRepositoryId, ExternalRepositoryIdentity, NormalizedTrigger,
    ProviderArchiveLimits, ProviderConfigurationRevision, ProviderConnectionConfiguration,
    ProviderConnectionId, ProviderConnectionManifest, ProviderConnectionRevision,
    ProviderControlKind, ProviderDefaultBranch, ProviderDelivery, ProviderDeliveryRejection,
    ProviderInstanceId, ProviderLifecycleState, ProviderRepositoryPath,
    ProviderRunnerPolicyBinding, ProviderSchemaVersion, ProviderSecret, ProviderSecretGeneration,
    ProviderSecretName, ProviderWebhookAuthenticationError, ProviderWebhookAuthenticationRequest,
    ProviderWebhookEndpointId, ProviderWebhookEndpointManifest, ProviderWebhookEndpointRevision,
    ProviderWebhookEndpointState, ProviderWebhookHeaderName, ProviderWebhookHeaders,
    ProviderWebhookMethod, ProviderWebhookRequest, ProviderWebhookSecretCandidates,
    ProviderWebhookSecretReference, ProviderWorkflowSource, PushCommitEvidence,
    RepositoryVisibility,
};
use automata_ci_provider_github::{
    GithubConnectionPolicy, GithubDeliveryAdapter, X_GITHUB_DELIVERY, X_GITHUB_EVENT,
    X_HUB_SIGNATURE_256,
};
use automata_ci_scm::RepositoryId;
use serde_json::{Value, json};

const OLD_SECRET: &[u8] = b"old GitHub webhook secret";
const CURRENT_SECRET: &[u8] = b"current GitHub webhook secret";

struct Fixture {
    endpoint: ProviderWebhookEndpointManifest,
    connection: ProviderConnectionManifest,
    unrelated_connection: ProviderConnectionManifest,
}

impl Fixture {
    fn new(instance_id: ProviderInstanceId, repository_id: &str) -> Self {
        let connection = Self::connection(instance_id, repository_id);
        let unrelated_connection = Self::connection(instance_id, "40");
        let endpoint = ProviderWebhookEndpointManifest::new(
            ProviderWebhookEndpointId::new(),
            ProviderWebhookEndpointRevision::new(1).expect("endpoint revision"),
            ProviderWebhookEndpointState::Active,
            "github".parse().expect("provider type"),
            instance_id,
            ProviderConfigurationRevision::new(1).expect("provider revision"),
            1_048_576,
            30 * 24 * 60 * 60 * 1_000,
            vec![
                ProviderWebhookSecretReference::new(
                    ProviderConfigurationRevision::new(1).expect("provider revision"),
                    ProviderSecretName::new("webhook-secret").expect("secret name"),
                    ProviderSecretGeneration::new(1).expect("old generation"),
                ),
                ProviderWebhookSecretReference::new(
                    ProviderConfigurationRevision::new(1).expect("provider revision"),
                    ProviderSecretName::new("webhook-secret").expect("secret name"),
                    ProviderSecretGeneration::new(2).expect("current generation"),
                ),
            ],
            UnixMillis::new(1_000),
            None,
        )
        .expect("endpoint");
        Self {
            endpoint,
            connection,
            unrelated_connection,
        }
    }

    fn connection(
        instance_id: ProviderInstanceId,
        repository_id: &str,
    ) -> ProviderConnectionManifest {
        let policy = GithubConnectionPolicy::new(
            71,
            RepositoryId::new("example/base-repository").expect("repository route"),
        )
        .expect("GitHub policy")
        .document()
        .expect("policy document");
        let configuration = ProviderConnectionConfiguration::new(
            ManagedTenantId::parse("11111111-1111-4111-8111-111111111111").expect("tenant"),
            ExternalRepositoryIdentity::new(
                instance_id,
                ExternalRepositoryId::new(repository_id).expect("repository ID"),
            ),
            ProviderConfigurationRevision::new(1).expect("provider revision"),
            Sha256Digest::from_bytes([3; 32]),
            Sha256Digest::from_bytes([4; 32]),
            RepositoryVisibility::Public,
            ProviderDefaultBranch::new("main").expect("default branch"),
            ProviderWorkflowSource::Directory(
                ProviderRepositoryPath::new(".github/workflows").expect("workflow source"),
            ),
            ProviderRunnerPolicyBinding::new(
                ProviderSchemaVersion::new(1).expect("runner schema"),
                Sha256Digest::from_bytes([5; 32]),
            ),
            ProviderArchiveLimits::new(1_024, 8_192, 100, 1_024, 10, 1_024)
                .expect("archive limits"),
            policy,
        );
        ProviderConnectionManifest::new(
            ProviderConnectionId::new(),
            ProviderConnectionRevision::new(1).expect("connection revision"),
            ProviderLifecycleState::Active,
            configuration,
            UnixMillis::new(1_000),
            Some(UnixMillis::new(1_000)),
            None,
        )
        .expect("connection")
    }

    fn candidates(&self) -> ProviderWebhookSecretCandidates {
        ProviderWebhookSecretCandidates::new(
            &self.endpoint,
            [
                (
                    ProviderConfigurationRevision::new(1).expect("revision"),
                    ProviderSecret::new(
                        ProviderSecretName::new("webhook-secret").expect("secret name"),
                        ProviderSecretGeneration::new(1).expect("generation"),
                        SecretBytes::new(OLD_SECRET.to_vec()).expect("old secret"),
                    ),
                ),
                (
                    ProviderConfigurationRevision::new(1).expect("revision"),
                    ProviderSecret::new(
                        ProviderSecretName::new("webhook-secret").expect("secret name"),
                        ProviderSecretGeneration::new(2).expect("generation"),
                        SecretBytes::new(CURRENT_SECRET.to_vec()).expect("current secret"),
                    ),
                ),
            ],
        )
        .expect("secret candidates")
    }

    fn authentication(
        &self,
        payload: &Value,
        event: &str,
        delivery: &str,
        secret: &[u8],
    ) -> ProviderWebhookAuthenticationRequest {
        let body = json_body(payload);
        let signed = signed_webhook_headers(secret, &body, event, delivery);
        let headers = ProviderWebhookHeaders::new(
            [X_GITHUB_DELIVERY, X_GITHUB_EVENT, X_HUB_SIGNATURE_256].map(|name| {
                (
                    ProviderWebhookHeaderName::new(name).expect("header name"),
                    signed.get(name).expect("signed header").as_bytes().to_vec(),
                )
            }),
        )
        .expect("selected headers");
        let request = ProviderWebhookRequest::new(
            self.endpoint.clone(),
            vec![self.unrelated_connection.clone(), self.connection.clone()],
            ProviderWebhookMethod::Post,
            headers,
            body,
            UnixMillis::new(2_000),
        )
        .expect("webhook request");
        ProviderWebhookAuthenticationRequest::new(request, self.candidates())
            .expect("authentication request")
    }
}

#[test]
fn authentication_is_rotation_exact_and_payload_blind() {
    let fixture = Fixture::new(ProviderInstanceId::new(), "41");
    let adapter = GithubDeliveryAdapter::new();
    let authenticated = adapter
        .authenticate(fixture.authentication(
            &json!({"not":"a GitHub event"}),
            "push",
            "delivery-rotation",
            OLD_SECRET,
        ))
        .expect("old generation remains eligible");
    assert_eq!(authenticated.signature().secret().generation().get(), 1);

    let error = adapter
        .authenticate(fixture.authentication(
            &json!({"not":"parsed"}),
            "push",
            "delivery-invalid-signature",
            b"another secret",
        ))
        .expect_err("unselected key must fail");
    assert_eq!(error, ProviderWebhookAuthenticationError::InvalidSignature);
}

#[test]
fn all_admission_events_normalize_through_the_common_contract() {
    let fixture = Fixture::new(ProviderInstanceId::new(), "41");
    let adapter = GithubDeliveryAdapter::new();
    for (payload, event, expected) in [
        (push_payload(), "push", "push"),
        (pull_request_payload(), "pull_request", "pull_request"),
        (merge_group_payload(), "merge_group", "merge_queue"),
        (
            repository_dispatch_payload(),
            "repository_dispatch",
            "repository_dispatch",
        ),
    ] {
        let authenticated = adapter
            .authenticate(fixture.authentication(
                &payload,
                event,
                &format!("delivery-{event}"),
                CURRENT_SECRET,
            ))
            .expect("signature");
        let normalized = adapter.normalize(authenticated).expect("normalization");
        let descriptor = normalized.raw_descriptor().expect("raw descriptor");
        let ProviderDelivery::Trigger(delivery) = normalized.seal(descriptor).expect("seal") else {
            panic!("{event} was rejected");
        };
        let actual = match delivery.trigger().trigger() {
            NormalizedTrigger::Push(push) => {
                assert_eq!(
                    push.commit_evidence(),
                    &PushCommitEvidence::complete([
                        GitObjectId::from_provider_hex(HEAD_SHA).expect("head object"),
                        GitObjectId::from_provider_hex(MERGE_SHA).expect("second pushed object"),
                    ])
                    .expect("commit evidence")
                );
                "push"
            }
            NormalizedTrigger::PullRequest(pull_request) => {
                assert!(pull_request.draft());
                assert_eq!(pull_request.execution_ref().full(), "refs/pull/7/merge");
                assert_eq!(
                    delivery.trigger().trigger().workflow_source_revision(),
                    Some(GitObjectId::from_provider_hex(HEAD_SHA).expect("head object"))
                );
                "pull_request"
            }
            NormalizedTrigger::MergeQueue(merge_queue) => {
                assert_eq!(
                    merge_queue.candidate_ref().full(),
                    "refs/heads/merge-queue/main/group-9"
                );
                assert_eq!(
                    delivery.trigger().trigger().workflow_source_revision(),
                    Some(GitObjectId::from_provider_hex(GROUP_SHA).expect("group object"))
                );
                "merge_queue"
            }
            NormalizedTrigger::RepositoryDispatch(dispatch) => {
                assert_eq!(dispatch.input().canonical_bytes(), br#"{"sequence":3}"#);
                "repository_dispatch"
            }
        };
        assert_eq!(actual, expected);
        assert_eq!(
            delivery.evidence().connection_id(),
            fixture.connection.connection_id()
        );
    }
}

#[test]
fn endpoint_repository_identity_is_enforced_after_authentication() {
    let fixture = Fixture::new(ProviderInstanceId::new(), "999");
    let adapter = GithubDeliveryAdapter::new();
    let authenticated = adapter
        .authenticate(fixture.authentication(
            &push_payload(),
            "push",
            "delivery-wrong-repository",
            CURRENT_SECRET,
        ))
        .expect("signature remains valid");
    let error = adapter
        .normalize(authenticated)
        .expect_err("unregistered repository must not select a connection");
    assert!(matches!(
        error,
        automata_ci_provider::ProviderWebhookError::PayloadIdentityMismatch
    ));
}

#[test]
fn rerequested_check_run_becomes_an_authenticated_control() {
    let fixture = Fixture::new(ProviderInstanceId::new(), "41");
    let adapter = GithubDeliveryAdapter::new();
    let authenticated = adapter
        .authenticate(fixture.authentication(
            &check_run_rerequested_payload(),
            "check_run",
            "delivery-check-run-rerequested",
            CURRENT_SECRET,
        ))
        .expect("signature");
    let normalized = adapter.normalize(authenticated).expect("normalization");
    let descriptor = normalized.raw_descriptor().expect("raw descriptor");
    let ProviderDelivery::Control(delivery) = normalized.seal(descriptor).expect("seal") else {
        panic!("rerequested Check Run was not admitted as a control");
    };
    assert_eq!(delivery.control().kind(), ProviderControlKind::Rerun);
    assert_eq!(delivery.control().repository().external_id().as_str(), "41");
    assert_eq!(delivery.control().object().to_string(), HEAD_SHA);
    assert_eq!(
        delivery
            .control()
            .actor()
            .expect("authenticated sender")
            .external_id()
            .as_str(),
        "301"
    );
    assert_eq!(
        serde_json::from_slice::<Value>(delivery.control().document().bytes())
            .expect("canonical document"),
        json!({
            "schema": 2,
            "installation_id": 71,
            "target": {
                "kind": "check_run",
                "app_id": 501,
                "run_id": 601,
                "suite_id": 701,
                "external_id": "automata-result-subject",
                "action": "rerequested"
            }
        })
    );
}

#[test]
fn requested_action_controls_are_rejected_until_selection_is_common() {
    let fixture = Fixture::new(ProviderInstanceId::new(), "41");
    let adapter = GithubDeliveryAdapter::new();
    let mut requested_action = check_run_rerequested_payload();
    requested_action["action"] = json!("requested_action");
    requested_action["requested_action"] = json!({"identifier": "rerun_failed"});

    let authenticated = adapter
        .authenticate(fixture.authentication(
            &requested_action,
            "check_run",
            "delivery-check-run-rerun-failed",
            CURRENT_SECRET,
        ))
        .expect("signature");
    let normalized = adapter.normalize(authenticated).expect("normalization");
    let descriptor = normalized.raw_descriptor().expect("raw descriptor");
    let ProviderDelivery::Rejected(delivery) = normalized.seal(descriptor).expect("seal") else {
        panic!("requested action unexpectedly entered control processing");
    };
    assert_eq!(
        delivery.reason(),
        ProviderDeliveryRejection::UnsupportedEvent
    );
}

#[test]
fn rerequested_check_suite_becomes_an_authenticated_control() {
    let fixture = Fixture::new(ProviderInstanceId::new(), "41");
    let adapter = GithubDeliveryAdapter::new();
    let authenticated = adapter
        .authenticate(fixture.authentication(
            &check_suite_rerequested_payload(),
            "check_suite",
            "delivery-check-suite-rerequested",
            CURRENT_SECRET,
        ))
        .expect("signature");
    let normalized = adapter.normalize(authenticated).expect("normalization");
    let descriptor = normalized.raw_descriptor().expect("raw descriptor");
    let ProviderDelivery::Control(delivery) = normalized.seal(descriptor).expect("seal") else {
        panic!("rerequested Check Suite was not admitted as a control");
    };
    assert_eq!(delivery.control().kind(), ProviderControlKind::Rerun);
    assert_eq!(delivery.control().repository().external_id().as_str(), "41");
    assert_eq!(delivery.control().object().to_string(), HEAD_SHA);
    assert_eq!(
        serde_json::from_slice::<Value>(delivery.control().document().bytes())
            .expect("canonical document"),
        json!({
            "schema": 2,
            "installation_id": 71,
            "target": {
                "kind": "check_suite",
                "app_id": 501,
                "suite_id": 701
            }
        })
    );
}

#[test]
fn provider_limit_is_not_downgraded_to_a_partial_commit_set() {
    let fixture = Fixture::new(ProviderInstanceId::new(), "41");
    let adapter = GithubDeliveryAdapter::new();
    let mut payload = push_payload();
    payload["commits"] = Value::Array(
        (1..=1_001)
            .map(|index| {
                json!({
                    "id": format!("{index:040x}")
                })
            })
            .collect(),
    );
    let authenticated = adapter
        .authenticate(fixture.authentication(
            &payload,
            "push",
            "delivery-large-push",
            CURRENT_SECRET,
        ))
        .expect("signature");
    let normalized = adapter.normalize(authenticated).expect("normalization");
    let descriptor = normalized.raw_descriptor().expect("raw descriptor");
    let ProviderDelivery::Trigger(delivery) = normalized.seal(descriptor).expect("seal") else {
        panic!("large push rejected");
    };
    let NormalizedTrigger::Push(push) = delivery.trigger().trigger() else {
        panic!("expected push");
    };
    assert_eq!(
        push.commit_evidence(),
        &PushCommitEvidence::ProviderLimitExceeded
    );
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
        "sender": { "id": 301, "login": "octocat", "type": "User" },
        "commits": [{"id": HEAD_SHA}, {"id": MERGE_SHA}]
    })
}

fn check_run_rerequested_payload() -> Value {
    json!({
        "action": "rerequested",
        "check_run": {
            "id": 601,
            "head_sha": HEAD_SHA,
            "external_id": "automata-result-subject",
            "status": "completed",
            "conclusion": "failure",
            "app": { "id": 501 },
            "check_suite": { "id": 701, "head_sha": HEAD_SHA }
        },
        "repository": base_repository(),
        "installation": { "id": 71 },
        "sender": { "id": 301, "login": "octocat", "type": "User" }
    })
}

fn check_suite_rerequested_payload() -> Value {
    json!({
        "action": "rerequested",
        "check_suite": {
            "id": 701,
            "head_sha": HEAD_SHA,
            "status": "completed",
            "conclusion": "failure",
            "app": { "id": 501 }
        },
        "repository": base_repository(),
        "installation": { "id": 71 },
        "sender": { "id": 301, "login": "octocat", "type": "User" }
    })
}

fn pull_request_payload() -> Value {
    json!({
        "action": "opened",
        "number": 7,
        "pull_request": {
            "number": 7,
            "merged": false,
            "draft": true,
            "merge_commit_sha": MERGE_SHA,
            "user": { "id": 302, "login": "contributor", "type": "User" },
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
        "sender": { "id": 301, "login": "octocat", "type": "User" }
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
        "sender": { "id": 301, "login": "octocat", "type": "User" }
    })
}

fn repository_dispatch_payload() -> Value {
    let mut repository = base_repository();
    repository["default_branch"] = json!("main");
    json!({
        "action": "synthetic_signal",
        "branch": "main",
        "client_payload": { "sequence": 3 },
        "repository": repository,
        "installation": { "id": 71 },
        "sender": { "id": 301, "login": "octocat", "type": "User" }
    })
}
