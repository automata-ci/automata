#![cfg(unix)]

use std::{collections::BTreeMap, sync::Arc};

use automata_ci_core::{
    AttemptId, ContextValue, FencingToken, JobAuthorityProfile, JobConclusion, JobContentReference,
    JobExecutionContext, JobId, JobInstanceIdentity, JobIr, JobIrEnvelope, JobPermissionGrant,
    JobPermissionRequest, JobRuntimeContext, JobSource, Lease, LeaseId, NeedContext, NeedOutput,
    OutputSensitivity, PermissionLevel, RunId, RunIdAlias, RunnerRequirements, SecretBinding,
    Sha256Digest, StrategyContext, UnixMillis, WorkflowId,
};
use automata_ci_execution::{
    ContainerHandle, ServiceContainerBinding, ServiceContainerBindings, ServiceNetwork,
    ServicePort, ServicePortBinding, ServiceTransportProtocol, TargetPath,
};
use automata_ci_expression_github::{
    GithubExpressionEvaluator, GithubObject, GithubStatus, GithubValue,
};
use automata_ci_github_runtime::{CommandFilePlatform, JobCommandState};
use automata_ci_job_executor_github::{
    GithubContextPort, GithubContextRequest, GithubExecutionIdentity, GithubExecutionPhase,
    PortErrorKind,
};
use automata_ci_protocol::{
    JobRuntimeAuthorities, JobRuntimeAuthority, RuntimeAuthorityCredential,
    RuntimeAuthorityEndpoint, RuntimeAuthorityName,
};
use automata_ci_runner::product::{RunnerProductConfig, StandardGithubContext};
use automata_ci_workflow_github::{GithubConditionCompiler, GithubConditionPhase};

const REPOSITORY_TOKEN: &str = "ghs_exact_job_repository_token";
const OIDC_REQUEST_TOKEN: &str = "oidc_exact_job_request_token";
const SECRET_DERIVED_NEED_SENTINEL: &str = "must-not-enter-expression-context";

#[test]
fn admitted_execution_context_is_exposed_without_workspace_or_ref_rederivation() {
    let fixture = ContextFixture::new();
    let snapshot = fixture.snapshot().expect("context snapshot");
    let environment = snapshot
        .environment()
        .iter()
        .map(|value| (value.name(), value.expose_value()))
        .collect::<BTreeMap<_, _>>();

    assert_eq!(environment["GITHUB_WORKFLOW"], "CI");
    assert_eq!(environment["GITHUB_REF"], "refs/heads/main");
    assert_eq!(environment["GITHUB_WORKSPACE"], "/__w/automata/automata");
    assert_eq!(environment["GITHUB_REPOSITORY_OWNER"], "automata-ci");
    assert_eq!(environment["GITHUB_REF_NAME"], "main");
    assert_eq!(environment["GITHUB_REF_TYPE"], "branch");
    assert_eq!(
        environment["GITHUB_WORKFLOW_REF"],
        "automata-ci/automata/.github/workflows/ci.yml@refs/heads/main"
    );
    assert_eq!(
        environment["GITHUB_WORKFLOW_SHA"],
        "0123456789abcdef0123456789abcdef01234567"
    );
    assert_eq!(environment["RUNNER_ENVIRONMENT"], "self-hosted");
    assert_eq!(
        environment["GITHUB_EVENT_PATH"],
        "/__automata/attempts/fixture/event.json"
    );
    assert_eq!(environment["GITHUB_ACTOR"], "local-bootstrap");
    assert_eq!(environment["GITHUB_RUN_ID"], "42");
    assert_eq!(environment["GITHUB_RUN_ATTEMPT"], "1");
    assert!(!environment.contains_key("GITHUB_RUN_NUMBER"));

    let github = snapshot
        .expression()
        .named_value("github")
        .expect("github context");
    let GithubValue::Object(github) = github else {
        panic!("github context must be an object");
    };
    assert_eq!(
        github.get("workflow").and_then(GithubValue::as_str),
        Some("CI")
    );
    assert_eq!(
        github.get("ref").and_then(GithubValue::as_str),
        Some("refs/heads/main")
    );
    assert_eq!(
        github.get("workspace").and_then(GithubValue::as_str),
        Some("/__w/automata/automata")
    );
    assert_eq!(
        github.get("event_path").and_then(GithubValue::as_str),
        Some("/__automata/attempts/fixture/event.json")
    );
    assert_eq!(
        github.get("workflow_ref").and_then(GithubValue::as_str),
        Some("automata-ci/automata/.github/workflows/ci.yml@refs/heads/main")
    );
    assert_eq!(
        github.get("run_id").and_then(GithubValue::as_str),
        Some("42")
    );
    assert!(github.get("run_number").is_none());
}

#[test]
fn verified_event_payload_is_exposed_as_github_event() {
    let fixture = ContextFixture::new();
    let event = object(vec![
        ("action", GithubValue::string("opened")),
        (
            "pull_request",
            object(vec![
                (
                    "head",
                    object(vec![("ref", GithubValue::string("feature/context"))]),
                ),
                ("base", object(vec![("ref", GithubValue::string("main"))])),
            ]),
        ),
    ]);
    let snapshot = fixture
        .snapshot_with_event(&event)
        .expect("context snapshot with verified event");
    let GithubValue::Object(github) = snapshot
        .expression()
        .named_value("github")
        .expect("github context")
    else {
        panic!("github context must be an object");
    };
    let GithubValue::Object(event) = github.get("event").expect("github.event") else {
        panic!("github.event must be an object");
    };
    assert_eq!(
        event.get("action").and_then(GithubValue::as_str),
        Some("opened")
    );
    assert_eq!(
        github.get("head_ref").and_then(GithubValue::as_str),
        Some("feature/context")
    );
    assert_eq!(
        github.get("base_ref").and_then(GithubValue::as_str),
        Some("main")
    );
    assert_eq!(
        github.get("workflow_sha").and_then(GithubValue::as_str),
        Some("0123456789abcdef0123456789abcdef01234567")
    );
    let GithubValue::Object(pull_request) =
        event.get("pull_request").expect("pull request payload")
    else {
        panic!("pull request payload must be an object");
    };
    let GithubValue::Object(head) = pull_request.get("head").expect("head payload") else {
        panic!("head payload must be an object");
    };
    assert_eq!(
        head.get("ref").and_then(GithubValue::as_str),
        Some("feature/context")
    );
    let environment = snapshot
        .environment()
        .iter()
        .map(|value| (value.name(), value.expose_value()))
        .collect::<BTreeMap<_, _>>();
    assert_eq!(environment["GITHUB_HEAD_REF"], "feature/context");
    assert_eq!(environment["GITHUB_BASE_REF"], "main");
}

#[test]
fn hydrated_runtime_context_exposes_typed_public_roots_and_keeps_secrets_opaque() {
    let fixture = ContextFixture::new();
    let snapshot = fixture.snapshot().expect("context snapshot");
    let expression = snapshot.expression();

    let GithubValue::Object(inputs) = expression.named_value("inputs").expect("inputs context")
    else {
        panic!("inputs context must be an object");
    };
    assert_eq!(
        inputs.get("deploy").and_then(GithubValue::as_bool),
        Some(true)
    );

    let GithubValue::Object(vars) = expression.named_value("vars").expect("vars context") else {
        panic!("vars context must be an object");
    };
    assert_eq!(
        vars.get("channel").and_then(GithubValue::as_str),
        Some("stable")
    );

    let GithubValue::Object(matrix) = expression.named_value("matrix").expect("matrix context")
    else {
        panic!("matrix context must be an object");
    };
    assert_eq!(
        matrix.get("os").and_then(GithubValue::as_str),
        Some("linux")
    );
    assert_eq!(
        matrix.get("shard").and_then(GithubValue::as_number),
        Some(2.0)
    );

    let GithubValue::Object(strategy) = expression
        .named_value("strategy")
        .expect("strategy context")
    else {
        panic!("strategy context must be an object");
    };
    assert_eq!(
        strategy.get("fail-fast").and_then(GithubValue::as_bool),
        Some(false)
    );
    assert_eq!(
        strategy.get("job-index").and_then(GithubValue::as_number),
        Some(1.0)
    );
    assert_eq!(
        strategy.get("job-total").and_then(GithubValue::as_number),
        Some(3.0)
    );

    let GithubValue::Object(needs) = expression.named_value("needs").expect("needs context") else {
        panic!("needs context must be an object");
    };
    let GithubValue::Object(build) = needs.get("build").expect("build need") else {
        panic!("build need must be an object");
    };
    assert_eq!(
        build.get("result").and_then(GithubValue::as_str),
        Some("success")
    );
    let GithubValue::Object(outputs) = build.get("outputs").expect("need outputs") else {
        panic!("need outputs must be an object");
    };
    assert_eq!(
        outputs.get("artifact").and_then(GithubValue::as_str),
        Some("bundle-42")
    );
    assert!(outputs.get("private").is_none());

    let GithubValue::Object(secrets) = expression.named_value("secrets").expect("secrets context")
    else {
        panic!("secrets context must be an object");
    };
    assert!(secrets.entries().is_empty());
    assert!(!format!("{snapshot:?}").contains(SECRET_DERIVED_NEED_SENTINEL));
    assert_eq!(
        fixture.runtime_context.secrets()["DEPLOY_KEY"].binding_id(),
        "secret/deploy-key"
    );
}

#[test]
fn healthy_service_discovery_is_exposed_through_the_job_context() {
    let fixture = ContextFixture::new();
    let postgres =
        ServicePort::new(5432, None, ServiceTransportProtocol::Tcp).expect("service port");
    let binding = ServiceContainerBinding::new(
        ContainerHandle::new("postgres-container").expect("container handle"),
        ServiceNetwork::new("job-network").expect("network"),
        [ServicePortBinding::new(postgres, 31_337).expect("port binding")],
    )
    .expect("service binding");
    let services =
        ServiceContainerBindings::new(BTreeMap::from([("postgres".to_owned(), binding)]))
            .expect("service bindings");
    let snapshot = fixture
        .snapshot_with_services(&services)
        .expect("context snapshot");
    let GithubValue::Object(job) = snapshot
        .expression()
        .named_value("job")
        .expect("job context")
    else {
        panic!("job context must be an object");
    };
    let GithubValue::Object(services) = job.get("services").expect("services context") else {
        panic!("services context must be an object");
    };
    let GithubValue::Object(postgres) = services.get("postgres").expect("postgres service") else {
        panic!("postgres context must be an object");
    };
    assert_eq!(
        postgres.get("id").and_then(GithubValue::as_str),
        Some("postgres-container")
    );
    assert_eq!(
        postgres.get("network").and_then(GithubValue::as_str),
        Some("job-network")
    );
    let GithubValue::Object(ports) = postgres.get("ports").expect("service ports") else {
        panic!("ports context must be an object");
    };
    assert_eq!(
        ports.get("5432").and_then(GithubValue::as_str),
        Some("31337")
    );
}

#[test]
fn github_token_is_unavailable_without_job_bound_authority() {
    let fixture = ContextFixture::new();
    let snapshot = fixture.snapshot().expect("context snapshot");
    let github = snapshot
        .expression()
        .named_value("github")
        .expect("github context");
    let GithubValue::Object(github) = github else {
        panic!("github context must be an object");
    };
    let GithubValue::Object(secrets) = snapshot
        .expression()
        .named_value("secrets")
        .expect("secrets context")
    else {
        panic!("secrets context must be an object");
    };

    assert_eq!(github.get("token").and_then(GithubValue::as_str), Some(""));
    assert!(secrets.get("GITHUB_TOKEN").is_none());
    assert!(snapshot.secret_masks().is_empty());
    assert!(
        snapshot
            .environment()
            .iter()
            .all(|value| value.name() != "GITHUB_TOKEN")
    );
}

#[test]
fn repository_token_aliases_receive_only_the_masked_repository_authority() {
    let mut fixture = ContextFixture::new();
    fixture.add_repository_authority("https://github.com/", REPOSITORY_TOKEN);
    let snapshot = fixture.snapshot().expect("context snapshot");
    let github = snapshot
        .expression()
        .named_value("github")
        .expect("github context");
    let GithubValue::Object(github) = github else {
        panic!("github context must be an object");
    };
    assert_eq!(
        github.get("token").and_then(GithubValue::as_str),
        Some(REPOSITORY_TOKEN)
    );
    let GithubValue::Object(secrets) = snapshot
        .expression()
        .named_value("secrets")
        .expect("secrets context")
    else {
        panic!("secrets context must be an object");
    };
    assert_eq!(
        secrets.get("GITHUB_TOKEN").and_then(GithubValue::as_str),
        Some(REPOSITORY_TOKEN)
    );
    assert_eq!(snapshot.secret_masks().len(), 1);
    assert_eq!(snapshot.secret_masks()[0].expose_secret(), REPOSITORY_TOKEN);
    assert!(
        snapshot
            .environment()
            .iter()
            .all(|value| value.name() != "GITHUB_TOKEN")
    );

    let checkout_default = GithubConditionCompiler::default()
        .compile_value_expression("${{ github.token }}", GithubConditionPhase::Step)
        .expect("checkout token default");
    let evaluated = GithubExpressionEvaluator::default()
        .evaluate(&checkout_default, snapshot.expression())
        .expect("evaluate checkout token default");
    assert_eq!(evaluated.as_str(), Some(REPOSITORY_TOKEN));
    let rendered = format!("{snapshot:?} {github:?} {secrets:?} {evaluated:?}");
    assert!(!rendered.contains(REPOSITORY_TOKEN));
}

#[test]
fn repository_authority_with_the_wrong_endpoint_fails_closed() {
    let mut fixture = ContextFixture::new();
    fixture.add_repository_authority("https://api.github.com/", REPOSITORY_TOKEN);

    assert_eq!(
        fixture
            .snapshot()
            .expect_err("wrong repository endpoint")
            .kind(),
        PortErrorKind::InvalidData
    );
}

#[test]
fn results_authority_is_injected_only_as_a_masked_job_secret() {
    let fixture = ContextFixture::new();
    let snapshot = fixture.snapshot().expect("context snapshot");
    let results_url = snapshot
        .environment()
        .iter()
        .find(|value| value.name() == "ACTIONS_RESULTS_URL")
        .expect("Results URL");
    assert_eq!(results_url.expose_value(), "https://results.example.test/");
    assert!(!results_url.is_secret());
    let cache_v2 = snapshot
        .environment()
        .iter()
        .find(|value| value.name() == "ACTIONS_CACHE_SERVICE_V2")
        .expect("cache v2 marker");
    assert_eq!(cache_v2.expose_value(), "true");
    assert!(!cache_v2.is_secret());
    let runtime_token = snapshot
        .environment()
        .iter()
        .find(|value| value.name() == "ACTIONS_RUNTIME_TOKEN")
        .expect("runtime token");
    assert_eq!(runtime_token.expose_value(), "fixture-results-jwt");
    assert!(runtime_token.is_secret());
    assert!(!format!("{snapshot:?}").contains("fixture-results-jwt"));
    assert!(snapshot.environment().iter().all(|value| {
        !matches!(
            value.name(),
            "ACTIONS_ID_TOKEN_REQUEST_URL" | "ACTIONS_ID_TOKEN_REQUEST_TOKEN"
        )
    }));
}

#[test]
fn credential_free_context_injects_no_authority_or_results_contract() {
    let fixture = ContextFixture::credential_free();
    let snapshot = fixture
        .snapshot()
        .expect("credential-free context snapshot");
    assert!(snapshot.secret_masks().is_empty());
    assert!(snapshot.environment().iter().all(|value| {
        !value.is_secret()
            && !matches!(
                value.name(),
                "ACTIONS_RESULTS_URL"
                    | "ACTIONS_CACHE_SERVICE_V2"
                    | "ACTIONS_RUNTIME_TOKEN"
                    | "ACTIONS_ID_TOKEN_REQUEST_URL"
                    | "ACTIONS_ID_TOKEN_REQUEST_TOKEN"
                    | "GITHUB_TOKEN"
            )
    }));
    let github_token = GithubConditionCompiler::default()
        .compile_value_expression("${{ github.token }}", GithubConditionPhase::Step)
        .expect("github token expression");
    assert_eq!(
        GithubExpressionEvaluator::default()
            .evaluate(&github_token, snapshot.expression())
            .expect("evaluate absent token")
            .as_str(),
        Some("")
    );

    let mut secret_binding = ContextFixture::credential_free();
    secret_binding.runtime_context = fixture_runtime_context();
    assert_eq!(
        secret_binding
            .snapshot()
            .expect_err("credential-free runtime secret binding")
            .kind(),
        PortErrorKind::InvalidData
    );
}

#[test]
fn oidc_authority_injects_only_the_exact_masked_request_contract() {
    let mut fixture = ContextFixture::new();
    fixture.add_oidc_authority(
        RuntimeAuthorityEndpoint::new("https://oidc.example.test/")
            .expect("OIDC authority endpoint"),
        OIDC_REQUEST_TOKEN,
    );

    let snapshot = fixture.snapshot().expect("context snapshot");
    let request_url = snapshot
        .environment()
        .iter()
        .find(|value| value.name() == "ACTIONS_ID_TOKEN_REQUEST_URL")
        .expect("OIDC request URL");
    assert_eq!(
        request_url.expose_value(),
        "https://oidc.example.test/oidc/token?api-version=2.0"
    );
    assert!(!request_url.is_secret());
    let request_token = snapshot
        .environment()
        .iter()
        .find(|value| value.name() == "ACTIONS_ID_TOKEN_REQUEST_TOKEN")
        .expect("OIDC request token");
    assert_eq!(request_token.expose_value(), OIDC_REQUEST_TOKEN);
    assert!(request_token.is_secret());
    assert!(!format!("{snapshot:?}").contains(OIDC_REQUEST_TOKEN));
}

#[test]
fn authority_context_custody_shares_original_secret_allocations() {
    let mut fixture = ContextFixture::new();
    fixture.add_repository_authority("https://github.com/", REPOSITORY_TOKEN);
    fixture.add_oidc_authority(
        RuntimeAuthorityEndpoint::new("https://oidc.example.test/")
            .expect("OIDC authority endpoint"),
        OIDC_REQUEST_TOKEN,
    );

    let results = fixture
        .runtime_authorities
        .get("github-actions-results")
        .expect("Results authority")
        .credential()
        .shared_secret();
    let repository = fixture
        .runtime_authorities
        .get("github-repository")
        .expect("repository authority")
        .credential()
        .shared_secret();
    let oidc = fixture
        .runtime_authorities
        .get("github-oidc")
        .expect("OIDC authority")
        .credential()
        .shared_secret();
    let results_count = Arc::strong_count(&results);
    let repository_count = Arc::strong_count(&repository);
    let oidc_count = Arc::strong_count(&oidc);

    let snapshot = fixture.snapshot().expect("context snapshot");
    let results_variable = snapshot
        .environment()
        .iter()
        .find(|value| value.name() == "ACTIONS_RUNTIME_TOKEN")
        .expect("Results token");
    let oidc_variable = snapshot
        .environment()
        .iter()
        .find(|value| value.name() == "ACTIONS_ID_TOKEN_REQUEST_TOKEN")
        .expect("OIDC token");

    assert_eq!(
        results_variable
            .shared_secret_value()
            .expect("shared Results token")
            .expose_secret()
            .as_ptr(),
        results.expose_secret().as_ptr()
    );
    assert_eq!(
        snapshot.secret_masks()[0].expose_secret().as_ptr(),
        repository.expose_secret().as_ptr()
    );
    assert_eq!(
        oidc_variable
            .shared_secret_value()
            .expect("shared OIDC token")
            .expose_secret()
            .as_ptr(),
        oidc.expose_secret().as_ptr()
    );
    assert_eq!(Arc::strong_count(&results), results_count + 1);
    assert_eq!(Arc::strong_count(&repository), repository_count + 1);
    assert_eq!(Arc::strong_count(&oidc), oidc_count + 1);
    let debug = format!("{snapshot:?} {results_variable:?} {oidc_variable:?}");
    assert!(!debug.contains(results.expose_secret()));
    assert!(!debug.contains(repository.expose_secret()));
    assert!(!debug.contains(oidc.expose_secret()));

    let GithubValue::Object(github) = snapshot
        .expression()
        .named_value("github")
        .expect("github context")
    else {
        panic!("github context must be an object");
    };
    let github_token = github
        .get("token")
        .and_then(GithubValue::as_str)
        .expect("github token");
    assert_eq!(github_token, REPOSITORY_TOKEN);
    assert_ne!(github_token.as_ptr(), repository.expose_secret().as_ptr());

    drop(snapshot);
    assert_eq!(Arc::strong_count(&results), results_count);
    assert_eq!(Arc::strong_count(&repository), repository_count);
    assert_eq!(Arc::strong_count(&oidc), oidc_count);
}

#[test]
fn oidc_authority_requires_tls_before_context_exposure() {
    let mut fixture = ContextFixture::new();
    fixture.add_oidc_authority(
        RuntimeAuthorityEndpoint::loopback_development("http://localhost:8080/")
            .expect("development authority endpoint"),
        OIDC_REQUEST_TOKEN,
    );

    assert_eq!(
        fixture
            .snapshot()
            .expect_err("insecure OIDC authority")
            .kind(),
        PortErrorKind::InvalidData
    );
}

#[test]
fn oidc_authority_requires_the_exact_job_permission_before_exposure() {
    let mut fixture = ContextFixture::new();
    fixture.add_oidc_authority(
        RuntimeAuthorityEndpoint::new("https://oidc.example.test/")
            .expect("OIDC authority endpoint"),
        OIDC_REQUEST_TOKEN,
    );
    fixture.replace_permission_request(JobPermissionRequest::mapping([]));

    let error = fixture
        .snapshot()
        .expect_err("an unentitled job must reject an injected OIDC authority");
    assert_eq!(error.kind(), PortErrorKind::InvalidData);
    assert!(!format!("{error:?}").contains(OIDC_REQUEST_TOKEN));
}

#[test]
fn id_token_source_permission_does_not_synthesize_runtime_authority() {
    let fixture = ContextFixture::new();
    assert_eq!(
        fixture.job.job().permission_request(),
        &JobPermissionRequest::mapping([JobPermissionGrant::new(
            "id-token",
            PermissionLevel::Write,
        )])
    );

    let snapshot = fixture.snapshot().expect("context snapshot");
    assert!(snapshot.environment().iter().all(|value| {
        !matches!(
            value.name(),
            "ACTIONS_ID_TOKEN_REQUEST_URL" | "ACTIONS_ID_TOKEN_REQUEST_TOKEN"
        )
    }));
}

#[test]
fn missing_or_cross_fence_results_authority_fails_closed() {
    let mut missing = ContextFixture::new();
    let unrelated = JobRuntimeAuthority::new(
        RuntimeAuthorityName::new("unrelated-service").expect("authority name"),
        missing.job.job().run_id(),
        missing.job.job().job_id(),
        missing.lease.attempt_id(),
        missing.lease.fencing_token(),
        RuntimeAuthorityEndpoint::new("https://unrelated.example.test/").expect("endpoint"),
        RuntimeAuthorityCredential::new("unrelated-token").expect("token"),
        missing.lease.issued_at(),
        missing.lease.expires_at(),
    )
    .expect("authority");
    missing.runtime_authorities =
        JobRuntimeAuthorities::new(vec![unrelated], &missing.job, &missing.lease)
            .expect("authority bundle");
    assert_eq!(
        missing
            .snapshot()
            .expect_err("missing Results authority")
            .kind(),
        PortErrorKind::InvalidData
    );

    let cross_fence = ContextFixture::new();
    let stale_lease = Lease::new(
        cross_fence.lease.lease_id(),
        cross_fence.lease.attempt_id(),
        cross_fence.lease.runner_id(),
        FencingToken::new(cross_fence.lease.fencing_token().get() + 1).expect("new fence"),
        cross_fence.lease.issued_at(),
        cross_fence.lease.expires_at(),
    )
    .expect("stale lease fixture");
    let commands = JobCommandState::new(CommandFilePlatform::Unix);
    let event_path = fixture_event_path();
    let event = empty_event();
    let error = cross_fence
        .context
        .snapshot(GithubContextRequest::new(
            GithubExecutionIdentity::new(
                &cross_fence.job,
                &cross_fence.runtime_context,
                &stale_lease,
                &cross_fence.runtime_authorities,
            ),
            &event_path,
            &event,
            &commands,
            &[],
            GithubStatus::Success,
            None,
            GithubExecutionPhase::Job,
        ))
        .expect_err("cross-fence authority");
    assert_eq!(error.kind(), PortErrorKind::InvalidData);
}

struct ContextFixture {
    context: StandardGithubContext,
    job: JobIrEnvelope,
    runtime_context: JobRuntimeContext,
    lease: Lease,
    runtime_authorities: JobRuntimeAuthorities,
}

impl ContextFixture {
    fn new() -> Self {
        let mut document: serde_json::Value =
            serde_json::from_slice(include_bytes!("../config/runner.local.example.json"))
                .expect("runner config JSON");
        document["github"]["server_url"] = serde_json::json!("https://github.com/");
        document["github"]["api_url"] = serde_json::json!("https://api.github.com/");
        document["github"]["graphql_url"] = serde_json::json!("https://api.github.com/graphql");
        document["github"]["allow_insecure_http"] = serde_json::json!(false);
        let encoded = serde_json::to_vec(&document).expect("runner config encoding");
        let config = RunnerProductConfig::from_json(&encoded).expect("valid runner config fixture");
        let (profile, _) = config
            .environments()
            .first_key_value()
            .expect("one configured environment");
        let runtime_context = fixture_runtime_context();
        let job = JobIrEnvelope::new(
            WorkflowId::new(),
            JobSource::new(
                "github",
                "automata-ci/automata",
                "0123456789abcdef0123456789abcdef01234567",
                ".github/workflows/ci.yml",
                "workflow_dispatch",
            ),
            JobExecutionContext::new(
                "CI",
                "refs/heads/main",
                "/__w/automata/automata",
                JobContentReference::new(
                    "events/dispatch.json",
                    Sha256Digest::from_bytes([0x42; 32]),
                    2,
                    "application/json",
                ),
                JobContentReference::new(
                    "contexts/context-fixture.pb",
                    Sha256Digest::from_bytes([0x43; 32]),
                    128,
                    "application/vnd.automata.job-runtime-context.protobuf",
                ),
            )
            .with_actor("local-bootstrap")
            .with_run_id_alias(RunIdAlias::new(42).expect("run ID alias"))
            .with_run_attempt(1),
            JobIr::new(
                JobId::new(),
                RunId::new(),
                "context fixture",
                RunnerRequirements::default().with_environment_profile(profile.clone()),
                JobInstanceIdentity::new(
                    "context-fixture",
                    1,
                    3,
                    Sha256Digest::from_bytes([0x44; 32]),
                )
                .expect("instance identity"),
                false,
                Vec::new(),
            )
            .with_permission_request(JobPermissionRequest::mapping([
                JobPermissionGrant::new("id-token", PermissionLevel::Write),
            ])),
        );
        let context = StandardGithubContext::new(
            config.runner_id(),
            config.environments(),
            config.executor(),
            config.github().clone(),
        )
        .expect("valid production context");
        let lease = Lease::new(
            LeaseId::new(),
            AttemptId::new(),
            config.runner_id(),
            FencingToken::new(1).expect("positive fixture fence"),
            UnixMillis::new(1_700_000_000_000),
            UnixMillis::new(4_000_000_000_000),
        )
        .expect("valid fixture lease");
        let authority = JobRuntimeAuthority::new(
            RuntimeAuthorityName::new("github-actions-results").expect("authority name"),
            job.job().run_id(),
            job.job().job_id(),
            lease.attempt_id(),
            lease.fencing_token(),
            RuntimeAuthorityEndpoint::new("https://results.example.test/")
                .expect("authority endpoint"),
            RuntimeAuthorityCredential::new("fixture-results-jwt").expect("authority token"),
            UnixMillis::new(1_700_000_000_000),
            UnixMillis::new(4_000_000_000_000),
        )
        .expect("valid fixture authority");
        let runtime_authorities = JobRuntimeAuthorities::new(vec![authority], &job, &lease)
            .expect("valid fixture authority bundle");
        Self {
            context,
            job,
            runtime_context,
            lease,
            runtime_authorities,
        }
    }

    fn credential_free() -> Self {
        let mut fixture = Self::new();
        let job = fixture
            .job
            .job()
            .clone()
            .with_authority_profile(JobAuthorityProfile::CredentialFree)
            .with_permission_request(JobPermissionRequest::Mapping(Vec::new()));
        fixture.job = JobIrEnvelope::new(
            fixture.job.workflow_id(),
            fixture.job.source().clone(),
            fixture.job.execution().clone(),
            job,
        );
        fixture.runtime_context = JobRuntimeContext::new(
            fixture.runtime_context.inputs().clone(),
            fixture.runtime_context.vars().clone(),
            fixture.runtime_context.matrix().clone(),
            fixture.runtime_context.strategy(),
            fixture.runtime_context.needs().clone(),
            BTreeMap::new(),
        )
        .expect("credential-free runtime context");
        fixture.runtime_authorities =
            JobRuntimeAuthorities::new(Vec::new(), &fixture.job, &fixture.lease)
                .expect("credential-free authority bundle");
        fixture
    }

    fn add_repository_authority(&mut self, endpoint: &str, token: &str) {
        let repository = JobRuntimeAuthority::new(
            RuntimeAuthorityName::new("github-repository").expect("authority name"),
            self.job.job().run_id(),
            self.job.job().job_id(),
            self.lease.attempt_id(),
            self.lease.fencing_token(),
            RuntimeAuthorityEndpoint::new(endpoint).expect("repository endpoint"),
            RuntimeAuthorityCredential::new(token).expect("repository token"),
            self.lease.issued_at(),
            self.lease.expires_at(),
        )
        .expect("repository authority");
        let mut authorities = self.runtime_authorities.as_slice().to_vec();
        authorities.push(repository);
        authorities.sort_by(|left, right| left.name().cmp(right.name()));
        self.runtime_authorities = JobRuntimeAuthorities::new(authorities, &self.job, &self.lease)
            .expect("authority bundle");
    }

    fn replace_permission_request(&mut self, permission_request: JobPermissionRequest) {
        let job = self
            .job
            .job()
            .clone()
            .with_permission_request(permission_request);
        self.job = JobIrEnvelope::new(
            self.job.workflow_id(),
            self.job.source().clone(),
            self.job.execution().clone(),
            job,
        );
    }

    fn add_oidc_authority(&mut self, endpoint: RuntimeAuthorityEndpoint, token: &str) {
        let oidc = JobRuntimeAuthority::new(
            RuntimeAuthorityName::new("github-oidc").expect("OIDC authority name"),
            self.job.job().run_id(),
            self.job.job().job_id(),
            self.lease.attempt_id(),
            self.lease.fencing_token(),
            endpoint,
            RuntimeAuthorityCredential::new(token).expect("OIDC request token"),
            self.lease.issued_at(),
            self.lease.expires_at(),
        )
        .expect("OIDC authority");
        let mut authorities = self.runtime_authorities.as_slice().to_vec();
        authorities.push(oidc);
        authorities.sort_by(|left, right| left.name().cmp(right.name()));
        self.runtime_authorities = JobRuntimeAuthorities::new(authorities, &self.job, &self.lease)
            .expect("authority bundle");
    }

    fn snapshot(
        &self,
    ) -> Result<
        automata_ci_job_executor_github::GithubContextSnapshot,
        automata_ci_job_executor_github::PortError,
    > {
        let event = empty_event();
        self.snapshot_with_event(&event)
    }

    fn snapshot_with_event(
        &self,
        event: &GithubValue,
    ) -> Result<
        automata_ci_job_executor_github::GithubContextSnapshot,
        automata_ci_job_executor_github::PortError,
    > {
        let commands = JobCommandState::new(CommandFilePlatform::Unix);
        let event_path = fixture_event_path();
        self.context.snapshot(GithubContextRequest::new(
            GithubExecutionIdentity::new(
                &self.job,
                &self.runtime_context,
                &self.lease,
                &self.runtime_authorities,
            ),
            &event_path,
            event,
            &commands,
            &[],
            GithubStatus::Success,
            None,
            GithubExecutionPhase::Job,
        ))
    }

    fn snapshot_with_services(
        &self,
        services: &ServiceContainerBindings,
    ) -> Result<
        automata_ci_job_executor_github::GithubContextSnapshot,
        automata_ci_job_executor_github::PortError,
    > {
        let commands = JobCommandState::new(CommandFilePlatform::Unix);
        let event_path = fixture_event_path();
        let event = empty_event();
        self.context.snapshot(
            GithubContextRequest::new(
                GithubExecutionIdentity::new(
                    &self.job,
                    &self.runtime_context,
                    &self.lease,
                    &self.runtime_authorities,
                ),
                &event_path,
                &event,
                &commands,
                &[],
                GithubStatus::Success,
                None,
                GithubExecutionPhase::Run,
            )
            .with_services(Some(services)),
        )
    }
}

fn fixture_runtime_context() -> JobRuntimeContext {
    let inputs = ContextValue::object(BTreeMap::from([(
        "deploy".to_owned(),
        ContextValue::boolean(true),
    )]))
    .expect("inputs context");
    let vars = ContextValue::object(BTreeMap::from([(
        "channel".to_owned(),
        ContextValue::string("stable"),
    )]))
    .expect("vars context");
    let matrix = ContextValue::object(BTreeMap::from([
        ("os".to_owned(), ContextValue::string("linux")),
        ("shard".to_owned(), ContextValue::number(2.0)),
    ]))
    .expect("matrix context");
    let outputs = BTreeMap::from([
        (
            "artifact".to_owned(),
            NeedOutput::new("bundle-42", OutputSensitivity::Public).expect("public output"),
        ),
        (
            "private".to_owned(),
            NeedOutput::new(
                SECRET_DERIVED_NEED_SENTINEL,
                OutputSensitivity::SecretDerived,
            )
            .expect("secret-derived output"),
        ),
    ]);
    let needs = BTreeMap::from([(
        "build".to_owned(),
        NeedContext::new(JobConclusion::Success, outputs).expect("need context"),
    )]);
    let secrets = BTreeMap::from([(
        "DEPLOY_KEY".to_owned(),
        SecretBinding::new("secret/deploy-key")
            .and_then(|binding| binding.with_version_id("version-7"))
            .expect("secret binding"),
    )]);
    JobRuntimeContext::new(
        inputs,
        vars,
        matrix,
        StrategyContext::new(false, 1, 3, 2).expect("strategy context"),
        needs,
        secrets,
    )
    .expect("runtime context")
}

fn fixture_event_path() -> TargetPath {
    TargetPath::posix("/__automata/attempts/fixture/event.json").expect("event target")
}

fn empty_event() -> GithubValue {
    object(Vec::new())
}

fn object(entries: Vec<(&str, GithubValue)>) -> GithubValue {
    GithubObject::new(
        entries
            .into_iter()
            .map(|(name, value)| (name.to_owned(), value))
            .collect(),
    )
    .map(GithubValue::object)
    .expect("valid synthetic GitHub context object")
}
