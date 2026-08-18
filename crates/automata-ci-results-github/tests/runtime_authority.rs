mod fixture_support;

use std::sync::Arc;

use automata_ci_control::runner_control::{
    RuntimeAuthorityIssueRequest, RuntimeAuthorityIssuer as _,
};
use automata_ci_core::{
    AttemptId, FencingToken, JobId, JobInstanceIdentity, JobIr, JobIrEnvelope,
    JobPermissionRequest, JobSource, Lease, LeaseId, RunId, RunValueTemplates, RunnerId,
    RunnerRequirements, RunnerSessionId, RuntimeBoolean, SemanticStep, Sha256Digest, ShellTemplate,
    StepId, StepIr, TrustActorEvidence, TrustActorKind, TrustAutomationKind, TrustEventKind,
    TrustEvidence, TrustOriginKind, TrustPermissionAuthority, TrustPolicy, TrustRepositoryEvidence,
    TrustSnapshot, TrustTokenRecursion, UnixMillis, ValueTemplate, WorkflowId,
};
use automata_ci_protocol::ProtocolLimits;
use automata_ci_protocol_protobuf::encode_job_ir;
use automata_ci_results_github::{
    CacheAccessScope, CachePermission, CacheRepositoryMetadata, GITHUB_RESULTS_RUNTIME_AUTHORITY,
    GithubResultsRuntimeAuthorityIssuer, HmacResultsAuthority, HmacResultsAuthorityConfig,
    ResultsPublicEndpoint, RuntimeTokenVerifier as _, TokenError,
};
use automata_ci_store::{
    JobIrMetadata, ObjectKey, RunnerGeneration, RunnerSessionFence, SessionEpoch, StableRunnerSlot,
};
use fixture_support::MutableClock;
use sha2::{Digest as _, Sha256};
use url::Url;

const SIGNING_KEY: &[u8] = b"runtime-authority-test-signing-key-material-v1";

fn job() -> JobIrEnvelope {
    job_for("owner/repository", "refs/heads/feature", "push")
}

fn job_for(repository: &str, git_ref: &str, event_name: &str) -> JobIrEnvelope {
    job_for_snapshot(
        repository,
        git_ref,
        event_name,
        same_repository_snapshot(repository),
    )
}

fn job_for_snapshot(
    repository: &str,
    git_ref: &str,
    event_name: &str,
    trust_snapshot: TrustSnapshot,
) -> JobIrEnvelope {
    let permission_request = match trust_snapshot.authority().permissions() {
        TrustPermissionAuthority::Requested => JobPermissionRequest::ProviderDefault,
        TrustPermissionAuthority::ReadOnly => JobPermissionRequest::ReadAll,
        TrustPermissionAuthority::DenyAll => JobPermissionRequest::mapping([]),
    };
    JobIrEnvelope::new(
        WorkflowId::new(),
        JobSource::new(
            "github",
            repository,
            automata_ci_core::GitObjectId::from_provider_hex(
                "0123456789abcdef0123456789abcdef01234567",
            )
            .expect("revision"),
            ".ci/workflows/ci.yml",
            event_name,
        ),
        automata_ci_core::JobExecutionContext::new(
            "CI",
            git_ref,
            "/__w/automata/automata",
            automata_ci_core::JobContentReference::new(
                "events/push.json",
                automata_ci_core::Sha256Digest::from_bytes([0x42; 32]),
                2,
                "application/json",
            ),
            automata_ci_core::JobContentReference::new(
                "contexts/dist.pb",
                automata_ci_core::Sha256Digest::from_bytes([0x43; 32]),
                2,
                "application/vnd.automata.job-runtime-context.protobuf",
            ),
        ),
        JobIr::new(
            JobId::new(),
            RunId::new(),
            "dist",
            RunnerRequirements::default(),
            JobInstanceIdentity::new("dist", 0, 1, Sha256Digest::from_bytes([0x44; 32]))
                .expect("job instance"),
            false,
            vec![StepIr::new(
                StepId::new("dist").expect("step ID"),
                ValueTemplate::literal("Build distribution").expect("step name template"),
                RuntimeBoolean::literal(false),
                SemanticStep::run(RunValueTemplates::new(
                    ValueTemplate::literal("cargo build").expect("command"),
                    ShellTemplate::default_shell(),
                )),
            )],
        )
        .with_permission_request(permission_request)
        .with_trust_snapshot(trust_snapshot),
    )
}

fn same_repository_snapshot(repository: &str) -> TrustSnapshot {
    TrustPolicy::current()
        .evaluate(
            TrustEvidence::new(TrustOriginKind::ProviderWebhook, TrustEventKind::Push)
                .with_original_actor(actor("actor-1"))
                .with_repositories(
                    TrustRepositoryEvidence::new(repository, "owner-1").expect("source repository"),
                    TrustRepositoryEvidence::new(repository, "owner-1").expect("target repository"),
                )
                .with_refs("refs/heads/main", "refs/heads/main", "refs/heads/main")
                .with_revisions("source-sha", "target-sha", "execution-sha")
                .with_fork(false)
                .with_token_recursion(TrustTokenRecursion::Suppressed),
        )
        .expect("same-repository trust")
}

fn fork_snapshot(repository: &str) -> TrustSnapshot {
    TrustPolicy::current()
        .evaluate(
            TrustEvidence::new(
                TrustOriginKind::ProviderWebhook,
                TrustEventKind::PullRequest,
            )
            .with_original_actor(actor("actor-1"))
            .with_source_actor(actor("fork-actor"))
            .with_repositories(
                TrustRepositoryEvidence::new("fork/repository", "fork-owner")
                    .expect("source repository"),
                TrustRepositoryEvidence::new(repository, "owner-1").expect("target repository"),
            )
            .with_refs("refs/heads/feature", "refs/heads/main", "refs/pull/1/merge")
            .with_revisions("source-sha", "target-sha", "execution-sha")
            .with_fork(true),
        )
        .expect("fork trust")
}

fn deny_all_snapshot() -> TrustSnapshot {
    TrustPolicy::current()
        .evaluate(TrustEvidence::new(
            TrustOriginKind::ProviderWebhook,
            TrustEventKind::Push,
        ))
        .expect("incomplete evidence is a deny-all decision")
}

fn actor(id: &str) -> TrustActorEvidence {
    TrustActorEvidence::new(id, TrustActorKind::User, TrustAutomationKind::None)
        .expect("actor evidence")
}

fn job_ir_metadata(job: &JobIrEnvelope) -> JobIrMetadata {
    let encoded = encode_job_ir(job, &ProtocolLimits::default()).expect("canonical JobIR");
    JobIrMetadata::new(
        job.job().job_id(),
        job.job().run_id(),
        job.version(),
        u64::try_from(encoded.len()).expect("bounded JobIR size"),
        Sha256Digest::from_bytes(Sha256::digest(encoded).into()),
        ObjectKey::new("job-ir/results-runtime-authority.pb").expect("object key"),
    )
    .expect("metadata")
}

fn authority_request<'a>(
    job: &'a JobIrEnvelope,
    metadata: &'a JobIrMetadata,
    lease: &'a Lease,
) -> RuntimeAuthorityIssueRequest<'a> {
    RuntimeAuthorityIssueRequest::new(
        job,
        metadata,
        lease,
        lease.issued_at(),
        RunnerSessionFence::new(
            RunnerSessionId::new(),
            lease.runner_id(),
            RunnerGeneration::new(1).expect("runner generation"),
            SessionEpoch::new(1).expect("session epoch"),
        ),
        StableRunnerSlot::new(1).expect("runner slot"),
    )
    .expect("valid runtime-authority request")
}

fn make_lease(attempt_id: AttemptId, fencing_token: FencingToken, issued_at: UnixMillis) -> Lease {
    Lease::new(
        LeaseId::new(),
        attempt_id,
        RunnerId::new(),
        fencing_token,
        issued_at,
        UnixMillis::new(issued_at.get() + 60_000),
    )
    .expect("lease")
}

fn authority(clock: Arc<MutableClock>) -> Arc<HmacResultsAuthority> {
    Arc::new(
        HmacResultsAuthority::new(
            SIGNING_KEY,
            HmacResultsAuthorityConfig::new(
                "automata-tests",
                "actions-results",
                "runtime-v1",
                ResultsPublicEndpoint::https(
                    Url::parse("https://results.example.test/").expect("URL"),
                )
                .expect("HTTPS endpoint"),
                900,
                300,
                0,
            )
            .expect("authority config"),
            clock,
        )
        .expect("authority"),
    )
}

fn cache_repository() -> CacheRepositoryMetadata {
    CacheRepositoryMetadata::new("owner/repository", "main").expect("cache repository metadata")
}

#[tokio::test]
async fn deterministic_issuance_replays_exact_bytes_and_binding() {
    let clock = Arc::new(MutableClock::new(10));
    let authority = authority(clock);
    let issuer =
        GithubResultsRuntimeAuthorityIssuer::new(authority.clone(), 120, [cache_repository()])
            .expect("runtime issuer");
    let job = job();
    let lease = make_lease(
        AttemptId::new(),
        FencingToken::new(7).expect("fence"),
        UnixMillis::new(10_987),
    );
    let metadata = job_ir_metadata(&job);
    let request = authority_request(&job, &metadata, &lease);

    let first = issuer.issue(request).await.expect("first issue");
    let replay = issuer.issue(request).await.expect("replay issue");
    assert_eq!(first, replay);
    let results_authority = first
        .get(GITHUB_RESULTS_RUNTIME_AUTHORITY)
        .expect("Results authority");
    assert_eq!(results_authority.issued_at(), UnixMillis::new(10_000));
    assert_eq!(results_authority.expires_at(), UnixMillis::new(130_000));
    assert_eq!(
        results_authority.endpoint().as_str(),
        "https://results.example.test/"
    );

    let claims = authority
        .verify(results_authority.credential().expose_secret())
        .expect("issued JWT verifies");
    assert_eq!(claims.authority().run_id(), job.job().run_id());
    assert_eq!(claims.authority().job_id(), job.job().job_id());
    assert_eq!(claims.authority().attempt_id(), lease.attempt_id());
    assert_eq!(claims.authority().fencing_token(), lease.fencing_token());
    assert_eq!(claims.cache().repository(), "owner/repository");
    assert_eq!(claims.cache().scopes().len(), 2);
    assert_eq!(claims.cache().scopes()[0].scope(), "refs/heads/feature");
    assert_eq!(
        claims.cache().scopes()[0].permission(),
        CachePermission::ReadWrite
    );
    assert_eq!(claims.cache().scopes()[1].scope(), "refs/heads/main");
    assert_eq!(
        claims.cache().scopes()[1].permission(),
        CachePermission::Read
    );
    assert!(!format!("{first:?}").contains(results_authority.credential().expose_secret()));
}

#[tokio::test]
async fn default_branch_metadata_is_routed_by_exact_repository() {
    let clock = Arc::new(MutableClock::new(15));
    let authority = authority(clock);
    let issuer = GithubResultsRuntimeAuthorityIssuer::new(
        authority.clone(),
        120,
        [
            cache_repository(),
            CacheRepositoryMetadata::new("sibling/repository", "stable").expect("sibling metadata"),
        ],
    )
    .expect("runtime issuer");

    for (repository, expected_default) in [
        ("owner/repository", Some("refs/heads/main")),
        ("sibling/repository", Some("refs/heads/stable")),
        ("unregistered/repository", None),
    ] {
        let job = job_for(repository, "refs/heads/feature", "push");
        let lease = make_lease(
            AttemptId::new(),
            FencingToken::new(8).expect("fence"),
            UnixMillis::new(15_000),
        );
        let metadata = job_ir_metadata(&job);
        let bundle = issuer
            .issue(authority_request(&job, &metadata, &lease))
            .await
            .expect("issue");
        let token = bundle
            .get(GITHUB_RESULTS_RUNTIME_AUTHORITY)
            .expect("Results authority")
            .credential()
            .expose_secret();
        let claims = authority.verify(token).expect("issued JWT verifies");
        assert_eq!(claims.cache().repository(), repository);
        assert_eq!(claims.cache().scopes()[0].scope(), "refs/heads/feature");
        assert_eq!(
            claims.cache().scopes()[0].permission(),
            CachePermission::ReadWrite
        );
        assert_eq!(
            claims.cache().scopes().get(1).map(CacheAccessScope::scope),
            expected_default
        );
        if let Some(scope) = claims.cache().scopes().get(1) {
            assert_eq!(scope.permission(), CachePermission::Read);
        }
    }
}

#[tokio::test]
async fn cross_attempt_fence_and_expiry_are_rejected() {
    let clock = Arc::new(MutableClock::new(20));
    let authority = authority(clock.clone());
    let issuer =
        GithubResultsRuntimeAuthorityIssuer::new(authority.clone(), 60, [cache_repository()])
            .expect("runtime issuer");
    let job = job();
    let lease = make_lease(
        AttemptId::new(),
        FencingToken::new(11).expect("fence"),
        UnixMillis::new(20_000),
    );
    let metadata = job_ir_metadata(&job);
    let bundle = issuer
        .issue(authority_request(&job, &metadata, &lease))
        .await
        .expect("issue");
    let wrong_attempt = make_lease(AttemptId::new(), lease.fencing_token(), lease.issued_at());
    assert!(bundle.validate_for(&job, &wrong_attempt).is_err());
    let wrong_fence = make_lease(
        lease.attempt_id(),
        FencingToken::new(12).expect("fence"),
        lease.issued_at(),
    );
    assert!(bundle.validate_for(&job, &wrong_fence).is_err());

    let token = bundle
        .get(GITHUB_RESULTS_RUNTIME_AUTHORITY)
        .expect("Results authority")
        .credential()
        .expose_secret();
    clock.set(80);
    assert_eq!(authority.verify(token), Err(TokenError::Expired));
}

#[tokio::test]
async fn fork_cache_is_read_only_and_incomplete_evidence_mints_no_authority() {
    let clock = Arc::new(MutableClock::new(25));
    let authority = authority(clock);
    let issuer =
        GithubResultsRuntimeAuthorityIssuer::new(authority.clone(), 60, [cache_repository()])
            .expect("runtime issuer");
    let lease = make_lease(
        AttemptId::new(),
        FencingToken::new(13).expect("fence"),
        UnixMillis::new(25_000),
    );

    let fork = job_for_snapshot(
        "owner/repository",
        "refs/pull/1/merge",
        "pull_request",
        fork_snapshot("owner/repository"),
    );
    let fork_metadata = job_ir_metadata(&fork);
    let fork_bundle = issuer
        .issue(authority_request(&fork, &fork_metadata, &lease))
        .await
        .expect("fork results authority");
    let fork_token = fork_bundle
        .get(GITHUB_RESULTS_RUNTIME_AUTHORITY)
        .expect("fork results authority remains available")
        .credential()
        .expose_secret();
    let fork_claims = authority.verify(fork_token).expect("fork token verifies");
    assert!(!fork_claims.cache().scopes().is_empty());
    assert!(
        fork_claims
            .cache()
            .scopes()
            .iter()
            .all(|scope| scope.permission() == CachePermission::Read)
    );

    let denied = job_for_snapshot(
        "owner/repository",
        "refs/heads/main",
        "push",
        deny_all_snapshot(),
    );
    let denied_metadata = job_ir_metadata(&denied);
    let denied_bundle = issuer
        .issue(authority_request(&denied, &denied_metadata, &lease))
        .await
        .expect("deny-all has an empty authority bundle");
    assert!(denied_bundle.as_slice().is_empty());
}

#[test]
fn closed_private_network_endpoint_is_ipv4_and_results_port_exact() {
    use automata_ci_results_github::PrivateNetworkResultsEndpoint;

    let endpoint = PrivateNetworkResultsEndpoint::new(
        Url::parse("http://results.automata.invalid:8081/").expect("URL"),
        "10.91.0.2:8081".parse().expect("private IPv4 bind"),
        "results.automata.invalid",
    )
    .expect("closed private Results endpoint");
    assert_eq!(endpoint.listener().to_string(), "10.91.0.2:8081");
    assert_eq!(
        endpoint.public_endpoint().url().as_str(),
        "http://results.automata.invalid:8081/"
    );

    for listener in [
        "10.91.0.2:8080",
        "0.0.0.0:8081",
        "127.0.0.1:8081",
        "203.0.113.2:8081",
    ] {
        assert!(
            PrivateNetworkResultsEndpoint::new(
                Url::parse("http://results.automata.invalid:8081/").expect("URL"),
                listener.parse().expect("IPv4 bind"),
                "results.automata.invalid",
            )
            .is_err()
        );
    }
    assert_eq!(
        PrivateNetworkResultsEndpoint::new(
            Url::parse("http://results.automata.invalid:8081/").expect("URL"),
            "10.91.0.2:8081".parse().expect("private IPv4 bind"),
            "different.automata.invalid",
        ),
        Err(TokenError::Policy)
    );
}
