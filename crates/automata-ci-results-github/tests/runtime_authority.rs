use std::sync::{
    Arc,
    atomic::{AtomicU64, Ordering},
};

use automata_ci_control::runner_control::{
    RuntimeAuthorityIssueRequest, RuntimeAuthorityIssuer as _,
};
use automata_ci_core::{
    AttemptId, FencingToken, JobId, JobInstanceIdentity, JobIr, JobIrEnvelope, JobSource, Lease,
    LeaseId, RunId, RunValueTemplates, RunnerId, RunnerRequirements, RunnerSessionId,
    RuntimeBoolean, SemanticStep, Sha256Digest, ShellTemplate, StepId, StepIr, UnixMillis,
    ValueTemplate, WorkflowId,
};
use automata_ci_protocol::ProtocolLimits;
use automata_ci_protocol_protobuf::encode_job_ir;
use automata_ci_results_github::{
    CacheAccessScope, CachePermission, CacheRepositoryMetadata, GITHUB_RESULTS_RUNTIME_AUTHORITY,
    GithubResultsRuntimeAuthorityIssuer, HmacResultsAuthority, HmacResultsAuthorityConfig,
    ResultsClock, ResultsPublicEndpoint, RuntimeTokenVerifier as _, TokenError,
};
use automata_ci_store::{
    JobIrMetadata, ObjectKey, RunnerGeneration, RunnerSessionFence, SessionEpoch, StableRunnerSlot,
};
use sha2::{Digest as _, Sha256};
use url::Url;

const SIGNING_KEY: &[u8] = b"runtime-authority-test-signing-key-material-v1";

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

fn job() -> JobIrEnvelope {
    job_for("owner/repository", "refs/heads/feature", "push")
}

fn job_for(repository: &str, git_ref: &str, event_name: &str) -> JobIrEnvelope {
    JobIrEnvelope::new(
        WorkflowId::new(),
        JobSource::new(
            "github",
            repository,
            "0123456789abcdef",
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
        ),
    )
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

#[test]
fn development_endpoint_requires_an_exact_safe_bind_and_host_assertion() {
    let podman = ResultsPublicEndpoint::trusted_private_development(
        Url::parse("http://host.containers.internal:8081/").expect("URL"),
        "10.88.0.1:8081".parse().expect("private bind"),
        "host.containers.internal",
    )
    .expect("trusted Podman bridge endpoint");
    assert_eq!(
        podman.development_listener_bind(),
        Some("10.88.0.1:8081".parse().expect("private bind"))
    );

    for rejected in [
        ResultsPublicEndpoint::trusted_private_development(
            Url::parse("http://host.containers.internal:8081/").expect("URL"),
            "0.0.0.0:8081".parse().expect("wildcard bind"),
            "host.containers.internal",
        ),
        ResultsPublicEndpoint::trusted_private_development(
            Url::parse("http://host.containers.internal:8081/").expect("URL"),
            "10.88.0.1:8082".parse().expect("private bind"),
            "host.containers.internal",
        ),
        ResultsPublicEndpoint::trusted_private_development(
            Url::parse("http://host.containers.internal:8081/").expect("URL"),
            "10.88.0.1:8081".parse().expect("private bind"),
            "different.internal",
        ),
        ResultsPublicEndpoint::trusted_private_development(
            Url::parse("http://host.containers.internal:8081/").expect("URL"),
            "203.0.113.10:8081".parse().expect("public bind"),
            "host.containers.internal",
        ),
    ] {
        assert_eq!(rejected, Err(TokenError::Policy));
    }
}
