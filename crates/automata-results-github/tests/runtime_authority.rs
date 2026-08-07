use std::sync::{
    Arc,
    atomic::{AtomicU64, Ordering},
};

use automata_core::{
    AttemptId, FencingToken, JobId, JobIr, JobIrEnvelope, JobSource, Lease, LeaseId, RunId,
    RunnerId, RunnerRequirements, UnixMillis, WorkflowId,
};
use automata_results_github::{
    GITHUB_RESULTS_RUNTIME_AUTHORITY, GithubResultsRuntimeAuthorityIssuer, HmacResultsAuthority,
    HmacResultsAuthorityConfig, ResultsClock, ResultsPublicEndpoint, RuntimeTokenVerifier as _,
    TokenError,
};
use automata_runner_control::{RuntimeAuthorityIssueRequest, RuntimeAuthorityIssuer as _};
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
    JobIrEnvelope::new(
        WorkflowId::new(),
        JobSource::new(
            "github",
            "GoNeuralAI/automata",
            "0123456789abcdef",
            ".github/workflows/ci.yml",
            "push",
        ),
        automata_core::JobExecutionContext::new(
            "CI",
            "refs/heads/main",
            "/__w/automata/automata",
            automata_core::JobContentReference::new(
                "events/push.json",
                automata_core::Sha256Digest::from_bytes([0x42; 32]),
                2,
                "application/json",
            ),
        ),
        JobIr::new(
            JobId::new(),
            RunId::new(),
            "dist",
            RunnerRequirements::default(),
            Vec::new(),
        ),
    )
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

#[tokio::test]
async fn deterministic_issuance_replays_exact_bytes_and_binding() {
    let clock = Arc::new(MutableClock::new(10));
    let authority = authority(clock);
    let issuer =
        GithubResultsRuntimeAuthorityIssuer::new(authority.clone(), 120).expect("runtime issuer");
    let job = job();
    let lease = make_lease(
        AttemptId::new(),
        FencingToken::new(7).expect("fence"),
        UnixMillis::new(10_987),
    );
    let request = RuntimeAuthorityIssueRequest::new(&job, &lease, lease.issued_at());

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
    assert!(!format!("{first:?}").contains(results_authority.credential().expose_secret()));
}

#[tokio::test]
async fn cross_attempt_fence_and_expiry_are_rejected() {
    let clock = Arc::new(MutableClock::new(20));
    let authority = authority(clock.clone());
    let issuer =
        GithubResultsRuntimeAuthorityIssuer::new(authority.clone(), 60).expect("runtime issuer");
    let job = job();
    let lease = make_lease(
        AttemptId::new(),
        FencingToken::new(11).expect("fence"),
        UnixMillis::new(20_000),
    );
    let bundle = issuer
        .issue(RuntimeAuthorityIssueRequest::new(
            &job,
            &lease,
            lease.issued_at(),
        ))
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
