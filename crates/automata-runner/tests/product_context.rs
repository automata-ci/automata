#![cfg(unix)]

use std::{
    collections::BTreeMap,
    fs::{self, OpenOptions},
    io::Write as _,
    os::unix::fs::{OpenOptionsExt as _, PermissionsExt as _},
    path::{Path, PathBuf},
};

use automata_core::{
    AttemptId, FencingToken, JobContentReference, JobExecutionContext, JobId, JobIr, JobIrEnvelope,
    JobSource, Lease, LeaseId, RunId, RunnerRequirements, Sha256Digest, UnixMillis, WorkflowId,
};
use automata_execution::TargetPath;
use automata_expression_github::GithubStatus;
use automata_expression_github::GithubValue;
use automata_github_runtime::{CommandFilePlatform, JobCommandState};
use automata_job_executor_github::{
    GithubContextPort, GithubContextRequest, GithubExecutionIdentity, GithubExecutionPhase,
    PortErrorKind,
};
use automata_protocol::{
    JobRuntimeAuthorities, JobRuntimeAuthority, RuntimeAuthorityCredential,
    RuntimeAuthorityEndpoint, RuntimeAuthorityName,
};
use automata_runner::product::{RunnerProductConfig, StandardGithubContext};
use serde_json::json;
use uuid::Uuid;

const TOKEN: &str = "github_pat_test_token_without_whitespace";

#[test]
fn admitted_execution_context_is_exposed_without_workspace_or_ref_rederivation() {
    let fixture = ContextFixture::new(format!("{TOKEN}\n").as_bytes());
    let snapshot = fixture.snapshot().expect("context snapshot");
    let environment = snapshot
        .environment()
        .iter()
        .map(|value| (value.name(), value.expose_value()))
        .collect::<BTreeMap<_, _>>();

    assert_eq!(environment["GITHUB_WORKFLOW"], "CI");
    assert_eq!(environment["GITHUB_REF"], "refs/heads/main");
    assert_eq!(environment["GITHUB_WORKSPACE"], "/__w/automata/automata");
    assert_eq!(
        environment["GITHUB_EVENT_PATH"],
        "/__automata/attempts/fixture/event.json"
    );
    assert_eq!(environment["GITHUB_ACTOR"], "local-bootstrap");
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
        Some("GoNeuralAI/automata/.github/workflows/ci.yml@refs/heads/main")
    );
    assert!(github.get("run_number").is_none());
}

#[test]
fn file_credentials_accept_one_terminal_line_ending() {
    for line_ending in ["\n", "\r\n"] {
        let fixture = ContextFixture::new(format!("{TOKEN}{line_ending}").as_bytes());
        let snapshot = fixture
            .snapshot()
            .expect("one terminal line ending is valid");

        assert_eq!(snapshot.secret_masks().len(), 1);
        assert_eq!(snapshot.secret_masks()[0].expose_secret(), TOKEN);
    }
}

#[test]
fn results_authority_is_injected_only_as_a_masked_job_secret() {
    let fixture = ContextFixture::new(format!("{TOKEN}\n").as_bytes());
    let snapshot = fixture.snapshot().expect("context snapshot");
    let results_url = snapshot
        .environment()
        .iter()
        .find(|value| value.name() == "ACTIONS_RESULTS_URL")
        .expect("Results URL");
    assert_eq!(results_url.expose_value(), "https://results.example.test/");
    assert!(!results_url.is_secret());
    let runtime_token = snapshot
        .environment()
        .iter()
        .find(|value| value.name() == "ACTIONS_RUNTIME_TOKEN")
        .expect("runtime token");
    assert_eq!(runtime_token.expose_value(), "fixture-results-jwt");
    assert!(runtime_token.is_secret());
    assert!(!format!("{snapshot:?}").contains("fixture-results-jwt"));
}

#[test]
fn missing_or_cross_fence_results_authority_fails_closed() {
    let mut missing = ContextFixture::new(format!("{TOKEN}\n").as_bytes());
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

    let cross_fence = ContextFixture::new(format!("{TOKEN}\n").as_bytes());
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
    let error = cross_fence
        .context
        .snapshot(GithubContextRequest::new(
            GithubExecutionIdentity::new(
                &cross_fence.job,
                &stale_lease,
                &cross_fence.runtime_authorities,
            ),
            &event_path,
            &commands,
            &[],
            GithubStatus::Success,
            None,
            GithubExecutionPhase::Job,
        ))
        .expect_err("cross-fence authority");
    assert_eq!(error.kind(), PortErrorKind::InvalidData);
}

#[test]
fn file_credentials_reject_embedded_or_multiple_line_endings() {
    for value in [format!("{TOKEN}\nembedded"), format!("{TOKEN}\n\n")] {
        let fixture = ContextFixture::new(value.as_bytes());
        let error = fixture
            .snapshot()
            .expect_err("embedded credential whitespace must fail closed");

        assert_eq!(error.kind(), PortErrorKind::InvalidData);
    }
}

struct ContextFixture {
    root: PathBuf,
    context: StandardGithubContext,
    job: JobIrEnvelope,
    lease: Lease,
    runtime_authorities: JobRuntimeAuthorities,
}

impl ContextFixture {
    fn new(token: &[u8]) -> Self {
        let root = scratch_root().join(Uuid::new_v4().to_string());
        fs::create_dir_all(&root).expect("create context fixture root");
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700))
            .expect("protect context fixture root");
        let token_path = root.join("workflow-token");
        let mut token_file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&token_path)
            .expect("create protected token fixture");
        token_file.write_all(token).expect("write token fixture");
        token_file.sync_all().expect("sync token fixture");

        let mut document: serde_json::Value =
            serde_json::from_slice(include_bytes!("../config/runner.local.example.json"))
                .expect("checked-in runner config JSON");
        document["github"]["workflow_token"] = json!({
            "kind": "file",
            "path": token_path,
        });
        let encoded = serde_json::to_vec(&document).expect("encode runner config fixture");
        let config = RunnerProductConfig::from_json(&encoded).expect("valid runner config fixture");
        let (profile, _) = config
            .environments()
            .first_key_value()
            .expect("one configured environment");
        let job = JobIrEnvelope::new(
            WorkflowId::new(),
            JobSource::new(
                "github",
                "GoNeuralAI/automata",
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
            )
            .with_actor("local-bootstrap")
            .with_run_attempt(1),
            JobIr::new(
                JobId::new(),
                RunId::new(),
                "context fixture",
                RunnerRequirements::default().with_environment_profile(profile.clone()),
                Vec::new(),
            ),
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
            root,
            context,
            job,
            lease,
            runtime_authorities,
        }
    }

    fn snapshot(
        &self,
    ) -> Result<
        automata_job_executor_github::GithubContextSnapshot,
        automata_job_executor_github::PortError,
    > {
        let commands = JobCommandState::new(CommandFilePlatform::Unix);
        let event_path = fixture_event_path();
        self.context.snapshot(GithubContextRequest::new(
            GithubExecutionIdentity::new(&self.job, &self.lease, &self.runtime_authorities),
            &event_path,
            &commands,
            &[],
            GithubStatus::Success,
            None,
            GithubExecutionPhase::Job,
        ))
    }
}

fn fixture_event_path() -> TargetPath {
    TargetPath::posix("/__automata/attempts/fixture/event.json").expect("event target")
}

impl Drop for ContextFixture {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.root).expect("remove context fixture root");
    }
}

fn scratch_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .expect("canonical workspace root")
        .join("target/agent-scratch/runner-product-context")
}
