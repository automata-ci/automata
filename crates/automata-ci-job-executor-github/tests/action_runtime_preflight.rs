mod support;

use std::sync::Arc;

use automata_ci_action_actions::GithubActionMetadataDecoder;
use automata_ci_core::{ActionReference, JobConclusion, LogChannel, Sha256Digest};
use automata_ci_job_executor_github::{
    CheckedOutLocalActionPreparer, LocalActionPreparationRequest, PreparedAction,
};
use automata_ci_runner_runtime::{ExecutionCancellation, ExecutionEvents, JobExecutor};
use automata_ci_workflow_actions::GithubConditionCompiler;
use bytes::Bytes;
use sha2::{Digest as _, Sha256};

use support::{Fixture, action_step, envelope};

const REVISION: &str = "0123456789abcdef0123456789abcdef01234567";

fn prepared_metadata(source: &str) -> PreparedAction {
    let reference = ActionReference::Local {
        path: "./synthetic".to_owned(),
    };
    let local = CheckedOutLocalActionPreparer::new(
        Arc::new(GithubActionMetadataDecoder::default()),
        GithubConditionCompiler::default(),
    )
    .prepare(LocalActionPreparationRequest::new(
        &reference,
        Some(source.as_bytes()),
        None,
    ))
    .expect("synthetic metadata compiles");
    let archive = Bytes::copy_from_slice(source.as_bytes());
    let digest = Sha256Digest::from_bytes(Sha256::digest(&archive).into());
    PreparedAction::with_definition(digest, archive, "", local.definition().clone())
        .expect("prepared action")
}

fn system_log(fixture: &Fixture) -> String {
    String::from_utf8(
        fixture
            .events
            .logs()
            .into_iter()
            .filter(|event| event.channel() == LogChannel::System)
            .flat_map(|event| event.payload().to_vec())
            .collect(),
    )
    .expect("UTF-8 system log")
}

async fn execute_preflight_failure(fixture: &Fixture) -> JobConclusion {
    let request = fixture.request(envelope(vec![action_step("action", "actions/example")]));
    let events: Arc<dyn ExecutionEvents> = fixture.events.clone();
    let result = fixture
        .executor
        .execute(request, events, ExecutionCancellation::new())
        .await
        .expect("preflight rejection is a terminal job result");
    assert_eq!(fixture.provider.counts(), (0, 0, 0));
    assert!(
        fixture
            .endpoint_state
            .lock()
            .expect("endpoint lock")
            .commands
            .is_empty(),
        "preflight rejection must not reach provider execution"
    );
    result.conclusion()
}

#[tokio::test]
async fn every_unprovided_legacy_node_generation_fails_before_provider_work() {
    for runtime in ["node12", "node16", "node20"] {
        let action = prepared_metadata(&format!(
            "runs:\n  using: {runtime}\n  main: dist/index.js\n"
        ));
        let fixture = Fixture::new(vec![action], Vec::new());

        assert_eq!(
            execute_preflight_failure(&fixture).await,
            JobConclusion::Failure,
            "{runtime}"
        );
        assert_eq!(
            system_log(&fixture),
            "Action preparation failed (RuntimeUnavailable)\n",
            "{runtime}"
        );
    }
}

#[tokio::test]
async fn current_node_generation_requires_an_exact_profile_tool() {
    let fixture = Fixture::without_node(
        vec![prepared_metadata(
            "runs:\n  using: node24\n  main: dist/index.js\n",
        )],
        Vec::new(),
    );

    assert_eq!(
        execute_preflight_failure(&fixture).await,
        JobConclusion::Failure
    );
    assert_eq!(
        system_log(&fixture),
        "Action preparation failed (RuntimeUnavailable)\n"
    );
}

#[tokio::test]
async fn nested_repository_runtime_is_checked_recursively_before_provider_work() {
    let parent =
        prepared_metadata("runs:\n  using: composite\n  steps:\n    - uses: actions/legacy@v1\n");
    let legacy = prepared_metadata("runs:\n  using: node20\n  main: dist/index.js\n");
    let fixture = Fixture::new(vec![parent, legacy], Vec::new());

    assert_eq!(
        execute_preflight_failure(&fixture).await,
        JobConclusion::Failure
    );
    assert_eq!(
        system_log(&fixture),
        "Action preparation failed (RuntimeUnavailable)\n"
    );
}

#[tokio::test]
async fn nested_container_actions_fail_closed_during_repository_preflight() {
    let parent = prepared_metadata(
        "runs:\n  using: composite\n  steps:\n    - uses: docker://alpine:3.22\n",
    );
    let fixture = Fixture::new(vec![parent], Vec::new());

    assert_eq!(
        execute_preflight_failure(&fixture).await,
        JobConclusion::Failure
    );
    assert_eq!(
        system_log(&fixture),
        "Action preparation failed (UnsupportedExecution)\n"
    );
}

#[tokio::test]
async fn unresolved_repository_local_child_fails_before_provider_work() {
    let parent = prepared_metadata(
        "runs:\n  using: composite\n  steps:\n    - uses: ./mutable-workspace-child\n",
    );
    let fixture = Fixture::new(vec![parent], Vec::new());

    assert_eq!(
        execute_preflight_failure(&fixture).await,
        JobConclusion::Failure
    );
    assert_eq!(
        system_log(&fixture),
        "Action preparation failed (Metadata)\n"
    );
}

#[tokio::test]
async fn recursive_repository_graph_fails_before_a_second_resolution_or_provider_work() {
    let recursive = prepared_metadata(&format!(
        "runs:\n  using: composite\n  steps:\n    - uses: actions/example@{REVISION}\n"
    ));
    let fixture = Fixture::new(vec![recursive], Vec::new());

    assert_eq!(
        execute_preflight_failure(&fixture).await,
        JobConclusion::Failure
    );
    assert_eq!(
        system_log(&fixture),
        "Action preparation failed (Metadata)\n"
    );
}
