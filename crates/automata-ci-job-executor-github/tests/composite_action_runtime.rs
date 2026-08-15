mod support;

use std::{
    collections::BTreeMap,
    sync::{Arc, atomic::Ordering},
};

use automata_ci_action_github::GithubActionMetadataDecoder;
use automata_ci_core::{
    ActionReference, JobConclusion, RuntimeBoolean, SemanticStep, Sha256Digest, StepId, StepIr,
    ValueSource, ValueTemplate,
};
use automata_ci_job_executor_github::{
    CheckedOutLocalActionPreparer, LocalActionPreparationRequest, PreparedAction,
};
use automata_ci_runner_runtime::{
    ExecutionCancellation, ExecutionEvents, ExecutorErrorKind, JobExecutor,
};
use automata_ci_workflow_github::{GithubConditionCompiler, GithubConditionPhase};
use bytes::Bytes;
use sha2::{Digest as _, Sha256};

use support::{
    Fixture, PhaseResponse, SECRET, assert_fresh_isolated_phase_files, envelope, environment_map,
    prepared_node24_action, run_step,
};

const REVISION: &str = "0123456789abcdef0123456789abcdef01234567";

const REPOSITORY_COMPOSITE: &str = r#"
name: Repository composite
inputs:
  message:
    default: default-message
  token:
    default: public-default
outputs:
  result:
    value: ${{ steps.producer.outputs.value }}
runs:
  using: composite
  steps:
    - id: producer
      run: printf '%s\n' "$MESSAGE"
      shell: bash
      working-directory: ${{ github.action_path }}
      env:
        MESSAGE: ${{ inputs.message }}
        TOKEN: ${{ inputs.token }}
      continue-on-error: true
    - id: observer
      if: ${{ steps.producer.outcome == 'failure' && steps.producer.conclusion == 'success' && env.READY == 'yes' }}
      run: printf '%s\n' "${{ steps.producer.outputs.value }}"
      shell: sh
      env:
        READY: yes
"#;

const LOCAL_PARENT: &str = r"
name: Local parent
outputs:
  result:
    value: ${{ steps.remote.outputs.value }}
runs:
  using: composite
  steps:
    - id: local
      uses: ./actions/child
      with:
        message: local-value
      env:
        NESTED_KIND: local
    - id: remote
      uses: owner/remote@0123456789abcdef0123456789abcdef01234567
      with:
        message: ${{ steps.local.outputs.value }}
      env:
        NESTED_KIND: repository
";

const CHILD_COMPOSITE: &str = r#"
name: Child
inputs:
  message:
    default: child-default
outputs:
  value:
    value: ${{ steps.emit.outputs.value }}
runs:
  using: composite
  steps:
    - id: emit
      run: printf '%s\n' "$INPUT_MESSAGE"
      shell: bash
"#;

const REPEATED_LOCAL_PARENT: &str = r"
name: Repeated local parent
runs:
  using: composite
  steps:
    - id: first
      uses: ./actions/child
    - id: second
      uses: ./actions/child
";

const POST_PARENT: &str = r"
name: Post parent
runs:
  using: composite
  steps:
    - uses: owner/first@0123456789abcdef0123456789abcdef01234567
    - uses: owner/second@0123456789abcdef0123456789abcdef01234567
";

const SELF_RECURSIVE: &str = r"
name: Recursive
runs:
  using: composite
  steps:
    - uses: ./actions/self
";

const CANCELLED_TAIL: &str = r"
name: Cancelled tail
outputs:
  token:
    value: ${{ github.token }}
runs:
  using: composite
  steps:
    - id: child
      run: true
      shell: bash
";

const RESERVED_ENVIRONMENT_COMPOSITE: &str = r"
name: Reserved environment
runs:
  using: composite
  steps:
    - id: malicious
      run: true
      shell: bash
      env:
        GITHUB_ENV: /tmp/shadow
";

#[tokio::test]
async fn repository_composite_runs_children_and_publishes_outputs() {
    let mut failed = PhaseResponse::success().with_file(
        automata_ci_github_runtime::CommandFileKind::Output,
        b"value=child\n".to_vec(),
    );
    failed.termination = automata_ci_execution::ExecutionTermination::Exited(1);
    let fixture = Fixture::new(
        vec![prepared_metadata(REPOSITORY_COMPOSITE)],
        vec![failed, PhaseResponse::success(), PhaseResponse::success()],
    );
    let action = repository_step(
        "composite",
        "owner/composite",
        BTreeMap::from([
            (
                "message".to_owned(),
                ValueSource::Literal("supplied-message".to_owned()),
            ),
            (
                "token".to_owned(),
                ValueSource::SecretReference("test-token".to_owned()),
            ),
        ]),
    );
    let follow_up = conditioned_run("after", "true", "steps.composite.outputs.result == 'child'");
    let request = fixture.request(envelope(vec![action, follow_up]));
    let events: Arc<dyn ExecutionEvents> = fixture.events.clone();

    let result = fixture
        .executor
        .execute(request, events, ExecutionCancellation::new())
        .await
        .expect("repository composite executes");

    assert_eq!(result.conclusion(), JobConclusion::Success);
    assert_eq!(result.steps()[0].conclusion(), JobConclusion::Success);
    assert_eq!(result.steps()[1].conclusion(), JobConclusion::Success);
    let state = fixture.endpoint_state.lock().expect("endpoint lock");
    let shells = state
        .commands
        .iter()
        .filter(|command| {
            matches!(
                command.argv().program().as_str(),
                "/usr/bin/bash" | "/usr/bin/sh"
            )
        })
        .collect::<Vec<_>>();
    assert_eq!(shells.len(), 3);
    assert!(
        shells[0]
            .working_directory()
            .as_str()
            .ends_with("/actions/action-0/root")
    );
    let environment = environment_map(shells[0]);
    assert_eq!(environment["MESSAGE"], "supplied-message");
    assert_eq!(environment["INPUT_MESSAGE"], "supplied-message");
    assert_eq!(environment["TOKEN"], SECRET);
    assert_eq!(environment["INPUT_TOKEN"], SECRET);
    for name in ["TOKEN", "INPUT_TOKEN"] {
        assert!(
            shells[0]
                .environment()
                .values()
                .iter()
                .find(|variable| variable.name().as_str() == name)
                .expect("secret composite environment variable")
                .is_secret()
        );
    }
    assert!(environment["GITHUB_ACTION_PATH"].ends_with("/actions/action-0/root"));
}

#[tokio::test]
async fn composite_action_environment_cannot_shadow_runner_names() {
    let fixture = Fixture::new(
        vec![prepared_metadata(RESERVED_ENVIRONMENT_COMPOSITE)],
        Vec::new(),
    );
    let action = repository_step("composite", "owner/composite", BTreeMap::new());
    let events: Arc<dyn ExecutionEvents> = fixture.events.clone();

    let error = fixture
        .executor
        .execute(
            fixture.request(envelope(vec![action])),
            events,
            ExecutionCancellation::new(),
        )
        .await
        .expect_err("reserved composite environment must fail before its process starts");

    assert_eq!(error.kind(), ExecutorErrorKind::InvalidJob);
    let state = fixture.endpoint_state.lock().expect("endpoint lock");
    assert!(state.scripts.is_empty());
    assert!(state.commands.iter().all(|command| {
        command
            .environment()
            .values()
            .iter()
            .all(|variable| variable.name().as_str() != "GITHUB_ENV")
    }));
}

#[tokio::test]
async fn checked_out_composite_nests_local_and_repository_actions() {
    let fixture = Fixture::new(
        vec![prepared_metadata(CHILD_COMPOSITE)],
        vec![
            PhaseResponse::success().with_file(
                automata_ci_github_runtime::CommandFileKind::Output,
                b"value=local-output\n".to_vec(),
            ),
            PhaseResponse::success().with_file(
                automata_ci_github_runtime::CommandFileKind::Output,
                b"value=repository-output\n".to_vec(),
            ),
        ],
    );
    {
        let mut state = fixture.endpoint_state.lock().expect("endpoint lock");
        state.files.insert(
            "/__w/automata/automata/actions/parent/action.yaml".to_owned(),
            LOCAL_PARENT.as_bytes().to_vec(),
        );
        state.files.insert(
            "/__w/automata/automata/actions/child/action.yml".to_owned(),
            CHILD_COMPOSITE.as_bytes().to_vec(),
        );
    }
    let request = fixture.request(envelope(vec![local_step("parent", "./actions/parent")]));
    let events: Arc<dyn ExecutionEvents> = fixture.events.clone();

    let result = fixture
        .executor
        .execute(request, events, ExecutionCancellation::new())
        .await
        .expect("nested local and repository composites execute");

    assert_eq!(result.conclusion(), JobConclusion::Success);
    let state = fixture.endpoint_state.lock().expect("endpoint lock");
    let shells = state
        .commands
        .iter()
        .filter(|command| command.argv().program().as_str() == "/usr/bin/bash")
        .collect::<Vec<_>>();
    assert_eq!(shells.len(), 2);
    let local = environment_map(shells[0]);
    let repository = environment_map(shells[1]);
    assert_eq!(local["INPUT_MESSAGE"], "local-value");
    assert_eq!(local["NESTED_KIND"], "local");
    assert_eq!(repository["INPUT_MESSAGE"], "local-output");
    assert_eq!(repository["NESTED_KIND"], "repository");
    assert_eq!(
        local["GITHUB_ACTION_PATH"],
        "/__w/automata/automata/actions/child"
    );
    assert!(repository["GITHUB_ACTION_PATH"].contains("/actions/action-"));
}

#[tokio::test]
async fn nested_repeated_composite_occurrences_receive_fresh_phase_file_sets() {
    let fixture = Fixture::new(
        Vec::new(),
        vec![
            PhaseResponse::success()
                .with_file(
                    automata_ci_github_runtime::CommandFileKind::StepSummary,
                    b"first child\n".to_vec(),
                )
                .with_artifacts_list_write(b"corrupt first list".to_vec()),
            PhaseResponse::success()
                .with_file(
                    automata_ci_github_runtime::CommandFileKind::StepSummary,
                    b"second child\n".to_vec(),
                )
                .with_artifacts_list_write(b"corrupt second list".to_vec()),
        ],
    );
    {
        let mut state = fixture.endpoint_state.lock().expect("endpoint lock");
        state.files.insert(
            "/__w/automata/automata/actions/parent/action.yaml".to_owned(),
            REPEATED_LOCAL_PARENT.as_bytes().to_vec(),
        );
        state.files.insert(
            "/__w/automata/automata/actions/child/action.yml".to_owned(),
            CHILD_COMPOSITE.as_bytes().to_vec(),
        );
    }
    let events: Arc<dyn ExecutionEvents> = fixture.events.clone();

    let result = fixture
        .executor
        .execute(
            fixture.request(envelope(vec![local_step("parent", "./actions/parent")])),
            events,
            ExecutionCancellation::new(),
        )
        .await
        .expect("repeated nested composite executes");

    assert_eq!(result.conclusion(), JobConclusion::Success);
    assert_eq!(
        result.steps()[0].summary_markdown(),
        Some("first child\nsecond child\n")
    );
    let state = fixture.endpoint_state.lock().expect("endpoint lock");
    let phases = state
        .commands
        .iter()
        .filter(|command| command.argv().program().as_str() == "/usr/bin/bash")
        .collect::<Vec<_>>();
    assert_eq!(phases.len(), 2);
    assert_fresh_isolated_phase_files(&state, &phases);
}

#[tokio::test]
async fn nested_javascript_posts_do_not_start_after_execution_cancellation() {
    let cancellation = ExecutionCancellation::new();
    let fixture = Fixture::new(
        vec![
            prepared_metadata(POST_PARENT),
            prepared_node24_action(),
            prepared_node24_action(),
        ],
        vec![
            PhaseResponse::success().with_file(
                automata_ci_github_runtime::CommandFileKind::State,
                b"saved=first\n".to_vec(),
            ),
            PhaseResponse::success()
                .with_file(
                    automata_ci_github_runtime::CommandFileKind::State,
                    b"saved=second\n".to_vec(),
                )
                .signal(cancellation.clone()),
            PhaseResponse::success(),
            PhaseResponse::success(),
        ],
    );
    let request = fixture.request(envelope(vec![repository_step(
        "parent",
        "owner/parent",
        BTreeMap::new(),
    )]));
    let events: Arc<dyn ExecutionEvents> = fixture.events.clone();

    let result = fixture
        .executor
        .execute(request, events, cancellation.clone())
        .await
        .expect("cancellation produces a terminal result");

    assert!(cancellation.is_cancelled());
    assert_eq!(result.conclusion(), JobConclusion::Cancelled);
    let state = fixture.endpoint_state.lock().expect("endpoint lock");
    let nodes = state
        .commands
        .iter()
        .filter(|command| command.argv().program().as_str() == "/opt/node24/bin/node")
        .collect::<Vec<_>>();
    let entries = nodes
        .iter()
        .map(|command| command.argv().arguments()[0].clone())
        .collect::<Vec<_>>();
    assert_eq!(entries.len(), 2);
    assert!(entries[0].contains("action-16777216"));
    assert!(entries[1].contains("action-16777217"));
    for command in nodes {
        assert!(
            command
                .environment()
                .values()
                .iter()
                .all(|variable| variable.name().as_str() != "STATE_saved"),
            "registered state must not be re-exposed through a post environment"
        );
    }
}

#[tokio::test]
async fn cancelled_composite_child_starts_no_tail_context_or_output_evaluation() {
    let cancellation = ExecutionCancellation::new();
    let (fixture, action_main_contexts) = Fixture::with_counted_action_main_contexts(
        vec![prepared_metadata(CANCELLED_TAIL)],
        vec![PhaseResponse::success().signal(cancellation.clone())],
    );
    let request = fixture.request(envelope(vec![repository_step(
        "composite",
        "owner/composite",
        BTreeMap::new(),
    )]));
    let events: Arc<dyn ExecutionEvents> = fixture.events.clone();

    let result = fixture
        .executor
        .execute(request, events, cancellation.clone())
        .await
        .expect("child cancellation remains a terminal result");

    assert!(cancellation.is_cancelled());
    assert_eq!(result.conclusion(), JobConclusion::Cancelled);
    assert_eq!(
        action_main_contexts.load(Ordering::SeqCst),
        3,
        "the executor must not request the composite-tail context after child cancellation"
    );
    let state = fixture.endpoint_state.lock().expect("endpoint lock");
    assert_eq!(
        state
            .commands
            .iter()
            .filter(|command| command.argv().program().as_str() == "/usr/bin/bash")
            .count(),
        1,
        "only the child command may start"
    );
}

#[tokio::test]
async fn tokenless_cancelled_last_composite_child_starts_no_tail_context_or_output_evaluation() {
    let (fixture, action_main_contexts) = Fixture::with_counted_action_main_contexts(
        vec![prepared_metadata(CANCELLED_TAIL)],
        vec![PhaseResponse::success().cancelled()],
    );
    let request = fixture.request(envelope(vec![repository_step(
        "composite",
        "owner/composite",
        BTreeMap::new(),
    )]));
    let events: Arc<dyn ExecutionEvents> = fixture.events.clone();

    let result = fixture
        .executor
        .execute(request, events, ExecutionCancellation::new())
        .await
        .expect("a tokenless cancelled child remains a terminal result");

    assert_eq!(result.conclusion(), JobConclusion::Cancelled);
    assert_eq!(
        action_main_contexts.load(Ordering::SeqCst),
        3,
        "the last child's cancelled outcome must suppress the composite-tail context"
    );
    let state = fixture.endpoint_state.lock().expect("endpoint lock");
    assert_eq!(
        state
            .commands
            .iter()
            .filter(|command| command.argv().program().as_str() == "/usr/bin/bash")
            .count(),
        1,
        "only the cancelled child command may start"
    );
}

#[tokio::test]
async fn cancellation_dominates_a_simultaneous_action_diagnostic_event_error() {
    let cancellation = ExecutionCancellation::new();
    let fixture = Fixture::new(Vec::new(), Vec::new());
    fixture
        .events
        .cancel_and_fail_on_next_log(cancellation.clone());
    let request = fixture.request(envelope(vec![repository_step(
        "missing",
        "owner/missing",
        BTreeMap::new(),
    )]));
    let events: Arc<dyn ExecutionEvents> = fixture.events.clone();

    let result = fixture
        .executor
        .execute(request, events, cancellation.clone())
        .await
        .expect("diagnostic-event failure must not escape simultaneous cancellation");

    assert!(cancellation.is_cancelled());
    assert_eq!(result.conclusion(), JobConclusion::Cancelled);
    let state = fixture.endpoint_state.lock().expect("endpoint lock");
    assert!(state.commands.iter().all(|command| {
        !matches!(
            command.argv().program().as_str(),
            "/usr/bin/bash" | "/usr/bin/sh" | "/opt/node24/bin/node"
        )
    }));
}

#[tokio::test]
async fn recursive_local_composite_fails_closed_without_reentering_metadata() {
    let fixture = Fixture::new(Vec::new(), Vec::new());
    fixture
        .endpoint_state
        .lock()
        .expect("endpoint lock")
        .files
        .insert(
            "/__w/automata/automata/actions/self/action.yml".to_owned(),
            SELF_RECURSIVE.as_bytes().to_vec(),
        );
    let request = fixture.request(envelope(vec![local_step("self", "./actions/self")]));
    let events: Arc<dyn ExecutionEvents> = fixture.events.clone();

    let result = fixture
        .executor
        .execute(request, events, ExecutionCancellation::new())
        .await
        .expect("recursion is a bounded action failure");

    assert_eq!(result.conclusion(), JobConclusion::Failure);
    let state = fixture.endpoint_state.lock().expect("endpoint lock");
    let probes = state
        .commands
        .iter()
        .filter(|command| {
            command.argv().program().as_str() == "/usr/bin/sh"
                && command
                    .argv()
                    .arguments()
                    .get(1)
                    .is_some_and(|argument| argument.contains("automata-local-action-metadata"))
        })
        .count();
    assert_eq!(probes, 1);
}

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
    let archive = Bytes::from_static(b"synthetic-action-archive");
    let digest = Sha256Digest::from_bytes(Sha256::digest(&archive).into());
    PreparedAction::with_definition(digest, archive, "", local.definition().clone())
        .expect("prepared action")
}

fn repository_step(id: &str, repository: &str, inputs: BTreeMap<String, ValueSource>) -> StepIr {
    StepIr::new(
        StepId::new(id).expect("step id"),
        ValueTemplate::literal(id).expect("step name template"),
        RuntimeBoolean::literal(false),
        SemanticStep::action(
            ActionReference::Repository {
                repository: repository.to_owned(),
                revision: REVISION.to_owned(),
                subpath: None,
            },
            inputs,
        ),
    )
}

fn local_step(id: &str, path: &str) -> StepIr {
    StepIr::new(
        StepId::new(id).expect("step id"),
        ValueTemplate::literal(id).expect("step name template"),
        RuntimeBoolean::literal(false),
        SemanticStep::action(
            ActionReference::Local {
                path: path.to_owned(),
            },
            BTreeMap::new(),
        ),
    )
}

fn conditioned_run(id: &str, command: &str, condition: &str) -> StepIr {
    let condition = GithubConditionCompiler::default()
        .compile_condition(Some(condition), GithubConditionPhase::Step)
        .expect("condition");
    run_step(id, id, command).with_condition(condition)
}
