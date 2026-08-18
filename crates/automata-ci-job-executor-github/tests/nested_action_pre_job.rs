mod support;

use std::{
    collections::{BTreeMap, BTreeSet},
    sync::Arc,
};

use automata_ci_action_github::{GithubActionMetadataDecoder, JavascriptRuntime};
use automata_ci_core::{
    ActionReference, JobConclusion, RuntimeBoolean, SemanticStep, Sha256Digest, StepId, StepIr,
    ValueTemplate,
};
use automata_ci_github_runtime::CommandFileKind;
use automata_ci_job_executor_github::{
    CheckedOutLocalActionPreparer, LocalActionPreparationRequest, PreparedAction,
    PreparedActionDefinition, PreparedActionExecution, PreparedJavascriptAction,
};
use automata_ci_runner_runtime::{ExecutionCancellation, ExecutionEvents, JobExecutor};
use automata_ci_workflow_github::{GithubConditionCompiler, GithubConditionPhase};
use bytes::Bytes;
use sha2::{Digest as _, Sha256};

use support::{Fixture, PhaseResponse, envelope, environment_map, run_step};

const REVISION: &str = "0123456789abcdef0123456789abcdef01234567";

const MIXED_POST_COMPOSITE: &str = r"
name: Mixed post lifecycle
runs:
  using: composite
  steps:
    - uses: owner/a@0123456789abcdef0123456789abcdef01234567
    - uses: owner/b@0123456789abcdef0123456789abcdef01234567
    - uses: owner/c@0123456789abcdef0123456789abcdef01234567
";

const REPEATED_ACTION_COMPOSITE: &str = r"
name: Repeated action lifecycle
runs:
  using: composite
  steps:
    - uses: owner/shared@0123456789abcdef0123456789abcdef01234567
    - uses: owner/shared@0123456789abcdef0123456789abcdef01234567
";

const PREPARATION_FAILURE_COMPOSITE: &str = r"
name: Nested preparation failure
runs:
  using: composite
  steps:
    - uses: owner/ready@0123456789abcdef0123456789abcdef01234567
    - uses: owner/missing@0123456789abcdef0123456789abcdef01234567
";

const RECURSIVE_COMPOSITE: &str = r"
name: Recursive lifecycle
runs:
  using: composite
  steps:
    - uses: owner/recursive@0123456789abcdef0123456789abcdef01234567
";

const DEFERRED_COMPOSITE_POSTS: &str = r"
name: Deferred composite posts
runs:
  using: composite
  steps:
    - uses: owner/a@0123456789abcdef0123456789abcdef01234567
    - uses: owner/b@0123456789abcdef0123456789abcdef01234567
";

#[tokio::test]
async fn top_level_posts_keep_registration_lifo_when_only_some_pres_ran() {
    let fixture = Fixture::new(
        vec![
            prepared_javascript("a", true, true),
            prepared_javascript("b", false, true),
            prepared_javascript("c", true, true),
        ],
        successful_phases(8),
    );
    let request = fixture.request(envelope(vec![
        repository_step("a", "owner/a"),
        repository_step("b", "owner/b"),
        repository_step("c", "owner/c"),
    ]));
    let events: Arc<dyn ExecutionEvents> = fixture.events.clone();

    let result = fixture
        .executor
        .execute(request, events, ExecutionCancellation::new())
        .await
        .expect("mixed top-level lifecycle executes");

    assert_eq!(result.conclusion(), JobConclusion::Success);
    let state = fixture.endpoint_state.lock().expect("endpoint lock");
    assert_eq!(
        node_entries(&state.commands),
        [
            "a-pre.js",
            "c-pre.js",
            "a-main.js",
            "b-main.js",
            "c-main.js",
            "b-post.js",
            "c-post.js",
            "a-post.js",
        ]
    );
}

#[tokio::test]
async fn nested_posts_keep_reverse_source_order_when_only_some_pres_ran() {
    let fixture = Fixture::new(
        vec![
            prepared_metadata(MIXED_POST_COMPOSITE),
            prepared_javascript("a", true, true),
            prepared_javascript("b", false, true),
            prepared_javascript("c", true, true),
        ],
        successful_phases(8),
    );
    let request = fixture.request(envelope(vec![repository_step("parent", "owner/parent")]));
    let events: Arc<dyn ExecutionEvents> = fixture.events.clone();

    let result = fixture
        .executor
        .execute(request, events, ExecutionCancellation::new())
        .await
        .expect("nested lifecycle executes");

    assert_eq!(result.conclusion(), JobConclusion::Success);
    let state = fixture.endpoint_state.lock().expect("endpoint lock");
    assert_eq!(
        node_entries(&state.commands),
        [
            "a-pre.js",
            "c-pre.js",
            "a-main.js",
            "b-main.js",
            "c-main.js",
            "c-post.js",
            "b-post.js",
            "a-post.js",
        ]
    );
}

#[tokio::test]
async fn composite_pre_reserves_its_top_level_post_group_before_children_register() {
    let fixture = Fixture::new(
        vec![
            prepared_metadata(DEFERRED_COMPOSITE_POSTS),
            prepared_javascript_with_pre_condition("a", "false", true),
            prepared_javascript("b", false, true),
            prepared_javascript("q", true, true),
        ],
        successful_phases(7),
    );
    let request = fixture.request(envelope(vec![
        repository_step("parent", "owner/parent"),
        repository_step("q", "owner/q"),
    ]));
    let events: Arc<dyn ExecutionEvents> = fixture.events.clone();

    let result = fixture
        .executor
        .execute(request, events, ExecutionCancellation::new())
        .await
        .expect("deferred composite posts execute");

    assert_eq!(result.conclusion(), JobConclusion::Success);
    let state = fixture.endpoint_state.lock().expect("endpoint lock");
    assert_eq!(
        node_entries(&state.commands),
        [
            "q-pre.js",
            "a-main.js",
            "b-main.js",
            "q-main.js",
            "q-post.js",
            "b-post.js",
            "a-post.js",
        ]
    );
}

#[tokio::test]
async fn repeated_nested_reference_keeps_state_per_occurrence() {
    let shared = prepared_javascript("shared", true, true);
    let fixture = Fixture::new(
        vec![prepared_metadata(REPEATED_ACTION_COMPOSITE), shared],
        vec![
            PhaseResponse::success().with_file(CommandFileKind::State, b"saved=first\n".to_vec()),
            PhaseResponse::success().with_file(CommandFileKind::State, b"saved=second\n".to_vec()),
            PhaseResponse::success(),
            PhaseResponse::success(),
            PhaseResponse::success(),
            PhaseResponse::success(),
        ],
    );
    let request = fixture.request(envelope(vec![repository_step("parent", "owner/parent")]));
    let events: Arc<dyn ExecutionEvents> = fixture.events.clone();

    let result = fixture
        .executor
        .execute(request, events, ExecutionCancellation::new())
        .await
        .expect("repeated nested action executes");

    assert_eq!(result.conclusion(), JobConclusion::Success);
    let state = fixture.endpoint_state.lock().expect("endpoint lock");
    let nodes = state
        .commands
        .iter()
        .filter(|command| command.argv().program().as_str() == "/opt/node24/bin/node")
        .collect::<Vec<_>>();
    assert_eq!(
        nodes
            .iter()
            .map(|command| command.operation_id())
            .collect::<BTreeSet<_>>()
            .len(),
        6,
        "each logical occurrence and phase needs a distinct operation identity"
    );
    assert_eq!(
        node_entries(&state.commands),
        [
            "shared-pre.js",
            "shared-pre.js",
            "shared-main.js",
            "shared-main.js",
            "shared-post.js",
            "shared-post.js",
        ]
    );
    assert_eq!(environment_map(nodes[4])["STATE_saved"], "second");
    assert_eq!(environment_map(nodes[5])["STATE_saved"], "first");
}

#[tokio::test]
async fn nested_preparation_failure_starts_no_pre_or_user_step() {
    let fixture = Fixture::new(
        vec![
            prepared_metadata(PREPARATION_FAILURE_COMPOSITE),
            prepared_javascript("ready", true, true),
        ],
        successful_phases(4),
    );
    let request = fixture.request(envelope(vec![
        run_step("first", "First", "true"),
        repository_step("parent", "owner/parent"),
    ]));
    let events: Arc<dyn ExecutionEvents> = fixture.events.clone();

    let result = fixture
        .executor
        .execute(request, events, ExecutionCancellation::new())
        .await
        .expect("nested preparation failure is a terminal job result");

    assert_eq!(result.conclusion(), JobConclusion::Failure);
    let state = fixture.endpoint_state.lock().expect("endpoint lock");
    assert!(
        state.commands.iter().all(|command| {
            !matches!(
                command.argv().program().as_str(),
                "/opt/node24/bin/node" | "/usr/bin/bash"
            )
        }),
        "the complete nested graph must be prepared before any pre or workflow command starts"
    );
}

#[tokio::test]
async fn recursive_repository_action_is_rejected_before_any_user_step() {
    let fixture = Fixture::new(
        vec![prepared_metadata(RECURSIVE_COMPOSITE)],
        successful_phases(2),
    );
    let request = fixture.request(envelope(vec![
        run_step("first", "First", "true"),
        repository_step("recursive", "owner/recursive"),
    ]));
    let events: Arc<dyn ExecutionEvents> = fixture.events.clone();

    let result = fixture
        .executor
        .execute(request, events, ExecutionCancellation::new())
        .await
        .expect("recursive graph is a terminal job result");

    assert_eq!(result.conclusion(), JobConclusion::Failure);
    let state = fixture.endpoint_state.lock().expect("endpoint lock");
    assert!(state.commands.iter().all(|command| {
        !matches!(
            command.argv().program().as_str(),
            "/opt/node24/bin/node" | "/usr/bin/bash"
        )
    }));
}

fn successful_phases(count: usize) -> Vec<PhaseResponse> {
    (0..count).map(|_| PhaseResponse::success()).collect()
}

fn node_entries(commands: &[automata_ci_execution::ExecutionCommand]) -> Vec<&str> {
    commands
        .iter()
        .filter(|command| command.argv().program().as_str() == "/opt/node24/bin/node")
        .filter_map(|command| {
            command
                .argv()
                .arguments()
                .first()
                .and_then(|path| path.rsplit('/').next())
        })
        .collect()
}

fn repository_step(id: &str, repository: &str) -> StepIr {
    StepIr::new(
        StepId::new(id).expect("valid step id"),
        ValueTemplate::literal(id).expect("valid step name"),
        RuntimeBoolean::literal(false),
        SemanticStep::action(
            ActionReference::Repository {
                repository: repository.to_owned(),
                selector: REVISION.to_owned(),
                subpath: None,
            },
            BTreeMap::new(),
        ),
    )
}

fn prepared_javascript(label: &str, has_pre: bool, has_post: bool) -> PreparedAction {
    prepared_javascript_with_optional_pre_condition(label, has_pre.then_some("always()"), has_post)
}

fn prepared_javascript_with_pre_condition(
    label: &str,
    pre_condition: &str,
    has_post: bool,
) -> PreparedAction {
    prepared_javascript_with_optional_pre_condition(label, Some(pre_condition), has_post)
}

fn prepared_javascript_with_optional_pre_condition(
    label: &str,
    pre_condition: Option<&str>,
    has_post: bool,
) -> PreparedAction {
    let compiler = GithubConditionCompiler::default();
    let always = compiler
        .compile_condition(Some("always()"), GithubConditionPhase::Step)
        .expect("valid lifecycle condition");
    let pre = pre_condition.map(|_| format!("dist/{label}-pre.js"));
    let compiled_pre_condition = compiler
        .compile_condition(
            Some(pre_condition.unwrap_or("always()")),
            GithubConditionPhase::Step,
        )
        .expect("valid pre condition");
    let javascript = PreparedJavascriptAction::new(
        JavascriptRuntime::Node24,
        format!("dist/{label}-main.js"),
        pre,
        compiled_pre_condition,
        has_post.then(|| format!("dist/{label}-post.js")),
        always,
    )
    .expect("valid JavaScript action");
    let archive = Bytes::from(format!("synthetic-{label}-archive"));
    let digest = Sha256Digest::from_bytes(Sha256::digest(&archive).into());
    let definition = PreparedActionDefinition::new(
        Vec::new(),
        Vec::new(),
        PreparedActionExecution::Javascript(Box::new(javascript)),
    )
    .expect("valid JavaScript definition");
    PreparedAction::with_definition(digest, archive, "", definition).expect("prepared action")
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
    let archive = Bytes::from_static(b"synthetic-composite-archive");
    let digest = Sha256Digest::from_bytes(Sha256::digest(&archive).into());
    PreparedAction::with_definition(digest, archive, "", local.definition().clone())
        .expect("prepared composite")
}
