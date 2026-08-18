mod support;

use std::{collections::BTreeMap, sync::Arc, time::Duration};

use automata_ci_action_actions::{GithubActionMetadataDecoder, JavascriptRuntime};
use automata_ci_actions_runtime::CommandFileKind;
use automata_ci_core::{
    ActionReference, JobConclusion, RuntimeBoolean, RuntimePositiveInteger, RuntimeTimeoutTemplate,
    SemanticStep, Sha256Digest, StepId, StepIr, ValueSource, ValueTemplate,
};
use automata_ci_execution::ExecutionTermination;
use automata_ci_job_executor_actions::{
    CheckedOutLocalActionPreparer, LocalActionPreparationRequest, PreparedAction,
    PreparedActionDefinition, PreparedActionExecution, PreparedInput, PreparedJavascriptAction,
    PreparedValue,
};
use automata_ci_runner_runtime::{ExecutionCancellation, ExecutionEvents, JobExecutor};
use automata_ci_workflow_actions::{GithubConditionCompiler, GithubConditionPhase};
use bytes::Bytes;
use sha2::{Digest as _, Sha256};

use support::{CONTEXT_SECRET, Fixture, PhaseResponse, envelope, environment_map};

const REVISION: &str = "0123456789abcdef0123456789abcdef01234567";

const POST_SCOPE_PARENT: &str = r"
name: Post scope parent
inputs:
  phase:
    default: ${{ github.phase }}
runs:
  using: composite
  steps:
    - id: producer
      run: printf result
      shell: bash
    - id: nested
      uses: owner/leaf@0123456789abcdef0123456789abcdef01234567
      continue-on-error: ${{ inputs.phase == 'action_post' }}
      with:
        phase: ${{ inputs.phase }}
        observed: ${{ steps.producer.outputs.value }}
        late: ${{ env.LATE_COPY }}
        token: ${{ github.token }}
      env:
        CHILD_PHASE: ${{ inputs.phase }}
        LATE_COPY: ${{ env.LATE }}
";

#[tokio::test]
async fn top_level_post_re_evaluates_env_inputs_defaults_timeout_and_continue_policy() {
    let mut post_failure = PhaseResponse::success().with_stdout(format!("{CONTEXT_SECRET}\n"));
    post_failure.termination = ExecutionTermination::Exited(1);
    let fixture = Fixture::new(
        vec![prepared_lifecycle_action("always()")],
        vec![
            PhaseResponse::success(),
            PhaseResponse::success()
                .with_file(CommandFileKind::Environment, b"LATE=post-value\n".to_vec())
                .with_file(CommandFileKind::State, b"saved=main\n".to_vec()),
            post_failure,
        ],
    );
    let step = repository_step(
        "lifecycle",
        "owner/lifecycle",
        BTreeMap::from([(
            "supplied".to_owned(),
            ValueSource::Expression(expression("env.RENDERED")),
        )]),
    )
    .with_environment(BTreeMap::from([(
        "RENDERED".to_owned(),
        ValueSource::Expression(expression("env.LATE")),
    )]))
    .with_timeout(RuntimeTimeoutTemplate::minutes(
        RuntimePositiveInteger::expression(expression("github.phase_timeout")),
    ))
    .with_continue_on_error(RuntimeBoolean::expression(expression(
        "github.continue_post",
    )));
    let request = fixture.request(envelope(vec![step]));
    let events: Arc<dyn ExecutionEvents> = fixture.events.clone();

    let result = fixture
        .executor
        .execute(request, events, ExecutionCancellation::new())
        .await
        .expect("post template evaluation succeeds");

    assert_eq!(result.conclusion(), JobConclusion::Success);
    let state = fixture.endpoint_state.lock().expect("endpoint lock");
    let nodes = state
        .commands
        .iter()
        .filter(|command| command.argv().program().as_str() == "/opt/node24/bin/node")
        .collect::<Vec<_>>();
    assert_eq!(nodes.len(), 3);
    let pre = environment_map(nodes[0]);
    let main = environment_map(nodes[1]);
    let post = environment_map(nodes[2]);
    assert_eq!(pre["INPUT_PHASE"], "action_pre");
    assert_eq!(main["INPUT_PHASE"], "action_main");
    assert_eq!(post["INPUT_PHASE"], "action_post");
    assert_eq!(pre["INPUT_SUPPLIED"], "");
    assert_eq!(main["INPUT_SUPPLIED"], "");
    assert_eq!(post["INPUT_SUPPLIED"], "post-value");
    assert_eq!(post["RENDERED"], "post-value");
    assert_eq!(post["STATE_saved"], "main");
    assert_eq!(post["INPUT_TOKEN"], CONTEXT_SECRET);
    assert_eq!(nodes[2].timeout(), Duration::from_mins(1));
    assert!(
        nodes[2]
            .environment()
            .values()
            .iter()
            .find(|variable| variable.name().as_str() == "INPUT_TOKEN")
            .expect("token input")
            .is_secret()
    );
    drop(state);
    assert_masked(&fixture);
}

#[tokio::test]
async fn nested_post_rebuilds_parent_inputs_env_and_main_steps_scope() {
    let mut post_failure = PhaseResponse::success().with_stdout(format!("{CONTEXT_SECRET}\n"));
    post_failure.termination = ExecutionTermination::Exited(1);
    let fixture = Fixture::new(
        vec![
            prepared_metadata(POST_SCOPE_PARENT),
            prepared_leaf_action(
                "inputs.phase == 'action_post' && steps.producer.outputs.value == 'main-scope' && env.LATE_COPY == 'post-late'",
            ),
        ],
        vec![
            PhaseResponse::success()
                .with_file(CommandFileKind::Output, b"value=main-scope\n".to_vec()),
            PhaseResponse::success()
                .with_file(CommandFileKind::Environment, b"LATE=post-late\n".to_vec())
                .with_file(CommandFileKind::State, b"saved=nested-main\n".to_vec()),
            post_failure,
        ],
    );
    let step = repository_step("parent", "owner/parent", BTreeMap::new()).with_timeout(
        RuntimeTimeoutTemplate::minutes(RuntimePositiveInteger::expression(expression(
            "github.phase_timeout",
        ))),
    );
    let request = fixture.request(envelope(vec![step]));
    let events: Arc<dyn ExecutionEvents> = fixture.events.clone();

    let result = fixture
        .executor
        .execute(request, events, ExecutionCancellation::new())
        .await
        .expect("nested post scope is reconstructed");

    assert_eq!(result.conclusion(), JobConclusion::Success);
    let state = fixture.endpoint_state.lock().expect("endpoint lock");
    let nodes = state
        .commands
        .iter()
        .filter(|command| command.argv().program().as_str() == "/opt/node24/bin/node")
        .collect::<Vec<_>>();
    assert_eq!(nodes.len(), 2, "the leaf main and registered post must run");
    let main = environment_map(nodes[0]);
    let post = environment_map(nodes[1]);
    assert_eq!(main["INPUT_PHASE"], "action_main");
    assert_eq!(main["INPUT_OBSERVED"], "main-scope");
    assert_eq!(post["INPUT_PHASE"], "action_post");
    assert_eq!(post["INPUT_OBSERVED"], "main-scope");
    assert_eq!(post["INPUT_LATE"], "post-late");
    assert_eq!(post["CHILD_PHASE"], "action_post");
    assert_eq!(post["LATE_COPY"], "post-late");
    assert_eq!(post["STATE_saved"], "nested-main");
    assert_eq!(post["INPUT_TOKEN"], CONTEXT_SECRET);
    assert_eq!(nodes[1].timeout(), Duration::from_mins(1));
    drop(state);
    assert_masked(&fixture);
}

#[tokio::test]
async fn skipped_post_does_not_evaluate_its_phase_dependent_inputs() {
    let fixture = Fixture::new(
        vec![prepared_lifecycle_action("false")],
        vec![PhaseResponse::success(), PhaseResponse::success()],
    );
    let step = repository_step(
        "lifecycle",
        "owner/lifecycle",
        BTreeMap::from([(
            "supplied".to_owned(),
            ValueSource::Expression(expression(
                "github.phase == 'action_post' && fromJSON('not-json') || 'safe'",
            )),
        )]),
    );
    let request = fixture.request(envelope(vec![step]));
    let events: Arc<dyn ExecutionEvents> = fixture.events.clone();

    let result = fixture
        .executor
        .execute(request, events, ExecutionCancellation::new())
        .await
        .expect("a false post condition skips input evaluation");

    assert_eq!(result.conclusion(), JobConclusion::Success);
    let state = fixture.endpoint_state.lock().expect("endpoint lock");
    assert_eq!(
        state
            .commands
            .iter()
            .filter(|command| command.argv().program().as_str() == "/opt/node24/bin/node")
            .count(),
        2,
        "only pre and main may run"
    );
}

#[tokio::test]
async fn skipped_main_without_a_completed_pre_registers_no_post() {
    let fixture = Fixture::new(vec![prepared_leaf_action("always()")], Vec::new());
    let never = GithubConditionCompiler::default()
        .compile_condition(Some("false"), GithubConditionPhase::Step)
        .expect("false condition");
    let step = repository_step("leaf", "owner/leaf", BTreeMap::new()).with_condition(never);
    let request = fixture.request(envelope(vec![step]));
    let events: Arc<dyn ExecutionEvents> = fixture.events.clone();

    let result = fixture
        .executor
        .execute(request, events, ExecutionCancellation::new())
        .await
        .expect("skipped main remains a successful job");

    assert_eq!(result.steps()[0].conclusion(), JobConclusion::Skipped);
    let state = fixture.endpoint_state.lock().expect("endpoint lock");
    assert!(
        state
            .commands
            .iter()
            .all(|command| command.argv().program().as_str() != "/opt/node24/bin/node")
    );
}

fn prepared_lifecycle_action(post_condition: &str) -> PreparedAction {
    let compiler = GithubConditionCompiler::default();
    let always = compiler
        .compile_condition(Some("always()"), GithubConditionPhase::Step)
        .expect("lifecycle condition");
    let post_condition = compiler
        .compile_condition(Some(post_condition), GithubConditionPhase::Step)
        .expect("post condition");
    let javascript = PreparedJavascriptAction::new(
        JavascriptRuntime::Node24,
        "dist/main.js",
        Some("dist/pre.js".to_owned()),
        always.clone(),
        Some("dist/post.js".to_owned()),
        post_condition,
    )
    .expect("JavaScript action");
    let definition = PreparedActionDefinition::new(
        vec![
            PreparedInput::new("supplied", None).expect("supplied input"),
            PreparedInput::new(
                "phase",
                Some(PreparedValue::Expression(expression("github.phase"))),
            )
            .expect("phase input"),
            PreparedInput::new(
                "token",
                Some(PreparedValue::Expression(expression("github.token"))),
            )
            .expect("token input"),
        ],
        Vec::new(),
        PreparedActionExecution::Javascript(Box::new(javascript)),
    )
    .expect("action definition");
    prepared_action(b"post-template-lifecycle", definition)
}

fn prepared_leaf_action(post_condition: &str) -> PreparedAction {
    let compiler = GithubConditionCompiler::default();
    let always = compiler
        .compile_condition(Some("always()"), GithubConditionPhase::Step)
        .expect("lifecycle condition");
    let post_condition = compiler
        .compile_condition(Some(post_condition), GithubConditionPhase::Step)
        .expect("post condition");
    let javascript = PreparedJavascriptAction::new(
        JavascriptRuntime::Node24,
        "dist/main.js",
        None,
        always,
        Some("dist/post.js".to_owned()),
        post_condition,
    )
    .expect("JavaScript action");
    let inputs = ["phase", "observed", "late", "token"]
        .into_iter()
        .map(|name| PreparedInput::new(name, None).expect("leaf input"))
        .collect();
    let definition = PreparedActionDefinition::new(
        inputs,
        Vec::new(),
        PreparedActionExecution::Javascript(Box::new(javascript)),
    )
    .expect("leaf definition");
    prepared_action(b"post-template-leaf", definition)
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
    prepared_action(b"post-template-parent", local.definition().clone())
}

fn prepared_action(archive: &'static [u8], definition: PreparedActionDefinition) -> PreparedAction {
    let archive = Bytes::from_static(archive);
    let digest = Sha256Digest::from_bytes(Sha256::digest(&archive).into());
    PreparedAction::with_definition(digest, archive, "", definition).expect("prepared action")
}

fn repository_step(id: &str, repository: &str, inputs: BTreeMap<String, ValueSource>) -> StepIr {
    StepIr::new(
        StepId::new(id).expect("step id"),
        ValueTemplate::literal(id).expect("step name"),
        RuntimeBoolean::literal(false),
        SemanticStep::action(
            ActionReference::Repository {
                repository: repository.to_owned(),
                selector: REVISION.to_owned(),
                subpath: None,
            },
            inputs,
        ),
    )
}

fn expression(source: &str) -> automata_ci_core::ExpressionProgram {
    GithubConditionCompiler::default()
        .compile_value_expression(&format!("${{{{ {source} }}}}"), GithubConditionPhase::Step)
        .expect("value expression")
}

fn assert_masked(fixture: &Fixture) {
    let logs = fixture
        .events
        .logs()
        .into_iter()
        .flat_map(|event| event.payload().to_vec())
        .collect::<Vec<_>>();
    assert!(
        !String::from_utf8(logs)
            .expect("UTF-8 logs")
            .contains(CONTEXT_SECRET)
    );
}
