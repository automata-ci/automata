mod support;

use std::{collections::BTreeMap, sync::Arc, time::Duration};

use automata_ci_core::{JobConclusion, LogChannel, ValueSource};
use automata_ci_execution::{
    EnvironmentName, EnvironmentValue, EnvironmentVariable, ExecutionEnvironment,
};
use automata_ci_github_runtime::CommandFileKind;
use automata_ci_runner_runtime::{ExecutionCancellation, ExecutionEvents, JobExecutor};
use automata_ci_workflow_github::{GithubConditionCompiler, GithubConditionPhase};

use support::{
    CONTEXT_SECRET, Fixture, PhaseResponse, PostContextCancellationPoint, action_step, envelope,
    envelope_with_environment, environment_map, prepared_node24_action,
    prepared_node24_action_with_post_condition, run_step,
};

#[tokio::test]
async fn checkout_materializes_the_github_workflow_directory_view() {
    let fixture = Fixture::new(
        vec![prepared_node24_action()],
        vec![
            PhaseResponse::success(),
            PhaseResponse::success(),
            PhaseResponse::success(),
        ],
    );
    let request = fixture.request(envelope(vec![action_step("checkout", "actions/checkout")]));
    let events: Arc<dyn ExecutionEvents> = fixture.events.clone();

    let result = fixture
        .executor
        .execute(request, events, ExecutionCancellation::new())
        .await
        .expect("checkout executes");

    assert_eq!(result.conclusion(), JobConclusion::Success);
    let state = fixture.endpoint_state.lock().expect("endpoint lock");
    let compatibility = state
        .commands
        .iter()
        .find(|command| {
            command.argv().program().as_str() == "/usr/bin/sh"
                && command
                    .argv()
                    .arguments()
                    .get(1)
                    .is_some_and(|script| script.contains(".ci/workflows"))
        })
        .expect("workflow-directory compatibility command");
    assert_eq!(
        compatibility.working_directory().as_str(),
        "/__w/automata/automata"
    );
    let script = &compatibility.argv().arguments()[1];
    assert!(script.contains("for source in .ci/workflows/*"));
    assert!(script.contains("[ ! -e \"$destination\" ] && [ ! -L \"$destination\" ]"));
    assert!(script.contains("cp -- \"$source\" \"$destination\""));
    assert!(!script.contains("cp -R"));
}

#[tokio::test]
async fn sandbox_profile_defaults_are_the_lowest_execution_environment_layer() {
    let defaults = ExecutionEnvironment::new(
        [
            ("PROFILE_ONLY", "profile"),
            ("PATH", "/profile/bin"),
            ("HOME", "/profile/home"),
            ("COMMAND_WINS", "profile"),
            ("STEP_WINS", "profile"),
            ("GITHUB_ACTION_PATH", "profile"),
        ]
        .into_iter()
        .map(|(name, value)| {
            EnvironmentVariable::new(
                EnvironmentName::new(name).expect("valid environment name"),
                EnvironmentValue::new(value).expect("valid environment value"),
            )
        })
        .collect(),
    )
    .expect("valid profile defaults");
    let responses = vec![
        PhaseResponse::success()
            .with_file(
                CommandFileKind::Environment,
                b"COMMAND_WINS=command\nSTEP_WINS=command\nGITHUB_ACTION_PATH=command\n".to_vec(),
            )
            .with_file(CommandFileKind::Path, b"/command/bin\n".to_vec()),
        PhaseResponse::success(),
        PhaseResponse::success(),
    ];
    let fixture =
        Fixture::with_default_environment(vec![prepared_node24_action()], responses, defaults);
    let setup = run_step("setup", "Setup", "true");
    let action = action_step("checkout", "actions/example").with_environment(BTreeMap::from([
        (
            "STEP_WINS".to_owned(),
            ValueSource::Literal("step".to_owned()),
        ),
        (
            "GITHUB_ACTION_PATH".to_owned(),
            ValueSource::Literal("step".to_owned()),
        ),
    ]));
    let job = envelope_with_environment(
        vec![setup, action],
        BTreeMap::from([
            (
                "HOME".to_owned(),
                ValueSource::Literal("/job/home".to_owned()),
            ),
            (
                "COMMAND_WINS".to_owned(),
                ValueSource::Literal("job".to_owned()),
            ),
            (
                "STEP_WINS".to_owned(),
                ValueSource::Literal("job".to_owned()),
            ),
            (
                "GITHUB_ACTION_PATH".to_owned(),
                ValueSource::Literal("job".to_owned()),
            ),
        ]),
    );
    let request = fixture.request(job);
    let events: Arc<dyn ExecutionEvents> = fixture.events.clone();

    let result = fixture
        .executor
        .execute(request, events, ExecutionCancellation::new())
        .await
        .expect("run and action steps execute");

    assert_eq!(result.conclusion(), JobConclusion::Success);
    let state = fixture.endpoint_state.lock().expect("endpoint lock");
    let run = state
        .commands
        .iter()
        .find(|command| command.argv().program().as_str() == "/usr/bin/bash")
        .expect("run command");
    let run_environment = environment_map(run);
    assert_eq!(run_environment["PROFILE_ONLY"], "profile");
    assert_eq!(run_environment["PATH"], "/usr/bin:/bin");
    assert_eq!(run_environment["HOME"], "/job/home");
    assert_eq!(run_environment["COMMAND_WINS"], "job");

    let action = state
        .commands
        .iter()
        .find(|command| command.argv().program().as_str() == "/opt/node24/bin/node")
        .expect("action command");
    let action_environment = environment_map(action);
    assert_eq!(action_environment["PROFILE_ONLY"], "profile");
    assert_eq!(action_environment["PATH"], "/command/bin:/usr/bin:/bin");
    assert_eq!(action_environment["COMMAND_WINS"], "command");
    assert_eq!(action_environment["STEP_WINS"], "step");
    assert!(
        action_environment["GITHUB_ACTION_PATH"].ends_with("/actions/action-1/root"),
        "action runtime extras must override every user-controlled environment layer"
    );
}

#[tokio::test]
async fn metadata_driven_node24_actions_run_main_then_posts_in_lifo_order() {
    let responses = vec![
        PhaseResponse::success()
            .with_stdout(format!("token={CONTEXT_SECRET}\n"))
            .with_file(CommandFileKind::State, b"saved=first\n".to_vec())
            .with_file(CommandFileKind::Output, b"main=one\n".to_vec()),
        PhaseResponse::success().with_file(CommandFileKind::State, b"saved=second\n".to_vec()),
        PhaseResponse::success().with_file(CommandFileKind::Output, b"post=two\n".to_vec()),
        PhaseResponse::success(),
    ];
    let fixture = Fixture::new(
        vec![prepared_node24_action(), prepared_node24_action()],
        responses,
    );
    let job = envelope(vec![
        action_step("checkout", "actions/example"),
        action_step("cache", "actions/cache"),
    ]);
    let request = fixture.request(job);
    let events: Arc<dyn ExecutionEvents> = fixture.events.clone();

    let result = fixture
        .executor
        .execute(request, events, ExecutionCancellation::new())
        .await
        .expect("actions execute");

    assert_eq!(result.conclusion(), JobConclusion::Success);
    let state = fixture.endpoint_state.lock().expect("endpoint lock");
    let node = state
        .commands
        .iter()
        .filter(|command| command.argv().program().as_str() == "/opt/node24/bin/node")
        .collect::<Vec<_>>();
    assert_eq!(node.len(), 4);
    let entry_paths = node
        .iter()
        .map(|command| command.argv().arguments()[0].as_str())
        .collect::<Vec<_>>();
    assert!(entry_paths[0].contains("/actions/action-0/root/dist/index.js"));
    assert!(entry_paths[1].contains("/actions/action-1/root/dist/index.js"));
    assert!(entry_paths[2].contains("/actions/action-1/root/dist/index.js"));
    assert!(entry_paths[3].contains("/actions/action-0/root/dist/index.js"));

    let first_main = environment_map(node[0]);
    assert_eq!(
        first_main.get("INPUT_FETCH-DEPTH").map(String::as_str),
        Some("1")
    );
    assert_eq!(
        first_main
            .get("INPUT_PERSIST-CREDENTIALS")
            .map(String::as_str),
        Some("false")
    );
    assert_eq!(
        first_main.get("INPUT_TOKEN").map(String::as_str),
        Some(CONTEXT_SECRET)
    );
    assert!(first_main["GITHUB_ACTION_PATH"].ends_with("/actions/action-0/root"));
    let second_post = environment_map(node[2]);
    let first_post = environment_map(node[3]);
    assert_eq!(
        second_post.get("STATE_saved").map(String::as_str),
        Some("second")
    );
    assert_eq!(
        first_post.get("STATE_saved").map(String::as_str),
        Some("first")
    );
    drop(state);

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

#[tokio::test]
async fn registered_post_does_not_start_when_execution_is_cancelled_before_posts() {
    let cancellation = ExecutionCancellation::new();
    let fixture = Fixture::new(
        vec![prepared_node24_action()],
        vec![PhaseResponse::success().signal(cancellation.clone())],
    );
    let request = fixture.request(envelope(vec![action_step("checkout", "actions/example")]));
    let events: Arc<dyn ExecutionEvents> = fixture.events.clone();

    let result = fixture
        .executor
        .execute(request, events, cancellation.clone())
        .await
        .expect("cancelled action remains a terminal job result");

    assert!(cancellation.is_cancelled());
    assert_eq!(result.conclusion(), JobConclusion::Cancelled);
    let state = fixture.endpoint_state.lock().expect("endpoint lock");
    let node = state
        .commands
        .iter()
        .filter(|command| command.argv().program().as_str() == "/opt/node24/bin/node")
        .collect::<Vec<_>>();
    assert_eq!(node.len(), 1, "only the action main may execute");
    assert!(node[0].argv().arguments()[0].ends_with("/dist/index.js"));
}

#[tokio::test]
async fn cancellation_after_post_exec_prevents_copy_output_and_later_posts() {
    let cancellation = ExecutionCancellation::new();
    let fixture = Fixture::new(
        vec![prepared_node24_action(), prepared_node24_action()],
        vec![
            PhaseResponse::success(),
            PhaseResponse::success(),
            PhaseResponse::success()
                .with_stdout(b"post output after cancellation\n".to_vec())
                .with_file(CommandFileKind::State, b"after=cancelled\n".to_vec())
                .signal_before_copy_from(cancellation.clone()),
            PhaseResponse::success(),
        ],
    );
    let request = fixture.request(envelope(vec![
        action_step("checkout", "actions/example"),
        action_step("cache", "actions/cache"),
    ]));
    let events: Arc<dyn ExecutionEvents> = fixture.events.clone();

    let result = fixture
        .executor
        .execute(request, events, cancellation.clone())
        .await
        .expect("post cancellation remains a terminal job result");

    assert!(cancellation.is_cancelled());
    assert_eq!(result.conclusion(), JobConclusion::Cancelled);
    let state = fixture.endpoint_state.lock().expect("endpoint lock");
    let node = state
        .commands
        .iter()
        .filter(|command| command.argv().program().as_str() == "/opt/node24/bin/node")
        .collect::<Vec<_>>();
    assert_eq!(node.len(), 3, "the earlier registered post must not start");
    assert!(node[2].argv().arguments()[0].contains("/actions/action-1/root/"));
    assert_eq!(
        state.copy_from_calls_since_exec, 0,
        "cancellation before the copy boundary must prevent command-file reads"
    );
    drop(state);

    let logs = fixture
        .events
        .logs()
        .into_iter()
        .flat_map(|event| event.payload().to_vec())
        .collect::<Vec<_>>();
    assert!(
        !String::from_utf8(logs)
            .expect("UTF-8 logs")
            .contains("post output after cancellation"),
        "cancelled post output must not be re-published"
    );
}

#[tokio::test]
async fn cancellation_during_first_post_log_emit_prevents_later_lines() {
    let cancellation = ExecutionCancellation::new();
    let fixture = Fixture::secretless(
        vec![prepared_node24_action()],
        vec![
            PhaseResponse::success(),
            PhaseResponse::success().with_stdout(b"first post line\nsecond post line\n".to_vec()),
        ],
    );
    fixture.events.cancel_on_next_log(cancellation.clone());
    let request = fixture.request(envelope(vec![action_step("checkout", "actions/example")]));
    let events: Arc<dyn ExecutionEvents> = fixture.events.clone();

    let result = fixture
        .executor
        .execute(request, events, cancellation.clone())
        .await
        .expect("log-emission cancellation remains a terminal job result");

    assert!(cancellation.is_cancelled());
    assert_eq!(result.conclusion(), JobConclusion::Cancelled);
    let stdout = fixture
        .events
        .logs()
        .into_iter()
        .filter(|event| event.channel() == LogChannel::Stdout)
        .flat_map(|event| event.payload().to_vec())
        .collect::<Vec<_>>();
    assert_eq!(
        String::from_utf8(stdout).expect("UTF-8 logs"),
        "first post line\n",
        "no later line may publish after cancellation from the first emit"
    );
}

#[tokio::test]
async fn cancellation_dominates_a_simultaneous_post_context_error() {
    let cancellation = ExecutionCancellation::new();
    let fixture = Fixture::with_post_context_cancellation(
        vec![prepared_node24_action()],
        vec![PhaseResponse::success()],
        cancellation.clone(),
        PostContextCancellationPoint::BeforeError,
    );
    let request = fixture.request(envelope(vec![action_step("checkout", "actions/example")]));
    let events: Arc<dyn ExecutionEvents> = fixture.events.clone();

    let result = fixture
        .executor
        .execute(request, events, cancellation.clone())
        .await
        .expect("post-context cancellation dominates its adapter error");

    assert!(cancellation.is_cancelled());
    assert_eq!(result.conclusion(), JobConclusion::Cancelled);
    let state = fixture.endpoint_state.lock().expect("endpoint lock");
    assert_eq!(
        state
            .commands
            .iter()
            .filter(|command| command.argv().program().as_str() == "/opt/node24/bin/node")
            .count(),
        1,
        "the post must not start after its context boundary cancels"
    );
}

#[tokio::test]
async fn cancellation_dominates_a_simultaneous_post_condition_error() {
    let cancellation = ExecutionCancellation::new();
    let fixture = Fixture::with_post_context_cancellation(
        vec![prepared_node24_action_with_post_condition(
            "hashFiles('post-condition')",
        )],
        vec![PhaseResponse::success()],
        cancellation.clone(),
        PostContextCancellationPoint::DuringEvaluation,
    );
    let request = fixture.request(envelope(vec![action_step("checkout", "actions/example")]));
    let events: Arc<dyn ExecutionEvents> = fixture.events.clone();

    let result = fixture
        .executor
        .execute(request, events, cancellation.clone())
        .await
        .expect("post-condition cancellation dominates its evaluation error");

    assert!(cancellation.is_cancelled());
    assert_eq!(result.conclusion(), JobConclusion::Cancelled);
    let state = fixture.endpoint_state.lock().expect("endpoint lock");
    assert_eq!(
        state
            .commands
            .iter()
            .filter(|command| command.argv().program().as_str() == "/opt/node24/bin/node")
            .count(),
        1,
        "the post must not start after its condition boundary cancels"
    );
}

#[tokio::test]
async fn cancellation_dominates_a_simultaneous_post_environment_error() {
    let cancellation = ExecutionCancellation::new();
    let post_only_error = GithubConditionCompiler::default()
        .compile_value_expression(
            "${{ failure() && hashFiles('post-environment') }}",
            GithubConditionPhase::Step,
        )
        .expect("valid post-only environment expression");
    let step = action_step("checkout", "actions/example").with_environment(BTreeMap::from([(
        "POST_ONLY".to_owned(),
        ValueSource::Expression(post_only_error),
    )]));
    let mut failed = PhaseResponse::success();
    failed.termination = automata_ci_execution::ExecutionTermination::Exited(1);
    let fixture = Fixture::with_post_context_cancellation(
        vec![prepared_node24_action()],
        vec![failed],
        cancellation.clone(),
        PostContextCancellationPoint::DuringEvaluation,
    );
    let request = fixture.request(envelope(vec![step]));
    let events: Arc<dyn ExecutionEvents> = fixture.events.clone();

    let result = fixture
        .executor
        .execute(request, events, cancellation.clone())
        .await
        .expect("post-environment cancellation dominates its evaluation error");

    let state = fixture.endpoint_state.lock().expect("endpoint lock");
    let node_count = state
        .commands
        .iter()
        .filter(|command| command.argv().program().as_str() == "/opt/node24/bin/node")
        .count();
    assert!(
        cancellation.is_cancelled(),
        "fixture hook did not fire: conclusion={:?}, node_count={node_count}",
        result.conclusion()
    );
    assert_eq!(result.conclusion(), JobConclusion::Cancelled);
    assert_eq!(
        node_count, 1,
        "the failing post environment must prevent post execution"
    );
}

#[tokio::test]
async fn ordinary_action_failure_still_runs_its_registered_post() {
    let mut failed = PhaseResponse::success();
    failed.termination = automata_ci_execution::ExecutionTermination::Exited(1);
    let fixture = Fixture::new(
        vec![prepared_node24_action()],
        vec![failed, PhaseResponse::success()],
    );
    let request = fixture.request(envelope(vec![action_step("checkout", "actions/example")]));
    let events: Arc<dyn ExecutionEvents> = fixture.events.clone();

    let result = fixture
        .executor
        .execute(request, events, ExecutionCancellation::new())
        .await
        .expect("ordinary failure remains a terminal job result");

    assert_eq!(result.conclusion(), JobConclusion::Failure);
    let state = fixture.endpoint_state.lock().expect("endpoint lock");
    let node = state
        .commands
        .iter()
        .filter(|command| command.argv().program().as_str() == "/opt/node24/bin/node")
        .collect::<Vec<_>>();
    assert_eq!(node.len(), 2, "ordinary failure must retain post cleanup");
}

#[tokio::test]
async fn post_cleanup_deadline_maps_success_to_timed_out() {
    let fixture = Fixture::with_step_timeout(
        vec![prepared_node24_action()],
        vec![
            PhaseResponse::success(),
            PhaseResponse::success().delay(Duration::from_millis(150)),
        ],
        Duration::from_millis(100),
    );
    let request = fixture.request(envelope(vec![action_step("checkout", "actions/example")]));
    let events: Arc<dyn ExecutionEvents> = fixture.events.clone();

    let result = fixture
        .executor
        .execute(request, events, ExecutionCancellation::new())
        .await
        .expect("cleanup deadline remains a terminal job result");

    assert_eq!(result.conclusion(), JobConclusion::TimedOut);
}

#[tokio::test]
async fn post_cleanup_deadline_preserves_an_existing_ordinary_failure() {
    let mut failed = PhaseResponse::success();
    failed.termination = automata_ci_execution::ExecutionTermination::Exited(1);
    let fixture = Fixture::with_step_timeout(
        vec![prepared_node24_action()],
        vec![
            failed,
            PhaseResponse::success().delay(Duration::from_millis(150)),
        ],
        Duration::from_millis(100),
    );
    let request = fixture.request(envelope(vec![action_step("checkout", "actions/example")]));
    let events: Arc<dyn ExecutionEvents> = fixture.events.clone();

    let result = fixture
        .executor
        .execute(request, events, ExecutionCancellation::new())
        .await
        .expect("ordinary failure dominates cleanup deadline expiry");

    assert_eq!(result.conclusion(), JobConclusion::Failure);
}

#[tokio::test]
async fn action_preparation_failure_logs_only_its_sanitized_kind() {
    let fixture = Fixture::new(Vec::new(), Vec::new());
    let request = fixture.request(envelope(vec![action_step(
        "checkout",
        "actions/credential-bearing-private-reference",
    )]));
    let events: Arc<dyn ExecutionEvents> = fixture.events.clone();

    let result = fixture
        .executor
        .execute(request, events, ExecutionCancellation::new())
        .await
        .expect("preparation failure remains a terminal job result");

    assert_eq!(result.conclusion(), JobConclusion::Failure);
    let system_logs = fixture
        .events
        .logs()
        .into_iter()
        .filter(|event| event.channel() == LogChannel::System)
        .map(|event| String::from_utf8(event.payload().to_vec()).expect("UTF-8 system log"))
        .collect::<Vec<_>>();
    assert_eq!(system_logs, ["Action preparation failed (Resolution)\n"]);
    assert!(!system_logs.concat().contains("credential-bearing"));
}
