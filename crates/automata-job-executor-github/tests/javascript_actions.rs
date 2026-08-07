mod support;

use std::{collections::BTreeMap, sync::Arc};

use automata_core::{
    JobConclusion, LogChannel, SemanticStep, ShellSpec, StepId, StepIr, ValueSource,
};
use automata_execution::{
    EnvironmentName, EnvironmentValue, EnvironmentVariable, ExecutionEnvironment,
};
use automata_github_runtime::CommandFileKind;
use automata_runner_runtime::{ExecutionCancellation, ExecutionEvents, JobExecutor};

use support::{
    CONTEXT_SECRET, Fixture, PhaseResponse, action_step, envelope, envelope_with_environment,
    environment_map, prepared_node24_action,
};

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
    let setup = StepIr::new(
        StepId::new("setup").expect("valid step"),
        "Setup",
        SemanticStep::run("true", ShellSpec::Default),
    );
    let action = action_step("checkout", "actions/checkout").with_environment(BTreeMap::from([
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
        action_step("checkout", "actions/checkout"),
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
async fn action_post_runs_with_cleanup_budget_after_job_cancellation_fires() {
    let cancellation = ExecutionCancellation::new();
    let fixture = Fixture::new(
        vec![prepared_node24_action()],
        vec![
            PhaseResponse::success()
                .cancelled()
                .signal(cancellation.clone()),
            PhaseResponse::success(),
        ],
    );
    let request = fixture.request(envelope(vec![action_step("checkout", "actions/checkout")]));
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
    assert_eq!(node.len(), 2, "action main and post must both execute");
    assert!(node[0].argv().arguments()[0].ends_with("/dist/index.js"));
    assert!(node[1].argv().arguments()[0].ends_with("/dist/index.js"));
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
