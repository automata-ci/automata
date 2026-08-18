mod support;

use std::sync::Arc;

use automata_ci_core::{
    JobConclusion, LogChannel, MAX_STEP_ATTACHMENT_TEXT_BYTES, StepAnnotationLevel,
};
use automata_ci_github_runtime::CommandFileKind;
use automata_ci_runner_runtime::{ExecutionCancellation, ExecutionEvents, JobExecutor};
use automata_ci_workflow_actions::{GithubConditionCompiler, GithubConditionPhase};

use support::{
    Fixture, PhaseResponse, action_step, assert_fresh_isolated_phase_files, envelope,
    environment_map, local_action_step, prepared_node24_action_with_pre,
    prepared_node24_action_with_pre_condition, run_step,
};

#[tokio::test]
async fn repository_action_pre_runs_before_every_main_job_step() {
    let fixture = Fixture::new(
        vec![prepared_node24_action_with_pre()],
        vec![
            PhaseResponse::success()
                .with_file(CommandFileKind::Environment, b"PRE_JOB=ready\n".to_vec())
                .with_file(CommandFileKind::State, b"from_pre=yes\n".to_vec())
                .with_file(CommandFileKind::StepSummary, b"pre\n".to_vec())
                .with_artifacts_list_write(b"corrupt pre list".to_vec()),
            PhaseResponse::success()
                .with_file(CommandFileKind::StepSummary, b"first run\n".to_vec())
                .with_artifacts_list_write(b"corrupt first-run list".to_vec()),
            PhaseResponse::success()
                .with_file(CommandFileKind::StepSummary, b"main\n".to_vec())
                .with_artifacts_list_write(b"corrupt main list".to_vec()),
            PhaseResponse::success()
                .with_file(CommandFileKind::StepSummary, b"last run\n".to_vec())
                .with_artifacts_list_write(b"corrupt last-run list".to_vec()),
            PhaseResponse::success()
                .with_file(CommandFileKind::StepSummary, b"post\n".to_vec())
                .with_artifacts_list_write(b"corrupt post list".to_vec()),
        ],
    );
    let request = fixture.request(envelope(vec![
        run_step("first", "First", "true"),
        action_step("lifecycle", "owner/lifecycle"),
        run_step("last", "Last", "true"),
    ]));
    let events: Arc<dyn ExecutionEvents> = fixture.events.clone();

    let result = fixture
        .executor
        .execute(request, events, ExecutionCancellation::new())
        .await
        .expect("action lifecycle executes");

    assert_eq!(result.conclusion(), JobConclusion::Success);
    assert_eq!(result.steps()[0].summary_markdown(), Some("first run\n"));
    assert_eq!(
        result.steps()[1].summary_markdown(),
        Some("pre\nmain\npost\n")
    );
    assert_eq!(result.steps()[2].summary_markdown(), Some("last run\n"));
    let state = fixture.endpoint_state.lock().expect("endpoint lock");
    let phase_commands = state
        .commands
        .iter()
        .filter(|command| {
            matches!(
                command.argv().program().as_str(),
                "/usr/bin/bash" | "/opt/node24/bin/node"
            )
        })
        .collect::<Vec<_>>();
    assert_fresh_isolated_phase_files(&state, &phase_commands);
    let phases = phase_commands
        .iter()
        .filter_map(|command| match command.argv().program().as_str() {
            "/usr/bin/bash" => Some("run".to_owned()),
            "/opt/node24/bin/node" => command
                .argv()
                .arguments()
                .first()
                .and_then(|path| path.rsplit('/').next())
                .map(str::to_owned),
            _ => None,
        })
        .collect::<Vec<_>>();
    assert_eq!(phases, ["pre.js", "run", "main.js", "run", "post.js"]);
    let first_run = state
        .commands
        .iter()
        .find(|command| command.argv().program().as_str() == "/usr/bin/bash")
        .expect("first workflow run");
    assert_eq!(environment_map(first_run)["PRE_JOB"], "ready");
    let post = state
        .commands
        .iter()
        .filter(|command| command.argv().program().as_str() == "/opt/node24/bin/node")
        .nth(2)
        .expect("post command");
    assert_eq!(environment_map(post)["STATE_from_pre"], "yes");
}

#[tokio::test]
async fn action_lifecycle_summary_crossing_the_cumulative_limit_is_nonfatal() {
    const CUMULATIVE_DIAGNOSTIC: &str = "$GITHUB_STEP_SUMMARY content was omitted after the cumulative step summary limit was reached";
    let half = MAX_STEP_ATTACHMENT_TEXT_BYTES / 2;
    let fixture = Fixture::new(
        vec![prepared_node24_action_with_pre()],
        vec![
            PhaseResponse::success().with_file(CommandFileKind::StepSummary, vec![b'p'; half]),
            PhaseResponse::success().with_file(CommandFileKind::StepSummary, vec![b'm'; half]),
            PhaseResponse::success().with_file(CommandFileKind::StepSummary, vec![b'x']),
        ],
    );
    let events: Arc<dyn ExecutionEvents> = fixture.events.clone();

    let result = fixture
        .executor
        .execute(
            fixture.request(envelope(vec![action_step("lifecycle", "owner/lifecycle")])),
            events,
            ExecutionCancellation::new(),
        )
        .await
        .expect("summary retention must not replace the successful lifecycle result");

    assert_eq!(result.conclusion(), JobConclusion::Success);
    let step = &result.steps()[0];
    assert_eq!(step.conclusion(), JobConclusion::Success);
    let summary = step
        .summary_markdown()
        .expect("the exact-boundary pre and main summaries are retained");
    assert_eq!(summary.len(), MAX_STEP_ATTACHMENT_TEXT_BYTES);
    assert!(summary.as_bytes()[..half].iter().all(|byte| *byte == b'p'));
    assert!(summary.as_bytes()[half..].iter().all(|byte| *byte == b'm'));
    assert_eq!(step.annotations().len(), 1);
    assert_eq!(step.annotations()[0].level(), StepAnnotationLevel::Warning);
    assert_eq!(step.annotations()[0].message(), CUMULATIVE_DIAGNOSTIC);

    let state = fixture.endpoint_state.lock().expect("endpoint lock");
    let phase_commands = state
        .commands
        .iter()
        .filter(|command| command.argv().program().as_str() == "/opt/node24/bin/node")
        .collect::<Vec<_>>();
    assert_eq!(phase_commands.len(), 3, "pre, main, and post all execute");
    assert_fresh_isolated_phase_files(&state, &phase_commands);
}

#[tokio::test]
async fn local_action_pre_is_skipped_with_a_sanitized_diagnostic() {
    let fixture = Fixture::new(
        Vec::new(),
        vec![PhaseResponse::success(), PhaseResponse::success()],
    );
    fixture
        .endpoint_state
        .lock()
        .expect("endpoint lock")
        .files
        .insert(
            "/__w/automata/automata/actions/local/action.yml".to_owned(),
            br"
name: Local lifecycle
runs:
  using: node24
  pre: dist/pre.js
  main: dist/main.js
  post: dist/post.js
"
            .to_vec(),
        );
    let request = fixture.request(envelope(vec![local_action_step(
        "local",
        "./actions/local",
    )]));
    let events: Arc<dyn ExecutionEvents> = fixture.events.clone();

    let result = fixture
        .executor
        .execute(request, events, ExecutionCancellation::new())
        .await
        .expect("local action main and post execute");

    assert_eq!(result.conclusion(), JobConclusion::Success);
    let state = fixture.endpoint_state.lock().expect("endpoint lock");
    let entries = state
        .commands
        .iter()
        .filter(|command| command.argv().program().as_str() == "/opt/node24/bin/node")
        .map(|command| {
            command.argv().arguments()[0]
                .rsplit('/')
                .next()
                .expect("entry name")
                .to_owned()
        })
        .collect::<Vec<_>>();
    assert_eq!(entries, ["main.js", "post.js"]);
    drop(state);
    let diagnostics = fixture
        .events
        .logs()
        .into_iter()
        .filter(|event| event.channel() == LogChannel::System)
        .flat_map(|event| event.payload().to_vec())
        .collect::<Vec<_>>();
    assert_eq!(
        String::from_utf8(diagnostics).expect("UTF-8 diagnostics"),
        "Pre entrypoints are unsupported for local actions\n"
    );
}

#[tokio::test]
async fn checked_out_local_action_with_unprovided_runtime_fails_before_action_code() {
    let fixture = Fixture::new(Vec::new(), Vec::new());
    fixture
        .endpoint_state
        .lock()
        .expect("endpoint lock")
        .files
        .insert(
            "/__w/automata/automata/actions/legacy/action.yml".to_owned(),
            b"runs:\n  using: node20\n  main: dist/index.js\n".to_vec(),
        );
    let request = fixture.request(envelope(vec![local_action_step(
        "legacy",
        "./actions/legacy",
    )]));
    let events: Arc<dyn ExecutionEvents> = fixture.events.clone();

    let result = fixture
        .executor
        .execute(request, events, ExecutionCancellation::new())
        .await
        .expect("local runtime rejection is a terminal action failure");

    assert_eq!(result.conclusion(), JobConclusion::Failure);
    let state = fixture.endpoint_state.lock().expect("endpoint lock");
    assert!(state.commands.iter().all(|command| {
        !matches!(
            command.argv().program().as_str(),
            "/opt/node12/bin/node" | "/opt/node16/bin/node" | "/opt/node20/bin/node"
        )
    }));
    drop(state);
    let diagnostics = fixture
        .events
        .logs()
        .into_iter()
        .filter(|event| event.channel() == LogChannel::System)
        .flat_map(|event| event.payload().to_vec())
        .collect::<Vec<_>>();
    assert_eq!(
        String::from_utf8(diagnostics).expect("UTF-8 diagnostics"),
        "Action preparation failed (RuntimeUnavailable)\n"
    );
}

#[tokio::test]
async fn a_pre_that_ran_registers_post_even_when_main_is_skipped() {
    let fixture = Fixture::new(
        vec![prepared_node24_action_with_pre()],
        vec![PhaseResponse::success(), PhaseResponse::success()],
    );
    let never = GithubConditionCompiler::default()
        .compile_condition(Some("false"), GithubConditionPhase::Step)
        .expect("valid false condition");
    let request = fixture.request(envelope(vec![
        action_step("lifecycle", "owner/lifecycle").with_condition(never),
    ]));
    let events: Arc<dyn ExecutionEvents> = fixture.events.clone();

    let result = fixture
        .executor
        .execute(request, events, ExecutionCancellation::new())
        .await
        .expect("skipped action lifecycle executes");

    assert_eq!(result.conclusion(), JobConclusion::Success);
    assert_eq!(result.steps()[0].conclusion(), JobConclusion::Skipped);
    let state = fixture.endpoint_state.lock().expect("endpoint lock");
    let entries = state
        .commands
        .iter()
        .filter(|command| command.argv().program().as_str() == "/opt/node24/bin/node")
        .map(|command| {
            command.argv().arguments()[0]
                .rsplit('/')
                .next()
                .expect("entry name")
                .to_owned()
        })
        .collect::<Vec<_>>();
    assert_eq!(entries, ["pre.js", "post.js"]);
}

#[tokio::test]
async fn a_false_pre_condition_is_not_retried_inline_with_main() {
    let fixture = Fixture::new(
        vec![prepared_node24_action_with_pre_condition("false")],
        vec![PhaseResponse::success(), PhaseResponse::success()],
    );
    let request = fixture.request(envelope(vec![action_step("lifecycle", "owner/lifecycle")]));
    let events: Arc<dyn ExecutionEvents> = fixture.events.clone();

    let result = fixture
        .executor
        .execute(request, events, ExecutionCancellation::new())
        .await
        .expect("main and post execute without a skipped pre");

    assert_eq!(result.conclusion(), JobConclusion::Success);
    let state = fixture.endpoint_state.lock().expect("endpoint lock");
    let entries = state
        .commands
        .iter()
        .filter(|command| command.argv().program().as_str() == "/opt/node24/bin/node")
        .map(|command| {
            command.argv().arguments()[0]
                .rsplit('/')
                .next()
                .expect("entry name")
                .to_owned()
        })
        .collect::<Vec<_>>();
    assert_eq!(entries, ["main.js", "post.js"]);
}

#[tokio::test]
async fn the_complete_repository_action_set_is_prepared_before_any_user_code() {
    let fixture = Fixture::new(
        vec![prepared_node24_action_with_pre()],
        vec![PhaseResponse::success()],
    );
    let never = GithubConditionCompiler::default()
        .compile_condition(Some("false"), GithubConditionPhase::Step)
        .expect("valid false condition");
    let request = fixture.request(envelope(vec![
        action_step("ready", "owner/ready"),
        action_step("missing", "owner/missing").with_condition(never),
    ]));
    let events: Arc<dyn ExecutionEvents> = fixture.events.clone();

    let result = fixture
        .executor
        .execute(request, events, ExecutionCancellation::new())
        .await
        .expect("preparation failure is a terminal job result");

    assert_eq!(result.conclusion(), JobConclusion::Failure);
    let state = fixture.endpoint_state.lock().expect("endpoint lock");
    assert!(
        state.commands.iter().all(|command| {
            !matches!(
                command.argv().program().as_str(),
                "/opt/node24/bin/node" | "/usr/bin/bash"
            )
        }),
        "neither an earlier pre nor a conditionally skipped missing action may run"
    );
    drop(state);
    let diagnostics = fixture
        .events
        .logs()
        .into_iter()
        .filter(|event| event.channel() == LogChannel::System)
        .flat_map(|event| event.payload().to_vec())
        .collect::<Vec<_>>();
    assert_eq!(
        String::from_utf8(diagnostics).expect("UTF-8 diagnostics"),
        "Action preparation failed (Resolution)\n"
    );
}

#[tokio::test]
async fn tokenless_pre_cancellation_suppresses_every_main_step() {
    let fixture = Fixture::new(
        vec![prepared_node24_action_with_pre()],
        vec![PhaseResponse::success().cancelled()],
    );
    let always = GithubConditionCompiler::default()
        .compile_condition(Some("always()"), GithubConditionPhase::Step)
        .expect("valid always condition");
    let request = fixture.request(envelope(vec![
        action_step("lifecycle", "owner/lifecycle"),
        run_step("must-not-run", "Must not run", "true").with_condition(always),
    ]));
    let events: Arc<dyn ExecutionEvents> = fixture.events.clone();

    let result = fixture
        .executor
        .execute(request, events, ExecutionCancellation::new())
        .await
        .expect("pre cancellation is terminal");

    assert_eq!(result.conclusion(), JobConclusion::Cancelled);
    let state = fixture.endpoint_state.lock().expect("endpoint lock");
    assert_eq!(
        state
            .commands
            .iter()
            .filter(|command| command.argv().program().as_str() == "/opt/node24/bin/node")
            .count(),
        1
    );
    assert!(
        state
            .commands
            .iter()
            .all(|command| command.argv().program().as_str() != "/usr/bin/bash")
    );
}

#[tokio::test]
async fn pre_outputs_cannot_escape_through_a_user_chosen_internal_looking_id() {
    let fixture = Fixture::new(
        vec![prepared_node24_action_with_pre()],
        vec![
            PhaseResponse::success()
                .with_file(CommandFileKind::Output, b"pre=private-phase\n".to_vec()),
            PhaseResponse::success(),
            PhaseResponse::success(),
        ],
    );
    let compiler = GithubConditionCompiler::default();
    let never = compiler
        .compile_condition(Some("false"), GithubConditionPhase::Step)
        .expect("valid false condition");
    let no_pre_output = compiler
        .compile_condition(
            Some("steps.__automata_pre_0.outputs.pre == ''"),
            GithubConditionPhase::Step,
        )
        .expect("valid output condition");
    let request = fixture.request(envelope(vec![
        action_step("__automata_pre_0", "owner/lifecycle").with_condition(never),
        run_step("observe", "Observe", "true").with_condition(no_pre_output),
    ]));
    let events: Arc<dyn ExecutionEvents> = fixture.events.clone();

    let result = fixture
        .executor
        .execute(request, events, ExecutionCancellation::new())
        .await
        .expect("pre output remains phase-private");

    assert_eq!(result.conclusion(), JobConclusion::Success);
    assert_eq!(result.steps()[0].conclusion(), JobConclusion::Skipped);
    assert_eq!(result.steps()[1].conclusion(), JobConclusion::Success);
}
