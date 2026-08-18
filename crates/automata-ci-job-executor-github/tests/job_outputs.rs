mod support;

use std::{
    collections::BTreeMap,
    sync::{Arc, atomic::Ordering},
};

use automata_ci_core::{
    JobConclusion, JobIrEnvelope, JobOutputDefinition, JobPermissionRequest, JobSecretExposure,
    OutputSensitivity, ValueSource, ValueTemplate,
};
use automata_ci_github_runtime::CommandFileKind;
use automata_ci_runner_runtime::{ExecutionCancellation, ExecutionEvents, JobExecutor};
use automata_ci_workflow_actions::{GithubConditionCompiler, GithubConditionPhase};

use support::{
    CONTEXT_SECRET, FinalContextCancellationPoint, Fixture, PhaseResponse, SECRET,
    envelope_with_output_definitions, run_step, untrusted_fork_snapshot,
};

fn step_output_definition(name: &str, step_id: &str, output_name: &str) -> JobOutputDefinition {
    let expression = GithubConditionCompiler::default()
        .compile_value_expression(
            &format!("${{{{ steps.{step_id}.outputs.{output_name} }}}}"),
            GithubConditionPhase::Step,
        )
        .expect("valid step-output expression");
    JobOutputDefinition::new(
        name,
        ValueTemplate::expression(expression).expect("output template"),
        OutputSensitivity::Public,
    )
    .expect("output definition")
}

fn github_token_output_definition() -> JobOutputDefinition {
    github_token_output_definition_named("token")
}

fn github_token_output_definition_named(name: &str) -> JobOutputDefinition {
    let expression = GithubConditionCompiler::default()
        .compile_value_expression("${{ github.token }}", GithubConditionPhase::Step)
        .expect("valid GitHub-token expression");
    JobOutputDefinition::new(
        name,
        ValueTemplate::expression(expression).expect("output template"),
        OutputSensitivity::Public,
    )
    .expect("output definition")
}

#[tokio::test]
async fn public_job_output_is_evaluated_after_steps_and_published() {
    let fixture = Fixture::secretless(
        Vec::new(),
        vec![
            PhaseResponse::success()
                .with_file(CommandFileKind::Output, b"artifact=bundle-42\n".to_vec()),
        ],
    );
    let job = envelope_with_output_definitions(
        vec![run_step("producer", "Producer", "true")],
        vec![step_output_definition("artifact", "producer", "artifact")],
    );
    let events: Arc<dyn ExecutionEvents> = fixture.events.clone();

    let result = fixture
        .executor
        .execute(fixture.request(job), events, ExecutionCancellation::new())
        .await
        .expect("job executes");

    assert_eq!(result.conclusion(), JobConclusion::Success);
    assert_eq!(result.secret_exposure(), JobSecretExposure::Secretless);
    let output = result.outputs().get("artifact").expect("published output");
    assert_eq!(output.sensitivity(), OutputSensitivity::Public);
    assert_eq!(output.public_value(), Some("bundle-42"));
}

#[tokio::test]
async fn untrusted_fork_output_is_persisted_only_as_a_classification_marker() {
    let fixture = Fixture::secretless(
        Vec::new(),
        vec![
            PhaseResponse::success()
                .with_file(CommandFileKind::Output, b"artifact=bundle-42\n".to_vec()),
        ],
    );
    let trusted = envelope_with_output_definitions(
        vec![run_step("producer", "Producer", "true")],
        vec![step_output_definition("artifact", "producer", "artifact")],
    );
    let job = JobIrEnvelope::new(
        trusted.workflow_id(),
        trusted.source().clone(),
        trusted.execution().clone(),
        trusted
            .job()
            .clone()
            .with_permission_request(JobPermissionRequest::ReadAll)
            .with_trust_snapshot(untrusted_fork_snapshot()),
    );
    let events: Arc<dyn ExecutionEvents> = fixture.events.clone();

    let result = fixture
        .executor
        .execute(fixture.request(job), events, ExecutionCancellation::new())
        .await
        .expect("untrusted job executes without publishing plaintext outputs");

    assert_eq!(result.conclusion(), JobConclusion::Success);
    let output = result.outputs().get("artifact").expect("classified output");
    assert_eq!(output.sensitivity(), OutputSensitivity::SecretDerived);
    assert_eq!(output.public_value(), None);
    assert!(
        !serde_json::to_string(&result)
            .expect("serialize result")
            .contains("bundle-42")
    );
}

#[tokio::test]
async fn output_matching_a_runtime_secret_is_persisted_only_as_a_classification_marker() {
    let step = run_step("producer", "Producer", "true").with_environment(BTreeMap::from([(
        "TOKEN".to_owned(),
        ValueSource::SecretReference("test-token".to_owned()),
    )]));
    let fixture = Fixture::new(
        Vec::new(),
        vec![PhaseResponse::success().with_file(
            CommandFileKind::Output,
            format!("token={SECRET}\n").into_bytes(),
        )],
    );
    let job = envelope_with_output_definitions(
        vec![step],
        vec![step_output_definition("token", "producer", "token")],
    );
    let events: Arc<dyn ExecutionEvents> = fixture.events.clone();

    let result = fixture
        .executor
        .execute(fixture.request(job), events, ExecutionCancellation::new())
        .await
        .expect("job executes");

    assert_eq!(result.conclusion(), JobConclusion::Success);
    assert_eq!(result.secret_exposure(), JobSecretExposure::ReadableSecret);
    let output = result.outputs().get("token").expect("classified output");
    assert_eq!(output.sensitivity(), OutputSensitivity::SecretDerived);
    assert_eq!(output.public_value(), None);
    assert!(!format!("{result:?}").contains(SECRET));
}

#[tokio::test]
async fn readable_secret_exposure_does_not_taint_an_unrelated_public_output() {
    let step = run_step("producer", "Producer", "true").with_environment(BTreeMap::from([(
        "TOKEN".to_owned(),
        ValueSource::SecretReference("test-token".to_owned()),
    )]));
    let public_value = "bundle-42";
    let fixture = Fixture::new(
        Vec::new(),
        vec![PhaseResponse::success().with_file(
            CommandFileKind::Output,
            format!("digest={public_value}\n").into_bytes(),
        )],
    );
    let job = envelope_with_output_definitions(
        vec![step],
        vec![step_output_definition("digest", "producer", "digest")],
    );
    let events: Arc<dyn ExecutionEvents> = fixture.events.clone();

    let result = fixture
        .executor
        .execute(fixture.request(job), events, ExecutionCancellation::new())
        .await
        .expect("job executes");

    assert_eq!(result.secret_exposure(), JobSecretExposure::ReadableSecret);
    let output = result.outputs().get("digest").expect("classified output");
    assert_eq!(output.sensitivity(), OutputSensitivity::Public);
    assert_eq!(output.public_value(), Some(public_value));
    assert!(
        serde_json::to_string(&result)
            .expect("serialize result")
            .contains(public_value)
    );
}

#[tokio::test]
async fn runtime_credentials_are_masked_without_hiding_logs_or_public_outputs() {
    let fixture = Fixture::new(
        Vec::new(),
        vec![
            PhaseResponse::success()
                .with_stdout(format!("ordinary {CONTEXT_SECRET} diagnostic\n"))
                .with_file(CommandFileKind::Output, b"artifact=bundle-42\n".to_vec()),
        ],
    );
    let job = envelope_with_output_definitions(
        vec![run_step("producer", "Producer", "true")],
        vec![step_output_definition("artifact", "producer", "artifact")],
    );
    let events: Arc<dyn ExecutionEvents> = fixture.events.clone();

    let result = fixture
        .executor
        .execute(fixture.request(job), events, ExecutionCancellation::new())
        .await
        .expect("job executes");

    assert_eq!(result.secret_exposure(), JobSecretExposure::ReadableSecret);
    let output = result.outputs().get("artifact").expect("public output");
    assert_eq!(output.sensitivity(), OutputSensitivity::Public);
    assert_eq!(output.public_value(), Some("bundle-42"));

    let logs = fixture.events.logs();
    assert_eq!(logs.len(), 1);
    assert_eq!(logs[0].payload(), b"ordinary *** diagnostic\n");
    assert!(
        !logs[0]
            .payload()
            .windows(CONTEXT_SECRET.len())
            .any(|window| window == CONTEXT_SECRET.as_bytes())
    );
}

#[tokio::test]
async fn empty_and_missing_job_outputs_are_omitted() {
    let fixture = Fixture::new(Vec::new(), vec![PhaseResponse::success()]);
    let job = envelope_with_output_definitions(
        vec![run_step("producer", "Producer", "true")],
        vec![
            step_output_definition("missing", "producer", "missing"),
            JobOutputDefinition::new(
                "empty",
                ValueTemplate::literal("").expect("empty template"),
                OutputSensitivity::Public,
            )
            .expect("output definition"),
        ],
    );
    let events: Arc<dyn ExecutionEvents> = fixture.events.clone();

    let result = fixture
        .executor
        .execute(fixture.request(job), events, ExecutionCancellation::new())
        .await
        .expect("job executes");

    assert_eq!(result.conclusion(), JobConclusion::Success);
    assert!(result.outputs().is_empty());
}

#[tokio::test]
async fn cancellation_returned_with_final_context_prevents_secret_registration_and_outputs() {
    let cancellation = ExecutionCancellation::new();
    let fixture = Fixture::with_final_context_cancellation(
        vec![PhaseResponse::success()],
        cancellation.clone(),
        FinalContextCancellationPoint::BeforeReturn,
    );
    let job = envelope_with_output_definitions(
        vec![run_step("producer", "Producer", "true")],
        vec![github_token_output_definition()],
    );
    let events: Arc<dyn ExecutionEvents> = fixture.events.clone();

    let result = fixture
        .executor
        .execute(fixture.request(job), events, cancellation.clone())
        .await
        .expect("final-context cancellation dominates output finalization");

    assert!(cancellation.is_cancelled());
    assert_eq!(result.conclusion(), JobConclusion::Cancelled);
    assert_eq!(result.secret_exposure(), JobSecretExposure::Secretless);
    assert!(result.outputs().is_empty());
    assert!(!format!("{result:?}").contains(CONTEXT_SECRET));
}

#[tokio::test]
async fn cancellation_dominates_a_simultaneous_final_context_error() {
    let cancellation = ExecutionCancellation::new();
    let fixture = Fixture::with_final_context_cancellation(
        vec![PhaseResponse::success()],
        cancellation.clone(),
        FinalContextCancellationPoint::BeforeError,
    );
    let job = envelope_with_output_definitions(
        vec![run_step("producer", "Producer", "true")],
        vec![github_token_output_definition()],
    );
    let events: Arc<dyn ExecutionEvents> = fixture.events.clone();

    let result = fixture
        .executor
        .execute(fixture.request(job), events, cancellation.clone())
        .await
        .expect("cancellation must not escape as a final-context adapter error");

    assert!(cancellation.is_cancelled());
    assert_eq!(result.conclusion(), JobConclusion::Cancelled);
    assert_eq!(result.secret_exposure(), JobSecretExposure::Secretless);
    assert!(result.outputs().is_empty());
}

#[tokio::test]
async fn cancellation_dominates_a_simultaneous_main_context_error() {
    let cancellation = ExecutionCancellation::new();
    let fixture = Fixture::with_main_context_error_cancellation(Vec::new(), cancellation.clone());
    let job = envelope_with_output_definitions(
        vec![run_step("producer", "Producer", "true")],
        vec![github_token_output_definition()],
    );
    let events: Arc<dyn ExecutionEvents> = fixture.events.clone();

    let result = fixture
        .executor
        .execute(fixture.request(job), events, cancellation.clone())
        .await
        .expect("main-context cancellation dominates its simultaneous adapter error");

    assert!(cancellation.is_cancelled());
    assert_eq!(result.conclusion(), JobConclusion::Cancelled);
    assert_eq!(result.secret_exposure(), JobSecretExposure::Secretless);
    assert!(result.steps().is_empty());
    assert!(result.outputs().is_empty());
    let state = fixture.endpoint_state.lock().expect("endpoint lock");
    assert!(
        state
            .commands
            .iter()
            .all(|command| command.argv().program().as_str() != "/usr/bin/bash"),
        "main user code must not start after the cancelled context boundary"
    );
}

#[tokio::test]
async fn cancellation_dominates_a_simultaneous_main_evaluator_error() {
    let cancellation = ExecutionCancellation::new();
    let fixture = Fixture::with_main_evaluation_cancellation(Vec::new(), cancellation.clone());
    let condition = GithubConditionCompiler::default()
        .compile_condition(
            Some("hashFiles('**/*.rs') != ''"),
            GithubConditionPhase::Step,
        )
        .expect("step-only extension expression compiles");
    let step = run_step("producer", "Producer", "true").with_condition(condition);
    let job = envelope_with_output_definitions(vec![step], vec![github_token_output_definition()]);
    let events: Arc<dyn ExecutionEvents> = fixture.events.clone();

    let result = fixture
        .executor
        .execute(fixture.request(job), events, cancellation.clone())
        .await
        .expect("main evaluator cancellation dominates its simultaneous extension error");

    assert!(cancellation.is_cancelled());
    assert_eq!(result.conclusion(), JobConclusion::Cancelled);
    assert!(result.steps().is_empty());
    assert!(result.outputs().is_empty());
}

#[tokio::test]
async fn tokenless_cancelled_step_stops_later_steps_and_suppresses_job_outputs() {
    let final_context_probe = ExecutionCancellation::new();
    let fixture = Fixture::with_final_context_cancellation(
        vec![
            PhaseResponse::success().cancelled(),
            PhaseResponse::success(),
        ],
        final_context_probe.clone(),
        FinalContextCancellationPoint::BeforeError,
    );
    let output = JobOutputDefinition::new(
        "must_not_publish",
        ValueTemplate::literal("cancelled-output").expect("literal output template"),
        OutputSensitivity::Public,
    )
    .expect("job output definition");
    let job = envelope_with_output_definitions(
        vec![
            run_step("cancelled", "Cancelled", "first"),
            run_step("later", "Later", "second"),
        ],
        vec![output],
    );
    let events: Arc<dyn ExecutionEvents> = fixture.events.clone();

    let result = fixture
        .executor
        .execute(fixture.request(job), events, ExecutionCancellation::new())
        .await
        .expect("a tokenless cancelled phase remains a terminal result");

    assert_eq!(result.conclusion(), JobConclusion::Cancelled);
    assert_eq!(result.steps().len(), 1);
    assert_eq!(result.steps()[0].conclusion(), JobConclusion::Cancelled);
    assert!(result.outputs().is_empty());
    assert!(
        !final_context_probe.is_cancelled(),
        "effective cancellation must suppress final context and output evaluation entirely"
    );
    let state = fixture.endpoint_state.lock().expect("endpoint lock");
    assert_eq!(
        state
            .commands
            .iter()
            .filter(|command| command.argv().program().as_str() == "/usr/bin/bash")
            .count(),
        1,
        "the tokenless cancelled outcome must stop the later user step"
    );
}

#[tokio::test]
async fn cancellation_during_output_evaluation_discards_the_evaluated_secret_output() {
    let cancellation = ExecutionCancellation::new();
    let fixture = Fixture::with_final_context_cancellation(
        vec![PhaseResponse::success()],
        cancellation.clone(),
        FinalContextCancellationPoint::DuringOutputEvaluation,
    );
    let job = envelope_with_output_definitions(
        vec![run_step("producer", "Producer", "true")],
        vec![github_token_output_definition()],
    );
    let events: Arc<dyn ExecutionEvents> = fixture.events.clone();

    let result = fixture
        .executor
        .execute(fixture.request(job), events, cancellation.clone())
        .await
        .expect("output-evaluation cancellation remains a terminal result");

    assert!(cancellation.is_cancelled());
    assert_eq!(result.conclusion(), JobConclusion::Cancelled);
    assert_eq!(result.secret_exposure(), JobSecretExposure::ReadableSecret);
    assert!(result.outputs().is_empty());
    assert!(!format!("{result:?}").contains(CONTEXT_SECRET));
}

#[tokio::test]
async fn cancellation_between_output_definitions_prevents_the_next_secret_access() {
    let cancellation = ExecutionCancellation::new();
    let (fixture, evaluation_calls) = Fixture::with_counted_output_cancellation(
        vec![PhaseResponse::success()],
        cancellation.clone(),
    );
    let job = envelope_with_output_definitions(
        vec![run_step("producer", "Producer", "true")],
        vec![
            github_token_output_definition_named("first"),
            github_token_output_definition_named("second"),
        ],
    );
    let events: Arc<dyn ExecutionEvents> = fixture.events.clone();

    let result = fixture
        .executor
        .execute(fixture.request(job), events, cancellation.clone())
        .await
        .expect("cancellation between outputs remains a terminal result");

    assert!(cancellation.is_cancelled());
    assert_eq!(result.conclusion(), JobConclusion::Cancelled);
    assert!(result.outputs().is_empty());
    assert_eq!(
        evaluation_calls.load(Ordering::SeqCst),
        1,
        "the second output must not invoke its context secret accessor"
    );
}
