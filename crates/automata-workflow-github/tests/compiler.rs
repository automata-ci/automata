mod support;

use std::{fmt::Write as _, sync::Arc};

use automata_core::{
    DeferredBoolean, ExpressionSegment, PlanSourceOrigin, PlanValue, PlannedStepKind, QueuePolicy,
    WorkflowEventProvenance, WorkflowJobKey, WorkflowPlan, WorkflowPlanVersion,
};
use automata_workflow_github::{
    CompileWorkflowRequest, DiagnosticKind, GithubWorkflowCompiler, SourceId, SourceOrigin,
    SourceProvenance,
};

const REPOSITORY_CI: &str = include_str!("../../../.github/workflows/ci.yml");
const CI_GOLDEN: &str = include_str!("fixtures/ci-workflow-plan-v1.golden");

fn compile(source: &str, event_name: &str) -> automata_workflow_github::CompilationReport {
    let parsed = support::parse(source);
    let source_plan = parsed.plan().expect("source plan should be retained");
    GithubWorkflowCompiler::new().compile(CompileWorkflowRequest::new(
        source_plan,
        WorkflowEventProvenance::new("github", event_name)
            .with_delivery_id("delivery-42")
            .with_commit_sha("0123456789abcdef")
            .with_git_ref("refs/heads/main"),
    ))
}

fn compile_repository_ci() -> automata_workflow_github::CompilationReport {
    let frontend = automata_workflow_github::GithubWorkflowFrontend::default();
    let provenance = SourceProvenance::new(
        SourceId::new(".github/workflows/ci.yml"),
        SourceOrigin::Repository {
            repository: Arc::from("GoNeuralAI/automata"),
            revision: Arc::from("0123456789abcdef"),
            path: Arc::from(".github/workflows/ci.yml"),
        },
    );
    let parsed = automata_workflow_github::WorkflowFrontend::parse(
        &frontend,
        automata_workflow_github::ParseWorkflowRequest::new(provenance, REPOSITORY_CI),
    );
    assert!(
        parsed.is_accepted(),
        "source diagnostics: {:#?}",
        parsed.diagnostics()
    );
    GithubWorkflowCompiler::new().compile(CompileWorkflowRequest::new(
        parsed.plan().expect("source plan"),
        WorkflowEventProvenance::new("github", "push")
            .with_delivery_id("delivery-42")
            .with_commit_sha("0123456789abcdef")
            .with_git_ref("refs/heads/main"),
    ))
}

#[test]
fn repository_ci_compiles_to_the_exact_v1_plan_golden() {
    let report = compile_repository_ci();
    assert!(
        report.is_accepted(),
        "compile diagnostics: {:#?}",
        report.diagnostics()
    );
    let plan = report.plan().expect("compiled plan");
    plan.validate().expect("valid workflow plan");

    let golden = render_plan_golden(plan);
    assert_eq!(golden, CI_GOLDEN);
    let encoded = serde_json::to_string(plan).expect("serialize plan");
    let decoded: WorkflowPlan = serde_json::from_str(&encoded).expect("deserialize plan");
    decoded.validate().expect("deserialized plan is valid");
    assert_eq!(decoded, *plan);
}

fn render_plan_golden(plan: &WorkflowPlan) -> String {
    let mut output = String::new();
    writeln!(output, "workflow-plan-v{}", plan.version().get()).expect("write string");
    writeln!(
        output,
        "source={}",
        serde_json::to_string(plan.source()).expect("serialize source")
    )
    .expect("write string");
    writeln!(
        output,
        "event={}",
        serde_json::to_string(plan.event()).expect("serialize event")
    )
    .expect("write string");
    writeln!(
        output,
        "name={}",
        plan.name().map_or("", |name| name.value())
    )
    .expect("write string");
    writeln!(
        output,
        "workflow-env={}",
        render_environment(plan.environment())
    )
    .expect("write string");
    writeln!(
        output,
        "workflow-defaults=shell:{} wd:{}",
        source_or_dash(plan.run_defaults().shell()),
        source_or_dash(plan.run_defaults().working_directory())
    )
    .expect("write string");
    let concurrency = plan.concurrency().expect("concurrency");
    writeln!(
        output,
        "concurrency={} segments={} cancel={:?} queue={:?}",
        json_string(concurrency.group().value().source()),
        serde_json::to_string(concurrency.group().value().segments()).expect("segments"),
        concurrency
            .cancel_in_progress()
            .map(automata_core::Located::value),
        concurrency.queue()
    )
    .expect("write string");

    for job in plan.jobs() {
        render_job_golden(&mut output, job);
    }
    output
}

fn render_job_golden(output: &mut String, job: &automata_core::PlannedJob) {
    writeln!(
        output,
        "job={} name={} needs={} runner-group={} runner-labels={} timeout={:?} defaults=shell:{} wd:{} env={} span={}",
        job.key().value(),
        json_string(job.name().map_or("", |name| name.value())),
        job.needs()
            .iter()
            .map(|need| need.value().as_str())
            .collect::<Vec<_>>()
            .join(","),
        job.runner()
            .group()
            .map_or_else(|| "-".to_owned(), |value| json_string(value.value().source())),
        job.runner()
            .labels()
            .iter()
            .map(|value| json_string(value.value().source()))
            .collect::<Vec<_>>()
            .join(","),
        job.timeout_seconds(),
        source_or_dash(job.run_defaults().shell()),
        source_or_dash(job.run_defaults().working_directory()),
        render_environment(job.environment()),
        render_span(job.span()),
    )
    .expect("write string");
    for step in job.steps() {
        let execution = match step.execution() {
            PlannedStepKind::Run(run) => format!(
                "run:script={} shell={} wd={}",
                json_string(run.script().value().source()),
                source_or_dash(run.shell()),
                source_or_dash(run.working_directory())
            ),
            PlannedStepKind::Uses(uses) => format!(
                "uses:ref={} inputs={} ref-span={}",
                json_string(uses.reference().value()),
                render_environment(uses.inputs()),
                render_span(uses.reference().span())
            ),
        };
        writeln!(
            output,
            "  step={} id={} name={} timeout={:?} env={} {} span={}",
            step.key(),
            step.id().map_or("-", |id| id.value()),
            json_string(step.name().map_or("", |name| name.value())),
            step.timeout_seconds(),
            render_environment(step.environment()),
            execution,
            render_span(step.span()),
        )
        .expect("write string");
    }
}

fn render_environment(environment: &automata_core::EnvironmentPlan) -> String {
    environment
        .entries()
        .iter()
        .map(|(key, value)| {
            format!(
                "{}={}",
                json_string(key.value()),
                json_string(value.value().source())
            )
        })
        .collect::<Vec<_>>()
        .join(",")
}

fn source_or_dash(value: Option<&automata_core::Located<PlanValue>>) -> String {
    value.map_or_else(
        || "-".to_owned(),
        |value| json_string(value.value().source()),
    )
}

fn json_string(value: &str) -> String {
    serde_json::to_string(value).expect("serialize string")
}

fn render_span(span: &automata_core::PlanSourceSpan) -> String {
    format!(
        "{}:{}-{}:{}",
        span.start().line(),
        span.start().column(),
        span.end().line(),
        span.end().column()
    )
}

#[test]
fn repository_ci_preserves_source_event_dag_runner_and_defaults() {
    let report = compile_repository_ci();
    let plan = report.plan().expect("compiled plan");

    assert_eq!(plan.version(), WorkflowPlanVersion::current());
    assert_eq!(plan.event().name(), "push");
    assert_eq!(plan.event().delivery_id(), Some("delivery-42"));
    assert_eq!(
        plan.event()
            .configured_trigger_span()
            .expect("selected trigger")
            .start()
            .line(),
        4
    );
    assert!(matches!(
        plan.source().origin(),
        PlanSourceOrigin::Repository {
            repository,
            revision,
            path,
        } if repository == "GoNeuralAI/automata"
            && revision == "0123456789abcdef"
            && path == ".github/workflows/ci.yml"
    ));
    assert_eq!(
        plan.jobs()
            .iter()
            .map(|job| job.key().value().as_str())
            .collect::<Vec<_>>(),
        ["verify", "frontend", "dist"]
    );

    let verify = plan
        .job(&WorkflowJobKey::new("verify").expect("key"))
        .expect("verify");
    assert!(verify.needs().is_empty());
    assert_eq!(verify.timeout_seconds(), Some(30 * 60));
    assert!(matches!(
        verify.runner().labels()[0].value(),
        PlanValue::Literal(label) if label == "ubuntu-24.04"
    ));

    let frontend = plan
        .job(&WorkflowJobKey::new("frontend").expect("key"))
        .expect("frontend");
    assert_eq!(frontend.timeout_seconds(), Some(30 * 60));
    assert_eq!(
        frontend
            .run_defaults()
            .working_directory()
            .expect("job default")
            .value()
            .source(),
        "ui"
    );

    let dist = plan
        .job(&WorkflowJobKey::new("dist").expect("key"))
        .expect("dist");
    assert_eq!(dist.timeout_seconds(), Some(45 * 60));
    assert_eq!(
        dist.needs()
            .iter()
            .map(|need| need.value().as_str())
            .collect::<Vec<_>>(),
        ["verify", "frontend"]
    );
}

#[test]
fn repository_ci_preserves_unresolved_steps_expressions_and_environment() {
    let report = compile_repository_ci();
    let plan = report.plan().expect("compiled plan");
    let verify = plan
        .job(&WorkflowJobKey::new("verify").expect("key"))
        .expect("verify");
    assert_eq!(verify.steps()[0].key().as_str(), "position/00000000");
    let PlannedStepKind::Uses(checkout) = verify.steps()[0].execution() else {
        panic!("checkout must remain an unresolved uses step");
    };
    assert_eq!(
        checkout.reference().value(),
        "actions/checkout@de0fac2e4500dabe0009e67214ff5f5447ce83dd"
    );
    assert_eq!(
        checkout
            .inputs()
            .get("persist-credentials")
            .expect("input")
            .value()
            .source(),
        "false"
    );
    assert_eq!(checkout.reference().span().start().line(), 33);

    let concurrency = plan.concurrency().expect("workflow concurrency");
    assert_eq!(concurrency.queue(), QueuePolicy::Single);
    assert_eq!(
        concurrency.group().value().source(),
        "ci-${{ github.workflow }}-${{ github.ref }}"
    );
    assert_eq!(
        concurrency.group().value().segments(),
        [
            ExpressionSegment::Literal("ci-".to_owned()),
            ExpressionSegment::Evaluation("${{ github.workflow }}".to_owned()),
            ExpressionSegment::Literal("-".to_owned()),
            ExpressionSegment::Evaluation("${{ github.ref }}".to_owned()),
        ]
    );
    assert!(matches!(
        concurrency
            .cancel_in_progress()
            .expect("cancel policy")
            .value(),
        DeferredBoolean::Literal(true)
    ));
    assert!(matches!(
        plan.environment()
            .get("AUTOMATA_BUILD_GIT_SHA")
            .expect("workflow env")
            .value(),
        PlanValue::Expression(expression) if expression.source() == "${{ github.sha }}"
    ));
}

#[test]
fn environment_and_run_default_layers_remain_distinct() {
    let report = compile(include_str!("fixtures/compiler-layering.yml"), "push");
    assert!(
        report.is_accepted(),
        "diagnostics: {:#?}",
        report.diagnostics()
    );
    let plan = report.plan().expect("plan");
    let job = &plan.jobs()[0];
    let step = &job.steps()[0];

    assert_eq!(
        plan.environment()
            .get("SHARED")
            .expect("workflow layer")
            .value()
            .source(),
        "workflow"
    );
    assert_eq!(
        job.environment()
            .get("SHARED")
            .expect("job layer")
            .value()
            .source(),
        "job"
    );
    assert_eq!(
        step.environment()
            .get("SHARED")
            .expect("step layer")
            .value()
            .source(),
        "step"
    );
    assert_eq!(
        plan.run_defaults()
            .working_directory()
            .expect("workflow default")
            .value()
            .source(),
        "workflow-dir"
    );
    assert_eq!(
        job.run_defaults()
            .working_directory()
            .expect("job default")
            .value()
            .source(),
        "job-dir"
    );
    let PlannedStepKind::Run(run) = step.execution() else {
        panic!("run step");
    };
    assert_eq!(
        run.working_directory()
            .expect("step override")
            .value()
            .source(),
        "step-dir"
    );
    assert!(matches!(
        run.script().value(),
        PlanValue::Expression(expression)
            if expression.source() == "echo \"${{ env.SHARED }}\""
    ));
}

#[test]
fn expression_compiler_preserves_delimiters_inside_quoted_expression_strings() {
    let report = compile(
        "on: push\nenv:\n  QUOTED: \"${{ format('x}}y') }}\"\njobs:\n  build:\n    runs-on: linux\n    steps:\n      - run: echo ok\n",
        "push",
    );
    assert!(
        report.is_accepted(),
        "diagnostics: {:#?}",
        report.diagnostics()
    );
    let value = report
        .plan()
        .expect("plan")
        .environment()
        .get("QUOTED")
        .expect("value")
        .value();
    let PlanValue::Expression(expression) = value else {
        panic!("deferred expression");
    };
    assert_eq!(expression.source(), "${{ format('x}}y') }}");
    assert_eq!(
        expression.segments(),
        [ExpressionSegment::Evaluation(
            "${{ format('x}}y') }}".to_owned()
        )]
    );
}

#[test]
fn compiler_refuses_unknown_fields_instead_of_dropping_them() {
    let report = compile(include_str!("fixtures/unsupported-compiler.yml"), "push");
    assert!(report.plan().is_none());
    assert!(report.diagnostics().iter().any(|diagnostic| {
        diagnostic.kind() == DiagnosticKind::Unsupported
            && diagnostic.code() == "github.compile.unsupported_field"
            && diagnostic.message().contains("jobs.build.strategy")
    }));
}

#[test]
fn compiler_refuses_duplicate_keys_even_when_called_on_a_retained_source_plan() {
    let report = compile(include_str!("fixtures/duplicate.yml"), "push");
    assert!(report.plan().is_none());
    assert!(report.diagnostics().iter().any(|diagnostic| {
        diagnostic.code() == "github.compile.duplicate_mapping_key"
            && diagnostic.related().len() == 1
    }));
}

#[test]
fn compiler_refuses_invalid_graphs_dynamic_timeouts_and_expressions() {
    let cases = [
        (
            "on: push\njobs:\n  build:\n    needs: missing\n    runs-on: linux\n    steps:\n      - run: echo ok\n",
            "github.compile.invalid_workflow_plan",
        ),
        (
            "on: push\njobs:\n  build:\n    runs-on: linux\n    timeout-minutes: ${{ github.run_attempt }}\n    steps:\n      - run: echo ok\n",
            "github.compile.dynamic_timeout",
        ),
        (
            "on: push\nenv:\n  BROKEN: '${{ github.sha'\njobs:\n  build:\n    runs-on: linux\n    steps:\n      - run: echo ok\n",
            "github.compile.invalid_expression",
        ),
    ];
    for (source, code) in cases {
        let report = compile(source, "push");
        assert!(report.plan().is_none(), "{code} must suppress the plan");
        assert!(
            report
                .diagnostics()
                .iter()
                .any(|diagnostic| diagnostic.code() == code),
            "diagnostics for {code}: {:#?}",
            report.diagnostics()
        );
    }
}

#[test]
fn compiler_refuses_unconfigured_events_and_yaml_aliases() {
    let unconfigured = compile(
        "on: push\njobs:\n  build:\n    runs-on: linux\n    steps:\n      - run: echo ok\n",
        "pull_request",
    );
    assert!(unconfigured.plan().is_none());
    assert!(
        unconfigured
            .diagnostics()
            .iter()
            .any(|diagnostic| diagnostic.code() == "github.compile.event_not_configured")
    );

    let aliases = compile(include_str!("fixtures/aliases.yml"), "push");
    assert!(aliases.plan().is_none());
    assert!(aliases.diagnostics().iter().any(|diagnostic| {
        matches!(
            diagnostic.code(),
            "github.compile.yaml_anchor" | "github.compile.yaml_alias"
        )
    }));
}
