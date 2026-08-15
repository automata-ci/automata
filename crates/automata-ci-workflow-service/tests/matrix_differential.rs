use std::{collections::BTreeMap, sync::Arc};

use automata_ci_core::{
    CompiledValueTemplate, ContextValue, ExpressionContext, LogicalJobKind,
    WorkflowEventProvenance, WorkflowJobKey, WorkflowPlan,
};
use automata_ci_expression_github::{GithubObject, GithubValue};
use automata_ci_workflow_github::{
    CompilationReport, CompileWorkflowRequest, GithubEventMetadata, GithubFrontendReport,
    GithubWorkflowCompiler, GithubWorkflowDispatchInputs, GithubWorkflowFrontend,
    ParseWorkflowRequest, SourceId, SourceOrigin, SourceProvenance, WorkflowFrontend as _,
};
use automata_ci_workflow_service::{
    ActivateLogicalJobRequest, ActivationStatus, GithubActivationContext,
    GithubActivationEvaluationError, GithubLogicalActivationEvaluator, LogicalActivationError,
    LogicalJobActivation, LogicalJobActivator, ValidatedLogicalPlan,
};
use serde::Deserialize;

const REPOSITORY: &str = "automata-ci/matrix-differential";
const REVISION: &str = "0123456789abcdef0123456789abcdef01234567";
const STATIC_SOURCE: &str = include_str!("fixtures/matrix-differential-v1/static.yml");
const EXPRESSION_AXES_SOURCE: &str =
    include_str!("fixtures/matrix-differential-v1/expression-axes.yml");
const WHOLE_EXPRESSION_SOURCE: &str =
    include_str!("fixtures/matrix-differential-v1/whole-expression.yml");
const INCLUDE_ONLY_SOURCE: &str = include_str!("fixtures/matrix-differential-v1/include-only.yml");
const EMPTY_AXIS_SOURCE: &str = include_str!("fixtures/matrix-differential-v1/empty-axis.yml");
const EXPECTED: &str = include_str!("fixtures/matrix-differential-v1/expected.json");

const LIMIT_SOURCE: &str = r"name: Matrix expansion limit
on:
  workflow_dispatch:
    inputs:
      matrix:
        type: string
jobs:
  build:
    runs-on: ubuntu-latest
    strategy:
      matrix: ${{ fromJSON(inputs.matrix) }}
    steps:
      - run: echo bounded
";

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct FixtureExpectation {
    schema_version: u16,
    evidence_class: String,
    live_github_observation: Option<serde_json::Value>,
    equivalent_rows: Vec<EquivalentRow>,
    include_only_rows: Vec<IncludeOnlyRow>,
}

#[derive(Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
struct EquivalentRow {
    runtime: String,
    platform: String,
    experimental: bool,
    channel: String,
}

#[derive(Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
struct IncludeOnlyRow {
    target: String,
    ordinal: String,
}

fn provenance(path: &str) -> SourceProvenance {
    SourceProvenance::new(
        SourceId::new(path),
        SourceOrigin::Repository {
            repository: Arc::from(REPOSITORY),
            revision: Arc::from(REVISION),
            path: Arc::from(path),
        },
    )
}

fn parse(source: &str, path: &str) -> GithubFrontendReport {
    GithubWorkflowFrontend::default().parse(ParseWorkflowRequest::new(provenance(path), source))
}

fn compile_report(source: &str, path: &str) -> CompilationReport {
    let parsed = parse(source, path);
    assert!(parsed.is_accepted(), "{:#?}", parsed.diagnostics());
    let dispatch = GithubWorkflowDispatchInputs::try_new(std::iter::empty::<(&str, &str)>())
        .expect("empty dispatch evidence");
    GithubWorkflowCompiler::new().compile(
        CompileWorkflowRequest::new(
            parsed.plan().expect("source plan"),
            WorkflowEventProvenance::new("github", "workflow_dispatch")
                .with_delivery_id("matrix-differential")
                .with_commit_sha(REVISION)
                .with_git_ref("refs/heads/main"),
        )
        .with_event_metadata(GithubEventMetadata::workflow_dispatch(dispatch)),
    )
}

fn compile_plan(source: &str, path: &str) -> WorkflowPlan {
    let report = compile_report(source, path);
    assert!(report.is_accepted(), "{:#?}", report.diagnostics());
    report.into_parts().0.expect("logical plan")
}

fn github_context() -> GithubActivationContext {
    GithubActivationContext::new(GithubValue::object(
        GithubObject::new(vec![
            (
                "event_name".to_owned(),
                GithubValue::string("workflow_dispatch"),
            ),
            ("ref".to_owned(), GithubValue::string("refs/heads/main")),
            ("sha".to_owned(), GithubValue::string(REVISION)),
            ("repository".to_owned(), GithubValue::string(REPOSITORY)),
            (
                "event".to_owned(),
                GithubValue::object(GithubObject::new(Vec::new()).expect("event")),
            ),
        ])
        .expect("github object"),
    ))
    .expect("activation-safe github context")
}

fn activate(
    plan: &WorkflowPlan,
    inputs: &ContextValue,
) -> Result<LogicalJobActivation, LogicalActivationError<GithubActivationEvaluationError>> {
    let validated = ValidatedLogicalPlan::new(plan).expect("validated plan");
    let job = validated
        .job(&WorkflowJobKey::new("build").expect("job key"))
        .expect("validated job");
    LogicalJobActivator::new(GithubLogicalActivationEvaluator::new(github_context())).activate(
        ActivateLogicalJobRequest::new(
            job,
            inputs,
            &ContextValue::empty_object(),
            &BTreeMap::new(),
            &BTreeMap::new(),
            ActivationStatus::Success,
        ),
    )
}

fn string_inputs(entries: &[(&str, String)]) -> ContextValue {
    ContextValue::object(
        entries
            .iter()
            .map(|(key, value)| ((*key).to_owned(), ContextValue::string(value)))
            .collect(),
    )
    .expect("bounded inputs")
}

fn matrix_string<'a>(matrix: &'a ContextValue, key: &str) -> &'a str {
    matrix
        .as_object()
        .and_then(|matrix| matrix.get(key))
        .and_then(ContextValue::as_string)
        .unwrap_or_else(|| panic!("missing matrix string `{key}`"))
}

fn matrix_boolean(matrix: &ContextValue, key: &str) -> bool {
    matrix
        .as_object()
        .and_then(|matrix| matrix.get(key))
        .and_then(ContextValue::as_boolean)
        .unwrap_or_else(|| panic!("missing matrix Boolean `{key}`"))
}

fn equivalent_rows(activation: &LogicalJobActivation) -> Vec<EquivalentRow> {
    activation
        .instances()
        .iter()
        .map(|instance| {
            let matrix = instance.runtime_context().matrix();
            EquivalentRow {
                runtime: matrix_string(matrix, "runtime").to_owned(),
                platform: matrix_string(matrix, "platform").to_owned(),
                experimental: matrix_boolean(matrix, "experimental"),
                channel: matrix_string(matrix, "channel").to_owned(),
            }
        })
        .collect()
}

fn expression_axis_inputs() -> ContextValue {
    string_inputs(&[
        ("runtimes", r#"["stable","next"]"#.to_owned()),
        ("platforms", r#"["linux","windows"]"#.to_owned()),
        ("experimental", "[false]".to_owned()),
        (
            "excludes",
            r#"[{"runtime":"next","platform":"windows"}]"#.to_owned(),
        ),
        (
            "includes",
            r#"[{"channel":"general"},{"runtime":"stable","channel":"stable"},{"runtime":"edge","platform":"linux","experimental":true,"channel":"edge"}]"#
                .to_owned(),
        ),
    ])
}

fn whole_matrix_input() -> ContextValue {
    string_inputs(&[(
        "matrix",
        r#"{"runtime":["stable","next"],"platform":["linux","windows"],"experimental":[false],"exclude":[{"runtime":"next","platform":"windows"}],"include":[{"channel":"general"},{"runtime":"stable","channel":"stable"},{"runtime":"edge","platform":"linux","experimental":true,"channel":"edge"}]}"#
            .to_owned(),
    )])
}

#[test]
fn exact_candidate_fixtures_use_the_real_evaluator_and_preserve_equivalent_identity() {
    let expected: FixtureExpectation = serde_json::from_str(EXPECTED).expect("expectation");
    assert_eq!(expected.schema_version, 1);
    assert_eq!(expected.evidence_class, "candidate");
    assert!(expected.live_github_observation.is_none());

    let static_plan = compile_plan(STATIC_SOURCE, "matrix-differential-v1/static.yml");
    let axes_plan = compile_plan(
        EXPRESSION_AXES_SOURCE,
        "matrix-differential-v1/expression-axes.yml",
    );
    let whole_plan = compile_plan(
        WHOLE_EXPRESSION_SOURCE,
        "matrix-differential-v1/whole-expression.yml",
    );
    let static_activation =
        activate(&static_plan, &ContextValue::empty_object()).expect("static activation");
    let repeated =
        activate(&static_plan, &ContextValue::empty_object()).expect("repeated activation");
    let axes_activation =
        activate(&axes_plan, &expression_axis_inputs()).expect("expression-axis activation");
    let whole_activation =
        activate(&whole_plan, &whole_matrix_input()).expect("whole-expression activation");

    assert_eq!(static_activation, repeated);
    assert_eq!(
        equivalent_rows(&static_activation),
        expected.equivalent_rows
    );
    assert_eq!(equivalent_rows(&axes_activation), expected.equivalent_rows);
    assert_eq!(equivalent_rows(&whole_activation), expected.equivalent_rows);
    for (index, ((static_instance, axes_instance), whole_instance)) in static_activation
        .instances()
        .iter()
        .zip(axes_activation.instances())
        .zip(whole_activation.instances())
        .enumerate()
    {
        let expected_row = &expected.equivalent_rows[index];
        assert_eq!(static_instance.identity(), axes_instance.identity());
        assert_eq!(static_instance.identity(), whole_instance.identity());
        assert_eq!(
            static_instance.identity().matrix_digest(),
            axes_instance.identity().matrix_digest()
        );
        assert_eq!(
            static_instance.identity().matrix_digest(),
            whole_instance.identity().matrix_digest()
        );
        assert_eq!(
            static_instance.runtime_context().matrix(),
            axes_instance.runtime_context().matrix()
        );
        assert_eq!(
            static_instance.runtime_context().matrix(),
            whole_instance.runtime_context().matrix()
        );
        assert_eq!(static_instance.name(), axes_instance.name());
        assert_eq!(static_instance.name(), whole_instance.name());
        assert_eq!(
            static_instance.name(),
            format!("Matrix {}-{}", expected_row.runtime, expected_row.platform)
        );
        assert_eq!(
            static_instance.continue_on_error(),
            matrix_boolean(static_instance.runtime_context().matrix(), "experimental")
        );
    }

    let job = &static_plan.jobs()[0];
    assert!(matches!(
        job.environment()
            .get("MATRIX_RUNTIME")
            .map(automata_ci_core::Located::value),
        Some(CompiledValueTemplate::Expression(expression))
            if expression.contexts().contains(&ExpressionContext::Matrix)
    ));
    let LogicalJobKind::Steps(steps) = job.execution() else {
        panic!("step job")
    };
    assert!(
        steps.steps()[0]
            .condition()
            .expect("matrix-bound step condition")
            .value()
            .contexts()
            .contains(&ExpressionContext::Matrix)
    );
}

#[test]
fn include_only_duplicates_keep_source_positions_and_stable_digest_identity() {
    let expected: FixtureExpectation = serde_json::from_str(EXPECTED).expect("expectation");
    let plan = compile_plan(
        INCLUDE_ONLY_SOURCE,
        "matrix-differential-v1/include-only.yml",
    );
    let first = activate(&plan, &ContextValue::empty_object()).expect("include-only activation");
    let second = activate(&plan, &ContextValue::empty_object()).expect("include-only replay");
    assert_eq!(first, second);
    assert_eq!(first.instances().len(), 3);
    let actual = first
        .instances()
        .iter()
        .map(|instance| IncludeOnlyRow {
            target: matrix_string(instance.runtime_context().matrix(), "target").to_owned(),
            ordinal: matrix_string(instance.runtime_context().matrix(), "ordinal").to_owned(),
        })
        .collect::<Vec<_>>();
    assert_eq!(actual, expected.include_only_rows);
    assert_eq!(
        first.instances()[0].identity().matrix_digest(),
        first.instances()[1].identity().matrix_digest(),
        "equal rows intentionally have equal value digests"
    );
    assert_ne!(
        first.instances()[0].identity(),
        first.instances()[1].identity(),
        "the zero-based index keeps duplicate rows independently addressable"
    );
    for (index, instance) in first.instances().iter().enumerate() {
        assert_eq!(
            instance.identity().matrix_index(),
            u32::try_from(index).expect("bounded fixture index")
        );
        assert_eq!(instance.identity().matrix_total(), 3);
    }
}

#[test]
fn empty_axes_and_the_257th_cartesian_cell_fail_before_any_activation_is_returned() {
    let report = parse(EMPTY_AXIS_SOURCE, "matrix-differential-v1/empty-axis.yml");
    assert!(!report.is_accepted());
    assert!(report.diagnostics().iter().any(|diagnostic| {
        diagnostic.code() == "github.empty_matrix_dimension"
            && diagnostic
                .message()
                .contains("must contain at least one value")
    }));

    let axes_plan = compile_plan(
        EXPRESSION_AXES_SOURCE,
        "matrix-differential-v1/expression-axes.yml",
    );
    let empty_inputs = string_inputs(&[
        ("runtimes", "[]".to_owned()),
        ("platforms", r#"["linux"]"#.to_owned()),
        ("experimental", "[false]".to_owned()),
        ("excludes", "[]".to_owned()),
        ("includes", "[]".to_owned()),
    ]);
    assert!(matches!(
        activate(&axes_plan, &empty_inputs),
        Err(LogicalActivationError::EmptyMatrixAxis)
    ));

    let limit_plan = compile_plan(LIMIT_SOURCE, "matrix-differential-v1/limit.yml");
    assert!(matches!(
        activate(&limit_plan, &string_inputs(&[("matrix", "{".to_owned())]),),
        Err(LogicalActivationError::Evaluation { .. })
    ));
    let boundary = serde_json::to_string(&serde_json::json!({
        "left": (0..16).collect::<Vec<_>>(),
        "right": (0..16).collect::<Vec<_>>()
    }))
    .expect("boundary matrix");
    let activation = activate(&limit_plan, &string_inputs(&[("matrix", boundary)]))
        .expect("exact 256-cell product");
    assert_eq!(activation.instances().len(), 256);
    assert_eq!(activation.instances()[255].identity().matrix_index(), 255);
    assert_eq!(activation.instances()[255].identity().matrix_total(), 256);

    let overflow = serde_json::to_string(&serde_json::json!({
        "left": [0, 1],
        "right": (0..129).collect::<Vec<_>>(),
        "exclude": [{"left": 0, "right": 0}]
    }))
    .expect("257-cell matrix");
    assert!(matches!(
        activate(&limit_plan, &string_inputs(&[("matrix", overflow)]),),
        Err(LogicalActivationError::MatrixExpansionLimitExceeded { maximum: 256 })
    ));
}

fn assert_compile_rejected(source: &str, code: &str) {
    let report = compile_report(source, "matrix-differential-v1/unsupported.yml");
    assert!(report.plan().is_none(), "unexpected plan for `{code}`");
    assert!(
        report
            .diagnostics()
            .iter()
            .any(|diagnostic| diagnostic.code() == code),
        "missing `{code}`: {:#?}",
        report.diagnostics()
    );
}

#[test]
fn later_wave_matrix_consumers_and_unobserved_nested_expressions_remain_fail_closed() {
    assert_compile_rejected(
        r"on: workflow_dispatch
jobs:
  build:
    strategy:
      matrix:
        target: [staging]
    environment:
      name: ${{ matrix.target }}
    runs-on: ubuntu-latest
    steps: [{run: echo unreachable}]
",
        "github.compile.deployment_environment_unavailable",
    );
    assert_compile_rejected(
        r"on: workflow_dispatch
jobs:
  build:
    strategy:
      matrix:
        target: [staging]
    concurrency:
      group: deploy-${{ matrix.target }}
    runs-on: ubuntu-latest
    steps: [{run: echo unreachable}]
",
        "github.compile.job_concurrency_unavailable",
    );
    assert_compile_rejected(
        r"on: workflow_dispatch
jobs:
  call:
    strategy:
      matrix:
        target: [staging]
    uses: ./.ci/workflows/reusable.yml
    with:
      target: ${{ matrix.target }}
",
        "github.compile.reusable_workflow_matrix_unavailable",
    );
    assert_compile_rejected(
        r"on: workflow_dispatch
jobs:
  build:
    strategy:
      matrix:
        config:
          - nested:
              target: ${{ inputs.target }}
    runs-on: ubuntu-latest
    steps: [{run: echo unreachable}]
",
        "github.compile.nested_matrix_expression",
    );
}
