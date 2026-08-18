use crate::support;

use automata_ci_core::WorkflowEventProvenance;
use automata_ci_workflow_actions::{
    BooleanValue, DiagnosticKind, GithubEventMetadata, MatrixConfigurations, MatrixDimensionValues,
    MatrixValue, ScalarResolution, StrategyMatrix,
};

#[test]
fn source_model_retains_static_matrix_strategy_without_flattening_values() {
    let source = r"on: push
jobs:
  test:
    runs-on: linux
    strategy:
      fail-fast: ${{ inputs.fail_fast }}
      max-parallel: 2
      matrix:
        os: [linux, windows]
        runtime:
          - version: 20
            experimental: false
        shard: ${{ fromJSON(inputs.shards) }}
        include:
          - os: linux
            runtime:
              version: 22
            tags: [fast, isolated]
        exclude:
          - os: windows
            experimental: true
    steps:
      - run: echo test
";

    let report = support::parse_accepted(source);
    let plan = report.plan().expect("source plan");
    let strategy = plan.workflow().jobs()[0]
        .job()
        .strategy()
        .expect("strategy");
    assert!(matches!(
        strategy.fail_fast(),
        Some(BooleanValue::Expression(expression))
            if expression.value() == "${{ inputs.fail_fast }}"
    ));
    let max_parallel = strategy.max_parallel().expect("max parallel");
    assert_eq!(max_parallel.decoded(), "2");
    assert_eq!(max_parallel.resolution(), ScalarResolution::Integer);
    assert!(
        plan.source()
            .slice(strategy.span())
            .expect("strategy source")
            .contains("fail-fast:")
    );

    let StrategyMatrix::Mapping(matrix) = strategy.matrix().expect("matrix") else {
        panic!("static matrix must retain its mapping form");
    };
    assert_eq!(matrix.dimensions().len(), 3);
    assert_eq!(matrix.dimensions()[0].name().value(), "os");
    let MatrixDimensionValues::Sequence { values, .. } = matrix.dimensions()[0].values() else {
        panic!("os must be a static sequence");
    };
    assert_eq!(values.len(), 2);
    assert!(matches!(
        &values[0],
        MatrixValue::Scalar(value) if value.decoded() == "linux"
    ));

    let MatrixDimensionValues::Sequence { values, .. } = matrix.dimensions()[1].values() else {
        panic!("runtime must be a static sequence");
    };
    assert!(matches!(
        &values[0],
        MatrixValue::Mapping { entries, .. }
            if entries.len() == 2
                && entries[0].key().value() == "version"
                && entries[1].key().value() == "experimental"
    ));
    assert!(matches!(
        matrix.dimensions()[2].values(),
        MatrixDimensionValues::Expression(expression)
            if expression.decoded() == "${{ fromJSON(inputs.shards) }}"
    ));

    let Some(MatrixConfigurations::Sequence { configurations, .. }) = matrix.include() else {
        panic!("static include list");
    };
    assert_eq!(configurations.len(), 1);
    assert_eq!(configurations[0].entries().len(), 3);
    assert!(matches!(
        configurations[0].entries()[1].value(),
        MatrixValue::Mapping { entries, .. }
            if entries[0].key().value() == "version"
    ));
    assert!(matches!(
        configurations[0].entries()[2].value(),
        MatrixValue::Sequence { values, .. } if values.len() == 2
    ));

    let Some(MatrixConfigurations::Sequence { configurations, .. }) = matrix.exclude() else {
        panic!("static exclude list");
    };
    assert_eq!(configurations.len(), 1);
    assert_eq!(configurations[0].entries()[0].key().value(), "os");
    assert!(matrix.extensions().is_empty());
    assert!(strategy.extensions().is_empty());
}

#[test]
fn source_model_retains_expression_valued_dynamic_matrix_and_configuration_lists() {
    let source = r"on: push
jobs:
  dynamic:
    runs-on: linux
    strategy:
      matrix: ${{ fromJSON(needs.plan.outputs.matrix) }}
    steps:
      - run: echo dynamic
  mixed:
    runs-on: linux
    strategy:
      matrix:
        os: ${{ fromJSON(inputs.operating_systems) }}
        include: ${{ fromJSON(inputs.additional_jobs) }}
        exclude: ${{ fromJSON(inputs.excluded_jobs) }}
    steps:
      - run: echo mixed
";

    let report = support::parse_accepted(source);
    let plan = report.plan().expect("source plan");
    assert!(matches!(
        plan.workflow().jobs()[0]
            .job()
            .strategy()
            .and_then(|strategy| strategy.matrix()),
        Some(StrategyMatrix::Expression(expression))
            if expression.decoded() == "${{ fromJSON(needs.plan.outputs.matrix) }}"
    ));

    let Some(StrategyMatrix::Mapping(matrix)) = plan.workflow().jobs()[1]
        .job()
        .strategy()
        .and_then(|strategy| strategy.matrix())
    else {
        panic!("mixed matrix mapping");
    };
    assert!(matches!(
        matrix.dimensions()[0].values(),
        MatrixDimensionValues::Expression(expression)
            if expression.decoded() == "${{ fromJSON(inputs.operating_systems) }}"
    ));
    assert!(matches!(
        matrix.include(),
        Some(MatrixConfigurations::Expression(expression))
            if expression.decoded() == "${{ fromJSON(inputs.additional_jobs) }}"
    ));
    assert!(matches!(
        matrix.exclude(),
        Some(MatrixConfigurations::Expression(expression))
            if expression.decoded() == "${{ fromJSON(inputs.excluded_jobs) }}"
    ));
}

#[test]
fn strategy_extensions_are_preserved_at_their_exact_path() {
    let source = r"on: push
jobs:
  test:
    runs-on: linux
    strategy:
      matrix:
        os: [linux]
      future-policy: ordered
    steps:
      - run: echo test
";

    let report = support::parse(source);
    let extension = &report
        .plan()
        .expect("loss-aware source plan")
        .workflow()
        .jobs()[0]
        .job()
        .strategy()
        .expect("strategy")
        .extensions()[0];
    assert_eq!(extension.path(), "jobs.test.strategy.future-policy");
    assert!(report.diagnostics().iter().any(|diagnostic| {
        diagnostic.kind() == DiagnosticKind::Unsupported
            && diagnostic.code() == "github.unsupported_field"
            && diagnostic.primary_span() == extension.entry().key().span()
    }));
}

#[test]
fn malformed_strategy_shapes_have_field_specific_diagnostics() {
    let source = r"on: push
jobs:
  scalar-strategy:
    runs-on: linux
    strategy: fast
    steps: [{run: echo test}]
  empty-strategy:
    runs-on: linux
    strategy: {}
    steps: [{run: echo test}]
  malformed-controls:
    runs-on: linux
    strategy:
      fail-fast: prefix-${{ inputs.fail_fast }}
      max-parallel: 0
      matrix: prefix-${{ inputs.matrix }}
    steps: [{run: echo test}]
  malformed-mapping:
    runs-on: linux
    strategy:
      matrix:
        empty: []
        literal: one
        include:
          - {}
          - not-a-mapping
        exclude: {}
    steps: [{run: echo test}]
  empty-matrix:
    runs-on: linux
    strategy:
      matrix: {}
    steps: [{run: echo test}]
";

    let report = support::parse(source);
    assert!(report.plan().is_some(), "loss-aware source plan");
    let expected = [
        "github.expected_strategy_mapping",
        "github.empty_strategy",
        "github.expected_strategy_fail_fast",
        "github.expected_strategy_max_parallel",
        "github.expected_strategy_matrix",
        "github.empty_matrix_dimension",
        "github.expected_matrix_dimension_values",
        "github.empty_matrix_configuration",
        "github.expected_matrix_configuration",
        "github.expected_matrix_configurations",
        "github.empty_strategy_matrix",
    ];
    for code in expected {
        let matching = report
            .diagnostics()
            .iter()
            .filter(|diagnostic| diagnostic.code() == code)
            .collect::<Vec<_>>();
        assert_eq!(matching.len(), 1, "diagnostic {code}: {matching:#?}");
        assert_eq!(matching[0].kind(), DiagnosticKind::Semantic);
        assert!(matching[0].message().contains("`jobs."));
    }
}

#[test]
fn strategy_controls_require_typed_canonical_yaml_literals() {
    let source = r#"on: push
jobs:
  quoted-bool:
    runs-on: linux
    strategy: {fail-fast: "false"}
    steps: [{run: echo test}]
  quoted-integer:
    runs-on: linux
    strategy: {max-parallel: "2"}
    steps: [{run: echo test}]
  leading-underscore:
    runs-on: linux
    strategy: {max-parallel: _1}
    steps: [{run: echo test}]
  separated-integer:
    runs-on: linux
    strategy: {max-parallel: 1_000}
    steps: [{run: echo test}]
  signed-integer:
    runs-on: linux
    strategy: {max-parallel: +1}
    steps: [{run: echo test}]
  leading-zero:
    runs-on: linux
    strategy: {max-parallel: 01}
    steps: [{run: echo test}]
  hexadecimal:
    runs-on: linux
    strategy: {max-parallel: 0x10}
    steps: [{run: echo test}]
  out-of-range:
    runs-on: linux
    strategy: {max-parallel: 9223372036854775808}
    steps: [{run: echo test}]
  largest-canonical:
    runs-on: linux
    strategy: {fail-fast: TRUE, max-parallel: 9223372036854775807}
    steps: [{run: echo test}]
"#;

    let report = support::parse(source);
    let plan = report.plan().expect("loss-aware source plan");
    assert!(
        plan.workflow().jobs()[0]
            .job()
            .strategy()
            .expect("quoted boolean strategy")
            .fail_fast()
            .is_none()
    );
    assert!(matches!(
        plan.workflow()
            .jobs()
            .last()
            .expect("largest canonical job")
            .job()
            .strategy()
            .expect("largest canonical strategy")
            .fail_fast(),
        Some(BooleanValue::Literal(value)) if *value.value()
    ));

    let boolean_diagnostics = report
        .diagnostics()
        .iter()
        .filter(|diagnostic| diagnostic.code() == "github.expected_boolean")
        .collect::<Vec<_>>();
    assert_eq!(boolean_diagnostics.len(), 1, "{boolean_diagnostics:#?}");
    assert!(
        boolean_diagnostics[0]
            .message()
            .contains("jobs.quoted-bool.strategy.fail-fast")
    );

    let integer_diagnostics = report
        .diagnostics()
        .iter()
        .filter(|diagnostic| diagnostic.code() == "github.expected_strategy_max_parallel")
        .collect::<Vec<_>>();
    assert_eq!(integer_diagnostics.len(), 7, "{integer_diagnostics:#?}");
    for diagnostic in integer_diagnostics {
        assert_eq!(diagnostic.kind(), DiagnosticKind::Semantic);
        assert!(diagnostic.message().contains("strategy.max-parallel"));
    }
}

#[test]
fn compiler_fails_closed_when_malformed_strategy_was_retained() {
    for value in ["fast", "null", "[fast, safe]"] {
        let source = format!(
            "on: workflow_dispatch\njobs:\n  test:\n    runs-on: linux\n    strategy: {value}\n    steps: [{{run: echo test}}]\n"
        );
        let parsed = support::parse(&source);
        let plan = parsed.plan().expect("loss-aware source plan");
        assert!(plan.workflow().jobs()[0].job().strategy().is_none());

        let report = support::compile(
            plan,
            WorkflowEventProvenance::new("github", "workflow_dispatch"),
            None,
        );
        assert!(report.plan().is_none(), "strategy value {value}");
        let diagnostics = report
            .diagnostics()
            .iter()
            .filter(|diagnostic| diagnostic.code() == "github.compile.invalid_job_strategy")
            .collect::<Vec<_>>();
        assert_eq!(
            diagnostics.len(),
            1,
            "strategy value {value}: {diagnostics:#?}"
        );
        assert_eq!(diagnostics[0].kind(), DiagnosticKind::Semantic);
        assert_eq!(
            plan.source().slice(diagnostics[0].primary_span()),
            Some(value)
        );
    }
}

#[test]
fn current_compiler_retains_static_and_dynamic_strategy_sources() {
    let cases = [
        r"on: push
jobs:
  test:
    runs-on: linux
    strategy:
      fail-fast: false
      max-parallel: 2
      matrix:
        os: [linux, windows]
    steps:
      - run: echo test
",
        r"on: push
jobs:
  test:
    runs-on: linux
    strategy:
      matrix: ${{ fromJSON(inputs.matrix) }}
    steps:
      - run: echo test
",
    ];

    for source in cases {
        let parsed = support::parse_accepted(source);
        let report = support::compile(
            parsed.plan().expect("source plan"),
            WorkflowEventProvenance::new("github", "push").with_git_ref("refs/heads/main"),
            Some(GithubEventMetadata::push(false)),
        );
        assert!(report.is_accepted(), "{:#?}", report.diagnostics());
        assert!(
            report.plan().expect("current plan").jobs()[0]
                .strategy()
                .is_some()
        );
    }
}
