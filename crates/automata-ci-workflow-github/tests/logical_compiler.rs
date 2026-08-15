use crate::support;

use automata_ci_core::{
    CompiledPositiveIntegerTemplate, CompiledValueTemplate, ExpressionContext,
    ExpressionInstruction, ExpressionLiteral, InvocationInputDefault, InvocationInputType,
    LogicalJobKind, LogicalJobOutputSource, LogicalOutputMergePolicy, LogicalResultValue,
    LogicalStepKind, LogicalTimeoutUnit, MatrixAxisValues, MatrixPatchSet,
    MatrixValue as PlanMatrixValue, MatrixValueTemplate, OutputSensitivity,
    ReusableSecretForwarding, WorkflowEventProvenance, WorkflowPlanVersion,
};
use automata_ci_workflow_github::{CompileWorkflowRequest, GithubWorkflowCompiler};

fn compile(source: &str, event: &str) -> automata_ci_workflow_github::CompilationReport {
    let parsed = support::parse(source);
    assert!(
        parsed.is_accepted(),
        "source diagnostics: {:#?}",
        parsed.diagnostics()
    );
    GithubWorkflowCompiler::new().compile(CompileWorkflowRequest::new(
        parsed.plan().expect("source plan"),
        WorkflowEventProvenance::new("github", event)
            .with_delivery_id("synthetic-current")
            .with_commit_sha("0123456789abcdef0123456789abcdef01234567")
            .with_git_ref("refs/heads/main"),
    ))
}

fn assert_rejected(source: &str, code: &str) {
    let report = compile(source, "workflow_dispatch");
    assert!(
        report.plan().is_none(),
        "unexpected plan: {:#?}",
        report.plan()
    );
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
fn run_name_is_limited_to_github_and_inputs_contexts() {
    let accepted = compile(
        "run-name: Deploy ${{ inputs.target }} from ${{ github.ref }}\non: workflow_dispatch\njobs:\n  build:\n    runs-on: linux\n    steps: [{run: echo ok}]\n",
        "workflow_dispatch",
    );
    assert!(accepted.is_accepted(), "{:#?}", accepted.diagnostics());
    assert_rejected(
        "run-name: Deploy ${{ vars.target }}\non: workflow_dispatch\njobs:\n  build:\n    runs-on: linux\n    steps: [{run: echo ok}]\n",
        "github.expression.unrecognized_context",
    );
}

#[test]
#[allow(clippy::too_many_lines)]
fn default_compiler_retains_dynamic_activation_execution_and_finalization_templates() {
    let source = r#"name: Synthetic matrix
run-name: Run ${{ github.ref }}
on:
  workflow_dispatch: {}
permissions:
  contents: read
concurrency:
  group: synthetic-${{ github.ref }}
  cancel-in-progress: ${{ inputs.cancel }}
env:
  ROOT: ${{ vars.root }}
defaults:
  run:
    shell: bash
jobs:
  plan:
    runs-on: linux
    outputs:
      matrix: ${{ steps.emit.outputs.matrix }}
    steps:
      - id: emit
        run: echo plan
  execute:
    needs: plan
    if: ${{ needs.plan.result == 'success' }}
    name: Execute ${{ matrix.os }}
    strategy:
      fail-fast: ${{ inputs.fail_fast }}
      max-parallel: 2
      matrix: ${{ fromJSON(needs.plan.outputs.matrix) }}
    runs-on: [self-hosted, "${{ matrix.os }}"]
    timeout-minutes: ${{ inputs.timeout }}
    continue-on-error: ${{ matrix.experimental }}
    env:
      TARGET: ${{ matrix.os }}
    defaults:
      run:
        working-directory: ${{ matrix.directory }}
    outputs:
      digest: ${{ steps.build.outputs.digest }}
    steps:
      - id: build
        name: Build ${{ matrix.os }}
        continue-on-error: ${{ inputs.step_tolerant }}
        timeout-minutes: ${{ inputs.step_timeout }}
        env:
          TOKEN: ${{ secrets.synthetic_token }}
        run: echo ${{ matrix.os }}
        shell: ${{ matrix.shell }}
        working-directory: ${{ matrix.directory }}
      - id: deploy
        uses: synthetic/example@0123456789abcdef
        with:
          label: result-${{ steps.build.outcome }}
"#;

    let report = compile(source, "workflow_dispatch");
    assert!(report.is_accepted(), "{:#?}", report.diagnostics());
    let plan = report.plan().expect("current plan");
    assert_eq!(plan.version(), WorkflowPlanVersion::v1());
    let logical = plan.logical();
    assert_eq!(logical.jobs().len(), 2);
    assert!(logical.permissions().is_some());
    assert_eq!(logical.environment().entries().len(), 1);
    assert!(logical.concurrency().is_some());

    let execute = &logical.jobs()[1];
    assert_eq!(execute.source_order(), 1);
    assert_eq!(execute.needs()[0].value().as_str(), "plan");
    assert!(execute.result_references().iter().any(|reference| {
        reference.value().job().as_str() == "plan"
            && matches!(reference.value().value(), LogicalResultValue::Result)
    }));
    assert!(execute.result_references().iter().any(|reference| {
        reference.value().job().as_str() == "plan"
            && matches!(
                reference.value().value(),
                LogicalResultValue::Output(output) if output.as_str() == "matrix"
            )
    }));
    let condition = execute.condition().expect("condition").value();
    assert_eq!(condition.programs().len(), 1);
    assert_eq!(
        condition.programs()[0].source(),
        "${{ needs.plan.result == 'success' }}"
    );
    assert!(
        condition.programs()[0]
            .instructions()
            .iter()
            .any(|instruction| {
                matches!(instruction, ExpressionInstruction::Call { name, .. } if name == "success")
            })
    );

    let strategy = execute.strategy().expect("strategy");
    assert!(matches!(
        strategy.max_parallel().expect("max parallel").value(),
        CompiledPositiveIntegerTemplate::Literal(2)
    ));
    let matrix = strategy.matrix();
    assert!(matrix.expression().is_some());
    assert!(matrix.axes().is_empty());
    assert!(
        matrix
            .expression()
            .expect("whole matrix expression")
            .value()
            .contexts()
            .contains(&ExpressionContext::Needs)
    );
    assert_eq!(
        execute.timeout().expect("job timeout").value().unit(),
        LogicalTimeoutUnit::Minutes
    );
    assert_eq!(
        execute.outputs()[0].merge(),
        LogicalOutputMergePolicy::LastSuccessfulCompletion
    );
    assert_eq!(
        execute.outputs()[0].sensitivity(),
        OutputSensitivity::Public
    );
    let LogicalJobKind::Steps(job) = execute.execution() else {
        panic!("step job");
    };
    assert_eq!(job.runner().labels().len(), 2);
    assert_eq!(job.steps().len(), 2);
    let LogicalStepKind::Run(run) = job.steps()[0].execution() else {
        panic!("run step");
    };
    assert!(matches!(
        run.script().value(),
        CompiledValueTemplate::Expression(_)
    ));
    assert_eq!(
        job.steps()[0]
            .timeout()
            .expect("step timeout")
            .value()
            .unit(),
        LogicalTimeoutUnit::Minutes
    );
}

#[test]
fn structured_matrix_preserves_axis_and_patch_order_with_typed_values() {
    let source = r"on: workflow_dispatch
jobs:
  test:
    strategy:
      fail-fast: false
      max-parallel: 999
      matrix:
        os: [linux, windows]
        runtime:
          - version: 20
            experimental: false
        include:
          - os: linux
            shard: 1
        exclude:
          - os: windows
    runs-on: ${{ matrix.os }}
    steps:
      - run: echo test
";
    let report = compile(source, "workflow_dispatch");
    assert!(report.is_accepted(), "{:#?}", report.diagnostics());
    let strategy = report.plan().expect("plan").jobs()[0]
        .strategy()
        .expect("strategy");
    assert!(matches!(
        strategy.max_parallel().expect("bounded max").value(),
        CompiledPositiveIntegerTemplate::Literal(999)
    ));
    let matrix = strategy.matrix();
    assert_eq!(
        matrix
            .axes()
            .iter()
            .map(|axis| axis.name().value().as_str())
            .collect::<Vec<_>>(),
        ["os", "runtime"]
    );
    let MatrixAxisValues::Static(runtime) = matrix.axes()[1].values() else {
        panic!("static runtime axis");
    };
    assert!(matches!(
        runtime[0].value(),
        MatrixValueTemplate::Literal(PlanMatrixValue::Object(entries))
            if entries == &vec![
                ("experimental".to_owned(), PlanMatrixValue::Boolean(false)),
                ("version".to_owned(), PlanMatrixValue::Number("20".to_owned())),
            ]
    ));
    assert!(matches!(matrix.include(), MatrixPatchSet::Static(values) if values.len() == 1));
    assert!(matches!(matrix.exclude(), MatrixPatchSet::Static(values) if values.len() == 1));
}

#[test]
fn max_parallel_literals_and_expressions_retain_the_same_positive_integer_range() {
    let source = r"on: workflow_dispatch
jobs:
  literal:
    strategy:
      max-parallel: 4096
      matrix:
        shard: [one]
    runs-on: linux
    steps:
      - run: echo literal
  expression:
    strategy:
      max-parallel: ${{ 4096 }}
      matrix:
        shard: [one]
    runs-on: linux
    steps:
      - run: echo expression
";
    let report = compile(source, "workflow_dispatch");
    assert!(report.is_accepted(), "{:#?}", report.diagnostics());
    let jobs = report.plan().expect("plan").jobs();
    assert!(matches!(
        jobs[0]
            .strategy()
            .expect("literal strategy")
            .max_parallel()
            .expect("literal max-parallel")
            .value(),
        CompiledPositiveIntegerTemplate::Literal(4096)
    ));
    let CompiledPositiveIntegerTemplate::Expression(expression) = jobs[1]
        .strategy()
        .expect("expression strategy")
        .max_parallel()
        .expect("expression max-parallel")
        .value()
    else {
        panic!("expression max-parallel");
    };
    assert!(matches!(
        expression.programs()[0].instructions(),
        [ExpressionInstruction::Literal {
            value: ExpressionLiteral::Number { ieee754_bits }
        }] if *ieee754_bits == 4096.0_f64.to_bits()
    ));
}

#[test]
fn provider_specific_matrix_key_matching_is_deferred_to_activation() {
    let source = r"on: workflow_dispatch
jobs:
  test:
    strategy:
      matrix:
        OS: [linux, windows]
        exclude:
          - os: windows
    runs-on: linux
    steps:
      - run: echo test
";
    let report = compile(source, "workflow_dispatch");
    assert!(report.is_accepted(), "{:#?}", report.diagnostics());
    let matrix = report.plan().expect("plan").jobs()[0]
        .strategy()
        .expect("strategy")
        .matrix();
    assert_eq!(matrix.axes()[0].name().value(), "OS");
    let MatrixPatchSet::Static(exclude) = matrix.exclude() else {
        panic!("static exclude");
    };
    assert_eq!(exclude[0].entries()[0].0.value(), "os");
}

#[test]
fn reusable_calls_retain_typed_inputs_opaque_secrets_and_inferred_outputs() {
    let source = r"on:
  workflow_call:
    inputs: {}
    secrets: {}
    outputs: {}
jobs:
  invoke:
    uses: ./synthetic-reusable.yml
    with:
      enabled: true
      attempts: 2
      label: stable
    secrets:
      token: ${{ secrets.synthetic_token }}
  consume:
    needs: invoke
    runs-on: linux
    steps:
      - run: echo ${{ needs.invoke.outputs.digest }}
";
    let report = compile(source, "workflow_call");
    assert!(report.is_accepted(), "{:#?}", report.diagnostics());
    let plan = report.plan().expect("plan");
    let logical = plan.logical();
    let contract = logical.invocation().expect("empty workflow_call contract");
    assert!(contract.inputs().is_empty());
    assert!(contract.secrets().is_empty());
    assert!(contract.outputs().is_empty());

    let invoke = &logical.jobs()[0];
    let LogicalJobKind::ReusableWorkflow(invocation) = invoke.execution() else {
        panic!("reusable invocation");
    };
    assert_eq!(invocation.reference().value(), "./synthetic-reusable.yml");
    assert_eq!(invocation.inputs().len(), 3);
    assert!(matches!(
        invocation.inputs()[0].value().value(),
        CompiledValueTemplate::Expression(expression)
            if expression.contexts().is_empty() && expression.programs().len() == 1
    ));
    assert!(matches!(
        invocation.inputs()[2].value().value(),
        CompiledValueTemplate::Literal(value) if value == "stable"
    ));
    let ReusableSecretForwarding::Mapping(secrets) = invocation.secrets() else {
        panic!("mapped secrets");
    };
    assert_eq!(secrets[0].target().value().as_str(), "token");
    assert_eq!(secrets[0].source().value().as_str(), "synthetic_token");
    assert_eq!(invoke.outputs().len(), 1);
    assert!(matches!(
        invoke.outputs()[0].source(),
        LogicalJobOutputSource::InvocationOutput(output) if output.value().as_str() == "digest"
    ));
    assert_eq!(
        invoke.outputs()[0].sensitivity(),
        OutputSensitivity::SecretDerived
    );
}

#[test]
fn reusable_workflow_contract_retains_typed_inputs_secrets_outputs_and_sensitivity() {
    let source = r"on:
  workflow_call:
    inputs:
      enabled:
        description: Enable publishing
        required: true
        type: boolean
      attempts:
        type: number
        default: 2
      channel:
        type: string
        default: stable
    secrets:
      token:
        description: Publishing credential
        required: true
    outputs:
      digest:
        description: Public digest
        value: ${{ jobs.build.outputs.digest }}
      protected:
        value: ${{ jobs.build.outputs.protected }}
jobs:
  build:
    runs-on: linux
    outputs:
      digest: ${{ steps.publish.outputs.digest }}
      protected: ${{ secrets.token }}
    steps:
      - id: publish
        run: echo digest=synthetic
";
    let report = compile(source, "workflow_call");
    assert!(report.is_accepted(), "{:#?}", report.diagnostics());
    let contract = report
        .plan()
        .expect("plan")
        .logical()
        .invocation()
        .expect("invocation contract");

    assert_eq!(contract.inputs().len(), 3);
    assert_eq!(
        *contract.inputs()[0].input_type().value(),
        InvocationInputType::Boolean
    );
    assert!(contract.inputs()[0].required());
    assert!(matches!(
        contract.inputs()[1].default().expect("number default").value(),
        InvocationInputDefault::Number(value) if value == "2"
    ));
    assert!(matches!(
        contract.inputs()[2].default().expect("string default").value(),
        InvocationInputDefault::String(value) if value == "stable"
    ));
    assert_eq!(contract.secrets().len(), 1);
    assert!(contract.secrets()[0].required());
    assert_eq!(contract.outputs().len(), 2);
    assert_eq!(
        contract.outputs()[0].sensitivity(),
        OutputSensitivity::Public
    );
    assert_eq!(
        contract.outputs()[1].sensitivity(),
        OutputSensitivity::SecretDerived
    );
    assert!(matches!(
        contract.outputs()[0].references()[0].value().value(),
        LogicalResultValue::Output(output) if output.as_str() == "digest"
    ));
}

#[test]
fn reusable_workflow_contract_rejects_malformed_types_and_unknown_outputs() {
    let cases = [
        (
            r"on:
  workflow_call:
    inputs:
      enabled:
        required: true
jobs:
  build:
    runs-on: linux
    steps:
      - run: echo build
",
            "github.compile.workflow_call_input_type_required",
        ),
        (
            r#"on:
  workflow_call:
    inputs:
      enabled:
        type: boolean
        default: "false"
jobs:
  build:
    runs-on: linux
    steps:
      - run: echo build
"#,
            "github.compile.invalid_workflow_call_boolean",
        ),
        (
            r"on:
  workflow_call:
    outputs:
      missing:
        value: ${{ jobs.build.outputs.missing }}
jobs:
  build:
    runs-on: linux
    steps:
      - run: echo build
",
            "github.compile.unknown_workflow_call_job_output",
        ),
    ];

    for (source, code) in cases {
        let report = compile(source, "workflow_call");
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
}

#[test]
fn current_compiler_rejects_context_and_graph_semantics_it_cannot_represent() {
    assert_rejected(
        "on: workflow_dispatch\njobs:\n  test:\n    if: ${{ matrix.os }}\n    runs-on: linux\n    steps: [{run: echo test}]\n",
        "github.expression.unrecognized_context",
    );
    assert_rejected(
        "on: workflow_dispatch\njobs:\n  first:\n    runs-on: linux\n    steps:\n      - run: echo first\n  second:\n    needs: first\n    runs-on: linux\n    steps:\n      - run: echo ${{ needs.first.outputs.missing }}\n",
        "github.compile.unknown_needs_output",
    );
    assert_rejected(
        "on: workflow_dispatch\ndefaults:\n  run:\n    shell: ${{ inputs.shell }}\njobs:\n  test:\n    runs-on: linux\n    steps: [{run: echo test}]\n",
        "github.compile.workflow_defaults_expression",
    );
    assert_rejected(
        "on: workflow_dispatch\njobs:\n  test:\n    runs-on: linux\n    steps:\n      - uses: synthetic/${{ inputs.action }}@main\n",
        "github.compile.dynamic_action_reference",
    );
}

#[test]
fn whole_and_dynamically_indexed_needs_contexts_compile_for_runtime_evaluation() {
    let source = r#"on: workflow_dispatch
jobs:
  prepare:
    runs-on: linux
    outputs:
      value: ${{ steps.result.outputs.value }}
    steps:
      - id: result
        run: echo 'value=ready' >> "$GITHUB_OUTPUT"
  consume:
    needs: prepare
    strategy:
      matrix:
        prerequisite: [prepare]
    runs-on: linux
    steps:
      - run: echo '${{ toJSON(needs) }}'
      - run: echo '${{ needs[matrix.prerequisite].outputs.value }}'
"#;

    let report = compile(source, "workflow_dispatch");
    assert!(report.is_accepted(), "{:#?}", report.diagnostics());
    let consume = report
        .plan()
        .expect("compiled plan")
        .jobs()
        .iter()
        .find(|job| job.key().value().as_str() == "consume")
        .expect("consumer job");
    assert!(consume.result_references().is_empty());
}
