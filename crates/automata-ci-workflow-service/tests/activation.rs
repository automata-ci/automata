use std::{
    collections::BTreeMap,
    sync::{
        Mutex,
        atomic::{AtomicUsize, Ordering},
    },
};

use automata_ci_core::{
    CompiledBooleanTemplate, CompiledExpressionTemplate, CompiledPositiveIntegerTemplate,
    CompiledValueTemplate, ContextValue, ExpressionContext, ExpressionDialect,
    ExpressionInstruction, ExpressionLiteral, ExpressionLogical, ExpressionProgram,
    ExpressionSegment, JobConclusion, Located, LogicalJobKind, LogicalRunStepTemplate,
    LogicalRunnerTemplate, LogicalStepKind, LogicalStepTemplate, LogicalTimeoutTemplate,
    MatrixAxis, MatrixAxisValues, MatrixPatch, MatrixPatchSet, MatrixTemplate, MatrixValue,
    MatrixValueTemplate, NeedContext, NeedOutput, OutputSensitivity, PlanEvaluationPhase,
    PlanExpression, PlanSourceLocation, PlanSourceOrigin, PlanSourceSpan, SecretBinding,
    StepJobTemplate, WorkflowEventProvenance, WorkflowJobKey, WorkflowPlan,
    WorkflowSourceProvenance, WorkflowStepKey, WorkflowStrategyTemplate,
};
use automata_ci_workflow_service::{
    ActivateLogicalJobRequest, ActivationEvaluationContext, ActivationStatus, ActivationValue,
    LogicalActivationError, LogicalActivationEvaluator, LogicalActivationSession,
    LogicalJobActivator, ValidatedLogicalJob, ValidatedLogicalPlan,
};
use thiserror::Error;

fn span() -> PlanSourceSpan {
    PlanSourceSpan::new(
        "synthetic.yml",
        PlanSourceLocation::new(0, 1, 1).expect("start"),
        PlanSourceLocation::new(1, 1, 2).expect("end"),
    )
    .expect("span")
}

fn located<T>(value: T) -> Located<T> {
    Located::new(value, span())
}

fn expression(source: &str, contexts: Vec<ExpressionContext>) -> CompiledExpressionTemplate {
    let mut instructions = contexts
        .iter()
        .map(|context| ExpressionInstruction::NamedValue {
            name: context.as_str().to_owned(),
        })
        .collect::<Vec<_>>();
    match instructions.len() {
        0 => instructions.push(ExpressionInstruction::Literal {
            value: ExpressionLiteral::Boolean { value: true },
        }),
        1 => {}
        count => instructions.push(ExpressionInstruction::Logical {
            operator: ExpressionLogical::And,
            operand_count: u16::try_from(count).expect("bounded synthetic contexts"),
        }),
    }
    let program = ExpressionProgram::new(
        ExpressionDialect::new("synthetic", 1).expect("dialect"),
        source,
        instructions,
    )
    .expect("program");
    CompiledExpressionTemplate::new(
        PlanEvaluationPhase::JobActivation,
        PlanExpression::new(
            source,
            vec![ExpressionSegment::Evaluation(source.to_owned())],
        )
        .expect("expression"),
        vec![program],
        contexts,
    )
}

fn literal(value: &str) -> Located<MatrixValueTemplate> {
    located(MatrixValueTemplate::Literal(MatrixValue::String(
        value.to_owned(),
    )))
}

fn patch(entries: &[(&str, MatrixValue)]) -> MatrixPatch {
    MatrixPatch::new(
        entries
            .iter()
            .map(|(key, value)| {
                (
                    located((*key).to_owned()),
                    located(MatrixValueTemplate::Literal(value.clone())),
                )
            })
            .collect(),
        span(),
    )
}

fn strategy() -> WorkflowStrategyTemplate {
    WorkflowStrategyTemplate::new(
        Some(located(CompiledBooleanTemplate::Literal(false))),
        Some(located(CompiledPositiveIntegerTemplate::Literal(2))),
        MatrixTemplate::new(
            vec![
                MatrixAxis::new(
                    located("fruit".to_owned()),
                    MatrixAxisValues::Static(vec![literal("apple"), literal("pear")]),
                    span(),
                ),
                MatrixAxis::new(
                    located("animal".to_owned()),
                    MatrixAxisValues::Static(vec![literal("cat"), literal("dog")]),
                    span(),
                ),
            ],
            MatrixPatchSet::Static(vec![
                patch(&[("color", MatrixValue::String("green".to_owned()))]),
                patch(&[
                    ("color", MatrixValue::String("pink".to_owned())),
                    ("animal", MatrixValue::String("cat".to_owned())),
                ]),
                patch(&[
                    ("fruit", MatrixValue::String("apple".to_owned())),
                    ("shape", MatrixValue::String("circle".to_owned())),
                ]),
                patch(&[
                    ("fruit", MatrixValue::String("banana".to_owned())),
                    ("allow_failure", MatrixValue::Boolean(true)),
                ]),
                patch(&[
                    ("fruit", MatrixValue::String("banana".to_owned())),
                    ("animal", MatrixValue::String("cat".to_owned())),
                ]),
            ]),
            MatrixPatchSet::Static(vec![patch(&[(
                "animal",
                MatrixValue::String("dog".to_owned()),
            )])]),
            span(),
        ),
        16,
        span(),
    )
}

fn job(
    strategy: Option<WorkflowStrategyTemplate>,
    needs: &[&str],
    condition: Option<CompiledExpressionTemplate>,
    continue_on_error: Option<CompiledBooleanTemplate>,
) -> WorkflowPlan {
    job_with_activation_fields(
        strategy,
        needs,
        condition,
        continue_on_error,
        None,
        LogicalRunnerTemplate::new(
            None,
            vec![located(CompiledValueTemplate::Literal("linux".to_owned()))],
            span(),
        ),
        None,
    )
}

#[allow(clippy::too_many_arguments)]
fn job_with_activation_fields(
    strategy: Option<WorkflowStrategyTemplate>,
    needs: &[&str],
    condition: Option<CompiledExpressionTemplate>,
    continue_on_error: Option<CompiledBooleanTemplate>,
    name: Option<CompiledValueTemplate>,
    runner: LogicalRunnerTemplate,
    timeout: Option<LogicalTimeoutTemplate>,
) -> WorkflowPlan {
    fn execution(runner: LogicalRunnerTemplate) -> StepJobTemplate {
        let step = LogicalStepTemplate::builder(
            located(WorkflowStepKey::new("position/00000000").expect("step key")),
            LogicalStepKind::Run(Box::new(LogicalRunStepTemplate::new(
                located(CompiledValueTemplate::Literal("true".to_owned())),
                None,
                None,
            ))),
            span(),
        )
        .build()
        .expect("step");
        StepJobTemplate::new(runner, vec![step], span())
    }
    let consumer = automata_ci_core::LogicalJobTemplate::builder(
        located(WorkflowJobKey::new("test").expect("job key")),
        u32::try_from(needs.len()).expect("bounded needs"),
        LogicalJobKind::Steps(execution(runner)),
        span(),
    )
    .name(name.map(located))
    .needs(
        needs
            .iter()
            .map(|value| located(WorkflowJobKey::new(*value).expect("need key")))
            .collect(),
    )
    .condition(condition.map(located))
    .strategy(strategy)
    .timeout(timeout.map(located))
    .continue_on_error(continue_on_error.map(located))
    .build()
    .expect("job");
    let mut jobs = needs
        .iter()
        .enumerate()
        .map(|(index, key)| {
            automata_ci_core::LogicalJobTemplate::builder(
                located(WorkflowJobKey::new(*key).expect("need key")),
                u32::try_from(index).expect("bounded needs"),
                LogicalJobKind::Steps(execution(LogicalRunnerTemplate::new(
                    None,
                    vec![located(CompiledValueTemplate::Literal("linux".to_owned()))],
                    span(),
                ))),
                span(),
            )
            .build()
            .expect("need job")
        })
        .collect::<Vec<_>>();
    jobs.push(consumer);
    WorkflowPlan::logical_builder(
        WorkflowSourceProvenance::new(
            "github",
            "synthetic.yml",
            PlanSourceOrigin::Memory {
                name: "synthetic.yml".to_owned(),
            },
        ),
        WorkflowEventProvenance::new("github", "workflow_dispatch"),
        jobs,
        span(),
    )
    .build()
    .expect("plan")
}

fn validated_job(plan: &WorkflowPlan) -> ValidatedLogicalJob<'_> {
    ValidatedLogicalPlan::new(plan)
        .expect("validated logical plan")
        .job(&WorkflowJobKey::new("test").expect("logical job key"))
        .expect("validated logical job")
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct EvaluationCall {
    source: String,
    matrix: bool,
    strategy: bool,
}

#[derive(Debug, Default)]
struct SyntheticEvaluator {
    values: BTreeMap<String, ActivationValue>,
    booleans: BTreeMap<String, bool>,
    integers: BTreeMap<String, u32>,
    calls: Mutex<Vec<EvaluationCall>>,
    base_context_conversions: AtomicUsize,
}

#[derive(Debug, Error)]
#[error("synthetic expression was not configured")]
struct SyntheticEvaluationError;

impl SyntheticEvaluator {
    fn record(
        &self,
        expression: &CompiledExpressionTemplate,
        context: &ActivationEvaluationContext<'_>,
    ) {
        assert_eq!(context.job_key().as_str(), "test");
        assert!(context.inputs().as_object().is_some());
        assert!(context.vars().as_object().is_some());
        assert!(context.needs().contains_key("prepare"));
        assert_eq!(expression.programs().len(), 1);
        assert_eq!(
            expression.programs()[0].source(),
            expression.expression().segments()[0].source()
        );
        self.calls.lock().expect("calls").push(EvaluationCall {
            source: expression.expression().source().to_owned(),
            matrix: context.matrix().is_some(),
            strategy: context.strategy().is_some(),
        });
    }
}

impl LogicalActivationEvaluator for SyntheticEvaluator {
    type Error = SyntheticEvaluationError;
    type Session<'a> = SyntheticSession<'a>;

    fn prepare(
        &self,
        _context: &ActivationEvaluationContext<'_>,
    ) -> Result<Self::Session<'_>, Self::Error> {
        self.base_context_conversions
            .fetch_add(1, Ordering::Relaxed);
        Ok(SyntheticSession { evaluator: self })
    }
}

#[derive(Debug)]
struct SyntheticSession<'a> {
    evaluator: &'a SyntheticEvaluator,
}

impl LogicalActivationSession for SyntheticSession<'_> {
    type Error = SyntheticEvaluationError;

    fn validate_expression_site(
        &self,
        _expression: &CompiledExpressionTemplate,
        _site: automata_ci_workflow_service::ActivationEvaluationSite,
    ) -> Result<(), Self::Error> {
        Ok(())
    }

    fn evaluate_value(
        &self,
        expression: &CompiledExpressionTemplate,
        context: &ActivationEvaluationContext<'_>,
    ) -> Result<ActivationValue, Self::Error> {
        self.evaluator.record(expression, context);
        self.evaluator
            .values
            .get(expression.expression().source())
            .cloned()
            .ok_or(SyntheticEvaluationError)
    }

    fn evaluate_string(
        &self,
        expression: &CompiledExpressionTemplate,
        context: &ActivationEvaluationContext<'_>,
    ) -> Result<String, Self::Error> {
        self.evaluator.record(expression, context);
        if let Some(property) = expression
            .expression()
            .source()
            .strip_prefix("${{ matrix.")
            .and_then(|source| source.strip_suffix(" }}"))
        {
            return context
                .matrix()
                .and_then(ContextValue::as_object)
                .and_then(|matrix| matrix.get(property))
                .and_then(ContextValue::as_string)
                .map(str::to_owned)
                .ok_or(SyntheticEvaluationError);
        }
        match self.evaluator.values.get(expression.expression().source()) {
            Some(ActivationValue::String(value)) => Ok(value.clone()),
            _ => Err(SyntheticEvaluationError),
        }
    }

    fn evaluate_condition(
        &self,
        expression: &CompiledExpressionTemplate,
        context: &ActivationEvaluationContext<'_>,
    ) -> Result<bool, Self::Error> {
        LogicalActivationSession::evaluate_boolean(self, expression, context)
    }

    fn evaluate_boolean(
        &self,
        expression: &CompiledExpressionTemplate,
        context: &ActivationEvaluationContext<'_>,
    ) -> Result<bool, Self::Error> {
        self.evaluator.record(expression, context);
        if expression.expression().source() == "${{ matrix.allow_failure }}" {
            return Ok(context
                .matrix()
                .and_then(ContextValue::as_object)
                .and_then(|matrix| matrix.get("allow_failure"))
                .and_then(ContextValue::as_boolean)
                .unwrap_or(false));
        }
        self.evaluator
            .booleans
            .get(expression.expression().source())
            .copied()
            .ok_or(SyntheticEvaluationError)
    }

    fn evaluate_positive_integer(
        &self,
        expression: &CompiledExpressionTemplate,
        context: &ActivationEvaluationContext<'_>,
    ) -> Result<u32, Self::Error> {
        self.evaluator.record(expression, context);
        self.evaluator
            .integers
            .get(expression.expression().source())
            .copied()
            .ok_or(SyntheticEvaluationError)
    }

    fn normalize_matrix_key(&self, key: &str) -> String {
        key.to_owned()
    }

    fn matrix_values_equal(&self, left: &ActivationValue, right: &ActivationValue) -> bool {
        left == right
    }

    fn matrix_value_matches(&self, original: &ActivationValue, patch: &ActivationValue) -> bool {
        original == patch
    }
}

fn common_contexts() -> (
    ContextValue,
    ContextValue,
    BTreeMap<String, NeedContext>,
    BTreeMap<String, SecretBinding>,
) {
    let inputs = ContextValue::object(BTreeMap::from([(
        "mode".to_owned(),
        ContextValue::string("test"),
    )]))
    .expect("inputs");
    let vars = ContextValue::object(BTreeMap::from([(
        "region".to_owned(),
        ContextValue::string("local"),
    )]))
    .expect("vars");
    let needs = BTreeMap::from([(
        "prepare".to_owned(),
        NeedContext::new(
            JobConclusion::Success,
            BTreeMap::from([(
                "artifact".to_owned(),
                NeedOutput::new("ready", OutputSensitivity::Public).expect("public output"),
            )]),
        )
        .expect("need"),
    )]);
    let secrets = BTreeMap::from([(
        "TOKEN".to_owned(),
        SecretBinding::new("binding/token")
            .expect("binding")
            .with_version_id("version/1")
            .expect("version"),
    )]);
    (inputs, vars, needs, secrets)
}

fn string_property<'a>(context: &'a ContextValue, key: &str) -> Option<&'a str> {
    context
        .as_object()
        .and_then(|matrix| matrix.get(key))
        .and_then(ContextValue::as_string)
}

#[test]
fn static_matrix_expands_in_axis_order_with_github_include_exclude_semantics() {
    let evaluator = SyntheticEvaluator::default();
    let activator = LogicalJobActivator::new(evaluator);
    let job = job(
        Some(strategy()),
        &["prepare"],
        None,
        Some(CompiledBooleanTemplate::Expression(expression(
            "${{ matrix.allow_failure }}",
            vec![ExpressionContext::Matrix],
        ))),
    );
    let (inputs, vars, needs, secrets) = common_contexts();
    let activation = activator
        .activate(ActivateLogicalJobRequest::new(
            validated_job(&job),
            &inputs,
            &vars,
            &needs,
            &secrets,
            ActivationStatus::Success,
        ))
        .expect("activation");

    assert!(activation.condition_matched());
    assert_eq!(activation.instances().len(), 4);
    let matrices = activation
        .instances()
        .iter()
        .map(|instance| instance.runtime_context().matrix())
        .collect::<Vec<_>>();
    assert_eq!(string_property(matrices[0], "fruit"), Some("apple"));
    assert_eq!(string_property(matrices[0], "animal"), Some("cat"));
    assert_eq!(string_property(matrices[0], "color"), Some("pink"));
    assert_eq!(string_property(matrices[0], "shape"), Some("circle"));
    assert_eq!(string_property(matrices[1], "fruit"), Some("pear"));
    assert_eq!(string_property(matrices[1], "color"), Some("pink"));
    assert_eq!(string_property(matrices[2], "fruit"), Some("banana"));
    assert_eq!(string_property(matrices[2], "animal"), None);
    assert_eq!(string_property(matrices[3], "fruit"), Some("banana"));
    assert_eq!(string_property(matrices[3], "animal"), Some("cat"));

    for (index, instance) in activation.instances().iter().enumerate() {
        assert_eq!(
            instance.identity().matrix_index(),
            u32::try_from(index).expect("bounded index")
        );
        assert_eq!(instance.identity().matrix_total(), 4);
        assert!(!instance.runtime_context().strategy().fail_fast());
        assert_eq!(instance.runtime_context().strategy().max_parallel(), 2);
        assert_eq!(instance.runtime_context().inputs(), &inputs);
        assert_eq!(instance.runtime_context().vars(), &vars);
        assert_eq!(instance.runtime_context().needs(), &needs);
        assert_eq!(instance.runtime_context().secrets(), &secrets);
        assert_eq!(instance.name(), "test");
        assert_eq!(
            instance
                .runner()
                .expect("step runner")
                .labels()
                .iter()
                .map(automata_ci_core::RunnerLabel::as_str)
                .collect::<Vec<_>>(),
            ["linux"]
        );
        assert_eq!(instance.timeout_seconds(), None);
    }
    assert!(activation.instances()[2].continue_on_error());
    assert!(!activation.instances()[0].continue_on_error());
    assert_ne!(
        activation.instances()[0].identity().matrix_digest(),
        activation.instances()[1].identity().matrix_digest()
    );

    let calls = activator.evaluator().calls.lock().expect("calls");
    assert_eq!(calls.len(), 4);
    assert!(calls.iter().all(|call| call.matrix && call.strategy));
    assert_eq!(
        activator
            .evaluator()
            .base_context_conversions
            .load(Ordering::Relaxed),
        1,
        "four expressions must share one prepared base-context conversion",
    );
}

#[test]
fn activation_resolves_matrix_bound_name_runner_and_timeout_per_instance() {
    let timeout_source = "${{ inputs.timeout_minutes }}";
    let plan = job_with_activation_fields(
        Some(strategy()),
        &["prepare"],
        None,
        None,
        Some(CompiledValueTemplate::Expression(expression(
            "${{ matrix.fruit }}",
            vec![ExpressionContext::Matrix],
        ))),
        LogicalRunnerTemplate::new(
            None,
            vec![located(CompiledValueTemplate::Expression(expression(
                "${{ matrix.fruit }}",
                vec![ExpressionContext::Matrix],
            )))],
            span(),
        ),
        Some(LogicalTimeoutTemplate::minutes(
            CompiledPositiveIntegerTemplate::Expression(expression(
                timeout_source,
                vec![ExpressionContext::Inputs],
            )),
        )),
    );
    let evaluator = SyntheticEvaluator {
        integers: BTreeMap::from([(timeout_source.to_owned(), 2)]),
        ..SyntheticEvaluator::default()
    };
    let (inputs, vars, needs, secrets) = common_contexts();
    let activation = LogicalJobActivator::new(evaluator)
        .activate(ActivateLogicalJobRequest::new(
            validated_job(&plan),
            &inputs,
            &vars,
            &needs,
            &secrets,
            ActivationStatus::Success,
        ))
        .expect("activation fields");

    assert_eq!(activation.instances().len(), 4);
    for instance in activation.instances() {
        let fruit = string_property(instance.runtime_context().matrix(), "fruit")
            .expect("fruit matrix value");
        assert_eq!(instance.name(), fruit);
        assert_eq!(
            instance.runner().expect("runner").labels()[0].as_str(),
            fruit
        );
        assert_eq!(instance.timeout_seconds(), Some(120));
    }
}

#[test]
fn implicit_success_skips_failed_needs_but_explicit_status_condition_can_activate() {
    let (inputs, vars, mut needs, secrets) = common_contexts();
    needs.insert(
        "prepare".to_owned(),
        NeedContext::new(JobConclusion::Failure, BTreeMap::new()).expect("failed need"),
    );
    let skipped_job = job(None, &["prepare"], None, None);
    let activation = LogicalJobActivator::new(SyntheticEvaluator::default())
        .activate(ActivateLogicalJobRequest::new(
            validated_job(&skipped_job),
            &inputs,
            &vars,
            &needs,
            &secrets,
            ActivationStatus::Failure,
        ))
        .expect("skip");
    assert!(!activation.condition_matched());
    assert!(activation.instances().is_empty());

    let condition = expression("${{ always() }}", vec![ExpressionContext::Needs]);
    let explicit_job = job(None, &["prepare"], Some(condition), None);
    let evaluator = SyntheticEvaluator {
        booleans: BTreeMap::from([("${{ always() }}".to_owned(), true)]),
        ..SyntheticEvaluator::default()
    };
    let activation = LogicalJobActivator::new(evaluator)
        .activate(ActivateLogicalJobRequest::new(
            validated_job(&explicit_job),
            &inputs,
            &vars,
            &needs,
            &secrets,
            ActivationStatus::Failure,
        ))
        .expect("explicit condition");
    assert!(activation.condition_matched());
    assert_eq!(activation.instances().len(), 1);
    assert_eq!(
        activation.instances()[0].runtime_context().matrix(),
        &ContextValue::empty_object()
    );
}

#[test]
fn whole_dynamic_matrix_preserves_object_axis_order_and_is_deterministic() {
    let source = "${{ needs.prepare.outputs.matrix }}";
    let dynamic = MatrixTemplate::from_expression(
        located(expression(source, vec![ExpressionContext::Needs])),
        span(),
    );
    let strategy = WorkflowStrategyTemplate::new(None, None, dynamic, 16, span());
    let job = job(Some(strategy), &["prepare"], None, None);
    let value = ActivationValue::Object(vec![
        (
            "runtime".to_owned(),
            ActivationValue::Array(vec![
                ActivationValue::string("stable"),
                ActivationValue::string("next"),
            ]),
        ),
        (
            "platform".to_owned(),
            ActivationValue::Array(vec![
                ActivationValue::string("linux"),
                ActivationValue::string("windows"),
            ]),
        ),
        (
            "exclude".to_owned(),
            ActivationValue::Array(vec![ActivationValue::Object(vec![
                ("runtime".to_owned(), ActivationValue::string("next")),
                ("platform".to_owned(), ActivationValue::string("windows")),
            ])]),
        ),
    ]);
    let evaluator = SyntheticEvaluator {
        values: BTreeMap::from([(source.to_owned(), value)]),
        ..SyntheticEvaluator::default()
    };
    let (inputs, vars, needs, secrets) = common_contexts();
    let activator = LogicalJobActivator::new(evaluator);
    let first = activator
        .activate(ActivateLogicalJobRequest::new(
            validated_job(&job),
            &inputs,
            &vars,
            &needs,
            &secrets,
            ActivationStatus::Success,
        ))
        .expect("first");
    let second = activator
        .activate(ActivateLogicalJobRequest::new(
            validated_job(&job),
            &inputs,
            &vars,
            &needs,
            &secrets,
            ActivationStatus::Success,
        ))
        .expect("second");
    assert_eq!(first, second);
    assert_eq!(first.instances().len(), 3);
    assert_eq!(
        string_property(first.instances()[0].runtime_context().matrix(), "runtime"),
        Some("stable")
    );
    assert_eq!(
        string_property(first.instances()[1].runtime_context().matrix(), "platform"),
        Some("windows")
    );
    assert_eq!(
        string_property(first.instances()[2].runtime_context().matrix(), "runtime"),
        Some("next")
    );
    assert_eq!(
        string_property(first.instances()[2].runtime_context().matrix(), "platform"),
        Some("linux")
    );
}

#[test]
fn undeclared_needs_and_malformed_dynamic_shapes_fail_closed() {
    let source = "${{ inputs.matrix }}";
    let strategy = WorkflowStrategyTemplate::new(
        None,
        None,
        MatrixTemplate::from_expression(
            located(expression(source, vec![ExpressionContext::Inputs])),
            span(),
        ),
        16,
        span(),
    );
    let job = job(Some(strategy), &["prepare"], None, None);
    let (inputs, vars, needs, secrets) = common_contexts();
    let evaluator = SyntheticEvaluator {
        values: BTreeMap::from([(
            source.to_owned(),
            ActivationValue::Object(vec![(
                "platform".to_owned(),
                ActivationValue::string("not-an-array"),
            )]),
        )]),
        ..SyntheticEvaluator::default()
    };
    let error = LogicalJobActivator::new(evaluator)
        .activate(ActivateLogicalJobRequest::new(
            validated_job(&job),
            &inputs,
            &vars,
            &needs,
            &secrets,
            ActivationStatus::Success,
        ))
        .expect_err("shape");
    assert!(matches!(
        error,
        LogicalActivationError::ExpectedMatrixArray {
            field: "matrix axis",
            ..
        }
    ));

    let mut unexpected = needs.clone();
    unexpected.insert(
        "undeclared".to_owned(),
        NeedContext::new(JobConclusion::Success, BTreeMap::new()).expect("need"),
    );
    let error = LogicalJobActivator::new(SyntheticEvaluator::default())
        .activate(ActivateLogicalJobRequest::new(
            validated_job(&job),
            &inputs,
            &vars,
            &unexpected,
            &secrets,
            ActivationStatus::Success,
        ))
        .expect_err("undeclared need");
    assert!(matches!(error, LogicalActivationError::UnexpectedNeed));
}

#[test]
fn dynamic_values_obey_text_and_number_safety_limits() {
    let source = "${{ inputs.matrix }}";
    let strategy = WorkflowStrategyTemplate::new(
        None,
        None,
        MatrixTemplate::from_expression(
            located(expression(source, vec![ExpressionContext::Inputs])),
            span(),
        ),
        16,
        span(),
    );
    let job = job(Some(strategy), &["prepare"], None, None);
    let (inputs, vars, needs, secrets) = common_contexts();
    for value in [
        ActivationValue::Object(vec![(
            "platform".to_owned(),
            ActivationValue::Array(vec![ActivationValue::String(
                "x".repeat(automata_ci_core::MAX_MATRIX_TEXT_BYTES + 1),
            )]),
        )]),
        ActivationValue::Object(vec![(
            "platform".to_owned(),
            ActivationValue::Array(vec![ActivationValue::number(f64::INFINITY)]),
        )]),
    ] {
        let evaluator = SyntheticEvaluator {
            values: BTreeMap::from([(source.to_owned(), value)]),
            ..SyntheticEvaluator::default()
        };
        assert!(
            LogicalJobActivator::new(evaluator)
                .activate(ActivateLogicalJobRequest::new(
                    validated_job(&job),
                    &inputs,
                    &vars,
                    &needs,
                    &secrets,
                    ActivationStatus::Success,
                ))
                .is_err()
        );
    }
}

fn numbered_axis(name: &str, count: usize) -> MatrixAxis {
    MatrixAxis::new(
        located(name.to_owned()),
        MatrixAxisValues::Static(
            (0..count)
                .map(|value| literal(&value.to_string()))
                .collect(),
        ),
        span(),
    )
}

fn activate_strategy(
    strategy: WorkflowStrategyTemplate,
) -> Result<
    automata_ci_workflow_service::LogicalJobActivation,
    LogicalActivationError<SyntheticEvaluationError>,
> {
    let plan = job(Some(strategy), &["prepare"], None, None);
    let (inputs, vars, needs, secrets) = common_contexts();
    LogicalJobActivator::new(SyntheticEvaluator::default()).activate(
        ActivateLogicalJobRequest::new(
            validated_job(&plan),
            &inputs,
            &vars,
            &needs,
            &secrets,
            ActivationStatus::Success,
        ),
    )
}

#[test]
fn generated_job_limit_is_applied_after_excludes() {
    let matrix = MatrixTemplate::new(
        vec![numbered_axis("row", 17), numbered_axis("column", 16)],
        MatrixPatchSet::Static(Vec::new()),
        MatrixPatchSet::Static(vec![patch(&[(
            "row",
            MatrixValue::String("16".to_owned()),
        )])]),
        span(),
    );
    let activation = activate_strategy(WorkflowStrategyTemplate::new(
        None,
        None,
        matrix,
        256,
        span(),
    ))
    .expect("272 candidates reduce to 256 generated jobs");
    assert_eq!(activation.instances().len(), 256);

    let matrix = MatrixTemplate::new(
        vec![numbered_axis("row", 17), numbered_axis("column", 16)],
        MatrixPatchSet::Static(Vec::new()),
        MatrixPatchSet::Static(Vec::new()),
        span(),
    );
    let error = activate_strategy(WorkflowStrategyTemplate::new(
        None,
        None,
        matrix,
        256,
        span(),
    ))
    .expect_err("272 generated jobs exceed the final limit");
    assert!(matches!(
        error,
        LogicalActivationError::MatrixExpansionLimitExceeded { maximum: 256 }
    ));
}

#[test]
fn static_matrix_text_does_not_consume_dynamic_output_budget() {
    let value = "x".repeat(automata_ci_core::MAX_MATRIX_TEXT_BYTES);
    let matrix = MatrixTemplate::new(
        vec![MatrixAxis::new(
            located("payload".to_owned()),
            MatrixAxisValues::Static((0..65).map(|_| literal(&value)).collect()),
            span(),
        )],
        MatrixPatchSet::Static(Vec::new()),
        MatrixPatchSet::Static(Vec::new()),
        span(),
    );
    let activation = activate_strategy(WorkflowStrategyTemplate::new(
        None,
        None,
        matrix,
        256,
        span(),
    ))
    .expect("static plan text is bounded by plan/runtime limits");
    assert_eq!(activation.instances().len(), 65);
}

#[test]
fn cumulative_include_width_fails_before_unbounded_growth() {
    let include = (0..automata_ci_core::MAX_MATRIX_OBJECT_ENTRIES)
        .map(|index| {
            let key = format!("field_{index}");
            MatrixPatch::new(
                vec![(
                    located(key),
                    located(MatrixValueTemplate::Literal(MatrixValue::Boolean(true))),
                )],
                span(),
            )
        })
        .collect();
    let matrix = MatrixTemplate::new(
        vec![numbered_axis("axis", 1)],
        MatrixPatchSet::Static(include),
        MatrixPatchSet::Static(Vec::new()),
        span(),
    );
    let error = activate_strategy(WorkflowStrategyTemplate::new(
        None,
        None,
        matrix,
        256,
        span(),
    ))
    .expect_err("expanded object width is bounded");
    assert!(matches!(
        error,
        LogicalActivationError::LimitExceeded {
            field: "expanded matrix entries",
            maximum: automata_ci_core::MAX_MATRIX_OBJECT_ENTRIES,
        }
    ));
}

#[test]
fn successful_aggregate_status_rejects_failed_direct_need() {
    let plan = job(None, &["prepare"], None, None);
    let (inputs, vars, mut needs, secrets) = common_contexts();
    needs.insert(
        "prepare".to_owned(),
        NeedContext::new(JobConclusion::Failure, BTreeMap::new()).expect("failed need"),
    );
    let error = LogicalJobActivator::new(SyntheticEvaluator::default())
        .activate(ActivateLogicalJobRequest::new(
            validated_job(&plan),
            &inputs,
            &vars,
            &needs,
            &secrets,
            ActivationStatus::Success,
        ))
        .expect_err("aggregate status must agree with direct prerequisites");
    assert!(matches!(
        error,
        LogicalActivationError::InconsistentAggregateStatus
    ));
}

#[test]
fn runner_context_omits_secret_derived_prerequisite_outputs() {
    let plan = job(None, &["prepare"], None, None);
    let (inputs, vars, mut needs, secrets) = common_contexts();
    needs.insert(
        "prepare".to_owned(),
        NeedContext::new(
            JobConclusion::Success,
            BTreeMap::from([(
                "sensitive".to_owned(),
                NeedOutput::new(
                    "secret-derived-runner-sentinel",
                    OutputSensitivity::SecretDerived,
                )
                .expect("sensitive output"),
            )]),
        )
        .expect("need"),
    );
    let activation = LogicalJobActivator::new(SyntheticEvaluator::default())
        .activate(ActivateLogicalJobRequest::new(
            validated_job(&plan),
            &inputs,
            &vars,
            &needs,
            &secrets,
            ActivationStatus::Success,
        ))
        .expect("activation");
    let runtime_need = activation.instances()[0]
        .runtime_context()
        .needs()
        .get("prepare")
        .expect("runtime need");
    assert!(runtime_need.outputs().is_empty());
    assert!(!format!("{activation:?}").contains("secret-derived-runner-sentinel"));
}
