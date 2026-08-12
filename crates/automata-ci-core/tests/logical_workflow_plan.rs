use automata_ci_core::{
    CompiledBooleanTemplate, CompiledExpressionTemplate, CompiledPositiveIntegerTemplate,
    CompiledValueTemplate, DeploymentSelection, ExpressionContext, ExpressionDialect,
    ExpressionInstruction, ExpressionLiteral, ExpressionLogical, ExpressionProgram,
    ExpressionSegment, InvocationInputDefault, InvocationInputDefinition, InvocationInputType,
    InvocationSecretDefinition, Located, LogicalJobKind, LogicalJobOutputDefinition,
    LogicalJobOutputSource, LogicalJobTemplate, LogicalOutputMergePolicy, LogicalResultReference,
    LogicalResultValue, LogicalRunStepTemplate, LogicalRunnerTemplate, LogicalStepKind,
    LogicalStepTemplate, LogicalTimeoutTemplate, LogicalTimeoutUnit, MAX_INVOCATION_DEFINITIONS,
    MAX_RUNTIME_CONTEXT_IDENTIFIER_BYTES, MAX_TEMPLATE_BYTES, MatrixAxis, MatrixAxisValues,
    MatrixPatch, MatrixPatchSet, MatrixTemplate, MatrixValue, MatrixValueTemplate,
    OutputSensitivity, PlanEvaluationPhase, PlanExpression, PlanSourceLocation, PlanSourceOrigin,
    PlanSourceSpan, ReusableInputBinding, ReusableSecretBinding, ReusableSecretForwarding,
    ReusableWorkflowInvocation, StepJobTemplate, WORKFLOW_PLAN_SCHEMA_VERSION,
    WorkflowEventProvenance, WorkflowInputKey, WorkflowInvocationContract, WorkflowJobKey,
    WorkflowOutputDefinition, WorkflowOutputKey, WorkflowPlan, WorkflowPlanVersion,
    WorkflowSecretKey, WorkflowSourceProvenance, WorkflowStepKey, WorkflowStrategyTemplate,
};

fn span() -> PlanSourceSpan {
    PlanSourceSpan::new(
        "pipeline.yml",
        PlanSourceLocation::new(0, 1, 1).expect("location"),
        PlanSourceLocation::new(1, 1, 2).expect("location"),
    )
    .expect("span")
}

fn located<T>(value: T) -> Located<T> {
    Located::new(value, span())
}

fn expression(
    source: &str,
    phase: PlanEvaluationPhase,
    contexts: Vec<ExpressionContext>,
) -> CompiledExpressionTemplate {
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
        phase,
        PlanExpression::new(
            source,
            vec![ExpressionSegment::Evaluation(source.to_owned())],
        )
        .expect("expression"),
        vec![program],
        contexts,
    )
}

fn value_expression(
    source: &str,
    phase: PlanEvaluationPhase,
    contexts: Vec<ExpressionContext>,
) -> CompiledValueTemplate {
    CompiledValueTemplate::Expression(expression(source, phase, contexts))
}

fn key(value: &str) -> WorkflowJobKey {
    WorkflowJobKey::new(value).expect("job key")
}

fn output_key(value: &str) -> WorkflowOutputKey {
    WorkflowOutputKey::new(value).expect("output key")
}

fn build_job() -> LogicalJobTemplate {
    let step = LogicalStepTemplate::builder(
        located(WorkflowStepKey::new("position/00000000").expect("step key")),
        LogicalStepKind::Run(Box::new(LogicalRunStepTemplate::new(
            located(CompiledValueTemplate::Literal("make package".to_owned())),
            None,
            None,
        ))),
        span(),
    )
    .id(Some(located("package".to_owned())))
    .timeout(Some(located(LogicalTimeoutTemplate::minutes(
        CompiledPositiveIntegerTemplate::Expression(expression(
            "${{ env.STEP_TIMEOUT }}",
            PlanEvaluationPhase::JobExecution,
            vec![ExpressionContext::Env],
        )),
    ))))
    .build()
    .expect("step template");
    let runner = LogicalRunnerTemplate::new(
        None,
        vec![located(value_expression(
            "${{ matrix.platform }}",
            PlanEvaluationPhase::JobActivation,
            vec![ExpressionContext::Matrix],
        ))],
        span(),
    );
    let matrix = MatrixTemplate::new(
        vec![MatrixAxis::new(
            located("platform".to_owned()),
            MatrixAxisValues::Static(vec![
                located(MatrixValueTemplate::Literal(MatrixValue::String(
                    "linux".to_owned(),
                ))),
                located(MatrixValueTemplate::Literal(MatrixValue::String(
                    "windows".to_owned(),
                ))),
            ]),
            span(),
        )],
        MatrixPatchSet::Static(Vec::new()),
        MatrixPatchSet::Static(Vec::new()),
        span(),
    );
    let strategy = WorkflowStrategyTemplate::new(
        Some(located(CompiledBooleanTemplate::Literal(true))),
        Some(located(CompiledPositiveIntegerTemplate::Literal(2))),
        matrix,
        8,
        span(),
    );
    let output = LogicalJobOutputDefinition::new(
        located(output_key("artifact")),
        LogicalJobOutputSource::Template(located(value_expression(
            "${{ steps.package.outputs.digest }}",
            PlanEvaluationPhase::JobFinalization,
            vec![ExpressionContext::Steps],
        ))),
        LogicalOutputMergePolicy::LastSuccessfulCompletion,
        OutputSensitivity::Public,
        span(),
    );
    LogicalJobTemplate::builder(
        located(key("build")),
        0,
        LogicalJobKind::Steps(StepJobTemplate::new(runner, vec![step], span())),
        span(),
    )
    .strategy(Some(strategy))
    .timeout(Some(located(LogicalTimeoutTemplate::minutes(
        CompiledPositiveIntegerTemplate::Expression(expression(
            "${{ matrix.timeout }}",
            PlanEvaluationPhase::JobActivation,
            vec![ExpressionContext::Matrix],
        )),
    ))))
    .outputs(vec![output])
    .deployment(Some(DeploymentSelection::new(
        located(value_expression(
            "${{ matrix.platform }}",
            PlanEvaluationPhase::JobActivation,
            vec![ExpressionContext::Matrix],
        )),
        Some(located(value_expression(
            "${{ steps.package.outputs.url }}",
            PlanEvaluationPhase::JobFinalization,
            vec![ExpressionContext::Steps],
        ))),
        span(),
    )))
    .build()
    .expect("build job")
}

fn publish_job() -> LogicalJobTemplate {
    let reference = LogicalResultReference::new(
        key("build"),
        LogicalResultValue::Output(output_key("artifact")),
    );
    let invocation = ReusableWorkflowInvocation::new(
        located("org/project/.github/workflows/release.yml@main".to_owned()),
        vec![ReusableInputBinding::new(
            located(WorkflowInputKey::new("artifact").expect("input key")),
            located(value_expression(
                "${{ needs.build.outputs.artifact }}",
                PlanEvaluationPhase::JobActivation,
                vec![ExpressionContext::Needs],
            )),
        )],
        ReusableSecretForwarding::Mapping(vec![ReusableSecretBinding::new(
            located(WorkflowSecretKey::new("token").expect("secret key")),
            located(WorkflowSecretKey::new("release_token").expect("secret key")),
        )]),
        span(),
    );
    LogicalJobTemplate::builder(
        located(key("publish")),
        1,
        LogicalJobKind::ReusableWorkflow(invocation),
        span(),
    )
    .needs(vec![located(key("build"))])
    .result_references(vec![located(reference)])
    .condition(Some(located(expression(
        "${{ needs.build.result == 'success' }}",
        PlanEvaluationPhase::JobActivation,
        vec![ExpressionContext::Needs],
    ))))
    .outputs(vec![LogicalJobOutputDefinition::new(
        located(output_key("release")),
        LogicalJobOutputSource::InvocationOutput(located(output_key("release"))),
        LogicalOutputMergePolicy::SingleInstance,
        OutputSensitivity::Public,
        span(),
    )])
    .build()
    .expect("publish job")
}

fn valid_plan() -> WorkflowPlan {
    let output_reference = LogicalResultReference::new(
        key("publish"),
        LogicalResultValue::Output(output_key("release")),
    );
    let contract = WorkflowInvocationContract::new(
        vec![InvocationInputDefinition::new(
            located(WorkflowInputKey::new("channel").expect("input key")),
            located(InvocationInputType::String),
            false,
            Some(located(InvocationInputDefault::String("stable".to_owned()))),
            Some(located("Release channel".to_owned())),
            span(),
        )],
        vec![InvocationSecretDefinition::new(
            located(WorkflowSecretKey::new("release_token").expect("secret key")),
            true,
            None,
            span(),
        )],
        vec![WorkflowOutputDefinition::new(
            located(output_key("published_release")),
            located(value_expression(
                "${{ jobs.publish.outputs.release }}",
                PlanEvaluationPhase::WorkflowFinalization,
                vec![ExpressionContext::Jobs],
            )),
            vec![located(output_reference)],
            OutputSensitivity::Public,
            None,
            span(),
        )],
        span(),
    );
    WorkflowPlan::logical_builder(
        WorkflowSourceProvenance::new(
            "github",
            "pipeline.yml",
            PlanSourceOrigin::Memory {
                name: "pipeline.yml".to_owned(),
            },
        ),
        WorkflowEventProvenance::new("github", "workflow_call"),
        vec![build_job(), publish_job()],
        span(),
    )
    .invocation(Some(contract))
    .run_name(Some(located(CompiledValueTemplate::Literal(
        "release".to_owned(),
    ))))
    .build()
    .expect("valid logical plan")
}

fn literal_matrix_value(value: MatrixValue) -> Located<MatrixValueTemplate> {
    located(MatrixValueTemplate::Literal(value))
}

fn matrix_axis(name: &str, values: Vec<MatrixValue>) -> MatrixAxis {
    MatrixAxis::new(
        located(name.to_owned()),
        MatrixAxisValues::Static(
            values
                .into_iter()
                .map(literal_matrix_value)
                .collect::<Vec<_>>(),
        ),
        span(),
    )
}

fn plan_value_with_matrix(matrix: &MatrixTemplate, expansion_limit: u16) -> serde_json::Value {
    let mut encoded = serde_json::to_value(valid_plan()).expect("serialize");
    encoded["logical"]["jobs"][0]["strategy"]["matrix"] =
        serde_json::to_value(matrix).expect("matrix");
    encoded["logical"]["jobs"][0]["strategy"]["expansion_limit"] =
        serde_json::json!(expansion_limit);
    encoded
}

#[test]
fn logical_plan_round_trips_with_strategy_contracts_and_result_references() {
    let plan = valid_plan();
    assert_eq!(plan.version(), WorkflowPlanVersion::v1());
    assert_eq!(plan.version().get(), WORKFLOW_PLAN_SCHEMA_VERSION);
    assert_eq!(plan.jobs().len(), 2);
    assert_eq!(plan.logical().jobs(), plan.jobs());
    assert_eq!(plan.jobs()[1].needs()[0].value().as_str(), "build");
    assert!(plan.job(&key("build")).is_some());
    let timeout = plan.jobs()[0].timeout().expect("job timeout");
    assert_eq!(timeout.value().unit(), LogicalTimeoutUnit::Minutes);
    assert_eq!(timeout.value().unit().seconds_multiplier(), 60);

    let encoded = serde_json::to_value(&plan).expect("serialize");
    for removed in [
        "jobs",
        "run_name",
        "permissions",
        "environment",
        "run_defaults",
        "concurrency",
    ] {
        assert!(
            encoded.get(removed).is_none(),
            "removed root field {removed}"
        );
    }
    assert!(encoded.get("logical").is_some());
    let decoded: WorkflowPlan = serde_json::from_value(encoded).expect("deserialize");
    assert_eq!(decoded, plan);
}

#[test]
fn current_plan_requires_an_explicit_resource_selection() {
    let encoded = serde_json::to_vec(&valid_plan()).expect("serialize plan");
    let value: serde_json::Value = serde_json::from_slice(&encoded).expect("decode JSON value");
    assert!(
        value["logical"]["jobs"][0]["execution"]["value"]
            .get("resources")
            .is_some_and(serde_json::Value::is_null),
        "policy defaults are represented by an explicit null resource selection"
    );

    let decoded: WorkflowPlan = serde_json::from_slice(&encoded).expect("decode workflow plan");
    assert_eq!(
        serde_json::to_vec(&decoded).expect("re-encode plan"),
        encoded
    );

    let mut missing = value;
    missing["logical"]["jobs"][0]["execution"]["value"]
        .as_object_mut()
        .expect("step-job object")
        .remove("resources");
    assert!(
        serde_json::from_value::<WorkflowPlan>(missing).is_err(),
        "documents predating the current resource-aware plan shape must fail closed"
    );
}

#[test]
fn only_the_current_version_and_required_logical_body_decode() {
    let encoded = serde_json::to_value(valid_plan()).expect("serialize");

    for version in [0, 1, 3] {
        assert!(serde_json::from_value::<WorkflowPlanVersion>(serde_json::json!(version)).is_err());
        let mut noncurrent = encoded.clone();
        noncurrent["version"] = serde_json::json!(version);
        assert!(
            serde_json::from_value::<WorkflowPlan>(noncurrent).is_err(),
            "workflow-plan version {version} must fail closed"
        );
    }
    assert!(WorkflowPlanVersion::new(1).is_err());
    assert_eq!(
        WorkflowPlanVersion::new(WORKFLOW_PLAN_SCHEMA_VERSION).expect("current"),
        WorkflowPlanVersion::current()
    );

    let mut missing_body = encoded;
    missing_body
        .as_object_mut()
        .expect("plan object")
        .remove("logical");
    assert!(serde_json::from_value::<WorkflowPlan>(missing_body).is_err());

    let mut missing_services = serde_json::to_value(valid_plan()).expect("serialize");
    missing_services["logical"]["jobs"][0]["execution"]["value"]
        .as_object_mut()
        .expect("step job")
        .remove("services");
    assert!(serde_json::from_value::<WorkflowPlan>(missing_services).is_err());
}

#[test]
fn phase_and_declared_context_availability_are_revalidated() {
    let mut encoded = serde_json::to_value(valid_plan()).expect("serialize");
    encoded["logical"]["jobs"][1]["condition"]["value"]["phase"] = serde_json::json!("admission");
    assert!(serde_json::from_value::<WorkflowPlan>(encoded).is_err());

    let mut noncanonical = serde_json::to_value(valid_plan()).expect("serialize");
    noncanonical["logical"]["jobs"][1]["condition"]["value"]["contexts"] =
        serde_json::json!(["needs", "github"]);
    assert!(serde_json::from_value::<WorkflowPlan>(noncanonical).is_err());
}

#[test]
fn compiled_programs_remain_aligned_with_lossless_evaluation_segments() {
    let plan = valid_plan();
    let condition = plan.jobs()[1].condition().expect("condition");
    assert_eq!(condition.value().programs().len(), 1);
    assert_eq!(
        condition.value().programs()[0].source(),
        condition.value().expression().segments()[0].source()
    );

    let mut missing = serde_json::to_value(&plan).expect("serialize");
    missing["logical"]["jobs"][1]["condition"]["value"]["programs"] = serde_json::json!([]);
    let error = serde_json::from_value::<WorkflowPlan>(missing).expect_err("program count");
    assert!(error.to_string().contains("program count"));

    let mut mismatched = serde_json::to_value(plan).expect("serialize");
    mismatched["logical"]["jobs"][1]["condition"]["value"]["programs"][0]["source"] =
        serde_json::json!("${{ always() }}");
    let error = serde_json::from_value::<WorkflowPlan>(mismatched).expect_err("program source");
    assert!(error.to_string().contains("does not preserve"));
}

#[test]
fn matrix_limits_and_source_order_are_enforced_before_activation() {
    let oversized_candidates = MatrixTemplate::new(
        vec![
            matrix_axis(
                "first",
                (0..17)
                    .map(|value| MatrixValue::Number(value.to_string()))
                    .collect(),
            ),
            matrix_axis(
                "second",
                (0..256)
                    .map(|value| MatrixValue::Number(value.to_string()))
                    .collect(),
            ),
        ],
        MatrixPatchSet::Static(Vec::new()),
        MatrixPatchSet::Static(Vec::new()),
        span(),
    );
    assert!(
        serde_json::from_value::<WorkflowPlan>(plan_value_with_matrix(&oversized_candidates, 256))
            .is_err()
    );

    let mut noncanonical_order = serde_json::to_value(valid_plan()).expect("serialize");
    noncanonical_order["logical"]["jobs"][1]["source_order"] = serde_json::json!(7);
    assert!(serde_json::from_value::<WorkflowPlan>(noncanonical_order).is_err());
}

#[test]
fn static_product_may_exceed_job_limit_when_excludes_reduce_the_emitted_set() {
    let mut first_values = vec![MatrixValue::String("drop".to_owned())];
    first_values.extend((0..16).map(|value| MatrixValue::String(format!("keep-{value}"))));
    let matrix = MatrixTemplate::new(
        vec![
            matrix_axis("first", first_values),
            matrix_axis(
                "second",
                (0..16)
                    .map(|value| MatrixValue::Number(value.to_string()))
                    .collect(),
            ),
        ],
        MatrixPatchSet::Static(Vec::new()),
        MatrixPatchSet::Static(vec![MatrixPatch::new(
            vec![(
                located("first".to_owned()),
                literal_matrix_value(MatrixValue::String("drop".to_owned())),
            )],
            span(),
        )]),
        span(),
    );

    let plan = serde_json::from_value::<WorkflowPlan>(plan_value_with_matrix(&matrix, 256))
        .expect("272 candidates with one 16-row slice excluded are plan-valid");
    assert_eq!(
        plan.jobs()[0]
            .strategy()
            .expect("strategy")
            .matrix()
            .axes()
            .iter()
            .map(|axis| match axis.values() {
                MatrixAxisValues::Static(values) => values.len(),
                MatrixAxisValues::Expression(_) => 0,
            })
            .product::<usize>(),
        272
    );
}

#[test]
fn matrix_root_keys_match_runtime_identifier_bounds_without_provider_normalization() {
    let matrix_with_keys = |axis: &str, patch: &str| {
        MatrixTemplate::new(
            vec![matrix_axis(
                axis,
                vec![MatrixValue::String("linux".to_owned())],
            )],
            MatrixPatchSet::Static(Vec::new()),
            MatrixPatchSet::Static(vec![MatrixPatch::new(
                vec![(
                    located(patch.to_owned()),
                    literal_matrix_value(MatrixValue::String("linux".to_owned())),
                )],
                span(),
            )]),
            span(),
        )
    };

    let boundary = "k".repeat(MAX_RUNTIME_CONTEXT_IDENTIFIER_BYTES);
    assert!(
        serde_json::from_value::<WorkflowPlan>(plan_value_with_matrix(
            &matrix_with_keys(&boundary, &boundary),
            256,
        ))
        .is_ok()
    );
    assert!(
        serde_json::from_value::<WorkflowPlan>(plan_value_with_matrix(
            &matrix_with_keys("OS", "os"),
            256,
        ))
        .is_ok(),
        "provider-specific key equivalence belongs to activation"
    );

    for invalid in [
        " padded".to_owned(),
        "control\n".to_owned(),
        "k".repeat(MAX_RUNTIME_CONTEXT_IDENTIFIER_BYTES + 1),
    ] {
        assert!(
            serde_json::from_value::<WorkflowPlan>(plan_value_with_matrix(
                &matrix_with_keys(&invalid, "axis"),
                256,
            ))
            .is_err(),
            "invalid axis root key was accepted"
        );
        assert!(
            serde_json::from_value::<WorkflowPlan>(plan_value_with_matrix(
                &matrix_with_keys("axis", &invalid),
                256,
            ))
            .is_err(),
            "invalid patch root key was accepted"
        );
    }
}

#[test]
fn nested_matrix_object_keys_match_runtime_identifier_bounds() {
    let matrix_with_key = |key: String| {
        MatrixTemplate::new(
            vec![matrix_axis(
                "configuration",
                vec![MatrixValue::Object(vec![(
                    key,
                    MatrixValue::String("value".to_owned()),
                )])],
            )],
            MatrixPatchSet::Static(Vec::new()),
            MatrixPatchSet::Static(Vec::new()),
            span(),
        )
    };

    assert!(
        serde_json::from_value::<WorkflowPlan>(plan_value_with_matrix(
            &matrix_with_key("k".repeat(MAX_RUNTIME_CONTEXT_IDENTIFIER_BYTES)),
            256,
        ))
        .is_ok()
    );
    for invalid in [
        " padded".to_owned(),
        "control\n".to_owned(),
        "k".repeat(MAX_RUNTIME_CONTEXT_IDENTIFIER_BYTES + 1),
    ] {
        assert!(
            serde_json::from_value::<WorkflowPlan>(plan_value_with_matrix(
                &matrix_with_key(invalid),
                256,
            ))
            .is_err(),
            "invalid nested object key was accepted"
        );
    }
}

#[test]
fn static_matrix_numbers_must_be_finite_binary64_values() {
    let matrix_with_number = |number: &str| {
        MatrixTemplate::new(
            vec![matrix_axis(
                "version",
                vec![MatrixValue::Number(number.to_owned())],
            )],
            MatrixPatchSet::Static(Vec::new()),
            MatrixPatchSet::Static(Vec::new()),
            span(),
        )
    };
    assert!(
        serde_json::from_value::<WorkflowPlan>(plan_value_with_matrix(
            &matrix_with_number("1e308"),
            256,
        ))
        .is_ok()
    );
    assert!(
        serde_json::from_value::<WorkflowPlan>(plan_value_with_matrix(
            &matrix_with_number("1e999"),
            256,
        ))
        .is_err()
    );
}

#[test]
fn generic_positive_integer_zero_error_names_the_actual_field() {
    let mut encoded = serde_json::to_value(valid_plan()).expect("serialize");
    encoded["logical"]["jobs"][0]["strategy"]["max_parallel"]["value"] =
        serde_json::json!({"kind": "literal", "value": 0});
    let error = serde_json::from_value::<WorkflowPlan>(encoded).expect_err("zero max-parallel");
    assert_eq!(
        error.to_string(),
        "strategy max-parallel must be greater than zero"
    );
}

#[test]
fn invocation_defaults_and_result_edges_are_cross_validated() {
    let mut wrong_default = serde_json::to_value(valid_plan()).expect("serialize");
    wrong_default["logical"]["invocation"]["inputs"][0]["default"]["value"] =
        serde_json::json!({"kind": "boolean", "value": true});
    assert!(serde_json::from_value::<WorkflowPlan>(wrong_default).is_err());

    let mut undeclared_need = serde_json::to_value(valid_plan()).expect("serialize");
    undeclared_need["logical"]["jobs"][1]["needs"] = serde_json::json!([]);
    assert!(serde_json::from_value::<WorkflowPlan>(undeclared_need).is_err());

    let mut unknown_output = serde_json::to_value(valid_plan()).expect("serialize");
    unknown_output["logical"]["jobs"][1]["result_references"][0]["value"]["value"] =
        serde_json::json!({"kind": "output", "value": "missing"});
    assert!(serde_json::from_value::<WorkflowPlan>(unknown_output).is_err());
}

#[test]
fn current_logical_dependencies_must_exist_and_remain_acyclic() {
    let mut unknown = serde_json::to_value(valid_plan()).expect("serialize");
    unknown["logical"]["jobs"][1]["needs"][0]["value"] = serde_json::json!("missing");
    let error = serde_json::from_value::<WorkflowPlan>(unknown).expect_err("unknown dependency");
    assert!(error.to_string().contains("needs unknown job"));

    let mut self_dependency = serde_json::to_value(valid_plan()).expect("serialize");
    self_dependency["logical"]["jobs"][1]["needs"][0]["value"] = serde_json::json!("publish");
    let error =
        serde_json::from_value::<WorkflowPlan>(self_dependency).expect_err("self dependency");
    assert!(error.to_string().contains("cannot need itself"));

    let mut cycle = serde_json::to_value(valid_plan()).expect("serialize");
    cycle["logical"]["jobs"][0]["needs"] =
        serde_json::json!([serde_json::to_value(located(key("publish"))).expect("dependency")]);
    let error = serde_json::from_value::<WorkflowPlan>(cycle).expect_err("dependency cycle");
    assert!(error.to_string().contains("dependency cycle"));
}

#[test]
fn direct_secret_dependencies_cannot_be_declared_public_outputs() {
    let mut encoded = serde_json::to_value(valid_plan()).expect("serialize");
    encoded["logical"]["jobs"][0]["outputs"][0]["source"]["value"]["value"]["value"]["contexts"] =
        serde_json::json!(["secrets"]);
    assert!(serde_json::from_value::<WorkflowPlan>(encoded).is_err());
}

#[test]
fn whole_matrix_expressions_are_distinct_and_activation_bounded() {
    let matrix = MatrixTemplate::from_expression(
        located(expression(
            "${{ inputs.matrix }}",
            PlanEvaluationPhase::JobActivation,
            vec![ExpressionContext::Inputs],
        )),
        span(),
    );
    assert!(matrix.expression().is_some());

    let mut encoded = serde_json::to_value(valid_plan()).expect("serialize");
    encoded["logical"]["jobs"][0]["strategy"]["matrix"] =
        serde_json::to_value(&matrix).expect("matrix");
    let decoded: WorkflowPlan = serde_json::from_value(encoded.clone()).expect("whole matrix");
    assert!(
        decoded.jobs()[0]
            .strategy()
            .expect("strategy")
            .matrix()
            .expression()
            .is_some()
    );

    encoded["logical"]["jobs"][0]["strategy"]["matrix"]["axes"] = serde_json::json!([{
        "name": {"value": "platform", "span": serde_json::to_value(span()).expect("span")},
        "values": {"kind": "static", "value": [{
            "value": {"kind": "literal", "value": {"kind": "string", "value": "linux"}},
            "span": serde_json::to_value(span()).expect("span")
        }]},
        "span": serde_json::to_value(span()).expect("span")
    }]);
    assert!(serde_json::from_value::<WorkflowPlan>(encoded).is_err());
}

#[test]
fn env_context_is_available_only_at_execution_or_later() {
    let mut encoded = serde_json::to_value(valid_plan()).expect("serialize");
    encoded["logical"]["jobs"][0]["execution"]["value"]["steps"][0]["execution"]["value"]["script"]
        ["value"] = serde_json::to_value(value_expression(
        "${{ env.COMMAND }}",
        PlanEvaluationPhase::JobExecution,
        vec![ExpressionContext::Env],
    ))
    .expect("value template");
    assert!(serde_json::from_value::<WorkflowPlan>(encoded.clone()).is_ok());

    encoded["logical"]["jobs"][0]["execution"]["value"]["steps"][0]["execution"]["value"]["script"]
        ["value"]["value"]["phase"] = serde_json::json!("job_activation");
    assert!(serde_json::from_value::<WorkflowPlan>(encoded).is_err());
}

#[test]
fn per_item_and_collection_bounds_fail_before_allocation_amplifies() {
    let mut oversized_template = serde_json::to_value(valid_plan()).expect("serialize");
    oversized_template["logical"]["jobs"][0]["execution"]["value"]["steps"][0]["execution"]["value"]
        ["script"]["value"]["value"] = serde_json::json!("x".repeat(MAX_TEMPLATE_BYTES + 1));
    assert!(serde_json::from_value::<WorkflowPlan>(oversized_template).is_err());

    let mut oversized_contract = serde_json::to_value(valid_plan()).expect("serialize");
    let input = oversized_contract["logical"]["invocation"]["inputs"][0].clone();
    oversized_contract["logical"]["invocation"]["inputs"] =
        serde_json::Value::Array(vec![input; MAX_INVOCATION_DEFINITIONS + 1]);
    assert!(serde_json::from_value::<WorkflowPlan>(oversized_contract).is_err());
}

#[test]
fn timeout_units_survive_deferred_values_and_literal_scaling_is_checked() {
    let plan = valid_plan();
    let step_timeout = match plan.jobs()[0].execution() {
        LogicalJobKind::Steps(steps) => steps.steps()[0].timeout().expect("step timeout"),
        LogicalJobKind::ReusableWorkflow(_) => panic!("expected steps"),
    };
    assert_eq!(step_timeout.value().unit(), LogicalTimeoutUnit::Minutes);
    assert!(matches!(
        step_timeout.value().value(),
        CompiledPositiveIntegerTemplate::Expression(_)
    ));

    let mut overflow = serde_json::to_value(plan).expect("serialize");
    overflow["logical"]["jobs"][0]["timeout"]["value"]["value"] =
        serde_json::json!({"kind": "literal", "value": u32::MAX});
    assert!(serde_json::from_value::<WorkflowPlan>(overflow).is_err());

    let mut zero = serde_json::to_value(valid_plan()).expect("serialize");
    zero["logical"]["jobs"][0]["timeout"]["value"]["value"] =
        serde_json::json!({"kind": "literal", "value": 0});
    assert!(serde_json::from_value::<WorkflowPlan>(zero).is_err());
}

#[test]
fn unknown_fields_fail_closed_inside_v2_boundaries() {
    let encoded = serde_json::to_value(valid_plan()).expect("serialize");
    for pointer in [
        "",
        "/source",
        "/source/origin",
        "/event",
        "/span",
        "/span/start",
        "/logical",
        "/logical/invocation",
        "/logical/invocation/inputs/0",
        "/logical/jobs/0",
        "/logical/jobs/0/strategy",
        "/logical/jobs/0/strategy/matrix",
        "/logical/jobs/0/execution",
        "/logical/jobs/0/execution/value",
        "/logical/jobs/0/execution/value/steps/0",
    ] {
        let mut adversarial = encoded.clone();
        adversarial
            .pointer_mut(pointer)
            .and_then(serde_json::Value::as_object_mut)
            .expect("object pointer")
            .insert("future_field".to_owned(), serde_json::json!(true));
        assert!(
            serde_json::from_value::<WorkflowPlan>(adversarial).is_err(),
            "unknown field at {pointer} was discarded"
        );
    }
}
