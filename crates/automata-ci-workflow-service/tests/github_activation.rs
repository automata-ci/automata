use std::{collections::BTreeMap, sync::Arc, thread};

use automata_ci_core::{
    CompiledBooleanTemplate, CompiledExpressionTemplate, CompiledPositiveIntegerTemplate,
    CompiledValueTemplate, ContextValue, ExpressionContext, ExpressionProgram, ExpressionSegment,
    JobConclusion, Located, LogicalJobKind, LogicalRunStepTemplate, LogicalRunnerTemplate,
    LogicalStepKind, LogicalStepTemplate, MatrixTemplate, NeedContext, NeedOutput,
    OutputSensitivity, PlanEvaluationPhase, PlanExpression, PlanSourceLocation, PlanSourceOrigin,
    PlanSourceSpan, StepJobTemplate, WorkflowEventProvenance, WorkflowJobKey, WorkflowPlan,
    WorkflowSourceProvenance, WorkflowStepKey, WorkflowStrategyTemplate,
};
use automata_ci_expression_github::{GithubObject, GithubValue};
use automata_ci_workflow_github::{GithubConditionCompiler, GithubConditionPhase};
use automata_ci_workflow_service::{
    ActivateLogicalJobRequest, ActivationStatus, GithubActivationContext,
    GithubActivationEvaluationError, GithubLogicalActivationEvaluator, LogicalActivationError,
    LogicalJobActivation, LogicalJobActivator, ValidatedLogicalPlan,
};

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

fn compiled(
    source: &str,
    program: ExpressionProgram,
    contexts: Vec<ExpressionContext>,
) -> CompiledExpressionTemplate {
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

fn condition(source: &str, contexts: Vec<ExpressionContext>) -> CompiledExpressionTemplate {
    let program = GithubConditionCompiler::default()
        .compile_condition(Some(source), GithubConditionPhase::Job)
        .expect("condition program");
    compiled(source, program, contexts)
}

fn value_expression(source: &str, contexts: Vec<ExpressionContext>) -> CompiledExpressionTemplate {
    let program = GithubConditionCompiler::default()
        .compile_value_expression(source, GithubConditionPhase::Job)
        .expect("value program");
    compiled(source, program, contexts)
}

fn job(
    needs: &[&str],
    condition: Option<CompiledExpressionTemplate>,
    strategy: Option<WorkflowStrategyTemplate>,
) -> WorkflowPlan {
    fn execution() -> StepJobTemplate {
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
        StepJobTemplate::new(
            LogicalRunnerTemplate::new(
                None,
                vec![located(CompiledValueTemplate::Literal("linux".to_owned()))],
                span(),
            ),
            vec![step],
            span(),
        )
    }
    let consumer = automata_ci_core::LogicalJobTemplate::builder(
        located(WorkflowJobKey::new("consumer").expect("job key")),
        u32::try_from(needs.len()).expect("bounded needs"),
        LogicalJobKind::Steps(execution()),
        span(),
    )
    .needs(
        needs
            .iter()
            .map(|value| located(WorkflowJobKey::new(*value).expect("need key")))
            .collect(),
    )
    .condition(condition.map(located))
    .strategy(strategy)
    .build()
    .expect("job");
    let mut jobs = needs
        .iter()
        .enumerate()
        .map(|(index, key)| {
            automata_ci_core::LogicalJobTemplate::builder(
                located(WorkflowJobKey::new(*key).expect("need key")),
                u32::try_from(index).expect("bounded needs"),
                LogicalJobKind::Steps(execution()),
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

fn github() -> GithubActivationContext {
    GithubActivationContext::new(GithubValue::object(
        GithubObject::new(vec![
            (
                "event_name".to_owned(),
                GithubValue::string("workflow_dispatch"),
            ),
            (
                "event".to_owned(),
                GithubValue::object(
                    GithubObject::new(vec![("mode".to_owned(), GithubValue::string("synthetic"))])
                        .expect("event"),
                ),
            ),
        ])
        .expect("github"),
    ))
    .expect("activation-safe github context")
}

fn public_output(value: &str) -> NeedOutput {
    NeedOutput::new(value, OutputSensitivity::Public).expect("public output")
}

fn inputs(entries: &[(&str, ContextValue)]) -> ContextValue {
    ContextValue::object(
        entries
            .iter()
            .map(|(key, value)| ((*key).to_owned(), value.clone()))
            .collect(),
    )
    .expect("inputs")
}

fn dynamic_matrix_plan(
    needs: &[&str],
    source: &str,
    contexts: Vec<ExpressionContext>,
) -> WorkflowPlan {
    let strategy = WorkflowStrategyTemplate::new(
        None,
        None,
        MatrixTemplate::from_expression(located(value_expression(source, contexts)), span()),
        32,
        span(),
    );
    job(needs, None, Some(strategy))
}

fn activate(
    plan: &WorkflowPlan,
    inputs: &ContextValue,
    needs: &BTreeMap<String, NeedContext>,
    status: ActivationStatus,
) -> Result<LogicalJobActivation, LogicalActivationError<GithubActivationEvaluationError>> {
    let evaluator = GithubLogicalActivationEvaluator::new(github());
    LogicalJobActivator::new(evaluator).activate(ActivateLogicalJobRequest::new(
        ValidatedLogicalPlan::new(plan)
            .expect("validated logical plan")
            .job(&WorkflowJobKey::new("consumer").expect("consumer key"))
            .expect("validated logical job"),
        inputs,
        &ContextValue::empty_object(),
        needs,
        &BTreeMap::new(),
        status,
    ))
}

#[test]
fn durable_implicit_success_guard_and_explicit_status_functions_use_need_status() {
    let source = "${{ needs.build.outputs.ready == 'yes' }}";
    let implicit = job(
        &["build"],
        Some(condition(source, vec![ExpressionContext::Needs])),
        None,
    );
    let successful = BTreeMap::from([(
        "build".to_owned(),
        NeedContext::new(
            JobConclusion::Success,
            BTreeMap::from([("ready".to_owned(), public_output("yes"))]),
        )
        .expect("need"),
    )]);
    assert!(
        activate(
            &implicit,
            &ContextValue::empty_object(),
            &successful,
            ActivationStatus::Success,
        )
        .expect("successful condition")
        .condition_matched()
    );

    for result in [JobConclusion::Failure, JobConclusion::Skipped] {
        let needs = BTreeMap::from([(
            "build".to_owned(),
            NeedContext::new(
                result,
                BTreeMap::from([("ready".to_owned(), public_output("yes"))]),
            )
            .expect("need"),
        )]);
        assert!(
            !activate(
                &implicit,
                &ContextValue::empty_object(),
                &needs,
                match result {
                    JobConclusion::Failure => ActivationStatus::Failure,
                    JobConclusion::Skipped => ActivationStatus::Skipped,
                    _ => unreachable!("bounded test results"),
                },
            )
            .expect("implicit status")
            .condition_matched()
        );
    }

    let always = job(
        &["build"],
        Some(condition("${{ always() }}", Vec::new())),
        None,
    );
    let skipped = BTreeMap::from([(
        "build".to_owned(),
        NeedContext::new(JobConclusion::Skipped, BTreeMap::new()).expect("need"),
    )]);
    assert!(
        activate(
            &always,
            &ContextValue::empty_object(),
            &skipped,
            ActivationStatus::Skipped,
        )
        .expect("always")
        .condition_matched()
    );
    let failure = job(
        &["build"],
        Some(condition("${{ failure() }}", Vec::new())),
        None,
    );
    assert!(
        !activate(
            &failure,
            &ContextValue::empty_object(),
            &skipped,
            ActivationStatus::Skipped,
        )
        .expect("skipped is not failure")
        .condition_matched()
    );
}

#[test]
fn dynamic_needs_index_is_bounded_to_the_declared_runtime_context() {
    let plan = job(
        &["build"],
        Some(condition(
            "${{ needs[inputs.dependency].outputs.ready == 'yes' }}",
            vec![ExpressionContext::Inputs, ExpressionContext::Needs],
        )),
        None,
    );
    let needs = BTreeMap::from([(
        "build".to_owned(),
        NeedContext::new(
            JobConclusion::Success,
            BTreeMap::from([("ready".to_owned(), public_output("yes"))]),
        )
        .expect("need"),
    )]);

    let selected = activate(
        &plan,
        &inputs(&[("dependency", ContextValue::string("build"))]),
        &needs,
        ActivationStatus::Success,
    )
    .expect("dynamic direct need");
    assert!(selected.condition_matched());

    let absent = activate(
        &plan,
        &inputs(&[("dependency", ContextValue::string("undeclared"))]),
        &needs,
        ActivationStatus::Success,
    )
    .expect("missing dynamic need follows GitHub null semantics");
    assert!(!absent.condition_matched());
}

#[test]
fn from_json_need_output_drives_insertion_stable_dynamic_matrix() {
    let source = "${{ fromJSON(needs.plan.outputs.matrix) }}";
    let strategy = WorkflowStrategyTemplate::new(
        None,
        None,
        MatrixTemplate::from_expression(
            located(value_expression(source, vec![ExpressionContext::Needs])),
            span(),
        ),
        16,
        span(),
    );
    let job = job(&["plan"], None, Some(strategy));
    let needs = BTreeMap::from([(
        "plan".to_owned(),
        NeedContext::new(
            JobConclusion::Success,
            BTreeMap::from([(
                "matrix".to_owned(),
                public_output(r#"{"runtime":["stable","next"],"platform":["linux","windows"]}"#),
            )]),
        )
        .expect("need"),
    )]);
    let activation = activate(
        &job,
        &ContextValue::empty_object(),
        &needs,
        ActivationStatus::Success,
    )
    .expect("matrix");
    assert_eq!(activation.instances().len(), 4);
    let values = activation
        .instances()
        .iter()
        .map(|instance| {
            let matrix = instance
                .runtime_context()
                .matrix()
                .as_object()
                .expect("matrix");
            (
                matrix
                    .get("runtime")
                    .and_then(ContextValue::as_string)
                    .expect("runtime"),
                matrix
                    .get("platform")
                    .and_then(ContextValue::as_string)
                    .expect("platform"),
            )
        })
        .collect::<Vec<_>>();
    assert_eq!(
        values,
        [
            ("stable", "linux"),
            ("stable", "windows"),
            ("next", "linux"),
            ("next", "windows"),
        ]
    );
}

#[test]
fn positive_integer_strategy_values_require_typed_nonzero_integers() {
    let source = "${{ fromJSON(inputs.parallel) }}";
    let matrix_source = "${{ fromJSON(inputs.matrix) }}";
    let strategy = WorkflowStrategyTemplate::new(
        None,
        Some(located(CompiledPositiveIntegerTemplate::Expression(
            value_expression(source, vec![ExpressionContext::Inputs]),
        ))),
        MatrixTemplate::from_expression(
            located(value_expression(
                matrix_source,
                vec![ExpressionContext::Inputs],
            )),
            span(),
        ),
        16,
        span(),
    );
    let job = job(&[], None, Some(strategy));
    let valid = inputs(&[
        ("parallel", ContextValue::string("2")),
        ("matrix", ContextValue::string(r#"{"item":[1,2,3]}"#)),
    ]);
    let activation =
        activate(&job, &valid, &BTreeMap::new(), ActivationStatus::Success).expect("integer");
    assert_eq!(activation.instances().len(), 3);
    assert!(
        activation
            .instances()
            .iter()
            .all(|instance| { instance.runtime_context().strategy().max_parallel() == 2 })
    );

    for invalid in ["0", "2.5", "\"2\""] {
        let inputs = inputs(&[
            ("parallel", ContextValue::string(invalid)),
            ("matrix", ContextValue::string(r#"{"item":[1,2,3]}"#)),
        ]);
        let error = activate(&job, &inputs, &BTreeMap::new(), ActivationStatus::Success)
            .expect_err("invalid integer");
        assert!(matches!(
            error,
            LogicalActivationError::Evaluation {
                source: GithubActivationEvaluationError::ExpectedPositiveInteger,
                ..
            }
        ));
    }
}

#[test]
fn adapter_rejects_non_object_github_context() {
    assert!(matches!(
        GithubActivationContext::new(GithubValue::Null),
        Err(GithubActivationEvaluationError::GithubContextMustBeObject)
    ));
}

#[test]
fn activation_snapshot_rejects_runtime_credentials_without_retaining_them() {
    let sentinel = "runtime-credential-sentinel\nsecond-line";
    let raw = GithubValue::object(
        GithubObject::new(vec![
            (
                "event_name".to_owned(),
                GithubValue::string("workflow_dispatch"),
            ),
            ("token".to_owned(), GithubValue::string(sentinel)),
        ])
        .expect("raw github context"),
    );
    let error = GithubActivationContext::new(raw).expect_err("token must be rejected");
    assert!(matches!(
        error,
        GithubActivationEvaluationError::UnsafeGithubContextProperty
    ));
    let diagnostics = format!("{error:?} {error}");
    assert!(!diagnostics.contains(sentinel));
    assert!(!diagnostics.contains("second-line"));

    for unavailable in ["workspace", "action_path", "future_runtime_credential"] {
        let raw = GithubValue::object(
            GithubObject::new(vec![(unavailable.to_owned(), GithubValue::Null)])
                .expect("raw github context"),
        );
        assert!(matches!(
            GithubActivationContext::new(raw),
            Err(GithubActivationEvaluationError::UnsafeGithubContextProperty)
        ));
    }
}

#[test]
fn documented_prerunner_github_properties_remain_available_but_token_is_null() {
    let properties = [
        "actor",
        "actor_id",
        "api_url",
        "base_ref",
        "event_name",
        "graphql_url",
        "head_ref",
        "ref",
        "ref_name",
        "ref_type",
        "repository",
        "repository_id",
        "repository_owner",
        "repository_owner_id",
        "repositoryUrl",
        "retention_days",
        "run_attempt",
        "run_id",
        "run_number",
        "server_url",
        "sha",
        "triggering_actor",
        "workflow",
        "workflow_ref",
        "workflow_sha",
    ];
    let mut entries = properties
        .into_iter()
        .map(|property| (property.to_owned(), GithubValue::string("value")))
        .collect::<Vec<_>>();
    entries.push(("ref_protected".to_owned(), GithubValue::Boolean(true)));
    entries.push((
        "event".to_owned(),
        GithubValue::object(GithubObject::new(Vec::new()).expect("event")),
    ));
    GithubActivationContext::new(GithubValue::object(
        GithubObject::new(entries).expect("documented context"),
    ))
    .expect("all documented prerunner roots remain available");

    let plan = job(
        &[],
        Some(condition(
            "${{ github.token == null && github.event_name == 'workflow_dispatch' }}",
            vec![ExpressionContext::Github],
        )),
        None,
    );
    assert!(
        activate(
            &plan,
            &ContextValue::empty_object(),
            &BTreeMap::new(),
            ActivationStatus::Success,
        )
        .expect("missing token evaluates as null")
        .condition_matched()
    );
}

#[test]
fn secret_derived_need_output_cannot_feed_a_dynamic_matrix() {
    let source = "${{ fromJSON(needs.plan.outputs.matrix) }}";
    let plan = dynamic_matrix_plan(&["plan"], source, vec![ExpressionContext::Needs]);
    let sentinel = r#"{"item":["secret-derived-sentinel"]}"#;
    let needs = BTreeMap::from([(
        "plan".to_owned(),
        NeedContext::new(
            JobConclusion::Success,
            BTreeMap::from([(
                "matrix".to_owned(),
                NeedOutput::new(sentinel, OutputSensitivity::SecretDerived)
                    .expect("secret-derived output"),
            )]),
        )
        .expect("need"),
    )]);
    let error = activate(
        &plan,
        &ContextValue::empty_object(),
        &needs,
        ActivationStatus::Success,
    )
    .expect_err("secret-derived matrix output must be unavailable");
    let diagnostics = format!("{error:?} {error}");
    assert!(!diagnostics.contains("secret-derived-sentinel"));
    assert!(!diagnostics.contains(sentinel));
}

#[test]
fn github_matrix_matching_is_case_insensitive_loose_and_directional() {
    let source = "${{ fromJSON(inputs.matrix) }}";
    let plan = dynamic_matrix_plan(&[], source, vec![ExpressionContext::Inputs]);

    let excluded = inputs(&[(
        "matrix",
        ContextValue::string(r#"{"OS":["Prod"],"exclude":[{"os":"prod"}]}"#),
    )]);
    let activation = activate(
        &plan,
        &excluded,
        &BTreeMap::new(),
        ActivationStatus::Success,
    )
    .expect("case-insensitive exclude");
    assert!(activation.instances().is_empty());

    let included = inputs(&[(
        "matrix",
        ContextValue::string(
            r#"{"Flavor":["Prod"],"version":[1],"include":[{"flavor":"prod","VERSION":"1","extra":"yes"}]}"#,
        ),
    )]);
    let activation = activate(
        &plan,
        &included,
        &BTreeMap::new(),
        ActivationStatus::Success,
    )
    .expect("loose compatible include");
    assert_eq!(activation.instances().len(), 1);
    let matrix = activation.instances()[0]
        .runtime_context()
        .matrix()
        .as_object()
        .expect("matrix");
    assert_eq!(
        matrix.get("Flavor").and_then(ContextValue::as_string),
        Some("Prod")
    );
    assert_eq!(
        matrix.get("version").and_then(ContextValue::as_number),
        Some(1.0)
    );
    assert_eq!(
        matrix.get("extra").and_then(ContextValue::as_string),
        Some("yes")
    );

    let nested = inputs(&[(
        "matrix",
        ContextValue::string(
            r#"{"config":[{"tier":"prod","nested":{"channel":"stable","arch":"x64"}},{"tier":"dev","nested":{"channel":"next","arch":"x64"}}],"exclude":[{"CONFIG":{"nested":{"CHANNEL":"stable"}}}]}"#,
        ),
    )]);
    let activation = activate(&plan, &nested, &BTreeMap::new(), ActivationStatus::Success)
        .expect("directional nested exclude");
    assert_eq!(activation.instances().len(), 1);
    let config = activation.instances()[0]
        .runtime_context()
        .matrix()
        .as_object()
        .and_then(|matrix| matrix.get("config"))
        .and_then(ContextValue::as_object)
        .expect("config object");
    assert_eq!(
        config.get("tier").and_then(ContextValue::as_string),
        Some("dev")
    );
}

#[test]
fn provider_equivalent_nested_duplicate_keys_fail_before_matrix_matching() {
    let source = "${{ fromJSON(inputs.matrix) }}";
    let plan = dynamic_matrix_plan(&[], source, vec![ExpressionContext::Inputs]);
    let duplicated = inputs(&[(
        "matrix",
        ContextValue::string(r#"{"axis":[{"A":1,"a":2}]}"#),
    )]);
    assert!(
        activate(
            &plan,
            &duplicated,
            &BTreeMap::new(),
            ActivationStatus::Success,
        )
        .is_err()
    );
}

#[test]
fn typed_boolean_fields_and_function_sites_fail_closed() {
    fn plan_with_fail_fast(source: &str) -> WorkflowPlan {
        let matrix_source = "${{ fromJSON(inputs.matrix) }}";
        let strategy = WorkflowStrategyTemplate::new(
            Some(located(CompiledBooleanTemplate::Expression(
                value_expression(source, Vec::new()),
            ))),
            None,
            MatrixTemplate::from_expression(
                located(value_expression(
                    matrix_source,
                    vec![ExpressionContext::Inputs],
                )),
                span(),
            ),
            8,
            span(),
        );
        job(&[], None, Some(strategy))
    }

    let inputs = inputs(&[("matrix", ContextValue::string(r#"{"item":[1]}"#))]);
    let error = activate(
        &plan_with_fail_fast("${{ 'false' }}"),
        &inputs,
        &BTreeMap::new(),
        ActivationStatus::Success,
    )
    .expect_err("string truthiness must not satisfy a typed Boolean field");
    assert!(matches!(
        error,
        LogicalActivationError::Evaluation {
            source: GithubActivationEvaluationError::ExpectedBoolean,
            ..
        }
    ));

    let error = activate(
        &plan_with_fail_fast("${{ always() }}"),
        &inputs,
        &BTreeMap::new(),
        ActivationStatus::Success,
    )
    .expect_err("status functions are unavailable in strategy fields");
    assert!(matches!(
        error,
        LogicalActivationError::Evaluation {
            source: GithubActivationEvaluationError::UnavailableFunction,
            ..
        }
    ));
}

#[test]
fn concurrent_activations_keep_prepared_base_contexts_isolated() {
    let activator = Arc::new(LogicalJobActivator::new(
        GithubLogicalActivationEvaluator::new(github()),
    ));
    let handles = ["alpha", "beta"].map(|marker| {
        let activator = Arc::clone(&activator);
        thread::spawn(move || {
            let source = "${{ fromJSON(inputs.matrix) }}";
            let plan = dynamic_matrix_plan(&[], source, vec![ExpressionContext::Inputs]);
            let encoded = format!(r#"{{"marker":["{marker}"]}}"#);
            let inputs = inputs(&[("matrix", ContextValue::string(encoded))]);
            let activation = activator
                .activate(ActivateLogicalJobRequest::new(
                    ValidatedLogicalPlan::new(&plan)
                        .expect("validated logical plan")
                        .job(&WorkflowJobKey::new("consumer").expect("consumer key"))
                        .expect("validated logical job"),
                    &inputs,
                    &ContextValue::empty_object(),
                    &BTreeMap::new(),
                    &BTreeMap::new(),
                    ActivationStatus::Success,
                ))
                .expect("concurrent activation");
            activation.instances()[0]
                .runtime_context()
                .matrix()
                .as_object()
                .and_then(|matrix| matrix.get("marker"))
                .and_then(ContextValue::as_string)
                .expect("marker")
                .to_owned()
        })
    });
    let mut markers = handles
        .into_iter()
        .map(|handle| handle.join().expect("activation thread"))
        .collect::<Vec<_>>();
    markers.sort();
    assert_eq!(markers, ["alpha", "beta"]);
}
