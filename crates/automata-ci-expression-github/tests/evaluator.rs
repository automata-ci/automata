use std::{
    collections::BTreeMap,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
};

use automata_ci_expression_github::{
    ExtensionFunctionResult, GithubExpressionEvaluationErrorKind, GithubExpressionEvaluator,
    GithubExpressionFunctionProvider, GithubExpressionLimits, GithubObject, GithubStatus,
    GithubValue, MapContext,
};
use automata_ci_workflow_github::{GithubConditionCompiler, GithubConditionPhase};

fn compile(source: &str) -> automata_ci_core::ExpressionProgram {
    GithubConditionCompiler::default()
        .compile_condition(Some(source), GithubConditionPhase::Step)
        .expect("test expression compiles")
}

fn object(entries: impl IntoIterator<Item = (&'static str, GithubValue)>) -> GithubValue {
    GithubValue::object(
        GithubObject::new(
            entries
                .into_iter()
                .map(|(key, value)| (key.to_owned(), value))
                .collect(),
        )
        .expect("valid object"),
    )
}

fn context(named: impl IntoIterator<Item = (&'static str, GithubValue)>) -> MapContext {
    MapContext::without_extensions(
        named
            .into_iter()
            .map(|(name, value)| (name.to_owned(), value))
            .collect(),
        GithubStatus::Success,
    )
    .expect("valid context")
}

#[test]
fn resolves_case_insensitive_properties_and_status() {
    let program = compile("${{ github.ref == 'REFS/HEADS/MAIN' }}");
    let context = context([(
        "github",
        object([("Ref", GithubValue::string("refs/heads/main"))]),
    )]);

    assert!(
        GithubExpressionEvaluator::default()
            .evaluate_condition(&program, &context)
            .expect("condition evaluates")
    );

    let failed = MapContext::without_extensions(BTreeMap::new(), GithubStatus::Failure)
        .expect("valid context");
    assert!(
        GithubExpressionEvaluator::default()
            .evaluate_condition(&compile("failure()"), &failed)
            .expect("status evaluates")
    );
    assert!(
        !GithubExpressionEvaluator::default()
            .evaluate_condition(&compile("success()"), &failed)
            .expect("status evaluates")
    );
}

#[test]
fn skipped_aggregate_status_matches_no_specific_status_function() {
    let context = MapContext::without_extensions(BTreeMap::new(), GithubStatus::Skipped)
        .expect("valid context");
    let evaluator = GithubExpressionEvaluator::default();
    for function in ["success()", "failure()", "cancelled()"] {
        assert!(
            !evaluator
                .evaluate_condition(&compile(function), &context)
                .expect("status evaluates"),
            "{function} unexpectedly matched skipped status"
        );
    }
    assert!(
        evaluator
            .evaluate_condition(&compile("always()"), &context)
            .expect("always evaluates")
    );
}

#[test]
fn matches_github_loose_primitive_coercion() {
    let evaluator = GithubExpressionEvaluator::default();
    let empty_context = context([]);
    for expression in [
        "${{ '0' == false }}",
        "${{ null == false }}",
        "${{ '' == 0 }}",
        "${{ '0x10' == 16 }}",
        "${{ '0xFFFFFFFF' == -1 }}",
        "${{ '0o10' == 8 }}",
        "${{ true > false }}",
        "${{ 'Zulu' > 'alpha' }}",
    ] {
        assert!(
            evaluator
                .evaluate_condition(&compile(expression), &empty_context)
                .expect("coercion evaluates"),
            "{expression}"
        );
    }
    assert!(
        !evaluator
            .evaluate_condition(&compile("${{ 'not-a-number' > 0 }}"), &empty_context)
            .expect("NaN comparison evaluates")
    );
}

#[test]
fn projects_wildcards_and_runs_collection_functions() {
    let items = GithubValue::array(vec![
        object([("name", GithubValue::string("one"))]),
        object([("name", GithubValue::string("TWO"))]),
    ])
    .expect("valid array");
    let context = context([("matrix", object([("items", items)]))]);
    let program = compile("${{ contains(matrix.items.*.name, 'two') }}");

    assert!(
        GithubExpressionEvaluator::default()
            .evaluate_condition(&program, &context)
            .expect("wildcard evaluates")
    );
}

#[derive(Debug)]
struct CountingFunctions {
    calls: AtomicUsize,
}

impl GithubExpressionFunctionProvider for CountingFunctions {
    fn call(&self, name: &str, _arguments: &[GithubValue]) -> ExtensionFunctionResult {
        self.calls.fetch_add(1, Ordering::SeqCst);
        (name == "hashfiles").then(|| Ok(GithubValue::string("digest")))
    }
}

#[test]
fn logical_and_case_evaluation_are_lazy() {
    let functions = Arc::new(CountingFunctions {
        calls: AtomicUsize::new(0),
    });
    let context = MapContext::new(BTreeMap::new(), GithubStatus::Success, functions.clone())
        .expect("valid context");
    let evaluator = GithubExpressionEvaluator::default();

    assert!(
        !evaluator
            .evaluate_condition(&compile("${{ false && hashFiles('**') }}"), &context)
            .expect("short circuit evaluates")
    );
    assert_eq!(functions.calls.load(Ordering::SeqCst), 0);

    let value = evaluator
        .evaluate(
            &compile("${{ case(true, 'selected', hashFiles('never')) }}"),
            &context,
        )
        .expect("case evaluates");
    assert_eq!(value.as_str(), Some("selected"));
    assert_eq!(functions.calls.load(Ordering::SeqCst), 0);

    for source in [
        "${{ contains(fromJSON('{}'), hashFiles('never')) }}",
        "${{ contains(fromJSON('[]'), hashFiles('never')) }}",
        "${{ join('already-scalar', hashFiles('never')) == 'already-scalar' }}",
    ] {
        let _ = evaluator
            .evaluate(&compile(source), &context)
            .expect("lazy function evaluates");
    }
    assert_eq!(functions.calls.load(Ordering::SeqCst), 0);

    let formatted = evaluator
        .evaluate(
            &compile("${{ format('{0}:{0}', hashFiles('once')) }}"),
            &context,
        )
        .expect("format evaluates");
    assert_eq!(formatted.as_str(), Some("digest:digest"));
    assert_eq!(functions.calls.load(Ordering::SeqCst), 1);
}

#[test]
fn supports_format_join_and_json_functions() {
    let evaluator = GithubExpressionEvaluator::default();
    let empty_context = context([]);
    let formatted = evaluator
        .evaluate(
            &compile("${{ format('{{{0}}}:{1}', 'key', join(fromJSON('[1,true,null]'), '|')) }}"),
            &empty_context,
        )
        .expect("functions evaluate");
    assert_eq!(formatted.as_str(), Some("{key}:1|true|"));

    let data = object([
        ("z", GithubValue::Boolean(true)),
        (
            "a",
            GithubValue::array(vec![GithubValue::Null, GithubValue::string("x")])
                .expect("valid array"),
        ),
    ]);
    let data_context = context([("github", object([("data", data)]))]);
    let json = evaluator
        .evaluate(&compile("${{ toJSON(github.data) }}"), &data_context)
        .expect("JSON evaluates");
    assert_eq!(
        json.as_str(),
        Some("{\n  \"z\": true,\n  \"a\": [\n    null,\n    \"x\"\n  ]\n}")
    );

    let round_trip = evaluator
        .evaluate(
            &compile("${{ toJSON(fromJSON('{\"z\":1,\"a\":2}')) }}"),
            &empty_context,
        )
        .expect("ordered JSON evaluates");
    assert_eq!(round_trip.as_str(), Some("{\n  \"z\": 1,\n  \"a\": 2\n}"));

    assert!(
        evaluator
            .evaluate_condition(
                &compile("${{ fromJSON('{\"\":7}')[''] == 7 }}"),
                &empty_context,
            )
            .expect("empty JSON property evaluates")
    );
}

#[test]
fn join_bounds_repeated_items_and_separators_during_construction() {
    let program = compile("${{ join(fromJSON('[1,1,1,1]'), '---') }}");
    let empty_context = context([]);
    let limited = GithubExpressionEvaluator::new(
        GithubExpressionLimits::new(8, 16, 4).expect("valid limits"),
    );

    let error = limited
        .evaluate(&program, &empty_context)
        .expect_err("repeated join output exceeds the byte limit");
    assert_eq!(
        error.kind(),
        GithubExpressionEvaluationErrorKind::ResourceLimit
    );

    let boundary = GithubExpressionEvaluator::new(
        GithubExpressionLimits::new(13, 16, 4).expect("valid limits"),
    );
    let value = boundary
        .evaluate(&program, &empty_context)
        .expect("exact-limit join output succeeds");
    assert_eq!(value.as_str(), Some("1---1---1---1"));
}

#[test]
fn format_bounds_repeated_placeholders_during_construction() {
    let program = compile("${{ format('{0}{0}{0}{0}', 'word') }}");
    let empty_context = context([]);
    let limited = GithubExpressionEvaluator::new(
        GithubExpressionLimits::new(12, 16, 4).expect("valid limits"),
    );

    let error = limited
        .evaluate(&program, &empty_context)
        .expect_err("repeated format output exceeds the byte limit");
    assert_eq!(
        error.kind(),
        GithubExpressionEvaluationErrorKind::ResourceLimit
    );

    let boundary = GithubExpressionEvaluator::new(
        GithubExpressionLimits::new(16, 16, 4).expect("valid limits"),
    );
    let value = boundary
        .evaluate(&program, &empty_context)
        .expect("exact-limit format output succeeds");
    assert_eq!(value.as_str(), Some("wordwordwordword"));
}

#[test]
fn json_functions_enforce_active_limits_during_construction() {
    let data = GithubValue::string("\0\0\0\0");
    let data_context = context([("github", object([("data", data)]))]);
    let limited = GithubExpressionEvaluator::new(
        GithubExpressionLimits::new(25, 16, 4).expect("valid limits"),
    );
    let error = limited
        .evaluate(&compile("${{ toJSON(github.data) }}"), &data_context)
        .expect_err("JSON escaping exceeds the result limit");
    assert_eq!(
        error.kind(),
        GithubExpressionEvaluationErrorKind::ResourceLimit
    );

    let boundary = GithubExpressionEvaluator::new(
        GithubExpressionLimits::new(26, 16, 4).expect("valid limits"),
    );
    let value = boundary
        .evaluate(&compile("${{ toJSON(github.data) }}"), &data_context)
        .expect("exact-limit JSON output succeeds");
    assert_eq!(value.as_str(), Some(r#""\u0000\u0000\u0000\u0000""#));

    let shallow = GithubExpressionEvaluator::new(
        GithubExpressionLimits::new(64, 16, 1).expect("valid limits"),
    );
    let error = shallow
        .evaluate(&compile("${{ fromJSON('[1]') }}"), &context([]))
        .expect_err("nested JSON exceeds the active depth limit");
    assert_eq!(
        error.kind(),
        GithubExpressionEvaluationErrorKind::ResourceLimit
    );
}

#[test]
fn object_and_array_equality_is_by_identity() {
    let shared = object([("value", GithubValue::string("same"))]);
    let independent = object([("value", GithubValue::string("same"))]);
    let context = context([(
        "github",
        object([
            ("left", shared.clone()),
            ("same", shared),
            ("other", independent),
        ]),
    )]);
    let evaluator = GithubExpressionEvaluator::default();

    assert!(
        evaluator
            .evaluate_condition(&compile("${{ github.left == github.same }}"), &context)
            .expect("identity evaluates")
    );
    assert!(
        !evaluator
            .evaluate_condition(&compile("${{ github.left == github.other }}"), &context)
            .expect("identity evaluates")
    );
}

#[test]
fn enforces_runtime_value_limits_and_redacts_debug() {
    let limits = GithubExpressionLimits::new(8, 16, 4).expect("valid limits");
    let evaluator = GithubExpressionEvaluator::new(limits);
    let context = context([(
        "github",
        object([("secret", GithubValue::string("super-secret-value"))]),
    )]);
    let error = evaluator
        .evaluate(&compile("${{ github.secret }}"), &context)
        .expect_err("oversized value is rejected");
    assert_eq!(
        error.kind(),
        GithubExpressionEvaluationErrorKind::ResourceLimit
    );
    assert!(!format!("{context:?}").contains("super-secret-value"));
}

#[test]
fn context_and_public_ports_are_object_safe() {
    static_assertions::assert_obj_safe!(GithubExpressionFunctionProvider);
    let _: &dyn automata_ci_expression_github::GithubEvaluationContext = &context([]);
}
