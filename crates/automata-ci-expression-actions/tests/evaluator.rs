use std::{
    collections::BTreeMap,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
};

use automata_ci_core::{ExpressionDialect, ExpressionInstruction, ExpressionProgram};
use automata_ci_expression_actions::{
    ExtensionFunctionResult, GithubEvaluationContext, GithubExpressionEvaluationErrorKind,
    GithubExpressionEvaluator, GithubExpressionFunctionProvider, GithubExpressionLimits,
    GithubObject, GithubStatus, GithubValue, MapContext,
};
use automata_ci_workflow_actions::{
    GITHUB_EXPRESSION_DIALECT, GITHUB_EXPRESSION_DIALECT_VERSION, GithubConditionCompiler,
    GithubConditionPhase,
};

fn compile(source: &str) -> automata_ci_core::ExpressionProgram {
    GithubConditionCompiler::default()
        .compile_condition(Some(source), GithubConditionPhase::Step)
        .expect("test expression compiles")
}

fn compile_value(source: &str) -> ExpressionProgram {
    GithubConditionCompiler::default()
        .compile_value_expression(source, GithubConditionPhase::Step)
        .expect("test value expression compiles")
}

fn manual_call(name: &str, argument_names: &[&str]) -> ExpressionProgram {
    let mut instructions = argument_names
        .iter()
        .map(|name| ExpressionInstruction::Call {
            name: (*name).to_owned(),
            argument_count: 0,
        })
        .collect::<Vec<_>>();
    instructions.push(ExpressionInstruction::Call {
        name: name.to_owned(),
        argument_count: u16::try_from(argument_names.len()).expect("bounded test arguments"),
    });
    ExpressionProgram::new(
        ExpressionDialect::new(GITHUB_EXPRESSION_DIALECT, GITHUB_EXPRESSION_DIALECT_VERSION)
            .expect("test dialect"),
        format!("manual {name}/{}", argument_names.len()),
        instructions,
    )
    .expect("structurally valid test program")
}

fn manual_named_call(name: &str, named: &str) -> ExpressionProgram {
    ExpressionProgram::new(
        ExpressionDialect::new(GITHUB_EXPRESSION_DIALECT, GITHUB_EXPRESSION_DIALECT_VERSION)
            .expect("test dialect"),
        format!("manual {name}({named})"),
        vec![
            ExpressionInstruction::NamedValue {
                name: named.to_owned(),
            },
            ExpressionInstruction::Call {
                name: name.to_owned(),
                argument_count: 1,
            },
        ],
    )
    .expect("structurally valid test program")
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
fn evaluator_rejects_forward_workflow_dialect_version() {
    let current = compile("true");
    let forward_version = GITHUB_EXPRESSION_DIALECT_VERSION
        .checked_add(1)
        .expect("test dialect version");
    let forward = automata_ci_core::ExpressionProgram::new(
        automata_ci_core::ExpressionDialect::new(GITHUB_EXPRESSION_DIALECT, forward_version)
            .expect("well-formed forward dialect"),
        current.source(),
        current.instructions().to_vec(),
    )
    .expect("structurally valid forward-dialect program");

    let error = GithubExpressionEvaluator::default()
        .evaluate(&forward, &context([]))
        .expect_err("forward dialect must fail closed");
    assert_eq!(
        error.kind(),
        GithubExpressionEvaluationErrorKind::UnsupportedProgram
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
        "${{ ' \t' == 0 }}",
        "${{ '1e2' == 100 }}",
        "${{ '+1.5e+2' == 150 }}",
        "${{ '0x10' == 16 }}",
        "${{ '0xFFFFFFFF' == -1 }}",
        "${{ '0o10' == 8 }}",
        "${{ '0o37777777777' == -1 }}",
        "${{ '-0' == 0 }}",
        "${{ 'Infinity' > 1e308 }}",
        "${{ '-Infinity' < -1e308 }}",
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
    for expression in [
        "${{ 'not-a-number' > 0 }}",
        "${{ 'NaN' == 0 }}",
        "${{ 'NaN' > 0 }}",
        "${{ '0X10' == 16 }}",
        "${{ '0o40000000000' == 0 }}",
        "${{ '1e9999' == 0 }}",
    ] {
        assert!(
            !evaluator
                .evaluate_condition(&compile(expression), &empty_context)
                .expect("numeric edge evaluates"),
            "{expression}"
        );
    }

    assert!(!GithubValue::number(f64::NAN).is_truthy());
    assert!(!GithubValue::number(f64::NAN).loosely_equals(&GithubValue::number(f64::NAN)));
    assert!(!GithubValue::number(-0.0).is_truthy());
    assert_eq!(GithubValue::number(-0.0).coerce_to_string(), "0");
}

#[test]
fn non_ascii_comparisons_follow_dotnet_ordinal_ignore_case() {
    let evaluator = GithubExpressionEvaluator::default();
    let empty_context = context([]);
    for expression in [
        "${{ 'É' == 'é' }}",
        "${{ 'Σ' == 'ς' }}",
        "${{ '𐐀' == '𐐨' }}",
        "${{ contains('CAFÉ', 'fé') }}",
        "${{ startsWith('Σigma', 'ςI') }}",
        "${{ endsWith('𐐀x𐐀', '𐐨') }}",
        "${{ '😀' < '\u{e000}' }}",
    ] {
        assert!(
            evaluator
                .evaluate_condition(&compile(expression), &empty_context)
                .expect("ordinal expression evaluates"),
            "{expression}"
        );
    }

    for expression in [
        "${{ 'ß' == 'ẞ' }}",
        "${{ 'İ' == 'i' }}",
        "${{ 'ı' == 'I' }}",
        "${{ '\u{212a}' == 'k' }}",
        "${{ 'ſ' == 's' }}",
        "${{ 'ﬀ' == 'FF' }}",
    ] {
        assert!(
            !evaluator
                .evaluate_condition(&compile(expression), &empty_context)
                .expect("ordinal edge evaluates"),
            "{expression}"
        );
    }

    GithubObject::new(vec![
        ("Σ".to_owned(), GithubValue::Null),
        ("ς".to_owned(), GithubValue::Null),
    ])
    .expect_err("ordinal-equivalent object keys collide");
    GithubObject::new(vec![
        ("\u{212a}".to_owned(), GithubValue::Null),
        ("k".to_owned(), GithubValue::Null),
    ])
    .expect("ordinal-distinct object keys coexist");
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
        match name {
            "hashfiles" => Some(Ok(GithubValue::string("digest"))),
            "echo" | "explode" => Some(Ok(GithubValue::string("extension"))),
            _ => None,
        }
    }
}

#[test]
fn evaluator_signature_dispatch_is_closed_and_preflight_is_lazy() {
    let functions = Arc::new(CountingFunctions {
        calls: AtomicUsize::new(0),
    });
    let successful = MapContext::new(BTreeMap::new(), GithubStatus::Success, functions.clone())
        .expect("valid context");
    let failed = MapContext::new(BTreeMap::new(), GithubStatus::Failure, functions.clone())
        .expect("valid context");
    let evaluator = GithubExpressionEvaluator::default();

    for (name, context, expected) in [
        ("success", &successful, true),
        ("success", &failed, false),
        ("failure", &successful, false),
        ("failure", &failed, true),
    ] {
        let value = evaluator
            .evaluate(&manual_call(name, &["explode", "explode"]), context)
            .expect("job-status call ignores arguments");
        assert_eq!(value.as_bool(), Some(expected));
    }
    assert_eq!(functions.calls.load(Ordering::SeqCst), 0);

    let invalid_signatures = [
        ("always", 1_usize),
        ("cancelled", 1),
        ("case", 2),
        ("case", 4),
        ("case", 256),
        ("contains", 1),
        ("contains", 3),
        ("startswith", 1),
        ("startswith", 3),
        ("endswith", 1),
        ("endswith", 3),
        ("format", 0),
        ("format", 256),
        ("join", 0),
        ("join", 3),
        ("fromjson", 0),
        ("fromjson", 2),
        ("tojson", 0),
        ("tojson", 2),
        ("hashfiles", 0),
        ("hashfiles", 256),
    ];
    for (name, count) in invalid_signatures {
        let arguments = vec!["explode"; count];
        let error = evaluator
            .evaluate(&manual_call(name, &arguments), &successful)
            .expect_err("known invalid arity fails before evaluating arguments");
        assert_eq!(
            error.kind(),
            GithubExpressionEvaluationErrorKind::InvalidOperation,
            "{name}/{count}"
        );
        assert_eq!(functions.calls.load(Ordering::SeqCst), 0, "{name}/{count}");
    }

    let error = evaluator
        .evaluate(&manual_call("unsupported", &[]), &successful)
        .expect_err("unsupported durable call fails closed");
    assert_eq!(
        error.kind(),
        GithubExpressionEvaluationErrorKind::UnavailableContext
    );
    assert_eq!(functions.calls.load(Ordering::SeqCst), 1);
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
    let empty_format_specifier = evaluator
        .evaluate(
            &compile_value("${{ format('{0:}', 'value') }}"),
            &empty_context,
        )
        .expect("empty runner format specifier evaluates");
    assert_eq!(empty_format_specifier.as_str(), Some("value"));

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
    let shared_array = GithubValue::array(vec![GithubValue::string("same")]).expect("valid array");
    let independent_array =
        GithubValue::array(vec![GithubValue::string("same")]).expect("valid array");
    let context = context([(
        "github",
        object([
            ("left", shared.clone()),
            ("same", shared),
            ("other", independent),
            ("left_array", shared_array.clone()),
            ("same_array", shared_array),
            ("other_array", independent_array),
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
    assert!(
        evaluator
            .evaluate_condition(
                &compile("${{ github.left_array == github.same_array }}"),
                &context,
            )
            .expect("array identity evaluates")
    );
    assert!(
        !evaluator
            .evaluate_condition(
                &compile("${{ github.left_array == github.other_array }}"),
                &context,
            )
            .expect("array identity evaluates")
    );
}

#[test]
fn missing_properties_and_filtered_wildcards_match_runner_behavior() {
    let rows = GithubValue::array(vec![
        object([
            ("name", GithubValue::string("one")),
            (
                "nested",
                GithubValue::array(vec![GithubValue::string("a"), GithubValue::string("b")])
                    .expect("valid array"),
            ),
        ]),
        object([("other", GithubValue::string("omitted"))]),
        object([
            ("name", GithubValue::string("three")),
            (
                "nested",
                GithubValue::array(vec![GithubValue::string("c")]).expect("valid array"),
            ),
        ]),
    ])
    .expect("valid array");
    let context = context([(
        "github",
        object([("rows", rows), ("scalar", GithubValue::string("value"))]),
    )]);
    let evaluator = GithubExpressionEvaluator::default();

    for expression in [
        "${{ github.missing == null }}",
        "${{ github.missing.child == null }}",
        "${{ github.rows[99] == null }}",
        "${{ github.scalar.missing == null }}",
    ] {
        assert!(
            evaluator
                .evaluate_condition(&compile(expression), &context)
                .expect("missing property evaluates"),
            "{expression}"
        );
    }

    let names = evaluator
        .evaluate(&compile_value("${{ github.rows.*.name }}"), &context)
        .expect("wildcard projection evaluates");
    let GithubValue::Array(names) = names else {
        panic!("wildcard result is an array");
    };
    assert_eq!(
        names
            .iter()
            .filter_map(GithubValue::as_str)
            .collect::<Vec<_>>(),
        ["one", "three"]
    );

    let flattened = evaluator
        .evaluate(&compile_value("${{ github.rows.*.nested.* }}"), &context)
        .expect("nested wildcard evaluates");
    let GithubValue::Array(flattened) = flattened else {
        panic!("nested wildcard result is an array");
    };
    assert_eq!(
        flattened
            .iter()
            .filter_map(GithubValue::as_str)
            .collect::<Vec<_>>(),
        ["a", "b", "c"]
    );
}

#[test]
fn sensitive_values_propagate_without_serialization_or_diagnostic_leaks() {
    let canary = "wf03-canary-\"}\\escaped\n::error::must-not-leak";
    let sensitive = GithubValue::sensitive_string(canary);
    let context = context([
        (
            "github",
            object([
                ("token", sensitive.clone()),
                (
                    "values",
                    GithubValue::array(vec![GithubValue::string("public"), sensitive.clone()])
                        .expect("valid array"),
                ),
                (
                    "secret_rows",
                    GithubValue::array(vec![object([(
                        "name",
                        GithubValue::string("secret projection"),
                    )])])
                    .expect("valid array")
                    .mark_sensitive(),
                ),
                ("event", object([("public", GithubValue::string("safe"))])),
                (
                    "secret_json",
                    GithubValue::sensitive_string("{\"token\":\"value\"}"),
                ),
            ]),
        ),
        ("secret", sensitive.clone()),
        (
            "secrets",
            object([("API_KEY", GithubValue::sensitive_string(canary))]),
        ),
    ]);
    let evaluator = GithubExpressionEvaluator::default();

    let direct = evaluator
        .evaluate(&compile_value("${{ github.token }}"), &context)
        .expect("direct sensitive value evaluates");
    assert!(direct.is_sensitive());
    assert_eq!(direct.as_str(), None);
    assert_eq!(direct.coerce_to_string(), canary);

    for expression in [
        "${{ format('prefix-{0}-suffix', github.token) }}",
        "${{ join(github.values.*, '|') }}",
        "${{ github.values.* }}",
        "${{ github.secret_rows.*.name }}",
        "${{ github.token == 'nope' }}",
        "${{ case(github.token == 'nope', 'never', 'selected') }}",
        "${{ fromJSON(github.secret_json).token }}",
    ] {
        let value = evaluator
            .evaluate(&compile_value(expression), &context)
            .expect("sensitive derivation evaluates");
        assert!(value.is_sensitive(), "lost sensitivity: {expression}");
        assert!(!format!("{value:?}").contains(canary));
    }

    let json = evaluator
        .evaluate(&compile_value("${{ toJSON(github.event) }}"), &context)
        .expect("public subtree remains serializable");
    assert_eq!(json.as_str(), Some("{\n  \"public\": \"safe\"\n}"));

    for expression in ["${{ toJSON(github) }}", "${{ format(github.token) }}"] {
        let error = evaluator
            .evaluate(&compile_value(expression), &context)
            .expect_err("sensitive serialization or malformed template fails closed");
        assert_eq!(
            error.kind(),
            GithubExpressionEvaluationErrorKind::InvalidOperation
        );
        assert!(!format!("{error:?}").contains(canary));
        assert!(!error.to_string().contains(canary));
    }

    let extension_context = MapContext::new(
        BTreeMap::from([("secret".to_owned(), sensitive)]),
        GithubStatus::Success,
        Arc::new(CountingFunctions {
            calls: AtomicUsize::new(0),
        }),
    )
    .expect("valid extension context");
    let extension = evaluator
        .evaluate(&manual_named_call("echo", "secret"), &extension_context)
        .expect("extension call evaluates");
    assert!(extension.is_sensitive());
    assert_eq!(extension.as_str(), None);
    assert_eq!(extension.coerce_to_string(), "extension");

    let Some(GithubValue::Object(secrets)) = context.named_value("secrets") else {
        panic!("secrets context is an object");
    };
    assert!(
        secrets
            .get("api_key")
            .is_some_and(GithubValue::is_sensitive)
    );
    assert!(!format!("{context:?}").contains(canary));
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
    let _: &dyn automata_ci_expression_actions::GithubEvaluationContext = &context([]);
}
