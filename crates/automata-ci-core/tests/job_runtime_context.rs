use std::collections::BTreeMap;

use automata_ci_core::{
    ContextValue, JOB_RUNTIME_CONTEXT_SCHEMA_VERSION, JobConclusion, JobRuntimeContext,
    MAX_CONTEXT_VALUE_DEPTH, MAX_CONTEXT_VALUE_NODES, MAX_CONTEXT_VALUE_TEXT_BYTES, NeedContext,
    NeedOutput, OutputSensitivity, RuntimeContextError, SecretBinding, StrategyContext,
};

fn object(entries: impl IntoIterator<Item = (&'static str, ContextValue)>) -> ContextValue {
    ContextValue::object(
        entries
            .into_iter()
            .map(|(key, value)| (key.to_owned(), value))
            .collect(),
    )
    .expect("bounded object")
}

fn strategy() -> StrategyContext {
    StrategyContext::new(true, 1, 3, 2).expect("strategy")
}

#[test]
fn canonical_values_preserve_types_order_and_exact_numbers() {
    let value = object([
        (
            "array",
            ContextValue::array(vec![ContextValue::null(), ContextValue::boolean(true)])
                .expect("array"),
        ),
        ("number", ContextValue::number(-0.0)),
        ("text", ContextValue::string("value")),
    ]);
    value.validate().expect("canonical value");
    assert_eq!(
        value
            .as_object()
            .expect("object")
            .get("number")
            .and_then(ContextValue::as_number)
            .expect("number")
            .to_bits(),
        (-0.0_f64).to_bits()
    );

    let encoded = serde_json::to_string(&value).expect("serialize");
    let decoded: ContextValue = serde_json::from_str(&encoded).expect("deserialize");
    assert_eq!(decoded, value);
}

#[test]
fn canonical_object_deserialization_rejects_duplicate_keys() {
    let duplicate = r#"{
        "kind":"object",
        "values":{
            "target":{"kind":"string","value":"linux"},
            "target":{"kind":"string","value":"windows"}
        }
    }"#;
    assert!(serde_json::from_str::<ContextValue>(duplicate).is_err());
}

#[test]
fn canonical_value_limits_reject_depth_nodes_text_and_nan_payloads() {
    let mut deep = ContextValue::null();
    for _ in 0..MAX_CONTEXT_VALUE_DEPTH {
        deep = ContextValue::Array { values: vec![deep] };
    }
    assert_eq!(
        deep.validate(),
        Err(RuntimeContextError::ValueTooDeep {
            maximum: MAX_CONTEXT_VALUE_DEPTH,
        })
    );

    let wide = ContextValue::Array {
        values: vec![ContextValue::null(); MAX_CONTEXT_VALUE_NODES],
    };
    assert_eq!(
        wide.validate(),
        Err(RuntimeContextError::TooManyValueNodes {
            maximum: MAX_CONTEXT_VALUE_NODES,
        })
    );

    let text = ContextValue::string("x".repeat(MAX_CONTEXT_VALUE_TEXT_BYTES + 1));
    assert_eq!(
        text.validate(),
        Err(RuntimeContextError::TooMuchValueText {
            maximum: MAX_CONTEXT_VALUE_TEXT_BYTES,
        })
    );

    let noncanonical_nan = ContextValue::Number {
        ieee754_bits: 0x7ff8_0000_0000_0001,
    };
    assert_eq!(
        noncanonical_nan.validate(),
        Err(RuntimeContextError::NonCanonicalNan)
    );
    assert_eq!(
        ContextValue::number(f64::from_bits(0x7ff8_0000_0000_0001)),
        ContextValue::number(f64::NAN)
    );
}

#[test]
fn runtime_context_round_trips_with_opaque_secret_bindings() {
    let needs = BTreeMap::from([(
        "compile".to_owned(),
        NeedContext::new(
            JobConclusion::Success,
            BTreeMap::from([(
                "digest".to_owned(),
                NeedOutput::new("abc123", OutputSensitivity::Public).expect("public output"),
            )]),
        )
        .expect("need"),
    )]);
    let secrets = BTreeMap::from([(
        "REGISTRY_TOKEN".to_owned(),
        SecretBinding::new("binding-42")
            .expect("binding")
            .with_version_id("version-7")
            .expect("version"),
    )]);
    let context = JobRuntimeContext::new(
        object([("release", ContextValue::boolean(false))]),
        object([("channel", ContextValue::string("nightly"))]),
        object([("target", ContextValue::string("linux-x64"))]),
        strategy(),
        needs,
        secrets,
    )
    .expect("runtime context");

    assert_eq!(context.schema_version(), JOB_RUNTIME_CONTEXT_SCHEMA_VERSION);
    assert_eq!(context.schema_version(), 2);
    assert_eq!(context.strategy().job_index(), 1);
    assert_eq!(context.needs()["compile"].result(), JobConclusion::Success);
    assert_eq!(
        context.secrets()["REGISTRY_TOKEN"].version_id(),
        Some("version-7")
    );

    let encoded = serde_json::to_string(&context).expect("serialize");
    assert!(encoded.contains("binding-42"));
    let decoded: JobRuntimeContext = serde_json::from_str(&encoded).expect("deserialize");
    assert_eq!(decoded, context);
}

#[test]
fn admitted_base_context_preserves_values_and_redacts_all_debug_payloads() {
    let binding_id = "opaque-binding-locator";
    let version_id = "opaque-version-locator";
    let input_value = "production-target";
    let variable_value = "stable-channel";
    let context = JobRuntimeContext::new_base(
        object([("target", ContextValue::string(input_value))]),
        object([("channel", ContextValue::string(variable_value))]),
        BTreeMap::from([(
            "DEPLOY_TOKEN".to_owned(),
            SecretBinding::new(binding_id)
                .expect("binding")
                .with_version_id(version_id)
                .expect("version"),
        )]),
    )
    .expect("admitted base context");

    assert_eq!(
        context
            .inputs()
            .as_object()
            .and_then(|inputs| inputs.get("target"))
            .and_then(ContextValue::as_string),
        Some(input_value)
    );
    assert_eq!(
        context
            .vars()
            .as_object()
            .and_then(|vars| vars.get("channel"))
            .and_then(ContextValue::as_string),
        Some(variable_value)
    );
    assert!(context.matrix().as_object().is_some_and(BTreeMap::is_empty));
    assert!(context.needs().is_empty());
    assert_eq!(context.strategy().job_total(), 1);
    assert_eq!(
        context.secrets()["DEPLOY_TOKEN"].version_id(),
        Some(version_id)
    );

    let context_debug = format!("{context:?}");
    let binding_debug = format!("{:?}", context.secrets()["DEPLOY_TOKEN"]);
    for sentinel in [binding_id, version_id, input_value, variable_value] {
        assert!(!context_debug.contains(sentinel));
        assert!(!binding_debug.contains(sentinel));
    }
    assert!(context_debug.contains("REDACTED"));
    assert!(binding_debug.contains("REDACTED"));
}

#[test]
fn need_outputs_retain_sensitivity_and_redact_debug_values() {
    let sentinel = "secret-output\nsecond-line";
    let public = NeedOutput::new("published", OutputSensitivity::Public).expect("public output");
    let secret =
        NeedOutput::new(sentinel, OutputSensitivity::SecretDerived).expect("secret-derived output");

    assert_eq!(public.public_value(), Some("published"));
    assert_eq!(secret.public_value(), None);
    assert_eq!(secret.expose_value(), sentinel);
    assert_eq!(secret.sensitivity(), OutputSensitivity::SecretDerived);

    let need = NeedContext::new(
        JobConclusion::Success,
        BTreeMap::from([
            ("public".to_owned(), public),
            ("secret".to_owned(), secret.clone()),
        ]),
    )
    .expect("need context");
    let output_debug = format!("{secret:?}");
    let need_debug = format!("{need:?}");
    for debug in [&output_debug, &need_debug] {
        assert!(!debug.contains(sentinel));
        assert!(!debug.contains("second-line"));
        assert!(debug.contains("REDACTED"));
    }

    let encoded = serde_json::to_string(&need).expect("serialize need");
    let decoded: NeedContext = serde_json::from_str(&encoded).expect("deserialize need");
    assert_eq!(decoded, need);
    assert_eq!(
        decoded.outputs()["secret"].sensitivity(),
        OutputSensitivity::SecretDerived
    );
}

#[test]
fn need_context_rejects_unclassified_or_malformed_output_json() {
    let unclassified = r#"{
        "result":"success",
        "outputs":{"digest":"abc123"}
    }"#;
    assert!(serde_json::from_str::<NeedContext>(unclassified).is_err());

    let missing_sensitivity = r#"{
        "result":"success",
        "outputs":{"digest":{"value":"abc123"}}
    }"#;
    assert!(serde_json::from_str::<NeedContext>(missing_sensitivity).is_err());

    let unknown_field = r#"{
        "result":"success",
        "outputs":{
            "digest":{
                "value":"abc123",
                "sensitivity":"public",
                "legacy":true
            }
        }
    }"#;
    assert!(serde_json::from_str::<NeedContext>(unknown_field).is_err());
}

#[test]
fn runtime_context_requires_object_roots_and_one_aggregate_budget() {
    assert_eq!(
        JobRuntimeContext::new(
            ContextValue::null(),
            ContextValue::empty_object(),
            ContextValue::empty_object(),
            strategy(),
            BTreeMap::new(),
            BTreeMap::new(),
        ),
        Err(RuntimeContextError::ContextMustBeObject("inputs"))
    );

    let half = "x".repeat(MAX_CONTEXT_VALUE_TEXT_BYTES / 2 + 1);
    assert!(matches!(
        JobRuntimeContext::new(
            object([("first", ContextValue::string(half.clone()))]),
            object([("second", ContextValue::string(half))]),
            ContextValue::empty_object(),
            strategy(),
            BTreeMap::new(),
            BTreeMap::new(),
        ),
        Err(RuntimeContextError::TooMuchValueText { .. })
    ));
}

#[test]
fn runtime_context_and_strategy_deserialization_fail_closed() {
    assert_eq!(
        StrategyContext::new(true, 0, 0, 1),
        Err(RuntimeContextError::ZeroJobTotal)
    );
    assert_eq!(
        StrategyContext::new(true, 2, 2, 1),
        Err(RuntimeContextError::JobIndexOutOfRange { index: 2, total: 2 })
    );
    assert_eq!(
        StrategyContext::new(true, 0, 1, 0),
        Err(RuntimeContextError::ZeroMaxParallel)
    );

    let context = JobRuntimeContext::new(
        ContextValue::empty_object(),
        ContextValue::empty_object(),
        ContextValue::empty_object(),
        StrategyContext::new(false, 0, 1, 1).expect("strategy"),
        BTreeMap::new(),
        BTreeMap::new(),
    )
    .expect("context");
    let mut encoded = serde_json::to_value(context).expect("serialize");
    encoded["schema_version"] = serde_json::json!(1);
    assert!(serde_json::from_value::<JobRuntimeContext>(encoded).is_err());
}
