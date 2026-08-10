use automata_ci_core::{
    ExpressionDialect, ExpressionInstruction, ExpressionProgram, MAX_VALUE_TEMPLATE_SEGMENTS,
    RuntimeBoolean, ValueTemplate, ValueTemplateError, ValueTemplateSegment,
};

fn expression(source: &str, name: &str) -> ExpressionProgram {
    ExpressionProgram::new(
        ExpressionDialect::new("github-actions", 1).expect("dialect"),
        source,
        vec![ExpressionInstruction::NamedValue {
            name: name.to_owned(),
        }],
    )
    .expect("expression")
}

#[test]
fn mixed_templates_round_trip_without_reparsing_expressions() {
    let program = expression("matrix.target", "matrix");
    let template = ValueTemplate::new(vec![
        ValueTemplateSegment::literal("build-"),
        ValueTemplateSegment::expression(program.clone()),
        ValueTemplateSegment::literal(".tar.zst"),
    ])
    .expect("mixed template");

    assert_eq!(template.segments().len(), 3);
    assert_eq!(template.segments()[0].literal_value(), Some("build-"));
    assert_eq!(template.segments()[1].expression_program(), Some(&program));

    let encoded = serde_json::to_value(&template).expect("serialize");
    assert!(encoded.get("segments").is_some());
    let decoded: ValueTemplate = serde_json::from_value(encoded).expect("deserialize");
    assert_eq!(decoded, template);
}

#[test]
fn template_segmentation_is_canonical_and_bounded() {
    assert_eq!(
        ValueTemplate::new(Vec::new()),
        Err(ValueTemplateError::Empty)
    );
    assert_eq!(
        ValueTemplate::new(vec![
            ValueTemplateSegment::literal("a"),
            ValueTemplateSegment::literal("b"),
        ]),
        Err(ValueTemplateError::AdjacentLiterals)
    );
    assert_eq!(
        ValueTemplate::new(vec![
            ValueTemplateSegment::literal(""),
            ValueTemplateSegment::expression(expression("inputs.value", "inputs")),
        ]),
        Err(ValueTemplateError::EmptyLiteral)
    );
    assert!(ValueTemplate::literal("").is_ok());

    let segments = (0..=MAX_VALUE_TEMPLATE_SEGMENTS)
        .map(|_| ValueTemplateSegment::expression(expression("vars.x", "vars")))
        .collect();
    assert_eq!(
        ValueTemplate::new(segments),
        Err(ValueTemplateError::TooManySegments {
            maximum: MAX_VALUE_TEMPLATE_SEGMENTS,
        })
    );
}

#[test]
fn serde_rejects_unknown_fields_and_invalid_segmentation() {
    let invalid = serde_json::json!({
        "segments": [
            {"kind": "literal", "value": "a"},
            {"kind": "literal", "value": "b"}
        ]
    });
    assert!(serde_json::from_value::<ValueTemplate>(invalid).is_err());

    let unknown = serde_json::json!({
        "segments": [{"kind": "literal", "value": "ok"}],
        "future": true
    });
    assert!(serde_json::from_value::<ValueTemplate>(unknown).is_err());
}

#[test]
fn deferred_runtime_boolean_preserves_typed_literals_and_programs() {
    assert_eq!(RuntimeBoolean::literal(false).literal_value(), Some(false));
    let program = expression("failure()", "failure");
    let value = RuntimeBoolean::expression(program.clone());
    assert_eq!(value.literal_value(), None);
    assert_eq!(value.expression_program(), Some(&program));
}
