use automata_expression_github::{
    GithubObject, GithubStatus, GithubValue, GithubValueError, MapContext,
};
use std::collections::BTreeMap;

#[test]
fn rejects_case_colliding_object_and_context_keys() {
    assert_eq!(
        GithubObject::new(vec![
            ("Key".to_owned(), GithubValue::Null),
            ("key".to_owned(), GithubValue::Null),
        ])
        .expect_err("collision is rejected"),
        GithubValueError::DuplicateKey
    );

    let values = BTreeMap::from([
        ("Github".to_owned(), GithubValue::Null),
        ("github".to_owned(), GithubValue::Null),
    ]);
    assert!(MapContext::without_extensions(values, GithubStatus::default()).is_err());
}

#[test]
fn value_debug_output_does_not_expose_payloads() {
    let value = GithubValue::string("credential-material");
    let rendered = format!("{value:?}");
    assert!(rendered.contains("REDACTED"));
    assert!(!rendered.contains("credential-material"));
}

#[test]
fn object_lookup_uses_unicode_case_insensitive_keys() {
    let object = GithubObject::new(vec![("Ärger".to_owned(), GithubValue::Boolean(true))])
        .expect("valid object");
    assert_eq!(
        object.get("ärger").and_then(GithubValue::as_bool),
        Some(true)
    );
}

#[test]
fn scalar_string_coercion_uses_runner_number_shape() {
    assert_eq!(GithubValue::Null.coerce_to_string(), "");
    assert_eq!(GithubValue::Boolean(true).coerce_to_string(), "true");
    assert_eq!(GithubValue::number(-0.0).coerce_to_string(), "0");
    assert_eq!(GithubValue::number(0.0001).coerce_to_string(), "0.0001");
    assert_eq!(GithubValue::number(0.00001).coerce_to_string(), "1E-05");
    assert_eq!(
        GithubValue::number(1.234_567_890_123_456_7).coerce_to_string(),
        "1.23456789012346"
    );
}
