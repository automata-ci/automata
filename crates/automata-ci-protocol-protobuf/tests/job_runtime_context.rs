use std::collections::BTreeMap;

use automata_ci_core::{
    ContextValue, JobConclusion, JobRuntimeContext, NeedContext, NeedOutput, OutputSensitivity,
    SecretBinding, StrategyContext,
};
use automata_ci_protocol::ProtocolLimits;
use automata_ci_protocol_protobuf::{
    DecodeError, decode_job_runtime_context, encode_job_runtime_context,
};
use prost::Message as _;

#[allow(clippy::all, clippy::pedantic, dead_code)]
mod fixture_wire {
    include!("../src/generated/automata.runner.v1.rs");
}

fn object(entries: impl IntoIterator<Item = (&'static str, ContextValue)>) -> ContextValue {
    ContextValue::object(
        entries
            .into_iter()
            .map(|(key, value)| (key.to_owned(), value))
            .collect(),
    )
    .expect("bounded context object")
}

fn context() -> JobRuntimeContext {
    JobRuntimeContext::new(
        object([("release", ContextValue::boolean(false))]),
        object([("channel", ContextValue::string("nightly"))]),
        object([(
            "targets",
            ContextValue::array(vec![
                ContextValue::string("linux-x64"),
                ContextValue::number(-0.0),
            ])
            .expect("bounded context array"),
        )]),
        StrategyContext::new(true, 1, 3, 2).expect("strategy"),
        BTreeMap::from([(
            "compile".to_owned(),
            NeedContext::new(
                JobConclusion::Success,
                BTreeMap::from([
                    (
                        "digest".to_owned(),
                        NeedOutput::new("abc123", OutputSensitivity::Public)
                            .expect("public output"),
                    ),
                    (
                        "receipt".to_owned(),
                        NeedOutput::new("sensitive-value", OutputSensitivity::SecretDerived)
                            .expect("secret-derived output"),
                    ),
                ]),
            )
            .expect("need context"),
        )]),
        BTreeMap::from([(
            "REGISTRY_TOKEN".to_owned(),
            SecretBinding::new("binding-42")
                .expect("secret binding")
                .with_version_id("version-7")
                .expect("secret version"),
        )]),
    )
    .expect("runtime context")
}

fn wire_context() -> fixture_wire::JobRuntimeContext {
    let encoded = encode_job_runtime_context(&context(), &ProtocolLimits::default())
        .expect("encode runtime context");
    fixture_wire::JobRuntimeContext::decode(encoded.as_slice()).expect("wire runtime context")
}

#[test]
fn runtime_context_is_deterministic_flat_and_round_trips() {
    let context = context();
    let limits = ProtocolLimits::default();
    let first = encode_job_runtime_context(&context, &limits).expect("encode context");
    let second = encode_job_runtime_context(&context, &limits).expect("encode context again");
    assert_eq!(first, second);
    assert_eq!(
        decode_job_runtime_context(&first, &limits).expect("decode context"),
        context
    );
    assert_eq!(
        context.needs()["compile"].outputs()["digest"].public_value(),
        Some("abc123")
    );
    assert_eq!(
        context.needs()["compile"].outputs()["receipt"].public_value(),
        None
    );

    let wire = fixture_wire::JobRuntimeContext::decode(first.as_slice()).expect("wire context");
    assert_eq!(wire.schema_version, 1);
    for (parent, node) in wire.nodes.iter().enumerate() {
        use fixture_wire::context_value_node::Value;
        match node.value.as_ref().expect("node value") {
            Value::Array(array) => assert!(
                array
                    .child_indices
                    .iter()
                    .all(|child| usize::try_from(*child).expect("index") < parent)
            ),
            Value::Object(object) => assert!(
                object
                    .entries
                    .iter()
                    .all(|entry| usize::try_from(entry.value_index).expect("index") < parent)
            ),
            Value::Null(_)
            | Value::Boolean(_)
            | Value::NumberIeee754Bits(_)
            | Value::StringValue(_) => {}
        }
    }
}

#[test]
fn runtime_context_rejects_missing_or_unknown_output_sensitivity() {
    let limits = ProtocolLimits::default();
    for sensitivity in [0, i32::MAX] {
        let mut wire = wire_context();
        wire.needs[0].value.as_mut().expect("need").outputs[0]
            .value
            .as_mut()
            .expect("output")
            .sensitivity = sensitivity;
        assert!(matches!(
            decode_job_runtime_context(&wire.encode_to_vec(), &limits),
            Err(DecodeError::UnknownEnum {
                field: "need_output.sensitivity",
                value
            }) if value == sensitivity
        ));
    }
}

#[test]
fn runtime_context_requires_canonical_classified_output_entries() {
    let limits = ProtocolLimits::default();

    let mut missing = wire_context();
    missing.needs[0].value.as_mut().expect("need").outputs[0].value = None;
    assert!(matches!(
        decode_job_runtime_context(&missing.encode_to_vec(), &limits),
        Err(DecodeError::MissingField {
            field: "need_output_entry.value"
        })
    ));

    let mut descending = wire_context();
    descending.needs[0]
        .value
        .as_mut()
        .expect("need")
        .outputs
        .reverse();
    assert!(matches!(
        decode_job_runtime_context(&descending.encode_to_vec(), &limits),
        Err(DecodeError::NonCanonicalOrder {
            field: "need_context.outputs"
        })
    ));
}

#[test]
fn runtime_context_rejects_a_noncurrent_schema() {
    let limits = ProtocolLimits::default();
    let mut wire = wire_context();
    wire.schema_version = 2;
    assert!(matches!(
        decode_job_runtime_context(&wire.encode_to_vec(), &limits),
        Err(DecodeError::UnsupportedSchema {
            field: "job_runtime_context.schema_version",
            received: 2,
            supported: 1,
        })
    ));
}

#[test]
fn flat_context_rejects_shared_forward_and_unreachable_nodes() {
    let limits = ProtocolLimits::default();

    let mut shared = wire_context();
    shared.vars_index = shared.inputs_index;
    assert!(matches!(
        decode_job_runtime_context(&shared.encode_to_vec(), &limits),
        Err(DecodeError::DuplicateEntry {
            field: "job_runtime_context.nodes"
        })
    ));

    let mut forward = wire_context();
    forward.nodes[0].value = Some(fixture_wire::context_value_node::Value::Array(
        fixture_wire::ContextValueArray {
            child_indices: vec![1],
        },
    ));
    assert!(matches!(
        decode_job_runtime_context(&forward.encode_to_vec(), &limits),
        Err(DecodeError::NonCanonicalOrder {
            field: "job_runtime_context.nodes"
        })
    ));

    let mut unreachable = wire_context();
    unreachable.nodes.push(fixture_wire::ContextValueNode {
        value: Some(fixture_wire::context_value_node::Value::Null(
            fixture_wire::Unit {},
        )),
    });
    assert!(matches!(
        decode_job_runtime_context(&unreachable.encode_to_vec(), &limits),
        Err(DecodeError::InvalidValue {
            field: "job_runtime_context.nodes"
        })
    ));
}

#[test]
fn flat_context_rejects_missing_nodes_and_noncanonical_object_keys() {
    let limits = ProtocolLimits::default();
    let mut missing = wire_context();
    missing.nodes[0].value = None;
    assert!(matches!(
        decode_job_runtime_context(&missing.encode_to_vec(), &limits),
        Err(DecodeError::MissingVariant {
            field: "context_value_node.value"
        })
    ));

    let mut unordered = wire_context();
    let object = unordered
        .nodes
        .iter_mut()
        .find_map(|node| match node.value.as_mut() {
            Some(fixture_wire::context_value_node::Value::Object(object))
                if !object.entries.is_empty() =>
            {
                Some(object)
            }
            _ => None,
        })
        .expect("nonempty object");
    let index = object.entries[0].value_index;
    object.entries = vec![
        fixture_wire::ContextValueEntry {
            key: "z".to_owned(),
            value_index: index,
        },
        fixture_wire::ContextValueEntry {
            key: "a".to_owned(),
            value_index: index,
        },
    ];
    assert!(matches!(
        decode_job_runtime_context(&unordered.encode_to_vec(), &limits),
        Err(DecodeError::NonCanonicalOrder {
            field: "context_value_object.entries"
        })
    ));
}

#[test]
fn runtime_context_decode_applies_the_configured_node_budget() {
    let wire = wire_context();
    let limits =
        ProtocolLimits::new(16 * 1024 * 1024, 3, 1024 * 1024, 1, 1024).expect("coherent limits");
    assert!(matches!(
        decode_job_runtime_context(&wire.encode_to_vec(), &limits),
        Err(DecodeError::CollectionTooLarge {
            field: "job_runtime_context.nodes",
            maximum: 3,
            ..
        })
    ));
}
