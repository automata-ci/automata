mod support;

use automata_ci_workflow_github::{ScalarResolution, YamlNode};

#[test]
fn yaml_1_2_does_not_resolve_on_off_yes_or_no_as_booleans() {
    let source = "on: push\nenv:\n  ON_VALUE: on\n  OFF_VALUE: off\n  YES_VALUE: yes\n  NO_VALUE: no\n  TRUE_VALUE: true\n  QUOTED_TRUE: 'true'\njobs:\n  build:\n    runs-on: linux\n    steps:\n      - run: echo test\n";
    let report = support::parse(source);
    assert!(
        report.is_accepted(),
        "diagnostics: {:#?}",
        report.diagnostics()
    );
    let plan = report.plan().expect("plan");
    let root = plan.document().root().as_mapping().expect("mapping");
    let on_key = root[0].key().as_scalar().expect("on key");
    assert_eq!(on_key.decoded(), "on");
    assert_eq!(on_key.resolution(), ScalarResolution::String);

    let env = mapping_value(plan.document().root(), "env");
    let env = env.as_mapping().expect("env mapping");
    let resolutions = env
        .iter()
        .map(|entry| {
            (
                entry.key().as_scalar().expect("key").decoded(),
                entry.value().as_scalar().expect("value").resolution(),
            )
        })
        .collect::<Vec<_>>();
    assert_eq!(
        resolutions,
        [
            ("ON_VALUE", ScalarResolution::String),
            ("OFF_VALUE", ScalarResolution::String),
            ("YES_VALUE", ScalarResolution::String),
            ("NO_VALUE", ScalarResolution::String),
            ("TRUE_VALUE", ScalarResolution::Boolean),
            ("QUOTED_TRUE", ScalarResolution::String),
        ]
    );
}

#[test]
fn original_text_is_an_exact_round_trip_artifact() {
    let source = include_str!("fixtures/valid.yml");
    let report = support::parse(source);
    let plan = report.plan().expect("plan");
    assert_eq!(plan.source().text().as_bytes(), source.as_bytes());
    assert!(plan.source().text().starts_with("# The comments"));
}

#[test]
fn spans_use_utf8_byte_offsets_and_one_based_display_locations() {
    let source = "name: 'café'\non: push\njobs:\n  build:\n    runs-on: linux\n    steps:\n      - run: echo test\n";
    let report = support::parse(source);
    assert!(
        report.is_accepted(),
        "diagnostics: {:#?}",
        report.diagnostics()
    );
    let plan = report.plan().expect("plan");
    let name = plan.document().root().as_mapping().expect("mapping")[0].value();
    assert_eq!(plan.source().slice(name.span()), Some("'café'"));
    assert_eq!(name.span().start().line(), 1);
    assert_eq!(name.span().start().column(), 7);
    assert_eq!(
        name.span().end().byte_offset() - name.span().start().byte_offset(),
        7
    );
}

fn mapping_value<'node>(node: &'node YamlNode, key: &str) -> &'node YamlNode {
    node.as_mapping()
        .expect("mapping")
        .iter()
        .find(|entry| {
            entry
                .key()
                .as_scalar()
                .is_some_and(|scalar| scalar.decoded() == key)
        })
        .expect("key")
        .value()
}
