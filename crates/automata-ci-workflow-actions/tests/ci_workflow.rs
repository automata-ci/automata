use crate::support;

use automata_ci_workflow_actions::YamlNodeKind;

#[test]
fn source_ast_retains_mapping_order_and_scalar_styles() {
    let source = include_str!("fixtures/valid.yml");
    let report = support::parse_accepted(source);
    let plan = report.plan().expect("plan");
    let entries = plan.document().root().as_mapping().expect("root mapping");

    assert_eq!(
        entries[0].key().as_scalar().expect("name key").decoded(),
        "name"
    );
    let env = entries
        .iter()
        .find(|entry| {
            entry
                .key()
                .as_scalar()
                .is_some_and(|key| key.decoded() == "env")
        })
        .expect("env");
    let env_entries = env.value().as_mapping().expect("env mapping");
    let version = env_entries[0].value();
    assert_eq!(plan.source().slice(version.span()), Some("\"0.1.0\""));

    let jobs = entries
        .iter()
        .find(|entry| {
            entry
                .key()
                .as_scalar()
                .is_some_and(|key| key.decoded() == "jobs")
        })
        .expect("jobs");
    assert!(matches!(jobs.value().kind(), YamlNodeKind::Mapping(_)));
}
