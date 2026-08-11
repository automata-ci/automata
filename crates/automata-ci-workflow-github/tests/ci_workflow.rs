mod support;

use automata_ci_workflow_github::{
    EventName, PermissionLevel, Permissions, ScalarResolution, StepExecution, TriggerConfiguration,
    YamlNodeKind,
};

const REPOSITORY_CI: &str = include_str!("fixtures/repository-ci.yml");

#[test]
fn packaged_ci_fixture_matches_the_repository_workflow() {
    let repository_ci =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../.github/workflows/ci.yml");
    if repository_ci.is_file() {
        let checked_in =
            std::fs::read_to_string(&repository_ci).expect("read repository CI workflow");
        assert_eq!(REPOSITORY_CI, checked_in);
    }
}

#[test]
fn repository_ci_produces_an_accepted_source_plan() {
    let report = support::parse(REPOSITORY_CI);
    assert!(
        report.is_accepted(),
        "diagnostics: {:#?}",
        report.diagnostics()
    );
    let plan = report.plan().expect("repository CI should produce a plan");

    assert_eq!(plan.source().text(), REPOSITORY_CI);
    assert_eq!(
        plan.workflow().name().map(|name| name.value().as_str()),
        Some("CI")
    );
    assert_eq!(plan.workflow().jobs().len(), 7);
    assert_eq!(
        plan.workflow()
            .jobs()
            .iter()
            .map(|job| job.id().as_str())
            .collect::<Vec<_>>(),
        [
            "verify",
            "rust_tests",
            "postgres_store",
            "postgres_integrations",
            "frontend",
            "renderer",
            "dist",
        ]
    );

    let Permissions::Mapping {
        entries: workflow_permissions,
        ..
    } = plan.workflow().permissions().expect("workflow permissions")
    else {
        panic!("workflow permissions must remain an explicit mapping");
    };
    assert_eq!(
        workflow_permissions
            .iter()
            .map(|entry| (entry.name().value().as_str(), *entry.level().value()))
            .collect::<Vec<_>>(),
        [("contents", PermissionLevel::Read)]
    );
    assert!(plan.workflow().jobs()[1].job().permissions().is_none());

    let renderer = plan
        .workflow()
        .jobs()
        .iter()
        .find(|job| job.id().as_str() == "renderer")
        .expect("renderer job")
        .job();
    assert_eq!(
        renderer.condition().expect("renderer condition").value(),
        "${{ github.event_name != 'pull_request' }}"
    );
    assert!(renderer.permissions().is_none());
    assert_eq!(renderer.steps().len(), 2);
    assert_eq!(
        plan.workflow()
            .jobs()
            .iter()
            .find(|job| job.id().as_str() == "dist")
            .expect("distribution job")
            .job()
            .condition()
            .expect("distribution condition")
            .value(),
        r"${{ !cancelled()
    && needs.verify.result == 'success'
    && needs.rust_tests.result == 'success'
    && needs.postgres_store.result == 'success'
    && needs.postgres_integrations.result == 'success'
    && needs.frontend.result == 'success'
    && (needs.renderer.result == 'success'
        || (github.event_name == 'pull_request'
            && needs.renderer.result == 'skipped')) }}"
    );

    let triggers = plan.workflow().triggers().expect("on is required");
    assert!(matches!(
        triggers.events()[0].name().value(),
        EventName::Push
    ));
    assert!(matches!(
        triggers.events()[0].configuration(),
        TriggerConfiguration::Push(_)
    ));
    assert!(matches!(
        plan.workflow().jobs()[0].job().steps()[0].execution(),
        Some(StepExecution::Action(_))
    ));
}

#[test]
fn repository_ci_retains_the_exact_on_key_source() {
    let report = support::parse(REPOSITORY_CI);
    let plan = report.plan().expect("plan");
    let entries = plan
        .document()
        .root()
        .as_mapping()
        .expect("workflow mapping");
    let on_entry = entries
        .iter()
        .find(|entry| {
            entry
                .key()
                .as_scalar()
                .is_some_and(|key| key.decoded() == "on")
        })
        .expect("on entry");
    let scalar = on_entry.key().as_scalar().expect("scalar key");

    assert_eq!(scalar.resolution(), ScalarResolution::String);
    assert_eq!(plan.source().slice(on_entry.key().span()), Some("on"));
    assert_eq!(on_entry.key().span().start().line(), 3);
    assert_eq!(on_entry.key().span().start().column(), 1);
}

#[test]
fn source_ast_retains_mapping_order_and_scalar_styles() {
    let source = include_str!("fixtures/valid.yml");
    let report = support::parse(source);
    assert!(
        report.is_accepted(),
        "diagnostics: {:#?}",
        report.diagnostics()
    );
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
