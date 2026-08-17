use crate::support;

use automata_ci_core::{
    PermissionLevel as PlanPermissionLevel, WorkflowEventProvenance, WorkflowPermissions,
};
use automata_ci_github_permissions::GITHUB_WORKFLOW_PERMISSIONS;
use automata_ci_workflow_github::{PermissionLevel, Permissions};

const JOB: &str = r"
jobs:
  verify:
    runs-on: linux
    steps:
      - run: echo verify
";

#[test]
fn id_token_read_is_rejected_without_losing_valid_sibling_permissions() {
    let source =
        format!("on: workflow_dispatch\npermissions:\n  id-token: read\n  contents: read\n{JOB}");
    let report = support::parse(&source);
    assert!(!report.is_accepted());
    assert!(report.diagnostics().iter().any(|diagnostic| {
        diagnostic.code() == "github.invalid_id_token_permission_level"
            && diagnostic.message().contains("permissions.id-token")
            && diagnostic.message().contains("`write` or `none`")
    }));

    let Permissions::Mapping { entries, .. } = report
        .plan()
        .expect("loss-aware source plan")
        .workflow()
        .permissions()
        .expect("permission mapping")
    else {
        panic!("permissions must remain a mapping");
    };
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].name().value(), "contents");
    assert_eq!(*entries[0].level().value(), PermissionLevel::Read);
}

#[test]
fn id_token_write_and_none_survive_current_logical_compilation() {
    let source = format!("on: workflow_dispatch\npermissions:\n  id-token: write\n{JOB}").replace(
        "    runs-on: linux",
        "    permissions:\n      id-token: none\n    runs-on: linux",
    );
    let parsed = support::parse_accepted(&source);
    let report = support::compile(
        parsed.plan().expect("source plan"),
        WorkflowEventProvenance::new("github", "workflow_dispatch")
            .with_delivery_id("synthetic-permissions")
            .with_commit_sha(
                automata_ci_core::GitObjectId::from_provider_hex(
                    "0123456789abcdef0123456789abcdef01234567",
                )
                .expect("revision"),
            )
            .with_git_ref("refs/heads/main"),
        None,
    );
    assert!(report.is_accepted(), "{:#?}", report.diagnostics());
    let logical = report.plan().expect("logical plan").logical();

    assert_permission(
        logical
            .permissions()
            .expect("workflow permission snapshot")
            .permissions(),
        PlanPermissionLevel::Write,
    );
    assert_permission(
        logical.jobs()[0]
            .permissions()
            .expect("job permission snapshot")
            .permissions(),
        PlanPermissionLevel::None,
    );
}

#[test]
fn every_catalog_permission_accepts_exactly_its_declared_levels() {
    for permission in GITHUB_WORKFLOW_PERMISSIONS {
        for (level, allowed) in [
            ("read", permission.allows_read()),
            ("write", permission.allows_write()),
            ("none", true),
        ] {
            let source = format!(
                "on: workflow_dispatch\npermissions:\n  {}: {level}\n{JOB}",
                permission.name()
            );
            let parsed = support::parse(&source);
            assert_eq!(
                parsed.is_accepted(),
                allowed,
                "{}:{level}: {:#?}",
                permission.name(),
                parsed.diagnostics()
            );
            if allowed {
                let compiled = support::compile(
                    parsed.plan().expect("source plan"),
                    WorkflowEventProvenance::new("github", "workflow_dispatch"),
                    None,
                );
                assert!(
                    compiled.is_accepted(),
                    "{}:{level}: {:#?}",
                    permission.name(),
                    compiled.diagnostics()
                );
            }
        }
    }
}

#[test]
fn an_unknown_permission_is_rejected_at_its_exact_key_span() {
    let source = format!(
        "on: workflow_dispatch\npermissions:\n  future-scope: read\n  contents: read\n{JOB}"
    );
    let parsed = support::parse(&source);
    assert!(!parsed.is_accepted());
    let plan = parsed.plan().expect("loss-aware source plan");
    let diagnostic = parsed
        .diagnostics()
        .iter()
        .find(|diagnostic| diagnostic.code() == "github.unknown_permission")
        .expect("unknown permission diagnostic");
    assert_eq!(
        plan.source().slice(diagnostic.primary_span()),
        Some("future-scope")
    );

    let Permissions::Mapping { entries, .. } = plan
        .workflow()
        .permissions()
        .expect("retained valid mapping")
    else {
        panic!("permissions must remain a mapping");
    };
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].name().value(), "contents");
}

#[test]
fn an_explicit_empty_mapping_is_a_valid_deny_all_request() {
    let source = format!("on: workflow_dispatch\npermissions: {{}}\n{JOB}");
    let parsed = support::parse_accepted(&source);
    let compiled = support::compile(
        parsed.plan().expect("source plan"),
        WorkflowEventProvenance::new("github", "workflow_dispatch"),
        None,
    );
    assert!(compiled.is_accepted(), "{:#?}", compiled.diagnostics());
    let WorkflowPermissions::Mapping(grants) = compiled
        .plan()
        .expect("logical plan")
        .logical()
        .permissions()
        .expect("permission snapshot")
        .permissions()
    else {
        panic!("permissions must remain an explicit mapping");
    };
    assert!(grants.is_empty());
}

fn assert_permission(permissions: &WorkflowPermissions, expected: PlanPermissionLevel) {
    let WorkflowPermissions::Mapping(entries) = permissions else {
        panic!("permissions must remain an explicit mapping");
    };
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].name().value(), "id-token");
    assert_eq!(*entries[0].level().value(), expected);
}
