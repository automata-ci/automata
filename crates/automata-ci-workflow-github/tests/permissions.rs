mod support;

use automata_ci_core::{
    PermissionLevel as PlanPermissionLevel, WorkflowEventProvenance, WorkflowPermissions,
};
use automata_ci_workflow_github::{
    CompileWorkflowRequest, GithubWorkflowCompiler, PermissionLevel, Permissions,
};

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
    let parsed = support::parse(&source);
    assert!(parsed.is_accepted(), "{:#?}", parsed.diagnostics());
    let report = GithubWorkflowCompiler::new().compile(CompileWorkflowRequest::new(
        parsed.plan().expect("source plan"),
        WorkflowEventProvenance::new("github", "workflow_dispatch")
            .with_delivery_id("synthetic-permissions")
            .with_commit_sha("0123456789abcdef0123456789abcdef01234567")
            .with_git_ref("refs/heads/main"),
    ));
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

fn assert_permission(permissions: &WorkflowPermissions, expected: PlanPermissionLevel) {
    let WorkflowPermissions::Mapping(entries) = permissions else {
        panic!("permissions must remain an explicit mapping");
    };
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].name().value(), "id-token");
    assert_eq!(*entries[0].level().value(), expected);
}
