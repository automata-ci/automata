use crate::support;

use std::{fs, path::Path};

use automata_ci_core::WorkflowEventProvenance;
use automata_ci_workflow_actions::ProviderEventMetadata;

#[test]
fn native_release_workflow_compiles_for_a_live_tag_push() {
    let repository = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let source = fs::read_to_string(repository.join(".ci/workflows/release.yml"))
        .expect("read native release workflow");
    let parsed = support::parse_accepted(&source);
    let event = WorkflowEventProvenance::new("github", "push")
        .with_delivery_id("release-workflow-contract")
        .with_commit_sha(
            automata_ci_core::GitObjectId::from_provider_hex(
                "0123456789abcdef0123456789abcdef01234567",
            )
            .expect("revision"),
        )
        .with_git_ref("refs/tags/v0.1.0");
    let report = support::compile(
        parsed.plan().expect("release source plan"),
        event,
        Some(ProviderEventMetadata::push(false)),
    );

    assert!(report.is_accepted(), "{:#?}", report.diagnostics());
    assert_eq!(
        report.plan().expect("compiled release plan").jobs().len(),
        5
    );
}
