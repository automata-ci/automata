use std::io;

use automata_ci_core::{PlanSourceOrigin, Sha256Digest};
use automata_ci_workflow_actions::{
    GithubWorkflowDispatchInputs, GithubWorkflowDispatchInputsError,
    LocalGithubArchiveCompilationFailureKind, MAX_GITHUB_WORKFLOW_DISPATCH_INPUT_CHARACTERS,
    MAX_GITHUB_WORKFLOW_DISPATCH_INPUTS, RepositoryWorkflowDiscoveryLimits,
    compile_local_github_archive,
};
use flate2::{Compression, GzBuilder};
use sha2::{Digest as _, Sha256};
use tar::{Builder, EntryType, Header};

const ROOT_PATH: &str = ".github/workflows/root.yml";
const ROOT: &str = "worktree";
const DISPATCH: &str = r"on:
  workflow_dispatch:
    inputs:
      enabled:
        type: boolean
        required: true
jobs:
  check:
    runs-on: linux
    steps:
      - run: true
";
const SIMPLE_DISPATCH: &[u8] =
    b"on: workflow_dispatch\njobs:\n  check:\n    runs-on: linux\n    steps:\n      - run: true\n";

#[test]
fn sealed_archive_derives_local_source_and_event_authority() {
    let archive = archive(&[Entry::File(ROOT_PATH, DISPATCH.as_bytes())]);
    let inputs = GithubWorkflowDispatchInputs::try_new([("enabled", true)]).unwrap();
    let report =
        compile_local_github_archive(&archive, Some(ROOT_PATH), inputs, limits(), &|| false)
            .expect("sealed local archive");

    let expected_digest = Sha256Digest::from_bytes(Sha256::digest(&archive).into());
    assert_eq!(report.snapshot_digest(), expected_digest);
    assert_eq!(report.selected_path(), ROOT_PATH);
    assert_eq!(report.root_plan().source().provider(), "local");
    assert_eq!(report.root_plan().event().provider(), "local");
    assert_eq!(report.root_plan().event().name(), "workflow_dispatch");
    assert!(report.root_plan().event().delivery_id().is_none());
    assert!(report.root_plan().event().commit_sha().is_none());
    let PlanSourceOrigin::Archive {
        snapshot_digest,
        path,
    } = report.root_plan().source().origin()
    else {
        panic!("archive-shaped local provenance")
    };
    assert_eq!(*snapshot_digest, expected_digest);
    assert_eq!(path, ROOT_PATH);
}

#[test]
fn exact_selector_github_namespace_and_explicit_dispatch_fail_closed() {
    let two = archive(&[
        Entry::File(ROOT_PATH, DISPATCH.as_bytes()),
        Entry::File(
            ".github/workflows/second.yml",
            b"on: workflow_dispatch\njobs:\n  ok:\n    runs-on: linux\n    steps:\n      - run: true\n",
        ),
    ]);
    assert_eq!(
        compile(&two, None).unwrap_err().kind(),
        LocalGithubArchiveCompilationFailureKind::WorkflowSelectionRequired
    );
    assert_eq!(
        compile(&two, Some("root.yml")).unwrap_err().kind(),
        LocalGithubArchiveCompilationFailureKind::WorkflowNotFound
    );

    let automata_namespace = archive(&[Entry::File(".ci/workflows/root.yml", DISPATCH.as_bytes())]);
    assert_eq!(
        compile(&automata_namespace, None).unwrap_err().kind(),
        LocalGithubArchiveCompilationFailureKind::Archive
    );

    let push = archive(&[Entry::File(
        ROOT_PATH,
        b"on: push\njobs:\n  check:\n    runs-on: linux\n    steps:\n      - run: true\n",
    )]);
    assert_eq!(
        compile(&push, Some(ROOT_PATH)).unwrap_err().kind(),
        LocalGithubArchiveCompilationFailureKind::Compilation
    );
}

#[test]
fn reachable_reusable_workflows_must_be_same_archive_local_members() {
    let local = archive(&[
        Entry::File(
            ROOT_PATH,
            b"on: workflow_dispatch\njobs:\n  call:\n    uses: ./.github/workflows/callee.yml\n",
        ),
        Entry::File(
            ".github/workflows/callee.yml",
            b"on: workflow_call\njobs:\n  check:\n    runs-on: linux\n    steps:\n      - run: true\n",
        ),
    ]);
    let compiled = compile(&local, Some(ROOT_PATH)).expect("same-archive reusable call");
    assert_eq!(compiled.reusable_workflows().len(), 1);
    let callee = &compiled.reusable_workflows()[0];
    assert_eq!(callee.path(), ".github/workflows/callee.yml");
    assert_eq!(callee.plan().source().provider(), "local");
    assert_eq!(callee.plan().event().provider(), "local");
    assert_eq!(callee.plan().event().name(), "workflow_call");

    for reference in [
        "owner/repository/.github/workflows/callee.yml@main",
        "./.github/workflows/missing.yml",
    ] {
        let body = format!("on: workflow_dispatch\njobs:\n  call:\n    uses: {reference}\n");
        let rejected = archive(&[Entry::File(ROOT_PATH, body.as_bytes())]);
        assert_eq!(
            compile(&rejected, Some(ROOT_PATH)).unwrap_err().kind(),
            LocalGithubArchiveCompilationFailureKind::ReusableWorkflow
        );
    }
}

#[test]
fn local_archive_symlinks_are_contained_and_cannot_alias_workflow_authority() {
    let contained = archive(&[
        Entry::File(ROOT_PATH, SIMPLE_DISPATCH),
        Entry::File("target", b"target"),
        Entry::Symlink("safe/link", "../target"),
    ]);
    compile(&contained, Some(ROOT_PATH)).expect("contained unrelated symlink");

    let alias = archive(&[
        Entry::File(ROOT_PATH, SIMPLE_DISPATCH),
        Entry::Symlink("alternate", ".github"),
    ]);
    assert_eq!(
        compile(&alias, Some(ROOT_PATH)).unwrap_err().kind(),
        LocalGithubArchiveCompilationFailureKind::Archive
    );

    let cycle = archive(&[
        Entry::File(ROOT_PATH, SIMPLE_DISPATCH),
        Entry::Symlink("one", "two"),
        Entry::Symlink("two", "one"),
    ]);
    assert_eq!(
        compile(&cycle, Some(ROOT_PATH)).unwrap_err().kind(),
        LocalGithubArchiveCompilationFailureKind::Archive
    );
}

#[test]
fn canonical_inputs_are_bounded_redacted_and_cancellable() {
    let too_many = (0..=MAX_GITHUB_WORKFLOW_DISPATCH_INPUTS)
        .map(|index| (format!("input_{index}"), String::new()));
    assert_eq!(
        GithubWorkflowDispatchInputs::try_new(too_many),
        Err(GithubWorkflowDispatchInputsError::TooManyInputs)
    );
    assert_eq!(
        GithubWorkflowDispatchInputs::try_new([(
            "input",
            "x".repeat(MAX_GITHUB_WORKFLOW_DISPATCH_INPUT_CHARACTERS),
        )]),
        Err(GithubWorkflowDispatchInputsError::PayloadTooLarge)
    );
    assert_eq!(
        GithubWorkflowDispatchInputs::try_new([("input", "line\nbreak".to_owned())]),
        Err(GithubWorkflowDispatchInputsError::InvalidInputValue)
    );
    let redacted =
        GithubWorkflowDispatchInputs::try_new([("input", "private-value".to_owned())]).unwrap();
    assert!(!format!("{redacted:?}").contains("private-value"));

    let archive = archive(&[Entry::File(ROOT_PATH, DISPATCH.as_bytes())]);
    let cancelled = compile_local_github_archive(
        &archive,
        Some(ROOT_PATH),
        GithubWorkflowDispatchInputs::try_new([("enabled", true)]).unwrap(),
        limits(),
        &|| true,
    )
    .unwrap_err();
    assert_eq!(
        cancelled.kind(),
        LocalGithubArchiveCompilationFailureKind::Cancelled
    );
}

fn compile(
    bytes: &[u8],
    selector: Option<&str>,
) -> Result<
    automata_ci_workflow_actions::LocalGithubArchiveCompilation,
    automata_ci_workflow_actions::LocalGithubArchiveCompilationFailure,
> {
    compile_local_github_archive(
        bytes,
        selector,
        GithubWorkflowDispatchInputs::try_new(Vec::<(String, String)>::new()).unwrap(),
        limits(),
        &|| false,
    )
}

fn limits() -> RepositoryWorkflowDiscoveryLimits {
    RepositoryWorkflowDiscoveryLimits::new(
        1024 * 1024,
        2 * 1024 * 1024,
        100,
        1024 * 1024,
        4_096,
        16,
        64 * 1024,
    )
    .unwrap()
}

enum Entry<'a> {
    File(&'a str, &'a [u8]),
    Symlink(&'a str, &'a str),
}

fn archive(entries: &[Entry<'_>]) -> Vec<u8> {
    let encoder = GzBuilder::new()
        .mtime(0)
        .write(Vec::new(), Compression::fast());
    let mut builder = Builder::new(encoder);
    append_directory(&mut builder, ROOT).unwrap();
    for entry in entries {
        match entry {
            Entry::File(path, bytes) => {
                let mut header = Header::new_ustar();
                header.set_entry_type(EntryType::Regular);
                header.set_mode(0o644);
                header.set_size(u64::try_from(bytes.len()).unwrap());
                header.set_cksum();
                builder
                    .append_data(&mut header, format!("{ROOT}/{path}"), *bytes)
                    .unwrap();
            }
            Entry::Symlink(path, target) => {
                let mut header = Header::new_ustar();
                header.set_entry_type(EntryType::Symlink);
                header.set_mode(0o777);
                header.set_size(0);
                header.set_link_name(target).unwrap();
                header.set_cksum();
                builder
                    .append_data(&mut header, format!("{ROOT}/{path}"), io::empty())
                    .unwrap();
            }
        }
    }
    let encoder = builder.into_inner().unwrap();
    encoder.finish().unwrap()
}

fn append_directory<W: io::Write>(builder: &mut Builder<W>, path: &str) -> io::Result<()> {
    let mut header = Header::new_ustar();
    header.set_entry_type(EntryType::Directory);
    header.set_mode(0o755);
    header.set_size(0);
    header.set_cksum();
    builder.append_data(&mut header, path, io::empty())
}
