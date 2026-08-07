mod support;

use automata_action::{
    ActionArchiveError, ActionBundleLimits, ActionDefinitionKind, ActionSubpath, inspect_archive,
};
use automata_scm::ArchiveLimits;
use support::{TestEntry, build_archive, snapshot, snapshot_from_bytes};

#[test]
fn metadata_precedence_and_subpaths_match_the_runner_contract() {
    let archive = snapshot(&[
        TestEntry::PaxGlobal(b"52 comment=de0fac2e4500dabe0009e67214ff5f5447ce83dd\n"),
        TestEntry::File("root/action.yaml", b"name: fallback"),
        TestEntry::File("root/Dockerfile", b"FROM scratch"),
        TestEntry::File("root/action.yml", b"name: preferred"),
        TestEntry::File("root/nested/action.yaml", b"name: nested"),
    ]);

    let root = inspect_archive(
        &archive,
        &ActionSubpath::root(),
        ActionBundleLimits::default(),
    )
    .unwrap();
    assert_eq!(root.kind(), ActionDefinitionKind::MetadataYaml);
    assert_eq!(root.path(), "action.yml");
    assert_eq!(root.bytes().as_ref(), b"name: preferred");

    let nested = inspect_archive(
        &archive,
        &ActionSubpath::new("nested").unwrap(),
        ActionBundleLimits::default(),
    )
    .unwrap();
    assert_eq!(nested.path(), "nested/action.yaml");
    assert_eq!(nested.bytes().as_ref(), b"name: nested");
}

#[test]
fn global_pax_metadata_is_narrowly_allowlisted() {
    let malicious = snapshot(&[
        TestEntry::PaxGlobal(b"19 path=../../evil\n"),
        TestEntry::File("root/action.yml", b"name: x"),
    ]);
    assert_eq!(
        inspect_archive(
            &malicious,
            &ActionSubpath::root(),
            ActionBundleLimits::default(),
        )
        .unwrap_err(),
        ActionArchiveError::UnsafePath
    );
}

#[test]
fn dockerfile_is_the_legacy_fallback_only_when_metadata_is_absent() {
    let archive = snapshot(&[
        TestEntry::File("root/dockerfile", b"FROM busybox"),
        TestEntry::File("root/Dockerfile", b"FROM scratch"),
    ]);
    let definition = inspect_archive(
        &archive,
        &ActionSubpath::root(),
        ActionBundleLimits::default(),
    )
    .unwrap();
    assert_eq!(definition.kind(), ActionDefinitionKind::Dockerfile);
    assert_eq!(definition.path(), "Dockerfile");
    assert_eq!(definition.bytes().as_ref(), b"FROM scratch");
}

#[test]
fn archive_budgets_are_independent_and_fail_closed() {
    let archive = snapshot(&[
        TestEntry::File("root/action.yml", b"name: x"),
        TestEntry::File("root/payload", &[7; 128]),
    ]);
    let expanded =
        ActionBundleLimits::new(ArchiveLimits::new(1024 * 1024).unwrap(), 10, 64, 32, 1024)
            .unwrap();
    assert_eq!(
        inspect_archive(&archive, &ActionSubpath::root(), expanded).unwrap_err(),
        ActionArchiveError::ResourceLimit
    );

    let entry_count =
        ActionBundleLimits::new(ArchiveLimits::new(1024 * 1024).unwrap(), 1, 1024, 32, 1024)
            .unwrap();
    assert_eq!(
        inspect_archive(&archive, &ActionSubpath::root(), entry_count).unwrap_err(),
        ActionArchiveError::ResourceLimit
    );
}

#[test]
fn traversal_links_special_entries_duplicates_and_multiple_roots_are_rejected() {
    let unsafe_link = snapshot(&[
        TestEntry::File("root/action.yml", b"name: x"),
        TestEntry::Symlink("root/bin/tool", "../../../outside"),
    ]);
    assert_eq!(
        inspect_archive(
            &unsafe_link,
            &ActionSubpath::root(),
            ActionBundleLimits::default(),
        )
        .unwrap_err(),
        ActionArchiveError::UnsafePath
    );

    let fifo = snapshot(&[
        TestEntry::File("root/action.yml", b"name: x"),
        TestEntry::Fifo("root/pipe"),
    ]);
    assert_eq!(
        inspect_archive(&fifo, &ActionSubpath::root(), ActionBundleLimits::default(),).unwrap_err(),
        ActionArchiveError::UnsupportedEntry
    );

    let duplicate = snapshot(&[
        TestEntry::File("root/action.yml", b"name: first"),
        TestEntry::File("root/action.yml", b"name: second"),
    ]);
    assert_eq!(
        inspect_archive(
            &duplicate,
            &ActionSubpath::root(),
            ActionBundleLimits::default(),
        )
        .unwrap_err(),
        ActionArchiveError::DuplicatePath
    );

    let roots = snapshot(&[
        TestEntry::File("first/action.yml", b"name: first"),
        TestEntry::File("second/data", b"x"),
    ]);
    assert_eq!(
        inspect_archive(
            &roots,
            &ActionSubpath::root(),
            ActionBundleLimits::default(),
        )
        .unwrap_err(),
        ActionArchiveError::UnsafePath
    );
}

#[test]
fn missing_definition_and_corrupt_gzip_are_typed() {
    let missing = snapshot(&[TestEntry::File("root/README.md", b"hello")]);
    assert_eq!(
        inspect_archive(
            &missing,
            &ActionSubpath::root(),
            ActionBundleLimits::default(),
        )
        .unwrap_err(),
        ActionArchiveError::MissingDefinition
    );

    let mut corrupt = build_archive(&[TestEntry::File("root/action.yml", b"name: x")]).to_vec();
    let last = corrupt.len() - 1;
    corrupt[last] ^= 0xff;
    let corrupt = snapshot_from_bytes(corrupt.into());
    assert_eq!(
        inspect_archive(
            &corrupt,
            &ActionSubpath::root(),
            ActionBundleLimits::default(),
        )
        .unwrap_err(),
        ActionArchiveError::Malformed
    );
}

#[test]
fn subpaths_and_limit_construction_reject_ambiguous_inputs() {
    for invalid in [
        "",
        "/nested",
        "nested/",
        "nested//child",
        "nested/../child",
        "a\\b",
    ] {
        assert!(ActionSubpath::new(invalid).is_err());
    }
    assert!(ActionBundleLimits::new(ArchiveLimits::new(1).unwrap(), 0, 1, 1, 1,).is_err());
}
