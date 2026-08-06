use automata::build_info::{BuildInfo, is_full_git_object_id};

#[test]
fn accepts_complete_git_object_ids_only() {
    assert!(is_full_git_object_id(&"a".repeat(40)));
    assert!(is_full_git_object_id(&"B".repeat(64)));
    assert!(!is_full_git_object_id(&"c".repeat(12)));
    assert!(!is_full_git_object_id(&"z".repeat(40)));
}

#[test]
fn embedded_commit_is_unknown_or_verifiable() {
    let build = BuildInfo::current();

    assert!(!build.version.is_empty());
    assert!(build.commit == "unknown" || build.has_verifiable_commit());
}
