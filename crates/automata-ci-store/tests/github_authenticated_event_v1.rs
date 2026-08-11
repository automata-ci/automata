use automata_ci_store::{
    GithubAuthenticatedEventKind, GithubAuthenticatedEventV1, GithubSubjectEvidenceValueError,
};

#[test]
fn event_kind_and_full_ref_are_exact_and_bounded() {
    for (kind, name, git_ref) in [
        (
            GithubAuthenticatedEventKind::Push,
            "push",
            "refs/heads/main",
        ),
        (
            GithubAuthenticatedEventKind::PullRequest,
            "pull_request",
            "refs/pull/7/merge",
        ),
        (
            GithubAuthenticatedEventKind::MergeGroup,
            "merge_group",
            "refs/heads/merge-queue/main/group-7",
        ),
    ] {
        let event = GithubAuthenticatedEventV1::new(kind, git_ref).expect("valid event");
        assert_eq!(event.kind(), kind);
        assert_eq!(kind.as_str(), name);
        assert_eq!(event.git_ref(), git_ref);
        let debug = format!("{event:?}");
        assert!(!debug.contains(git_ref));
    }
}

#[test]
fn malformed_or_excessive_refs_fail_closed() {
    for git_ref in [
        "",
        "main",
        "refs/",
        "refs/heads/main\nother",
        &format!("refs/heads/{}", "x".repeat(1_025)),
    ] {
        assert_eq!(
            GithubAuthenticatedEventV1::new(GithubAuthenticatedEventKind::Push, git_ref)
                .expect_err("invalid ref"),
            GithubSubjectEvidenceValueError::InvalidAuthenticatedEvent
        );
    }
}
