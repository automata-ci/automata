use automata_ci_results_github::GithubResultsHttpLimits;

#[test]
fn artifact_http_body_limits_are_hard_bounded() {
    assert!(GithubResultsHttpLimits::new(1, 1).is_ok());
    assert!(
        GithubResultsHttpLimits::new(
            GithubResultsHttpLimits::MAXIMUM_TWIRP_BODY_BYTES,
            GithubResultsHttpLimits::MAXIMUM_AZURE_BODY_BYTES,
        )
        .is_ok()
    );
    assert!(
        GithubResultsHttpLimits::new(
            GithubResultsHttpLimits::MAXIMUM_TWIRP_BODY_BYTES + 1,
            GithubResultsHttpLimits::MAXIMUM_AZURE_BODY_BYTES,
        )
        .is_err()
    );
    assert!(
        GithubResultsHttpLimits::new(
            GithubResultsHttpLimits::MAXIMUM_TWIRP_BODY_BYTES,
            GithubResultsHttpLimits::MAXIMUM_AZURE_BODY_BYTES + 1,
        )
        .is_err()
    );
    assert!(GithubResultsHttpLimits::new(0, 1).is_err());
    assert!(GithubResultsHttpLimits::new(1, 0).is_err());
}
