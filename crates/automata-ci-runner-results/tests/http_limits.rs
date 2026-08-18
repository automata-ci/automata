use automata_ci_runner_results::ActionsResultsHttpLimits;

#[test]
fn artifact_http_body_limits_are_hard_bounded() {
    assert!(ActionsResultsHttpLimits::new(1, 1).is_ok());
    assert!(
        ActionsResultsHttpLimits::new(
            ActionsResultsHttpLimits::MAXIMUM_TWIRP_BODY_BYTES,
            ActionsResultsHttpLimits::MAXIMUM_AZURE_BODY_BYTES,
        )
        .is_ok()
    );
    assert!(
        ActionsResultsHttpLimits::new(
            ActionsResultsHttpLimits::MAXIMUM_TWIRP_BODY_BYTES + 1,
            ActionsResultsHttpLimits::MAXIMUM_AZURE_BODY_BYTES,
        )
        .is_err()
    );
    assert!(
        ActionsResultsHttpLimits::new(
            ActionsResultsHttpLimits::MAXIMUM_TWIRP_BODY_BYTES,
            ActionsResultsHttpLimits::MAXIMUM_AZURE_BODY_BYTES + 1,
        )
        .is_err()
    );
    assert!(ActionsResultsHttpLimits::new(0, 1).is_err());
    assert!(ActionsResultsHttpLimits::new(1, 0).is_err());
}
