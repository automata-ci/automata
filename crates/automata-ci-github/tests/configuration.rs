mod support;

use std::time::Duration;

use automata_ci_github::{
    GithubHttpConfigurationError, GithubHttpEndpoint, GithubHttpLimits, GithubTrustedOrigins,
};
use url::Url;

#[test]
fn production_configuration_requires_https_and_clean_bases() {
    let limits = GithubHttpLimits::default();
    let http_oauth = Url::parse("http://github.example/").unwrap();
    let https_api = Url::parse("https://api.github.example/").unwrap();
    assert_eq!(
        GithubTrustedOrigins::new(http_oauth, https_api.clone(), "automata/0.1.0", limits)
            .unwrap_err(),
        GithubHttpConfigurationError::InvalidOAuthOrigin
    );

    let oauth = Url::parse("https://github.example/").unwrap();
    let base_without_trailing_slash = Url::parse("https://github.example/api/v3").unwrap();
    assert_eq!(
        GithubTrustedOrigins::new(oauth, base_without_trailing_slash, "automata/0.1.0", limits)
            .unwrap_err(),
        GithubHttpConfigurationError::InvalidApiBase
    );

    let origin_with_query = Url::parse("https://github.example/?tenant=other").unwrap();
    assert_eq!(
        GithubTrustedOrigins::new(origin_with_query, https_api, "automata/0.1.0", limits)
            .unwrap_err(),
        GithubHttpConfigurationError::InvalidOAuthOrigin
    );
}

#[test]
fn loopback_escape_hatch_rejects_non_loopback_http() {
    let error = GithubHttpEndpoint::new_for_loopback_emulator(
        Url::parse("http://example.com/").unwrap(),
        Url::parse("http://example.com/api/").unwrap(),
        "automata-tests/0.1.0",
        GithubHttpLimits::default(),
    )
    .unwrap_err();
    assert_eq!(error, GithubHttpConfigurationError::InvalidOAuthOrigin);

    for api_base in [
        "http://different.invalid/api/v3/",
        "http://automata-git.invalid:8088/api/v3/",
    ] {
        let error = GithubHttpEndpoint::new_for_mapped_emulator(
            Url::parse("http://automata-git.invalid/").unwrap(),
            Url::parse(api_base).unwrap(),
            "automata-tests/0.1.0",
            GithubHttpLimits::default(),
        )
        .unwrap_err();
        assert_eq!(error, GithubHttpConfigurationError::InvalidApiBase);
    }
}

#[test]
fn mapped_emulator_accepts_only_reserved_invalid_http() {
    GithubHttpEndpoint::new_for_mapped_emulator(
        Url::parse("http://automata-git.invalid/").unwrap(),
        Url::parse("http://automata-git.invalid/api/v3/").unwrap(),
        "automata-tests/0.1.0",
        GithubHttpLimits::default(),
    )
    .expect("reserved mapped emulator host");

    let error = GithubHttpEndpoint::new_for_mapped_emulator(
        Url::parse("http://automata-git.test/").unwrap(),
        Url::parse("http://automata-git.test/api/v3/").unwrap(),
        "automata-tests/0.1.0",
        GithubHttpLimits::default(),
    )
    .unwrap_err();
    assert_eq!(error, GithubHttpConfigurationError::InvalidOAuthOrigin);
}

#[test]
fn limits_are_nonzero_bounded_and_coherent() {
    let exact = GithubHttpLimits::new(
        1_024,
        2,
        10,
        Duration::from_secs(1),
        Duration::from_millis(2_001),
    )
    .expect("valid exact limits");
    assert_eq!(exact.request_timeout(), Duration::from_millis(2_001));
    let invalid =
        GithubHttpLimits::new(1_024, 2, 10, Duration::from_secs(2), Duration::from_secs(1));
    assert_eq!(
        invalid.unwrap_err(),
        GithubHttpConfigurationError::InvalidTimeout
    );
    assert_eq!(
        GithubHttpLimits::new(0, 2, 10, Duration::from_secs(1), Duration::from_secs(2))
            .unwrap_err(),
        GithubHttpConfigurationError::InvalidResponseByteLimit
    );
}
