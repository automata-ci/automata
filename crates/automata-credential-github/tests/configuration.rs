mod support;

use std::{sync::Arc, time::Duration};

use automata_auth::secret::SecretString;
use automata_credential::ProviderResourceId;
use automata_credential_github::{
    GithubAppCredentialBroker, GithubAppCredentialConfig, GithubAppHttpLimits, GithubInstallationId,
};
use support::{FixedClock, INSTALLATION_ID, ISSUER, NOW, pkcs8_private_key, private_key};
use url::Url;

fn issuer() -> ProviderResourceId {
    ProviderResourceId::new(ISSUER).unwrap()
}

fn installation() -> GithubInstallationId {
    GithubInstallationId::new(INSTALLATION_ID).unwrap()
}

#[test]
fn production_requires_a_credential_free_https_base() {
    for invalid in [
        "http://api.github.com/",
        "https://user:pass@api.github.com/",
        "https://api.github.com/path",
        "https://api.github.com/?query=value",
        "https://api.github.com/#fragment",
    ] {
        assert!(
            GithubAppCredentialConfig::new(
                Url::parse(invalid).unwrap(),
                issuer(),
                installation(),
                "automata/0.1.0",
                GithubAppHttpLimits::default(),
            )
            .is_err(),
            "accepted {invalid}"
        );
    }
    assert!(
        GithubAppCredentialConfig::new(
            Url::parse("https://github.example/api/v3/").unwrap(),
            issuer(),
            installation(),
            "automata/0.1.0",
            GithubAppHttpLimits::default(),
        )
        .is_ok()
    );
}

#[test]
fn loopback_escape_hatch_rejects_non_loopback_http() {
    assert!(
        GithubAppCredentialConfig::new_for_loopback_testing(
            Url::parse("http://example.test/api/v3/").unwrap(),
            issuer(),
            installation(),
            "automata-tests/0.1.0",
            GithubAppHttpLimits::default(),
        )
        .is_err()
    );
    assert!(
        GithubAppCredentialConfig::new_for_loopback_testing(
            Url::parse("http://127.0.0.1:4567/api/v3/").unwrap(),
            issuer(),
            installation(),
            "automata-tests/0.1.0",
            GithubAppHttpLimits::default(),
        )
        .is_ok()
    );
}

#[test]
fn identifiers_limits_and_key_material_are_validated() {
    assert!(GithubInstallationId::new(0).is_err());
    assert!(GithubAppHttpLimits::new(0, Duration::from_secs(1), Duration::from_secs(2)).is_err());
    assert!(GithubAppHttpLimits::new(10, Duration::from_secs(3), Duration::from_secs(2)).is_err());
    let invalid_issuer = ProviderResourceId::new("bad:issuer").unwrap();
    assert!(
        GithubAppCredentialConfig::github_dot_com(invalid_issuer, installation(), "automata/0.1.0")
            .is_err()
    );

    let config =
        GithubAppCredentialConfig::github_dot_com(issuer(), installation(), "automata/0.1.0")
            .unwrap();
    let invalid_key = SecretString::new("not a PEM key").unwrap();
    assert!(
        GithubAppCredentialBroker::with_clock(config, &invalid_key, Arc::new(FixedClock(NOW)),)
            .is_err()
    );

    let config =
        GithubAppCredentialConfig::github_dot_com(issuer(), installation(), "automata/0.1.0")
            .unwrap();
    assert!(
        GithubAppCredentialBroker::with_clock(config, &private_key(), Arc::new(FixedClock(59)))
            .is_ok()
    );
}

#[test]
fn only_bounded_rsa_pkcs1_or_pkcs8_pem_is_accepted() {
    let make_config = || {
        GithubAppCredentialConfig::github_dot_com(issuer(), installation(), "automata/0.1.0")
            .unwrap()
    };
    assert!(
        GithubAppCredentialBroker::with_clock(
            make_config(),
            &pkcs8_private_key(),
            Arc::new(FixedClock(NOW)),
        )
        .is_ok()
    );

    let with_preamble = SecretString::new(format!(
        "ignored preamble\n{}",
        private_key().expose_secret()
    ))
    .unwrap();
    let two_keys = SecretString::new(format!(
        "{}{}",
        private_key().expose_secret(),
        private_key().expose_secret()
    ))
    .unwrap();
    let wrong_label = SecretString::new(
        private_key()
            .expose_secret()
            .replace("RSA PRIVATE KEY", "EC PRIVATE KEY"),
    )
    .unwrap();
    let oversized = SecretString::new("x".repeat(32 * 1_024 + 1)).unwrap();
    for invalid in [with_preamble, two_keys, wrong_label, oversized] {
        assert!(
            GithubAppCredentialBroker::with_clock(
                make_config(),
                &invalid,
                Arc::new(FixedClock(NOW)),
            )
            .is_err()
        );
    }
}
