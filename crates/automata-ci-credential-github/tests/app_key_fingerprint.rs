mod support;

use automata_ci_credential::ProviderResourceId;
use automata_ci_credential_github::{
    GithubAppCredentialBroker, GithubAppCredentialConfig, GithubInstallationId,
};
use support::{INSTALLATION_ID, ISSUER, pkcs8_private_key, private_key};

const EXPECTED_SPKI_SHA256: &str =
    "efeda9bfead9fd0594f6a5cf6fdf6c163116a3b1fad6d73cea05295b68fd1794";
const EXPECTED_BROKER_POLICY_V2_SHA256: &str =
    "ce7b0f55188ada8d003efc3765e87c1bf0860501437ed5a6b3ded9e08b3e6612";
const EXPECTED_COMPATIBLE_BROKER_POLICY_V1_SHA256: &str =
    "79035a0f4a3a0d97d3843099ae48f5ec5c85fb2a10b00fa3849660bdbc642f0d";

#[test]
fn pkcs1_and_pkcs8_derive_the_same_exact_spki_fingerprint() {
    let config = GithubAppCredentialConfig::github_dot_com(
        ProviderResourceId::new(ISSUER).expect("issuer"),
        GithubInstallationId::new(INSTALLATION_ID).expect("installation"),
        "automata-ci-spki-test/0.1.0",
    )
    .expect("configuration");
    let pkcs1 = GithubAppCredentialBroker::new(config.clone(), &private_key()).expect("PKCS#1");
    let pkcs8 = GithubAppCredentialBroker::new(config, &pkcs8_private_key()).expect("PKCS#8");

    assert_eq!(pkcs1.app_key_spki_sha256(), pkcs8.app_key_spki_sha256());
    assert_eq!(
        pkcs1.broker_policy_fingerprint(),
        pkcs8.broker_policy_fingerprint()
    );
    assert_eq!(
        pkcs1.compatible_historical_broker_policy_fingerprints(),
        pkcs8.compatible_historical_broker_policy_fingerprints()
    );
    assert_ne!(
        pkcs1.broker_policy_fingerprint(),
        pkcs1.compatible_historical_broker_policy_fingerprints()[0]
    );
    assert_eq!(
        pkcs1.broker_policy_fingerprint().to_string(),
        EXPECTED_BROKER_POLICY_V2_SHA256
    );
    assert_eq!(
        pkcs1.compatible_historical_broker_policy_fingerprints()[0].to_string(),
        EXPECTED_COMPATIBLE_BROKER_POLICY_V1_SHA256
    );
    assert_eq!(
        pkcs1.app_key_spki_sha256().to_string(),
        EXPECTED_SPKI_SHA256
    );
}
