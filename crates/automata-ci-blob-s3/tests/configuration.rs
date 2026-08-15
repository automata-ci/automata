use std::time::Duration;

use automata_ci_blob_s3::{
    MAX_S3_PRIVATE_CA_PEM_BYTES, S3AtRestEncryption, S3BlobStoreConfig, S3BlobStoreConfigError,
    S3TlsTrust, StaticS3Credentials,
};
use rcgen::{BasicConstraints, CertificateParams, IsCa, KeyPair, KeyUsagePurpose};
use url::Url;

#[test]
fn production_requires_a_credential_free_https_root_endpoint() {
    let valid = S3BlobStoreConfig::new(
        Url::parse("https://objects.example.test/").expect("URL"),
        "us-east-1",
        "automata-production",
        Some("tenant-a".to_owned()),
        false,
        S3TlsTrust::web_pki(),
        Duration::from_secs(10),
    );
    assert!(valid.is_ok());

    for endpoint in [
        "http://objects.example.test/",
        "https://user:password@objects.example.test/",
        "https://objects.example.test/base/",
        "https://objects.example.test/?query=true",
    ] {
        assert!(
            S3BlobStoreConfig::new(
                Url::parse(endpoint).expect("URL fixture"),
                "us-east-1",
                "automata-production",
                None,
                false,
                S3TlsTrust::web_pki(),
                Duration::from_secs(10),
            )
            .is_err(),
            "accepted {endpoint}"
        );
    }
}

#[test]
fn development_http_is_restricted_to_loopback() {
    for endpoint in ["http://127.0.0.1:9000/", "http://[::1]:9000/"] {
        assert!(
            S3BlobStoreConfig::loopback_development(
                Url::parse(endpoint).expect("URL"),
                "us-east-1",
                "automata-dev",
                None,
                Duration::from_secs(10),
            )
            .is_ok(),
            "rejected {endpoint}"
        );
    }
    for endpoint in [
        "http://localhost:9000/",
        "http://objects.example.test/",
        "http://192.0.2.1:9000/",
    ] {
        assert!(
            S3BlobStoreConfig::loopback_development(
                Url::parse(endpoint).expect("URL"),
                "us-east-1",
                "automata-dev",
                None,
                Duration::from_secs(10),
            )
            .is_err(),
            "accepted {endpoint}"
        );
    }
}

#[test]
fn namespaces_and_credentials_fail_closed() {
    for bucket in ["ABCD", "ab", "-bad", "bad..dots", "127.0.0.1"] {
        assert!(
            S3BlobStoreConfig::new(
                Url::parse("https://objects.example.test/").expect("URL"),
                "us-east-1",
                bucket,
                None,
                false,
                S3TlsTrust::web_pki(),
                Duration::from_secs(10),
            )
            .is_err(),
            "accepted bucket {bucket}"
        );
    }
    for prefix in ["/absolute", "ends/", "a//b", "a/../b"] {
        assert!(
            S3BlobStoreConfig::new(
                Url::parse("https://objects.example.test/").expect("URL"),
                "us-east-1",
                "automata-production",
                Some(prefix.to_owned()),
                false,
                S3TlsTrust::web_pki(),
                Duration::from_secs(10),
            )
            .is_err(),
            "accepted prefix {prefix}"
        );
    }
    assert!(StaticS3Credentials::new("", "secret", None).is_err());
    assert!(StaticS3Credentials::new("access", "", None).is_err());
    assert!(StaticS3Credentials::new("access", "secret", Some(String::new())).is_err());
}

#[test]
fn credential_debug_output_is_redacted() {
    let credentials = StaticS3Credentials::new(
        "visible-access-key",
        "very-secret-value",
        Some("secret-session-token".to_owned()),
    )
    .expect("credentials");
    let debug = format!("{credentials:?}");
    for secret in [
        "visible-access-key",
        "very-secret-value",
        "secret-session-token",
    ] {
        assert!(!debug.contains(secret));
    }
}

#[test]
fn encryption_at_rest_is_mandatory_and_kms_identity_is_exact() {
    let config = S3BlobStoreConfig::new(
        Url::parse("https://objects.example.test/").expect("URL"),
        "us-east-1",
        "automata-production",
        None,
        false,
        S3TlsTrust::web_pki(),
        Duration::from_secs(10),
    )
    .expect("S3 configuration");
    assert_eq!(config.at_rest_encryption(), &S3AtRestEncryption::aes256());

    let key_arn = "arn:aws:kms:us-east-1:123456789012:key/00000000-0000-0000-0000-000000000001";
    let kms = S3AtRestEncryption::aws_kms(key_arn).expect("exact KMS identity");
    let configured = config.with_at_rest_encryption(kms.clone());
    assert_eq!(configured.at_rest_encryption(), &kms);

    for invalid in ["", " key", "key\n"] {
        assert!(S3AtRestEncryption::aws_kms(invalid).is_err());
        assert!(S3AtRestEncryption::aws_kms_dsse(invalid).is_err());
    }
}

#[test]
fn private_ca_trust_accepts_exactly_one_valid_ca_and_redacts_it() {
    let ca_pem = certificate_pem(true);
    let trust = S3TlsTrust::private_ca(ca_pem.clone()).expect("one exact private CA");
    assert_eq!(
        format!("{trust:?}"),
        "S3TlsTrust::PrivateCa([certificate redacted])"
    );

    let mut bundle = ca_pem.clone();
    bundle.extend_from_slice(&certificate_pem(true));
    for invalid in [
        Vec::new(),
        b"not a PEM certificate".to_vec(),
        certificate_pem(false),
        bundle,
        vec![b'x'; MAX_S3_PRIVATE_CA_PEM_BYTES + 1],
    ] {
        assert_eq!(
            S3TlsTrust::private_ca(invalid),
            Err(S3BlobStoreConfigError::InvalidPrivateCa)
        );
    }
}

#[test]
fn private_ca_trust_is_incompatible_with_plaintext() {
    let result = S3BlobStoreConfig::new(
        Url::parse("http://127.0.0.1:9000/").expect("URL"),
        "us-east-1",
        "automata-tests",
        None,
        true,
        S3TlsTrust::private_ca(certificate_pem(true)).expect("private CA"),
        Duration::from_secs(10),
    );
    assert_eq!(result, Err(S3BlobStoreConfigError::PrivateCaRequiresHttps));
}

fn certificate_pem(is_ca: bool) -> Vec<u8> {
    let key = KeyPair::generate().expect("certificate key");
    let mut params = CertificateParams::new(Vec::<String>::new()).expect("certificate params");
    if is_ca {
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    }
    params
        .self_signed(&key)
        .expect("self-signed certificate")
        .pem()
        .into_bytes()
}
